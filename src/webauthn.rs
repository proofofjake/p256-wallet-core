//! WebAuthn: reading a security key's public key at registration, and turning its assertions into the
//! `WebAuthnAuth` struct Coinbase Smart Wallet verifies onchain (github.com/base/webauthn-sol).

use crate::abi::{self, Token};
use crate::cbor;
use crate::error::{bad_assertion, invalid, Result};
use crate::hash::sha256;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use ruint::aliases::U256;

pub const FLAG_USER_PRESENT: u8 = 0x01;
pub const FLAG_USER_VERIFIED: u8 = 0x04;
pub const FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0x40;

/// A P-256 public key that is a valid point on the curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl PublicKey {
    /// Rejects coordinates that aren't a point on P-256: registering one would create an account no key can sign for.
    pub fn new(x: [u8; 32], y: [u8; 32]) -> Result<Self> {
        let key = PublicKey { x, y };
        key.verifying_key()?;
        Ok(key)
    }

    /// The 64-byte `x || y` form Coinbase Smart Wallet stores as an owner.
    pub fn owner_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.x);
        out[32..].copy_from_slice(&self.y);
        out
    }

    fn verifying_key(&self) -> Result<VerifyingKey> {
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..].copy_from_slice(&self.owner_bytes());
        VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| invalid("Public key is not a valid P-256 point"))
    }
}

/// Parsed authenticator data (WebAuthn §6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatorData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    /// Present at registration: the new credential's ID and public key.
    pub attested: Option<(Vec<u8>, PublicKey)>,
}

impl AuthenticatorData {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let error = |detail: &str| invalid(format!("Authenticator data is malformed: {detail}"));
        if data.len() < 37 {
            return Err(error("too short"));
        }
        let rp_id_hash = data[..32].try_into().expect("32 bytes");
        let flags = data[32];
        let sign_count = u32::from_be_bytes(data[33..37].try_into().expect("4 bytes"));
        if flags & FLAG_ATTESTED_CREDENTIAL_DATA == 0 {
            return Ok(AuthenticatorData { rp_id_hash, flags, sign_count, attested: None });
        }
        // aaguid (16) | credentialIdLength (2) | credentialId | credentialPublicKey (COSE_Key)
        let rest = data.get(37 + 16..).ok_or_else(|| error("truncated"))?;
        let id_length =
            u16::from_be_bytes(rest.get(..2).ok_or_else(|| error("truncated"))?.try_into().expect("2 bytes"));
        let rest = &rest[2..];
        let credential_id = rest.get(..id_length as usize).ok_or_else(|| error("truncated credential ID"))?.to_vec();
        let (cose_key, _) = cbor::decode_prefix(&rest[id_length as usize..])?;
        let public_key = public_key_from_cose(&cose_key)?;
        Ok(AuthenticatorData { rp_id_hash, flags, sign_count, attested: Some((credential_id, public_key)) })
    }
}

/// Reads an EC2 / ES256 / P-256 COSE_Key.
pub fn public_key_from_cose(key: &cbor::Value) -> Result<PublicKey> {
    let int = |label| key.get_int(label).and_then(cbor::Value::as_int);
    if int(1) != Some(2) {
        return Err(invalid("Security key returned a non-EC key"));
    }
    if int(3) != Some(-7) {
        return Err(invalid("Security key returned a key for an algorithm other than ES256"));
    }
    if int(-1) != Some(1) {
        return Err(invalid("Security key returned a key on a curve other than P-256"));
    }
    let coordinate = |label| -> Result<[u8; 32]> {
        key.get_int(label)
            .and_then(cbor::Value::as_bytes)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| invalid("Security key's public key is missing a coordinate"))
    };
    PublicKey::new(coordinate(-2)?, coordinate(-3)?)
}

/// Extracts the public key from a registration's attestation object, checking it belongs to `credential_id`.
pub fn public_key_from_attestation_object(attestation_object: &[u8], credential_id: &[u8]) -> Result<PublicKey> {
    let object = cbor::decode(attestation_object)?;
    let auth_data = object
        .get_text("authData")
        .and_then(cbor::Value::as_bytes)
        .ok_or_else(|| invalid("Attestation object has no authenticator data"))?;
    let parsed = AuthenticatorData::parse(auth_data)?;
    let (attested_id, public_key) =
        parsed.attested.ok_or_else(|| invalid("Attestation has no credential public key"))?;
    if attested_id != credential_id {
        return Err(invalid("Attestation is for a different credential"));
    }
    Ok(public_key)
}

/// An assertion as returned by the authenticator, all fields raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    /// ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }`.
    pub signature_der: Vec<u8>,
}

/// `(r, s)` with `s` in low form. Coinbase Smart Wallet rejects `s > n/2` to prevent malleability, but
/// authenticators (YubiKeys included) return either form, so it is normalized here.
pub fn parse_signature(der: &[u8]) -> Result<Signature> {
    let signature =
        Signature::from_der(der).map_err(|_| bad_assertion("Security key returned a malformed signature"))?;
    Ok(signature.normalize_s().unwrap_or(signature))
}

/// `"challenge":"<base64url(challenge)>"`, the exact bytes the onchain verifier compares at `challengeIndex`.
pub fn challenge_needle(challenge: &[u8]) -> String {
    format!("\"challenge\":\"{}\"", base64url(challenge))
}

const TYPE_NEEDLE: &str = "\"type\":\"webauthn.get\"";

/// Checks `assertion` signs `challenge` with `public_key`, then returns `abi.encode(WebAuthnAuth)`:
/// `(bytes authenticatorData, string clientDataJSON, uint256 challengeIndex, uint256 typeIndex, uint256 r, uint256 s)`.
///
/// Every check the onchain verifier makes is repeated here (user-present flag, challenge and type at their
/// offsets, low-s, the P-256 signature), so a bad response fails with a clear message instead of an opaque
/// onchain validation error.
pub fn signature_data(assertion: &Assertion, challenge: &[u8], public_key: &PublicKey) -> Result<Vec<u8>> {
    let auth = AuthenticatorData::parse(&assertion.authenticator_data)
        .map_err(|_| bad_assertion("Security key returned malformed authenticator data"))?;
    if auth.flags & FLAG_USER_PRESENT == 0 {
        return Err(bad_assertion("Security key response is missing user presence (touch the key)"));
    }
    let json = &assertion.client_data_json;
    let challenge_index = find(json, challenge_needle(challenge).as_bytes())
        .ok_or_else(|| bad_assertion("Security key signed a different challenge than this request"))?;
    let type_index =
        find(json, TYPE_NEEDLE.as_bytes()).ok_or_else(|| bad_assertion("Security key response is not an assertion"))?;

    let signature = parse_signature(&assertion.signature_der)?;
    let mut message = assertion.authenticator_data.clone();
    message.extend_from_slice(&sha256(json));
    public_key
        .verifying_key()?
        .verify(&message, &signature)
        .map_err(|_| bad_assertion("Signature doesn't match this key's registered public key"))?;

    let (r, s) = signature.split_bytes();
    Ok(abi::encode(&[Token::Tuple(vec![
        Token::Bytes(assertion.authenticator_data.clone()),
        // `string clientDataJSON` encodes identically to bytes; the raw bytes are kept so offsets stay exact.
        Token::Bytes(json.clone()),
        Token::Uint(U256::from(challenge_index)),
        Token::Uint(U256::from(type_index)),
        Token::Uint(U256::from_be_slice(&r)),
        Token::Uint(U256::from_be_slice(&s)),
    ])]))
}

/// Base64url without padding (RFC 4648 §5), as WebAuthn encodes the challenge in `clientDataJSON`.
pub fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n =
            (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(n >> (18 - 6 * i) & 0x3f) as usize] as char);
        }
    }
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};

    /// Signs like a security key would, including high-s signatures half the time.
    pub fn assert_with(key: &SigningKey, challenge: &[u8], flags: u8) -> Assertion {
        let mut authenticator_data = sha256(b"p256wallet.dev").to_vec();
        authenticator_data.extend_from_slice(&[flags, 0, 0, 0, 1]);
        let client_data_json = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://p256wallet.dev\",\"crossOrigin\":false}}",
            base64url(challenge)
        )
        .into_bytes();
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&sha256(&client_data_json));
        let signature: Signature = key.sign(&message);
        Assertion {
            credential_id: sha256(key.verifying_key().to_encoded_point(false).as_bytes()).to_vec(),
            authenticator_data,
            client_data_json,
            signature_der: signature.to_der().as_bytes().to_vec(),
        }
    }

    pub fn public_key(key: &SigningKey) -> PublicKey {
        let point = key.verifying_key().to_encoded_point(false);
        PublicKey::new((*point.x().unwrap()).into(), (*point.y().unwrap()).into()).unwrap()
    }

    pub fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32].into()).unwrap()
    }

    fn cbor_header(major: u8, value: usize) -> Vec<u8> {
        match value {
            0..=23 => vec![major << 5 | value as u8],
            24..=255 => vec![major << 5 | 24, value as u8],
            _ => vec![major << 5 | 25, (value >> 8) as u8, value as u8],
        }
    }

    fn cbor_int(value: i64) -> Vec<u8> {
        if value >= 0 {
            cbor_header(0, value as usize)
        } else {
            cbor_header(1, (-1 - value) as usize)
        }
    }

    fn cbor_bytes(bytes: &[u8]) -> Vec<u8> {
        [cbor_header(2, bytes.len()), bytes.to_vec()].concat()
    }

    fn cbor_text(text: &str) -> Vec<u8> {
        [cbor_header(3, text.len()), text.as_bytes().to_vec()].concat()
    }

    fn attestation_object(key: &PublicKey, credential_id: &[u8], alg: i64) -> Vec<u8> {
        let cose = [
            cbor_header(5, 5),
            cbor_int(1),
            cbor_int(2),
            cbor_int(3),
            cbor_int(alg),
            cbor_int(-1),
            cbor_int(1),
            cbor_int(-2),
            cbor_bytes(&key.x),
            cbor_int(-3),
            cbor_bytes(&key.y),
        ]
        .concat();
        let mut auth_data = sha256(b"example.com").to_vec();
        auth_data.extend_from_slice(&[FLAG_USER_PRESENT | FLAG_ATTESTED_CREDENTIAL_DATA, 0, 0, 0, 7]);
        auth_data.extend_from_slice(&[0xaa; 16]);
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend(cose);
        [
            cbor_header(5, 3),
            cbor_text("fmt"),
            cbor_text("none"),
            cbor_text("attStmt"),
            cbor_header(5, 0),
            cbor_text("authData"),
            cbor_bytes(&auth_data),
        ]
        .concat()
    }

    #[test]
    fn reads_public_key_from_attestation() {
        let key = public_key(&test_key(1));
        let credential_id: Vec<u8> = (0..48).collect();
        let object = attestation_object(&key, &credential_id, -7);
        assert_eq!(public_key_from_attestation_object(&object, &credential_id).unwrap(), key);
        assert!(public_key_from_attestation_object(&object, &[1, 2, 3]).is_err());
        assert!(public_key_from_attestation_object(&attestation_object(&key, &credential_id, -257), &credential_id)
            .is_err());
    }

    #[test]
    fn rejects_points_off_the_curve() {
        let key = public_key(&test_key(1));
        let mut y = key.y;
        y[31] ^= 1;
        assert!(PublicKey::new(key.x, y).is_err());
    }

    #[test]
    fn encodes_a_verified_assertion() {
        let key = test_key(2);
        let challenge = [0x42u8; 32];
        let assertion = assert_with(&key, &challenge, FLAG_USER_PRESENT | FLAG_USER_VERIFIED);
        let encoded = signature_data(&assertion, &challenge, &public_key(&key)).unwrap();

        let decoder = abi::Decoder::new(&encoded);
        let base = decoder.usize(0).unwrap();
        let json = decoder.bytes(base + 32, base).unwrap();
        let challenge_index = decoder.usize(base + 64).unwrap();
        let type_index = decoder.usize(base + 96).unwrap();
        let s = decoder.uint(base + 160).unwrap();
        let needle = challenge_needle(&challenge);
        assert_eq!(&json[challenge_index..challenge_index + needle.len()], needle.as_bytes());
        assert_eq!(&json[type_index..type_index + TYPE_NEEDLE.len()], TYPE_NEEDLE.as_bytes());
        let half_n =
            U256::from_str_radix("7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8", 16).unwrap();
        assert!(s <= half_n);
    }

    #[test]
    fn normalizes_high_s() {
        let half_n =
            U256::from_str_radix("7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8", 16).unwrap();
        let key = test_key(3);
        let mut saw_high_s = false;
        for i in 0..64u8 {
            let signature: Signature = key.sign(&[i]);
            let (_, s) = signature.split_bytes();
            saw_high_s |= U256::from_be_slice(&s) > half_n;
            let normalized = parse_signature(signature.to_der().as_bytes()).unwrap();
            let (_, s) = normalized.split_bytes();
            assert!(U256::from_be_slice(&s) <= half_n);
            assert!(key.verifying_key().verify(&[i], &normalized).is_ok());
        }
        assert!(saw_high_s, "64 signatures without a high-s value is astronomically unlikely");
    }

    #[test]
    fn rejects_bad_assertions() {
        let key = test_key(4);
        let challenge = [7u8; 32];
        let good = assert_with(&key, &challenge, FLAG_USER_PRESENT);
        let public_key = public_key(&key);

        assert!(signature_data(&good, &[8u8; 32], &public_key).is_err(), "wrong challenge");
        assert!(signature_data(&good, &challenge, &self::public_key(&test_key(5))).is_err(), "wrong key");
        let no_presence = assert_with(&key, &challenge, 0);
        assert!(signature_data(&no_presence, &challenge, &public_key).is_err(), "no user presence");
        let mut tampered = good.clone();
        tampered.authenticator_data[36] ^= 1;
        assert!(signature_data(&tampered, &challenge, &public_key).is_err(), "tampered authenticator data");
        let mut bad_der = good.clone();
        bad_der.signature_der[0] = 0x31;
        assert!(signature_data(&bad_der, &challenge, &public_key).is_err(), "bad DER");
    }

    #[test]
    fn base64url_vectors() {
        assert_eq!(base64url(&[0xfb, 0xff, 0xfe]), "-__-");
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64url(&[0u8; 32]).len(), 43);
    }
}
