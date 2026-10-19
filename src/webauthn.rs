//! WebAuthn: reading a security key's public key at registration, and turning its assertions into the
//! `WebAuthnAuth` struct Coinbase Smart Wallet verifies onchain (github.com/base/webauthn-sol).

use crate::abi::{self, Token};
use crate::cbor;
use crate::error::{bad_assertion, invalid, refused, Result};
use crate::hash::sha256;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use ruint::aliases::U256;

pub const FLAG_USER_PRESENT: u8 = 0x01;
pub const FLAG_USER_VERIFIED: u8 = 0x04;
/// Set by credentials that can be synced or backed up (iCloud Keychain, Google Password Manager, phone passkeys),
/// never by hardware security keys.
pub const FLAG_BACKUP_ELIGIBLE: u8 = 0x08;
pub const FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0x40;
pub const FLAG_EXTENSION_DATA: u8 = 0x80;

/// `credProtect` level 3: the authenticator itself refuses to use the credential without user verification (PIN).
pub const CRED_PROTECT_UV_REQUIRED: i64 = 3;

/// Half the P-256 group order. Coinbase Smart Wallet rejects signatures with `s` above it.
pub const P256_HALF_N: U256 =
    U256::from_limbs([0x79dc_e561_7e31_92a8, 0xde73_7d56_d38b_cf42, 0x7fff_ffff_ffff_ffff, 0x7fff_ffff_8000_0000]);

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
    /// Authenticator extension outputs, parsed at registration (e.g. `credProtect`).
    pub extensions: Option<cbor::Value>,
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
            return Ok(AuthenticatorData { rp_id_hash, flags, sign_count, attested: None, extensions: None });
        }
        // aaguid (16) | credentialIdLength (2) | credentialId | credentialPublicKey (COSE_Key)
        let rest = data.get(37 + 16..).ok_or_else(|| error("truncated"))?;
        let id_length =
            u16::from_be_bytes(rest.get(..2).ok_or_else(|| error("truncated"))?.try_into().expect("2 bytes"));
        let rest = &rest[2..];
        let credential_id = rest.get(..id_length as usize).ok_or_else(|| error("truncated credential ID"))?.to_vec();
        let rest = &rest[id_length as usize..];
        // Both are encoded by the authenticator itself, so they must be canonical CTAP2 CBOR.
        let (cose_key, used) = cbor::decode_prefix(rest, cbor::Form::Canonical)?;
        let public_key = public_key_from_cose(&cose_key)?;
        // Extensions follow the key when the ED flag is set; otherwise nothing may follow it.
        let rest = &rest[used..];
        let extensions = match flags & FLAG_EXTENSION_DATA {
            0 if rest.is_empty() => None,
            0 => return Err(error("unexpected bytes after the public key")),
            _ => Some(cbor::decode(rest, cbor::Form::Canonical)?),
        };
        Ok(AuthenticatorData { rp_id_hash, flags, sign_count, attested: Some((credential_id, public_key)), extensions })
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

/// A newly registered credential, as checked by [`register`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub public_key: PublicKey,
    /// The key verified its PIN (or biometric) while registering.
    pub user_verified: bool,
    /// The key reported `credProtect` level 3, so it will refuse to sign without its PIN regardless of what any app
    /// asks for. Always true when the registration required a PIN.
    pub pin_enforced_by_key: bool,
}

/// Checks a registration response and extracts its public key. Refuses:
/// - a response for another credential, or another relying party (`rp_id`);
/// - a credential that can be synced or backed up (a passkey, not a hardware key);
/// - when `require_user_verification` is set (the user chose a PIN), a response without user verification, or from a
///   key that didn't apply `credProtect` level 3. A PIN only protects a key if the key enforces it: a flag the app
///   stores can be cleared by anyone who can edit the app's storage or a backup file.
pub fn register(
    attestation_object: &[u8],
    credential_id: &[u8],
    rp_id: &str,
    require_user_verification: bool,
) -> Result<Registration> {
    // Assembled by the browser or OS, not the authenticator, so it isn't required to be canonical.
    let object = cbor::decode(attestation_object, cbor::Form::Relaxed)?;
    let auth_data = object
        .get_text("authData")
        .and_then(cbor::Value::as_bytes)
        .ok_or_else(|| invalid("Attestation object has no authenticator data"))?;
    let parsed = AuthenticatorData::parse(auth_data)?;
    if parsed.rp_id_hash != sha256(rp_id.as_bytes()) {
        return Err(invalid(format!("Registration is for a different relying party than {rp_id}")));
    }
    if parsed.flags & FLAG_USER_PRESENT == 0 {
        return Err(invalid("Registration is missing user presence (touch the key)"));
    }
    if parsed.flags & FLAG_BACKUP_ELIGIBLE != 0 {
        return Err(refused(
            "This is a synced passkey (iCloud, Google or a phone), not a hardware security key. Use a YubiKey.",
        ));
    }
    let user_verified = parsed.flags & FLAG_USER_VERIFIED != 0;
    let cred_protect = parsed.extensions.as_ref().and_then(|e| e.get_text("credProtect")).and_then(cbor::Value::as_int);
    let pin_enforced_by_key = cred_protect == Some(CRED_PROTECT_UV_REQUIRED);
    if require_user_verification && !user_verified {
        return Err(refused(
            "The key didn't verify a PIN. Set a FIDO2 PIN on it (for example with Yubico Authenticator) and try again.",
        ));
    }
    if require_user_verification && !pin_enforced_by_key {
        return Err(refused(
            "This key can't enforce a PIN by itself, so it can't be registered with one. YubiKey 5 keys with \
             firmware 5.2 or later can; otherwise register it without a PIN.",
        ));
    }
    let (attested_id, public_key) =
        parsed.attested.ok_or_else(|| invalid("Attestation has no credential public key"))?;
    if attested_id != credential_id {
        return Err(invalid("Attestation is for a different credential"));
    }
    Ok(Registration { public_key, user_verified, pin_enforced_by_key })
}

/// What an assertion must match: the owner's public key, the relying party it was registered under, and whether
/// the key was registered with a PIN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedKey {
    pub public_key: PublicKey,
    pub rp_id: String,
    pub require_user_verification: bool,
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

/// Checks `assertion` signs `challenge` with the expected key, then returns `abi.encode(WebAuthnAuth)`:
/// `(bytes authenticatorData, string clientDataJSON, uint256 challengeIndex, uint256 typeIndex, uint256 r, uint256 s)`.
///
/// Every check the onchain verifier makes is repeated here (user-present flag, challenge and type at their
/// offsets, low-s, the P-256 signature), so a bad response fails with a clear message instead of an opaque
/// onchain validation error. Some checks go further than the contract: the relying party must be the one the key
/// was registered under, a key registered with a PIN must have verified it, the response can't come from a page
/// embedded in another site (`crossOrigin`), and `type` and `challenge` must each appear once.
pub fn signature_data(assertion: &Assertion, challenge: &[u8], expected: &ExpectedKey) -> Result<Vec<u8>> {
    let auth = AuthenticatorData::parse(&assertion.authenticator_data)
        .map_err(|_| bad_assertion("Security key returned malformed authenticator data"))?;
    if auth.flags & FLAG_USER_PRESENT == 0 {
        return Err(bad_assertion("Security key response is missing user presence (touch the key)"));
    }
    if auth.rp_id_hash != sha256(expected.rp_id.as_bytes()) {
        return Err(bad_assertion("Security key response is for a different site or app than this wallet"));
    }
    if expected.require_user_verification && auth.flags & FLAG_USER_VERIFIED == 0 {
        return Err(bad_assertion("This key requires its PIN, but the response wasn't PIN-verified"));
    }
    let json = &assertion.client_data_json;
    if json_value(json, "crossOrigin").is_some_and(|value| value.starts_with(b"true")) {
        return Err(bad_assertion("Security key response came from a page embedded in another site"));
    }
    // A quote can't appear unescaped inside a JSON string, so each of these can only be a key (or a whole value).
    if count(json, b"\"type\"") != 1 || count(json, b"\"challenge\"") != 1 {
        return Err(bad_assertion("Security key response has a malformed clientDataJSON"));
    }
    let challenge_index = find(json, challenge_needle(challenge).as_bytes())
        .ok_or_else(|| bad_assertion("Security key signed a different challenge than this request"))?;
    let type_index =
        find(json, TYPE_NEEDLE.as_bytes()).ok_or_else(|| bad_assertion("Security key response is not an assertion"))?;

    let signature = parse_signature(&assertion.signature_der)?;
    let mut message = assertion.authenticator_data.clone();
    message.extend_from_slice(&sha256(json));
    expected
        .public_key
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

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack.windows(needle.len()).filter(|window| window == &needle).count()
}

/// The JSON after `"key"` and its colon, with surrounding whitespace skipped.
fn json_value<'a>(json: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let at = find(json, format!("\"{key}\"").as_bytes())? + key.len() + 2;
    let rest = json[at..].trim_ascii_start().strip_prefix(b":")?;
    Some(rest.trim_ascii_start())
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

    /// What `assert_with` responses match: rpId `p256wallet.dev`, no PIN required.
    pub fn expected(key: &SigningKey) -> ExpectedKey {
        ExpectedKey { public_key: public_key(key), rp_id: "p256wallet.dev".into(), require_user_verification: false }
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
        attestation_with(key, credential_id, alg, FLAG_USER_PRESENT, &[])
    }

    /// `extensions` is the raw CBOR extension map; when present the ED flag is set.
    fn attestation_with(key: &PublicKey, credential_id: &[u8], alg: i64, flags: u8, extensions: &[u8]) -> Vec<u8> {
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
        let ed = if extensions.is_empty() { 0 } else { FLAG_EXTENSION_DATA };
        auth_data.extend_from_slice(&[flags | FLAG_ATTESTED_CREDENTIAL_DATA | ed, 0, 0, 0, 7]);
        auth_data.extend_from_slice(&[0xaa; 16]);
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend(cose);
        auth_data.extend_from_slice(extensions);
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
        let registration = register(&object, &credential_id, "example.com", false).unwrap();
        assert_eq!(registration.public_key, key);
        assert!(!registration.user_verified && !registration.pin_enforced_by_key);
        assert!(register(&object, &[1, 2, 3], "example.com", false).is_err(), "other credential");
        assert!(register(&object, &credential_id, "evil.example", false).is_err(), "other relying party");
        let rsa = attestation_object(&key, &credential_id, -257);
        assert!(register(&rsa, &credential_id, "example.com", false).is_err(), "not ES256");
    }

    #[test]
    fn registration_policy() {
        let key = public_key(&test_key(1));
        let id = [9u8; 16];
        // Synced passkeys (backup eligible) are refused.
        let synced = attestation_with(&key, &id, -7, FLAG_USER_PRESENT | FLAG_BACKUP_ELIGIBLE | 0x10, &[]);
        assert!(register(&synced, &id, "example.com", false).is_err());
        // A PIN was asked for but not verified.
        let touch_only = attestation_object(&key, &id, -7);
        assert!(register(&touch_only, &id, "example.com", true).is_err());
        // Verified, but the key didn't agree to enforce it.
        let unenforced = attestation_with(&key, &id, -7, FLAG_USER_PRESENT | FLAG_USER_VERIFIED, &[]);
        assert!(matches!(register(&unenforced, &id, "example.com", true), Err(crate::CoreError::Refused(_))));
        assert!(register(&unenforced, &id, "example.com", false).unwrap().user_verified);
        // PIN verified, and the key enforces it itself (credProtect = 3).
        let cred_protect = [cbor_header(5, 1), cbor_text("credProtect"), cbor_int(3)].concat();
        let protected = attestation_with(&key, &id, -7, FLAG_USER_PRESENT | FLAG_USER_VERIFIED, &cred_protect);
        let registration = register(&protected, &id, "example.com", true).unwrap();
        assert!(registration.user_verified && registration.pin_enforced_by_key);
        // credProtect 2 doesn't count as enforced.
        let optional = [cbor_header(5, 1), cbor_text("credProtect"), cbor_int(2)].concat();
        let lax = attestation_with(&key, &id, -7, FLAG_USER_PRESENT | FLAG_USER_VERIFIED, &optional);
        assert!(register(&lax, &id, "example.com", true).is_err());
        assert!(!register(&lax, &id, "example.com", false).unwrap().pin_enforced_by_key);
        // Bytes after the key without the ED flag are malformed.
        let mut trailing = attestation_object(&key, &id, -7);
        let object = cbor::decode(&trailing, cbor::Form::Relaxed).unwrap();
        let mut auth = object.get_text("authData").unwrap().as_bytes().unwrap().to_vec();
        auth.push(0);
        trailing = [
            cbor_header(5, 3),
            cbor_text("fmt"),
            cbor_text("none"),
            cbor_text("attStmt"),
            cbor_header(5, 0),
            cbor_text("authData"),
            cbor_bytes(&auth),
        ]
        .concat();
        assert!(register(&trailing, &id, "example.com", false).is_err());
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
        let encoded = signature_data(&assertion, &challenge, &expected(&key)).unwrap();

        let decoder = abi::Decoder::new(&encoded);
        let base = decoder.usize(0).unwrap();
        let json = decoder.bytes(base + 32, base).unwrap();
        let challenge_index = decoder.usize(base + 64).unwrap();
        let type_index = decoder.usize(base + 96).unwrap();
        let s = decoder.uint(base + 160).unwrap();
        let needle = challenge_needle(&challenge);
        assert_eq!(&json[challenge_index..challenge_index + needle.len()], needle.as_bytes());
        assert_eq!(&json[type_index..type_index + TYPE_NEEDLE.len()], TYPE_NEEDLE.as_bytes());
        assert!(s <= P256_HALF_N);
    }

    #[test]
    fn normalizes_high_s() {
        let half_n = P256_HALF_N;
        assert_eq!(
            half_n,
            U256::from_str_radix("7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8", 16).unwrap()
        );
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
        let owner = expected(&key);
        assert!(signature_data(&good, &challenge, &owner).is_ok());

        assert!(signature_data(&good, &[8u8; 32], &owner).is_err(), "wrong challenge");
        assert!(signature_data(&good, &challenge, &expected(&test_key(5))).is_err(), "wrong key");
        let no_presence = assert_with(&key, &challenge, 0);
        assert!(signature_data(&no_presence, &challenge, &owner).is_err(), "no user presence");
        let mut tampered = good.clone();
        tampered.authenticator_data[36] ^= 1;
        assert!(signature_data(&tampered, &challenge, &owner).is_err(), "tampered authenticator data");
        let mut bad_der = good.clone();
        bad_der.signature_der[0] = 0x31;
        assert!(signature_data(&bad_der, &challenge, &owner).is_err(), "bad DER");
        let other_rp = ExpectedKey { rp_id: "evil.example".into(), ..owner.clone() };
        assert!(signature_data(&good, &challenge, &other_rp).is_err(), "other relying party");
        let with_pin = ExpectedKey { require_user_verification: true, ..owner };
        assert!(signature_data(&good, &challenge, &with_pin).is_err(), "PIN required, touch only");
        let verified = assert_with(&key, &challenge, FLAG_USER_PRESENT | FLAG_USER_VERIFIED);
        assert!(signature_data(&verified, &challenge, &with_pin).is_ok(), "PIN required and verified");
    }

    #[test]
    fn client_data_must_be_same_origin_and_unambiguous() {
        let key = test_key(4);
        let challenge = [7u8; 32];
        let owner = expected(&key);
        let sign = |json: String| {
            let mut assertion = assert_with(&key, &challenge, FLAG_USER_PRESENT);
            assertion.client_data_json = json.into_bytes();
            let mut message = assertion.authenticator_data.clone();
            message.extend_from_slice(&sha256(&assertion.client_data_json));
            let signature: Signature = key.sign(&message);
            assertion.signature_der = signature.to_der().as_bytes().to_vec();
            assertion
        };
        let needle = challenge_needle(&challenge);
        let origin = "\"origin\":\"https://p256wallet.dev\"";
        let ok = sign(format!("{{{TYPE_NEEDLE},{needle},{origin},\"crossOrigin\":false}}"));
        assert!(signature_data(&ok, &challenge, &owner).is_ok());
        for refused in [
            format!("{{{TYPE_NEEDLE},{needle},{origin},\"crossOrigin\":true}}"),
            format!("{{{TYPE_NEEDLE},{needle},{origin},\"crossOrigin\" : true}}"),
            format!("{{{TYPE_NEEDLE},{needle},{origin},{TYPE_NEEDLE}}}"),
            format!("{{{TYPE_NEEDLE},{needle},{origin},\"challenge\":\"AAAA\"}}"),
        ] {
            assert!(signature_data(&sign(refused.clone()), &challenge, &owner).is_err(), "{refused}");
        }
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
