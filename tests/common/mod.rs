//! Shared pieces of the test harness: a software P-256 key that answers like a security key, a wallet built from
//! such keys, and a small seeded random generator (no extra dependencies, so `Cargo.lock` is untouched).

#![allow(dead_code)]

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256_wallet_core::api;
use p256_wallet_core::hash::sha256;
use p256_wallet_core::records::{Assertion, Call, GasEstimate, GasPrice, OwnerKey, PublicKey, UserOperation};
use p256_wallet_core::{hex, webauthn};

pub const CHAIN: u64 = 84532;
/// The relying party `Key::assert` and `Key::attestation` answer for.
pub const RP_ID: &str = "p256wallet.dev";
pub const DEAD: &str = "0x000000000000000000000000000000000000dEaD";
pub const FLAG_UP: u8 = 0x01;
pub const FLAG_UV: u8 = 0x04;
/// Backup eligible / backed up: set by synced passkeys (iCloud Keychain, Google Password Manager), not hardware keys.
pub const FLAG_BE: u8 = 0x08;
pub const FLAG_BS: u8 = 0x10;

/// A P-256 key that answers WebAuthn `get()` like an authenticator would.
pub struct Key {
    pub signing: SigningKey,
    pub credential_id: Vec<u8>,
}

impl Key {
    pub fn from_seed(seed: u8) -> Key {
        let signing = SigningKey::from_bytes(&[seed; 32].into()).expect("valid scalar");
        let credential_id = sha256(signing.verifying_key().to_encoded_point(false).as_bytes()).to_vec();
        Key { signing, credential_id }
    }

    pub fn public_key(&self) -> PublicKey {
        let point = self.signing.verifying_key().to_encoded_point(false);
        PublicKey { x: hex::encode(point.x().unwrap()), y: hex::encode(point.y().unwrap()) }
    }

    pub fn owner_bytes(&self) -> String {
        api::owner_bytes(self.public_key()).unwrap()
    }

    /// Signs `challenge` with a browser-shaped `clientDataJSON`.
    pub fn assert(&self, challenge: &[u8], flags: u8) -> Assertion {
        let json = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://p256wallet.dev\",\"crossOrigin\":false}}",
            webauthn::base64url(challenge)
        );
        self.assert_raw(json.as_bytes(), &rp_auth_data(b"p256wallet.dev", flags))
    }

    /// Signs arbitrary `clientDataJSON` and authenticator data, for crafted responses.
    pub fn assert_raw(&self, client_data_json: &[u8], authenticator_data: &[u8]) -> Assertion {
        let mut message = authenticator_data.to_vec();
        message.extend_from_slice(&sha256(client_data_json));
        let signature: Signature = self.signing.sign(&message);
        Assertion {
            credential_id: hex::encode(&self.credential_id),
            authenticator_data: hex::encode(authenticator_data),
            client_data_json: hex::encode(client_data_json),
            signature: hex::encode(signature.to_der().as_bytes()),
        }
    }
}

/// `rpIdHash || flags || signCount(1)`.
pub fn rp_auth_data(rp_id: &[u8], flags: u8) -> Vec<u8> {
    let mut data = sha256(rp_id).to_vec();
    data.extend_from_slice(&[flags, 0, 0, 0, 1]);
    data
}

pub struct Wallet {
    pub keys: Vec<Key>,
    pub address: String,
    pub owners: Vec<String>,
    pub owner_keys: Vec<OwnerKey>,
}

impl Wallet {
    pub fn new(seeds: &[u8]) -> Wallet {
        let keys: Vec<Key> = seeds.iter().map(|&s| Key::from_seed(s)).collect();
        let owners: Vec<String> = keys.iter().map(Key::owner_bytes).collect();
        let owner_keys = keys
            .iter()
            .enumerate()
            .map(|(index, key)| OwnerKey {
                credential_id: hex::encode(&key.credential_id),
                owner_index: index as u32,
                public_key: key.public_key(),
                rp_id: RP_ID.into(),
                require_user_verification: false,
            })
            .collect();
        let address = api::account_address(owners.clone()).unwrap();
        Wallet { keys, address, owners, owner_keys }
    }

    /// A deployable, gas-estimated operation for `calls`.
    pub fn op(&self, calls: Vec<Call>, deployed: bool) -> UserOperation {
        let op = api::build_user_operation(
            self.address.clone(),
            "0x0".into(),
            deployed,
            self.owners.clone(),
            calls,
            gas(),
            0,
        )
        .unwrap();
        api::apply_gas_estimate(
            op,
            GasEstimate {
                pre_verification_gas: "0xc350".into(),
                verification_gas_limit: "0x61a80".into(),
                call_gas_limit: "0x2710".into(),
            },
            30_000,
        )
        .unwrap()
    }

    pub fn send_eth(&self) -> UserOperation {
        self.op(vec![api::transfer_call(None, DEAD.into(), "0x1".into()).unwrap()], false)
    }

    /// Reviews `op`, has key `index` sign the reviewed hash, and attaches the signature.
    pub fn sign(&self, op: &UserOperation, index: usize) -> Result<UserOperation, p256_wallet_core::CoreError> {
        let review = api::review_user_operation(op.clone(), CHAIN, vec![], vec![])?;
        let assertion = self.keys[index].assert(&hex::decode(&review.hash).unwrap(), FLAG_UP);
        api::sign_user_operation(op.clone(), CHAIN, assertion, self.owner_keys.clone(), self.owners.clone())
    }
}

pub fn gas() -> GasPrice {
    GasPrice { max_fee_per_gas: "0x3b9aca00".into(), max_priority_fee_per_gas: "0xf4240".into() }
}

pub fn raw_call(target: &str, value: &str, data: &[u8]) -> Call {
    Call { target: target.into(), value: value.into(), data: hex::encode(data) }
}

/// SplitMix64: tiny, seeded, good enough to drive mutation fuzzing reproducibly.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    pub fn chance(&mut self, one_in: u64) -> bool {
        self.next() % one_in == 0
    }
    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
    /// Random bytes, up to `max - 1` of them.
    pub fn bytes_upto(&mut self, max: usize) -> Vec<u8> {
        let len = self.below(max);
        self.bytes(len)
    }
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    /// Byte-level mutations that matter for parsers: flips, interesting values (0x00, 0xff, 0x80, length-ish words),
    /// truncation, extension, splicing and word-sized overwrites that hit ABI offsets and lengths.
    pub fn mutate(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = input.to_vec();
        for _ in 0..1 + self.below(4) {
            match self.below(8) {
                0 if !out.is_empty() => {
                    let i = self.below(out.len());
                    out[i] ^= 1 << self.below(8);
                }
                1 if !out.is_empty() => {
                    let i = self.below(out.len());
                    out[i] = *self.pick(&[0x00, 0xff, 0x7f, 0x80, 0x01, 0x20, 0x40, 0x60]);
                }
                2 if !out.is_empty() => {
                    let keep = self.below(out.len());
                    out.truncate(keep);
                }
                3 => {
                    let extra = self.bytes_upto(70);
                    out.extend(extra);
                }
                4 if out.len() >= 32 => {
                    // Overwrite an aligned-ish word with a small or huge number: offsets and lengths.
                    let start = self.below(out.len() - 31);
                    let value: u64 = *self.pick(&[0, 1, 0x20, 0x40, 0x60, 0x80, 0xffff, u32::MAX as u64, u64::MAX]);
                    out[start..start + 32].fill(0);
                    out[start + 24..start + 32].copy_from_slice(&value.to_be_bytes());
                }
                5 if out.len() > 2 => {
                    let a = self.below(out.len());
                    let b = self.below(out.len());
                    let (lo, hi) = (a.min(b), a.max(b));
                    let chunk = out[lo..hi].to_vec();
                    let at = self.below(out.len());
                    out.splice(at..at, chunk);
                }
                6 if !out.is_empty() => {
                    let i = self.below(out.len());
                    out.remove(i);
                }
                _ => {
                    let at = self.below(out.len() + 1);
                    let byte = self.next() as u8;
                    out.insert(at, byte);
                }
            }
        }
        out
    }
}

// ---------- CBOR, for building registration responses ----------

fn cbor_header(major: u8, value: usize) -> Vec<u8> {
    match value {
        0..=23 => vec![major << 5 | value as u8],
        24..=255 => vec![major << 5 | 24, value as u8],
        _ => vec![major << 5 | 25, (value >> 8) as u8, value as u8],
    }
}
pub fn cbor_int(value: i64) -> Vec<u8> {
    if value >= 0 {
        cbor_header(0, value as usize)
    } else {
        cbor_header(1, (-1 - value) as usize)
    }
}
pub fn cbor_bytes(bytes: &[u8]) -> Vec<u8> {
    [cbor_header(2, bytes.len()), bytes.to_vec()].concat()
}
pub fn cbor_text(text: &str) -> Vec<u8> {
    [cbor_header(3, text.len()), text.as_bytes().to_vec()].concat()
}
pub fn cbor_map(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = cbor_header(5, pairs.len());
    for (k, v) in pairs {
        out.extend_from_slice(k);
        out.extend_from_slice(v);
    }
    out
}

/// An EC2 / ES256 / P-256 COSE key for `(x, y)`, with optional extra pairs appended (e.g. a duplicate label).
pub fn cose_key(x: &[u8], y: &[u8], extra: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut pairs = vec![
        (cbor_int(1), cbor_int(2)),
        (cbor_int(3), cbor_int(-7)),
        (cbor_int(-1), cbor_int(1)),
        (cbor_int(-2), cbor_bytes(x)),
        (cbor_int(-3), cbor_bytes(y)),
    ];
    pairs.extend(extra.iter().cloned());
    cbor_map(&pairs)
}

/// A `fmt: none` attestation object for `cose`, with the given authenticator flags (AT is added).
pub fn attestation_object(cose: &[u8], credential_id: &[u8], flags: u8) -> Vec<u8> {
    let mut auth_data = sha256(b"p256wallet.dev").to_vec();
    auth_data.extend_from_slice(&[flags | 0x40, 0, 0, 0, 0]);
    auth_data.extend_from_slice(&[0xaa; 16]);
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(credential_id);
    auth_data.extend_from_slice(cose);
    cbor_map(&[
        (cbor_text("fmt"), cbor_text("none")),
        (cbor_text("attStmt"), cbor_map(&[])),
        (cbor_text("authData"), cbor_bytes(&auth_data)),
    ])
}

impl Key {
    pub fn attestation(&self, flags: u8) -> Vec<u8> {
        let point = self.signing.verifying_key().to_encoded_point(false);
        attestation_object(&cose_key(point.x().unwrap(), point.y().unwrap(), &[]), &self.credential_id, flags)
    }
}
