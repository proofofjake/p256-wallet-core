//! Checks the core against the live contracts on Base Sepolia (and Base, for addresses). No funds needed.
//! Run with `CORE_INTEGRATION=1 cargo test --test base_sepolia`; skipped otherwise.
//!
//! `EntryPoint.simulateValidation` with zero gas fees needs no prefund and reports whether the account accepted the
//! signature, so the full signing path is exercised against the real Coinbase Smart Wallet without a transaction.

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256_wallet_core::records::{Assertion, GasEstimate, GasPrice, OwnerKey, PublicKey, UserOperation};
use p256_wallet_core::{api, smart_wallet, webauthn};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const SEPOLIA: &str = "https://sepolia.base.org";
const BASE: &str = "https://mainnet.base.org";
const CHAIN_ID: u64 = 84532;
const DEAD: &str = "0x000000000000000000000000000000000000dEaD";

fn enabled() -> bool {
    let on = std::env::var("CORE_INTEGRATION").is_ok();
    if !on {
        eprintln!("skipped: set CORE_INTEGRATION=1 to run against Base Sepolia");
    }
    on
}

/// `eth_call`; `Err` carries the revert data.
fn eth_call(rpc: &str, to: Option<&str>, data: &str, overrides: Option<Value>) -> Result<String, String> {
    let mut tx = json!({ "data": data });
    if let Some(to) = to {
        tx["to"] = json!(to);
    }
    let mut params = vec![tx, json!("latest")];
    if let Some(overrides) = overrides {
        params.push(overrides);
    }
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": params });
    let response: Value =
        ureq::post(rpc).send_json(&body).expect("RPC request").body_mut().read_json().expect("RPC response");
    if let Some(error) = response.get("error") {
        return Err(error["data"].as_str().unwrap_or_else(|| panic!("no revert data: {error}")).to_string());
    }
    Ok(response["result"].as_str().expect("result").to_string())
}

fn rpc(rpc: &str, method: &str, params: Value) -> Value {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let response: Value = ureq::post(rpc).send_json(&body).unwrap().body_mut().read_json().unwrap();
    response["result"].clone()
}

fn call(rpc: &str, to: &str, signature: &str, args: &[&str]) -> String {
    let data = api::encode_function_call(signature.into(), args.iter().map(|a| a.to_string()).collect()).unwrap().data;
    eth_call(rpc, Some(to), &data, None).unwrap()
}

/// A software P-256 key that answers like a security key.
struct Key(SigningKey);

impl Key {
    fn random() -> Key {
        let seed: [u8; 32] = std::array::from_fn(|_| rand_byte());
        Key(SigningKey::from_bytes(&seed.into()).unwrap())
    }

    fn public_key(&self) -> PublicKey {
        let point = self.0.verifying_key().to_encoded_point(false);
        PublicKey { x: hex(point.x().unwrap()), y: hex(point.y().unwrap()) }
    }

    fn credential_id(&self) -> String {
        hex(&Sha256::digest(self.0.verifying_key().to_encoded_point(false).as_bytes()))
    }

    fn owner(&self, index: u32) -> OwnerKey {
        OwnerKey {
            credential_id: self.credential_id(),
            owner_index: index,
            public_key: self.public_key(),
            rp_id: "p256wallet.dev".into(),
            require_user_verification: false,
            added_on_chain_id: None,
        }
    }

    fn assert(&self, challenge_hex: &str) -> Assertion {
        let challenge = unhex(challenge_hex);
        let mut authenticator_data = Sha256::digest(b"p256wallet.dev").to_vec();
        authenticator_data.extend_from_slice(&[0x05, 0, 0, 0, 1]);
        let client_data_json = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://p256wallet.dev\",\"crossOrigin\":false}}",
            base64url(&challenge)
        );
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&Sha256::digest(client_data_json.as_bytes()));
        let signature: Signature = self.0.sign(&message);
        Assertion {
            credential_id: self.credential_id(),
            authenticator_data: hex(&authenticator_data),
            client_data_json: hex(client_data_json.as_bytes()),
            signature: hex(signature.to_der().as_bytes()),
        }
    }
}

struct Account {
    address: String,
    owners: Vec<String>,
}

fn account(keys: &[&Key]) -> Account {
    let owners: Vec<String> = keys.iter().map(|k| api::owner_bytes(k.public_key()).unwrap()).collect();
    Account { address: api::account_address(owners.clone()).unwrap(), owners }
}

/// A first operation (deploys the account) with fixed gas and zero fees, so simulation needs no prefund.
fn first_operation(account: &Account) -> UserOperation {
    let call = api::transfer_call(None, DEAD.into(), "0x0".into()).unwrap();
    let zero = GasPrice { max_fee_per_gas: "0x0".into(), max_priority_fee_per_gas: "0x0".into() };
    let op = api::build_user_operation(
        account.address.clone(),
        "0x0".into(),
        false,
        account.owners.clone(),
        vec![call],
        zero,
        0,
    )
    .unwrap();
    let estimate = GasEstimate {
        pre_verification_gas: "0x186a0".into(),
        verification_gas_limit: "0x2dc6c0".into(),
        call_gas_limit: "0x186a0".into(),
    };
    api::apply_gas_estimate(op, estimate, 0).unwrap()
}

const OP_TUPLE: &str = "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)";

fn op_args(op: &UserOperation) -> String {
    format!(
        "{},{},{},{},{},{},{},{},{},{},{}",
        op.sender,
        op.nonce,
        op.init_code,
        op.call_data,
        op.call_gas_limit,
        op.verification_gas_limit,
        op.pre_verification_gas,
        op.max_fee_per_gas,
        op.max_priority_fee_per_gas,
        op.paymaster_and_data,
        op.signature
    )
}

/// ABI-encodes a call taking one UserOperation tuple. `encode_function_call` doesn't do tuples, so this builds the
/// tuple encoding from its flat parts: a head of 11 words (dynamic fields as offsets) followed by the tails.
fn encode_op_call(function: &str, op: &UserOperation) -> String {
    let fields = op_args(op);
    let parts: Vec<&str> = fields.split(',').collect();
    let dynamic = [2, 3, 9, 10];
    let mut head = String::new();
    let mut tail = String::new();
    for (index, part) in parts.iter().enumerate() {
        if dynamic.contains(&index) {
            head += &word(11 * 32 + tail.len() / 2);
            let bytes = unhex(part);
            tail += &word(bytes.len());
            let mut padded = hex(&bytes)[2..].to_string();
            padded += &"0".repeat((64 - padded.len() % 64) % 64);
            tail += &padded;
        } else if index == 0 {
            head += &format!("{:0>64}", part[2..].to_lowercase());
        } else {
            let value = api::parse_quantity(part.to_string()).unwrap();
            head += &format!("{:0>64}", &value[2..]);
        }
    }
    let selector = keccak_selector(&format!("{function}({OP_TUPLE})"));
    format!("{selector}{}{head}{tail}", word(32))
}

fn keccak_selector(signature: &str) -> String {
    use sha3::{Digest as _, Keccak256};
    hex(&Keccak256::digest(signature.as_bytes())[..4])
}

/// Runs `EntryPoint.simulateValidation(op)`, which always reverts; returns `sigFailed` from `ValidationResult`.
fn sig_failed(op: &UserOperation) -> bool {
    let data = encode_op_call("simulateValidation", op);
    let revert = eth_call(SEPOLIA, Some(&api::entry_point_address()), &data, None).expect_err("always reverts");
    let failed_op = keccak_selector("FailedOp(uint256,string)");
    assert!(
        !revert.starts_with(&failed_op),
        "FailedOp: {:?}",
        api::abi_decode(vec!["uint256".into(), "string".into()], format!("0x{}", &revert[10..]))
    );
    let validation_result = keccak_selector(
        "ValidationResult((uint256,uint256,bool,uint48,uint48,bytes),(uint256,uint256),(uint256,uint256),(uint256,uint256))",
    );
    assert!(revert.starts_with(&validation_result), "unexpected revert {}", &revert[..10.min(revert.len())]);
    let payload = unhex(&format!("0x{}", &revert[10..]));
    let return_info = usize::from_str_radix(&hex(&payload[24..32])[2..], 16).unwrap();
    payload[return_info + 64 + 31] == 1
}

#[test]
fn address_derivation_matches_factory_on_both_chains() {
    if !enabled() {
        return;
    }
    let factory = api::factory_address();
    for rpc in [SEPOLIA, BASE] {
        let init_code_hash = call(rpc, &factory, "initCodeHash()", &[]);
        assert_eq!(init_code_hash, "0x5153041b4b8e36c84ca233b2fb610f85b8831b5e56a365618f507f8784fe034e");
    }
    let (primary, backup) = (Key::random(), Key::random());
    let account = account(&[&primary, &backup]);
    // getAddress(bytes[],uint256) takes an array, which encode_function_call doesn't; build it by hand.
    let owners = [unhex(&account.owners[0]), unhex(&account.owners[1])];
    let mut data = keccak_selector("getAddress(bytes[],uint256)");
    data += &word(64);
    data += &word(0);
    data += &word(2);
    data += &word(64);
    data += &word(64 + 32 + 64);
    for owner in &owners {
        data += &word(64);
        data += &hex(owner)[2..];
    }
    for rpc in [SEPOLIA, BASE] {
        let onchain = eth_call(rpc, Some(&factory), &data, None).unwrap();
        let decoded = api::abi_decode(vec!["address".into()], onchain).unwrap();
        assert_eq!(decoded[0], account.address);
    }
}

#[test]
fn user_operation_hash_matches_entry_point() {
    if !enabled() {
        return;
    }
    let key = Key::random();
    let mut op = first_operation(&account(&[&key]));
    op.max_fee_per_gas = "0xf4240".into();
    op.max_priority_fee_per_gas = "0x3e8".into();
    op.paymaster_and_data = "0x010203".into();
    let onchain =
        eth_call(SEPOLIA, Some(&api::entry_point_address()), &encode_op_call("getUserOpHash", &op), None).unwrap();
    assert_eq!(onchain, api::user_operation_hash(op, CHAIN_ID).unwrap());
}

#[test]
fn account_accepts_signatures_from_each_owner_and_rejects_others() {
    if !enabled() {
        return;
    }
    let (primary, backup, stranger) = (Key::random(), Key::random(), Key::random());
    let account = account(&[&primary, &backup]);
    let owners = vec![primary.owner(0), backup.owner(1)];
    let op = first_operation(&account);
    let hash = api::review_user_operation(op.clone(), CHAIN_ID, vec![], vec![], None).unwrap().hash;

    for key in [&primary, &backup] {
        let signed = api::sign_user_operation(
            op.clone(),
            CHAIN_ID,
            key.assert(&hash),
            owners.clone(),
            account.owners.clone(),
            None,
        )
        .unwrap();
        assert!(!sig_failed(&signed), "the account rejected a valid signature");
    }

    // The core refuses a non-owner outright, including one claiming an owner's index. Forge the wrapper from the
    // lower-level pieces anyway (claiming owner 0) to check the contract rejects it too.
    assert!(api::sign_user_operation(
        op.clone(),
        CHAIN_ID,
        stranger.assert(&hash),
        owners,
        account.owners.clone(),
        None
    )
    .is_err());
    let claimed = vec![OwnerKey { owner_index: 0, ..stranger.owner(0) }];
    assert!(api::sign_user_operation(
        op.clone(),
        CHAIN_ID,
        stranger.assert(&hash),
        claimed,
        account.owners.clone(),
        None
    )
    .is_err());
    let raw = stranger.assert(&hash);
    let assertion = webauthn::Assertion {
        credential_id: unhex(&raw.credential_id),
        authenticator_data: unhex(&raw.authenticator_data),
        client_data_json: unhex(&raw.client_data_json),
        signature_der: unhex(&raw.signature),
    };
    let point = stranger.0.verifying_key().to_encoded_point(false);
    let expected = webauthn::ExpectedKey {
        public_key: webauthn::PublicKey::new((*point.x().unwrap()).into(), (*point.y().unwrap()).into()).unwrap(),
        rp_id: "p256wallet.dev".into(),
        require_user_verification: false,
    };
    let data = webauthn::signature_data(&assertion, &unhex(&hash), &expected).unwrap();
    let forged = UserOperation { signature: hex(&smart_wallet::wrap_signature(0, data)), ..op.clone() };
    assert!(sig_failed(&forged), "the account accepted a signature from a key that isn't an owner");
}

#[test]
fn replay_safe_hash_matches_the_account() {
    if !enabled() {
        return;
    }
    // Run the implementation's code at an arbitrary address: replaySafeHash only reads address(this) and chainid.
    let implementation = "0x000100abaad02f1cfC8Bbe32bD5a564817339E72";
    let code = rpc(SEPOLIA, "eth_getCode", json!([implementation, "latest"]));
    let account = "0x1234567890123456789012345678901234567890";
    let challenge = api::message_challenge("hello world".into(), account.into(), CHAIN_ID).unwrap();
    let data = api::encode_function_call("replaySafeHash(bytes32)".into(), vec![challenge.message_hash]).unwrap().data;
    let onchain = eth_call(SEPOLIA, Some(account), &data, Some(json!({ account: { "code": code } }))).unwrap();
    assert_eq!(onchain, challenge.challenge);
}

#[test]
fn erc6492_message_signature_verifies_before_deployment() {
    if !enabled() {
        return;
    }
    let key = Key::random();
    let account = account(&[&key]);
    let message = "gm from p256-wallet-core";
    let challenge = api::message_challenge(message.into(), account.address.clone(), CHAIN_ID).unwrap();
    let signed = api::sign_message(
        message.into(),
        account.address.clone(),
        CHAIN_ID,
        key.assert(&challenge.challenge),
        vec![key.owner(0)],
        false,
        account.owners.clone(),
    )
    .unwrap();

    // ERC-6492 reference validator (via viem), run as a deployless call: deploys the account in simulation, then
    // calls isValidSignature. Returns 1 for valid.
    let validator = include_str!("data/erc6492-validator.hex").trim();
    let verify = |hash: &str| {
        let signature = unhex(&signed.signature);
        let mut args = String::new();
        args += &format!("{:0>64}", account.address[2..].to_lowercase());
        args += &hash[2..];
        args += &word(96);
        args += &word(signature.len());
        let mut padded = hex(&signature)[2..].to_string();
        padded += &"0".repeat((64 - padded.len() % 64) % 64);
        args += &padded;
        eth_call(SEPOLIA, None, &format!("{validator}{args}"), None)
            .map(|result| result.ends_with('1'))
            .unwrap_or(false)
    };
    assert!(verify(&signed.message_hash));
    let other = api::message_challenge("tampered".into(), account.address.clone(), CHAIN_ID).unwrap();
    assert!(!verify(&other.message_hash));
}

// MARK: Helpers

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::from("0x"), |mut out, b| {
        out += &format!("{b:02x}");
        out
    })
}

fn unhex(text: &str) -> Vec<u8> {
    let digits = text.trim_start_matches("0x");
    (0..digits.len()).step_by(2).map(|i| u8::from_str_radix(&digits[i..i + 2], 16).unwrap()).collect()
}

fn word(value: usize) -> String {
    format!("{value:064x}")
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n =
            (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(n >> (18 - 6 * i) & 0x3f) as usize] as char);
        }
    }
    out
}

/// Seeded from the clock and a counter: test keys only need to differ between runs, not be secret.
fn rand_byte() -> u8 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64;
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(nanos.to_le_bytes());
    hasher.update(n.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.finalize()[0]
}
