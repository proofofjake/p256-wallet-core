//! Mutation fuzzing of every function the apps call, plus the parsers under them. The core runs in the browser
//! extension as WebAssembly, where a panic aborts the whole instance, and across UniFFI in the iOS app, so the bar is:
//! **no input may panic**; bad input must come back as an error.
//!
//! Seeded and reproducible. `FUZZ_ITERS` (default 2000 per target) and `FUZZ_SEED` (default fixed) tune it:
//!
//! ```sh
//! cargo test --test fuzz --release                       # quick
//! FUZZ_ITERS=200000 cargo test --test fuzz --release     # long run
//! ```

mod common;

use common::*;
use p256_wallet_core::records::{GasEstimate, OwnerKey, Token};
use p256_wallet_core::{abi, api, cbor, hex, smart_wallet};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn iterations() -> usize {
    std::env::var("FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(2000)
}
fn seed() -> u64 {
    std::env::var("FUZZ_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x5eed_0256)
}

/// Runs `body` for every iteration; a panic is recorded with the iteration's seed so it can be replayed.
fn fuzz(target: &str, body: impl Fn(&mut Rng)) {
    std::panic::set_hook(Box::new(|_| {})); // keep output readable; failures are reported below
    let base = seed() ^ target.bytes().fold(0u64, |h, b| h.wrapping_mul(31).wrapping_add(b as u64));
    let mut failures = Vec::new();
    for i in 0..iterations() {
        let s = base.wrapping_add(i as u64);
        let mut rng = Rng(s);
        if let Err(panic) = catch_unwind(AssertUnwindSafe(|| body(&mut rng))) {
            let message = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            failures.push(format!("seed {s:#x}: {message}"));
            if failures.len() >= 5 {
                break;
            }
        }
    }
    let _ = std::panic::take_hook();
    assert!(failures.is_empty(), "{target} panicked:\n{}", failures.join("\n"));
}

fn token_list() -> Vec<Token> {
    vec![Token {
        address: "0x036CbD53842c5426634e7929541eC2318f3dCF7e".into(),
        symbol: "USDC".into(),
        name: "USD Coin".into(),
        decimals: 6,
    }]
}

const SIGNATURES: &[&str] = &[
    "transfer(address,uint256)",
    "approve(address spender, uint256 amount)",
    "mint(address,uint8,bytes32,bool,string,bytes,int16)",
    "f()",
    "g(bytes)",
    "h(string,string)",
];

fn seed_calldata() -> Vec<Vec<u8>> {
    let wallet = Wallet::new(&[1]);
    let token =
        api::transfer_call(Some("0x036CbD53842c5426634e7929541eC2318f3dCF7e".into()), DEAD.into(), "0x16e360".into())
            .unwrap();
    let eth = api::transfer_call(None, DEAD.into(), "0x1".into()).unwrap();
    let mint = api::encode_function_call(
        SIGNATURES[2].into(),
        [
            "0x000000000000000000000000000000000000dEaD",
            "7",
            "0x0100000000000000000000000000000000000000000000000000000000000000",
            "true",
            "hi",
            "0xbeef",
            "-3",
        ]
        .map(String::from)
        .to_vec(),
    )
    .unwrap();
    [
        wallet.op(vec![eth.clone()], true),
        wallet.op(vec![eth, token.clone(), raw_call(DEAD, "0x0", &hex::decode(&mint.data).unwrap())], true),
        wallet.op(vec![token], false),
    ]
    .iter()
    .map(|op| hex::decode(&op.call_data).unwrap())
    .collect()
}

#[test]
fn review_never_panics_on_mutated_call_data() {
    let seeds = seed_calldata();
    let wallet = Wallet::new(&[1]);
    let base = wallet.op(vec![api::transfer_call(None, DEAD.into(), "0x1".into()).unwrap()], true);
    let signatures: Vec<String> = SIGNATURES.iter().map(|s| s.to_string()).collect();
    fuzz("review", |rng| {
        let mut op = base.clone();
        let seed = rng.pick(&seeds).clone();
        op.call_data = hex::encode(&rng.mutate(&seed));
        if rng.chance(4) {
            op.paymaster_and_data = hex::encode(&rng.bytes_upto(60));
        }
        if let Ok(review) = api::review_user_operation(op.clone(), CHAIN, token_list(), signatures.clone()) {
            // Whatever the core agreed to describe, it must also agree to sign (same check), and the hash it shows
            // must be the operation's hash.
            assert_eq!(review.hash, api::user_operation_hash(op, CHAIN).unwrap());
        }
    });
}

#[test]
fn signing_never_panics_on_mutated_assertions() {
    let wallet = Wallet::new(&[1, 2]);
    let op = wallet.send_eth();
    let hash = hex::decode(&api::user_operation_hash(op.clone(), CHAIN).unwrap()).unwrap();
    let good = wallet.keys[0].assert(&hash, FLAG_UP);
    fuzz("sign_user_operation", |rng| {
        let mut a = good.clone();
        let field = rng.below(4);
        let mutate = |text: &str, rng: &mut Rng| hex::encode(&rng.mutate(&hex::decode(text).unwrap()));
        match field {
            0 => a.authenticator_data = mutate(&a.authenticator_data, rng),
            1 => a.client_data_json = mutate(&a.client_data_json, rng),
            2 => a.signature = mutate(&a.signature, rng),
            _ => a.credential_id = mutate(&a.credential_id, rng),
        }
        let mutated = a != good;
        if let Ok(signed) =
            api::sign_user_operation(op.clone(), CHAIN, a.clone(), wallet.owner_keys.clone(), wallet.owners.clone())
        {
            // A mutated response may only be accepted if the signature still verifies over what it covers, i.e. the
            // mutation hit bytes outside the signed message (credential ID is a lookup key, not signed).
            if mutated && field != 3 {
                // authenticatorData and clientDataJSON are both signed; a valid DER re-encoding of the same (r, s)
                // is the only acceptable change to the signature itself.
                assert_eq!(field, 2, "accepted a changed signed field: {a:?}");
            }
            assert!(!signed.signature.is_empty());
        }
    });
}

#[test]
fn attestation_parsing_never_panics() {
    let key = Key::from_seed(3);
    let good = key.attestation(FLAG_UP);
    fuzz("verify_registration", |rng| {
        let data = rng.mutate(&good);
        let pin = rng.chance(2);
        let _ = api::verify_registration(hex::encode(&data), hex::encode(&key.credential_id), RP_ID.into(), pin);
        let _ = cbor::decode(&data);
    });
}

#[test]
fn cbor_never_panics_on_random_bytes() {
    fuzz("cbor", |rng| {
        let data = rng.bytes_upto(80);
        let _ = cbor::decode(&data);
        let _ = cbor::decode_prefix(&data);
    });
}

#[test]
fn init_code_decoding_never_panics() {
    let wallet = Wallet::new(&[1, 2, 3]);
    let op = wallet.send_eth();
    let init = hex::decode(&op.init_code).unwrap();
    fuzz("decode_init_code", |rng| {
        let data = rng.mutate(&init);
        let _ = smart_wallet::decode_init_code(&data);
        let mut changed = op.clone();
        changed.init_code = hex::encode(&data);
        let _ = api::review_user_operation(changed, CHAIN, vec![], vec![]);
    });
}

#[test]
fn abi_decoding_never_panics() {
    let types = [
        "uint256", "uint8", "int256", "address", "bool", "bytes", "string", "bytes32", "bytes1", "uint", "garbage",
        "uint7", "bytes33", "",
    ];
    fuzz("abi_decode", |rng| {
        let wanted: Vec<String> = (0..rng.below(4)).map(|_| rng.pick(&types).to_string()).collect();
        let number = rng.next();
        let blob = rng.bytes_upto(40);
        let encoded = abi::encode(&[
            abi::Token::Uint(ruint::aliases::U256::from(number)),
            abi::Token::Bytes(blob),
            abi::Token::String("hello".into()),
        ]);
        let data = rng.mutate(&encoded);
        let _ = api::abi_decode(wanted, hex::encode(&data));
        let mut revert = abi::encode_call("Error(string)", &[abi::Token::String("nope".into())]);
        if rng.chance(2) {
            revert = abi::encode_call("Panic(uint256)", &[abi::Token::Uint(ruint::aliases::U256::from(0x11))]);
        }
        let _ = api::decode_revert_reason(hex::encode(&rng.mutate(&revert)));
        let _ = api::is_erc1271_success(hex::encode(&rng.bytes_upto(40)));
    });
}

fn random_text(rng: &mut Rng) -> String {
    const PIECES: &[&str] = &[
        "0",
        "1",
        "9",
        ".",
        ",",
        "0x",
        "0X",
        "-",
        " ",
        "e",
        "ff",
        "1e18",
        "١",
        "＄",
        "\u{202e}",
        "(",
        ")",
        "uint",
        "256",
        "address",
        "bytes",
        "[",
        "]",
        "string",
        "a",
        "_",
        "function ",
        "returns",
    ];
    (0..rng.below(12)).map(|_| *rng.pick(PIECES)).collect()
}

#[test]
fn value_parsing_never_panics() {
    fuzz("values", |rng| {
        let text = random_text(rng);
        let decimals = rng.next() as u8;
        let _ = api::parse_units(text.clone(), decimals);
        let _ = api::parse_quantity(text.clone());
        let _ = api::checksum_address(text.clone());
        let _ = api::compare_quantities(text.clone(), random_text(rng));
        let q = hex::quantity(ruint::aliases::U256::from_limbs([rng.next(), rng.next(), rng.next(), rng.next()]));
        let _ = api::format_units(q.clone(), decimals, rng.next() as u8);
        let _ = api::format_units_plain(q.clone(), decimals);
        let _ = api::fallback_gas_price(q.clone(), q);
    });
}

#[test]
fn function_encoding_never_panics() {
    fuzz("encode_function_call", |rng| {
        let signature =
            if rng.chance(2) { rng.pick(SIGNATURES).to_string() } else { format!("f({})", random_text(rng)) };
        let args: Vec<String> = (0..rng.below(8)).map(|_| random_text(rng)).collect();
        if let Ok(call) = api::encode_function_call(signature, args) {
            // Anything it encodes must decode under its own canonical types.
            let parsed = p256_wallet_core::function_call::parse_signature(&call.signature).unwrap();
            let data = hex::decode(&call.data).unwrap();
            // `abi_decode` doesn't read intN (the apps never need it), so only check the other types.
            if !parsed.types.iter().any(|t| t.starts_with("int")) {
                api::abi_decode(parsed.types.clone(), hex::encode(&data[4..])).unwrap();
            }
        }
    });
}

#[test]
fn gas_and_keys_never_panic() {
    let wallet = Wallet::new(&[1]);
    let op = wallet.send_eth();
    fuzz("gas_and_keys", |rng| {
        let q = |rng: &mut Rng| {
            if rng.chance(3) {
                random_text(rng)
            } else {
                hex::quantity(ruint::aliases::U256::from_limbs([
                    rng.next(),
                    rng.next(),
                    rng.next() >> rng.below(64),
                    0,
                ]))
            }
        };
        let estimate =
            GasEstimate { pre_verification_gas: q(rng), verification_gas_limit: q(rng), call_gas_limit: q(rng) };
        let _ = api::apply_gas_estimate(op.clone(), estimate, rng.next());
        let key =
            p256_wallet_core::records::PublicKey { x: hex::encode(&rng.bytes(32)), y: hex::encode(&rng.bytes(32)) };
        let _ = api::owner_bytes(key.clone());
        let _ = api::add_owner_call(wallet.address.clone(), key.clone());
        let length = *rng.pick(&[0, 20, 32, 63, 64, 65]);
        let owners = vec![hex::encode(&rng.bytes(length))];
        let _ = api::account_address(owners.clone());
        let fake = OwnerKey {
            credential_id: hex::encode(&rng.bytes_upto(70)),
            owner_index: rng.next() as u32,
            public_key: key,
            rp_id: random_text(rng),
            require_user_verification: rng.chance(2),
        };
        let _ = api::check_wallet_record(random_text(rng), owners.clone(), vec![fake.clone()]);
        let _ = api::check_wallet_record(wallet.address.clone(), wallet.owners.clone(), vec![fake.clone()]);
        let assertion = wallet.keys[0].assert(&rng.bytes(32), rng.next() as u8);
        let _ = api::sign_user_operation(op.clone(), rng.next(), assertion.clone(), vec![fake.clone()], owners.clone());
        let _ = api::sign_message(
            random_text(rng),
            wallet.address.clone(),
            rng.next(),
            assertion,
            vec![fake],
            rng.chance(2),
            owners,
        );
    });
}
