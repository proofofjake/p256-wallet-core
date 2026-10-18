//! Security harness: attacks the core must refuse, and the open findings from the 2026-10-18 review.
//!
//! - `guarantee_*` tests are attacks the core already refuses. They must keep passing.
//! - `finding_*` tests assert the safer behaviour each finding asks for. They're `#[ignore]`d while open, so plain
//!   `cargo test` stays green and `cargo test --test security -- --ignored` lists what's still open. Remove the
//!   `ignore` when a finding is fixed (or delete the test if the behaviour is accepted by design).

mod common;

use common::*;
use p256_wallet_core::records::{OwnerKey, Token};
use p256_wallet_core::{abi, api, hex, smart_wallet, webauthn};
use ruint::aliases::U256;

fn address(text: &str) -> [u8; 20] {
    p256_wallet_core::address::parse(text).unwrap()
}

const ATTACKER: &str = "0xbadbadbadbadbadbadbadbadbadbadbadbadbad0";

/// An operation whose only call is `wallet.<signature>(args)`, i.e. a self-call through `execute`.
fn self_call(wallet: &Wallet, signature: &str, tokens: &[abi::Token]) -> p256_wallet_core::records::UserOperation {
    wallet.op(vec![raw_call(&wallet.address, "0x0", &abi::encode_call(signature, tokens))], true)
}

fn review_text(review: &p256_wallet_core::records::OperationReview) -> String {
    review.details.iter().map(|d| format!("{}: {}\n", d.label, d.value)).collect()
}

// ======================================================================================================
// Guarantees: attacks the core refuses today
// ======================================================================================================

#[test]
fn guarantee_signature_is_bound_to_chain_operation_and_owner() {
    let wallet = Wallet::new(&[1, 2]);
    let op = wallet.send_eth();
    let review = api::review_user_operation(op.clone(), CHAIN, vec![], vec![]).unwrap();
    let assertion = wallet.keys[0].assert(&hex::decode(&review.hash).unwrap(), FLAG_UP);
    assert!(api::sign_user_operation(
        op.clone(),
        CHAIN,
        assertion.clone(),
        wallet.owner_keys.clone(),
        wallet.owners.clone()
    )
    .is_ok());

    // Replayed on Base mainnet.
    assert!(api::sign_user_operation(
        op.clone(),
        8453,
        assertion.clone(),
        wallet.owner_keys.clone(),
        wallet.owners.clone()
    )
    .is_err());
    // Any field changed after review: calldata, fees, nonce, paymaster.
    type Change = fn(&mut p256_wallet_core::records::UserOperation);
    let changes: [Change; 4] = [
        |o| o.nonce = "0x1".into(),
        |o| o.max_fee_per_gas = "0x1".into(),
        |o| o.paymaster_and_data = "0x1234".into(),
        |o| {
            o.call_data = api::build_user_operation(
                Wallet::new(&[1, 2]).address,
                "0x0".into(),
                true,
                Wallet::new(&[1, 2]).owners,
                vec![api::transfer_call(None, ATTACKER.into(), "0x1".into()).unwrap()],
                gas(),
                0,
            )
            .unwrap()
            .call_data
        },
    ];
    for change in changes {
        let mut changed = op.clone();
        change(&mut changed);
        assert!(api::sign_user_operation(
            changed,
            CHAIN,
            assertion.clone(),
            wallet.owner_keys.clone(),
            wallet.owners.clone()
        )
        .is_err());
    }
}

#[test]
fn guarantee_impersonating_an_owner_credential_fails() {
    // The attacker's own key signs the right hash but claims the victim owner's credential ID.
    let wallet = Wallet::new(&[1]);
    let op = wallet.send_eth();
    let hash = hex::decode(&api::user_operation_hash(op.clone(), CHAIN).unwrap()).unwrap();
    let mut forged = Key::from_seed(66).assert(&hash, FLAG_UP);
    forged.credential_id = hex::encode(&wallet.keys[0].credential_id);
    assert!(api::sign_user_operation(op, CHAIN, forged, wallet.owner_keys, wallet.owners).is_err());
}

#[test]
fn guarantee_user_presence_and_assertion_type_are_required() {
    let wallet = Wallet::new(&[1]);
    let op = wallet.send_eth();
    let hash = hex::decode(&api::user_operation_hash(op.clone(), CHAIN).unwrap()).unwrap();
    let no_touch = wallet.keys[0].assert(&hash, 0);
    assert!(api::sign_user_operation(op.clone(), CHAIN, no_touch, wallet.owner_keys.clone(), wallet.owners.clone())
        .is_err());
    // A registration (`webauthn.create`) response over the same challenge.
    let create = format!(
        "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"https://p256wallet.dev\"}}",
        webauthn::base64url(&hash)
    );
    let created = wallet.keys[0].assert_raw(create.as_bytes(), &rp_auth_data(b"p256wallet.dev", FLAG_UP));
    assert!(api::sign_user_operation(op, CHAIN, created, wallet.owner_keys, wallet.owners).is_err());
}

#[test]
fn guarantee_message_and_operation_signatures_dont_cross() {
    // A signature over a message challenge can't authorise an operation, and vice versa.
    let wallet = Wallet::new(&[1]);
    let op = wallet.send_eth();
    let challenge = api::message_challenge("hi".into(), wallet.address.clone(), CHAIN).unwrap();
    let on_message = wallet.keys[0].assert(&hex::decode(&challenge.challenge).unwrap(), FLAG_UP);
    assert!(api::sign_user_operation(op.clone(), CHAIN, on_message, wallet.owner_keys.clone(), wallet.owners.clone())
        .is_err());
    let on_op = wallet.keys[0].assert(&hex::decode(&api::user_operation_hash(op, CHAIN).unwrap()).unwrap(), FLAG_UP);
    assert!(api::sign_message(
        "hi".into(),
        wallet.address.clone(),
        CHAIN,
        on_op,
        wallet.owner_keys,
        true,
        wallet.owners
    )
    .is_err());
}

#[test]
fn guarantee_deployment_must_create_the_sender() {
    let wallet = Wallet::new(&[1]);
    let mut op = wallet.send_eth();
    let attacker = Wallet::new(&[66]);
    op.init_code = hex::encode(&smart_wallet::init_code(&[hex::decode(&attacker.owners[0]).unwrap()], U256::ZERO));
    assert!(api::review_user_operation(op.clone(), CHAIN, vec![], vec![]).is_err());
    // Another factory with the right createAccount call is refused too.
    let mut other_factory = hex::decode(&wallet.send_eth().init_code).unwrap();
    other_factory[0] ^= 0xff;
    op.init_code = hex::encode(&other_factory);
    assert!(api::review_user_operation(op, CHAIN, vec![], vec![]).is_err());
}

#[test]
fn guarantee_only_execute_and_execute_batch_are_signed() {
    let wallet = Wallet::new(&[1]);
    let mut op = wallet.send_eth();
    // Cross-chain replayable path, and a direct owner change not wrapped in execute.
    for data in [
        abi::encode_call("executeWithoutChainIdValidation(bytes[])", &[abi::Token::Array(vec![])]),
        abi::encode_call("addOwnerAddress(address)", &[abi::Token::Address(address(ATTACKER))]),
    ] {
        op.call_data = hex::encode(&data);
        assert!(api::review_user_operation(op.clone(), CHAIN, vec![], vec![]).is_err());
    }
}

#[test]
fn guarantee_wallet_record_and_keys_are_validated() {
    let wallet = Wallet::new(&[1]);
    let other = Wallet::new(&[2]);
    // Owners that don't produce the address.
    assert!(api::build_user_operation(
        wallet.address.clone(),
        "0x0".into(),
        true,
        other.owners.clone(),
        vec![api::transfer_call(None, DEAD.into(), "0x1".into()).unwrap()],
        gas(),
        0
    )
    .is_err());
    // Off-curve public key.
    let mut key = wallet.keys[0].public_key();
    key.y.replace_range(key.y.len() - 1.., if key.y.ends_with('0') { "1" } else { "0" });
    assert!(api::owner_bytes(key).is_err());
    // An attestation for a different credential.
    let attestation = wallet.keys[0].attestation(FLAG_UP);
    assert!(api::verify_registration(hex::encode(&attestation), hex::encode(&[1, 2, 3]), RP_ID.into(), false).is_err());
}

#[test]
fn guarantee_high_s_is_normalised_and_verifies_like_the_contract() {
    // Recheck the produced WebAuthnAuth exactly as webauthn-sol does, for many signatures (about half start high-s).
    let half_n = U256::from_str_radix("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8", 16).unwrap();
    let wallet = Wallet::new(&[7]);
    for nonce in 0..40u64 {
        let mut op = wallet.send_eth();
        op.nonce = hex::quantity(U256::from(nonce));
        let signed = wallet.sign(&op, 0).unwrap();
        let wrapper = hex::decode(&signed.signature).unwrap();
        let outer = abi::Decoder::new(&wrapper);
        let tuple = outer.usize(0).unwrap();
        let data = outer.bytes(tuple + 32, tuple).unwrap();
        let auth = abi::Decoder::new(&data);
        let base = auth.usize(0).unwrap();
        let json = auth.bytes(base + 32, base).unwrap();
        let challenge_index = auth.usize(base + 64).unwrap();
        let type_index = auth.usize(base + 96).unwrap();
        assert!(auth.uint(base + 160).unwrap() <= half_n, "s must be low");
        let hash = hex::decode(&api::user_operation_hash(op, CHAIN).unwrap()).unwrap();
        let needle = webauthn::challenge_needle(&hash);
        assert_eq!(&json[challenge_index..challenge_index + needle.len()], needle.as_bytes());
        assert_eq!(&json[type_index..type_index + 21], b"\"type\":\"webauthn.get\"");
    }
}

#[test]
fn guarantee_review_lists_every_call_and_the_total_cost() {
    let wallet = Wallet::new(&[1]);
    let calls: Vec<_> =
        (1..=5).map(|i| api::transfer_call(None, DEAD.into(), hex::quantity(U256::from(i))).unwrap()).collect();
    let op = wallet.op(calls, false);
    let review = api::review_user_operation(op, CHAIN, vec![], vec![]).unwrap();
    for i in 1..=5 {
        assert!(review.details.iter().any(|d| d.label == format!("Call {i} of 5")));
    }
    assert_eq!(api::compare_quantities(review.total_value.clone(), "15".into()).unwrap(), 0);
    let sum = U256::from_str_radix(review.max_gas_cost.trim_start_matches("0x"), 16).unwrap() + U256::from(15);
    assert_eq!(review.required_balance, hex::quantity(sum));
}

// ======================================================================================================
// Findings (open). Each asserts the behaviour the finding asks for.
// ======================================================================================================

/// F1 (high): any non-empty `paymasterAndData` makes the review say "sponsored" with a zero fee, and the paymaster
/// isn't shown. An ERC-20 paymaster the wallet has already approved can charge tokens in `postOp` while the user is
/// told the transaction is free, and a bogus paymaster turns "free" into a failed transaction.
#[test]
fn finding_f1_review_shows_the_paymaster() {
    let wallet = Wallet::new(&[1]);
    let mut op = wallet.send_eth();
    let paymaster = "0x00000000000000000000000000000000000Aa000";
    op.paymaster_and_data = format!("{}{}", paymaster.to_lowercase(), "ab".repeat(20));
    let review = api::review_user_operation(op, CHAIN, vec![], vec![]).unwrap();
    assert!(!review.sponsored, "an unknown paymaster must not be called a sponsor");
    assert!(
        review_text(&review).to_lowercase().contains(&paymaster.to_lowercase()[2..]),
        "the paymaster must be named:\n{}",
        review_text(&review)
    );
}

/// F2 (high): self-calls other than `addOwnerPublicKey` are summarised as "Change wallet settings" plus a selector.
/// `addOwnerAddress(attacker)` (an EOA takes over the wallet) and `upgradeToAndCall(evil, …)` (the implementation is
/// replaced) look the same as a harmless setting change.
#[test]
fn finding_f2_owner_takeover_calls_are_refused_or_spelled_out() {
    let wallet = Wallet::new(&[1]);
    for op in [
        self_call(&wallet, "addOwnerAddress(address)", &[abi::Token::Address(address(ATTACKER))]),
        self_call(
            &wallet,
            "upgradeToAndCall(address,bytes)",
            &[abi::Token::Address(address(ATTACKER)), abi::Token::Bytes(vec![])],
        ),
        self_call(
            &wallet,
            "removeOwnerAtIndex(uint256,bytes)",
            &[abi::Token::Uint(U256::ZERO), abi::Token::Bytes(vec![0; 64])],
        ),
    ] {
        match api::review_user_operation(op, CHAIN, vec![], vec![]) {
            Err(_) => {} // refusing is fine
            Ok(review) => {
                let text = review_text(&review);
                assert!(
                    text.contains(&ATTACKER[2..]) || text.contains("Remove owner"),
                    "must name the new owner, implementation or removal:\n{text}"
                );
            }
        }
    }
}

/// F3 (medium): function names come from the app-supplied signature list and are trusted on a 4-byte selector
/// match. Selectors collide by construction, so a malicious contract can register a benign name for its selector
/// in a public signature database. Here `burn(uint256)` is shown as `collate_propagate_storage`.
#[test]
fn finding_f3_colliding_function_names_are_flagged() {
    assert_eq!(abi::selector("burn(uint256)"), abi::selector("collate_propagate_storage(bytes16)"));
    let wallet = Wallet::new(&[1]);
    // A burn whose argument also decodes as a clean bytes16.
    let data = abi::encode_call("burn(uint256)", &[abi::Token::Uint(U256::from(1) << 200)]);
    let op = wallet.op(vec![raw_call("0x036CbD53842c5426634e7929541eC2318f3dCF7e", "0x0", &data)], true);
    let review =
        api::review_user_operation(op, CHAIN, vec![], vec!["collate_propagate_storage(bytes16)".into()]).unwrap();
    let text = review_text(&review);
    assert!(text.contains("collate_propagate_storage"), "current behaviour: the colliding name is shown");
    assert!(
        text.to_lowercase().contains("unverified"),
        "a name matched only by selector must be marked unverified:\n{text}"
    );
}

/// F4 (medium): text from calldata strings, token symbols and names is shown verbatim, so newlines, tabs and
/// bidi overrides can fake extra review rows or reverse an address.
#[test]
fn finding_f4_review_text_has_no_control_or_bidi_characters() {
    let wallet = Wallet::new(&[1]);
    let spoof = "ok\nSend: 0 ETH\nTo: 0x000000000000000000000000000000000000dEaD\u{202e}";
    let data = abi::encode_call("note(string)", &[abi::Token::String(spoof.into())]);
    let token = Token {
        address: "0x036CbD53842c5426634e7929541eC2318f3dCF7e".into(),
        symbol: "USDC\u{202e}\n".into(),
        name: "x".into(),
        decimals: 6,
    };
    let transfer = api::transfer_call(Some(token.address.clone()), DEAD.into(), "0x1".into()).unwrap();
    let op = wallet.op(vec![raw_call(DEAD, "0x0", &data), transfer], true);
    let review = api::review_user_operation(op, CHAIN, vec![token], vec!["note(string)".into()]).unwrap();
    for detail in &review.details {
        let bad =
            detail.value.chars().chain(detail.label.chars()).find(|c| {
                c.is_control() || ('\u{202a}'..='\u{202e}').contains(c) || ('\u{2066}'..='\u{2069}').contains(c)
            });
        assert!(bad.is_none(), "{:?} in {:?}: {:?}", bad, detail.label, detail.value);
    }
}

/// F5 (medium, design): only user presence (a touch) was required. Resolved as a per-key choice: a key registered
/// with a PIN (`require_user_verification`) can't sign without user verification, and registration with a PIN
/// requires the key to verify it. Keys registered without a PIN still sign with a touch, by the owner's choice.
#[test]
fn finding_f5_pin_is_required_for_keys_registered_with_one() {
    let wallet = Wallet::new(&[1]);
    let op = wallet.send_eth();
    let hash = hex::decode(&api::user_operation_hash(op.clone(), CHAIN).unwrap()).unwrap();
    let with_pin = vec![OwnerKey { require_user_verification: true, ..wallet.owner_keys[0].clone() }];
    let touch_only = wallet.keys[0].assert(&hash, FLAG_UP);
    assert!(api::sign_user_operation(op.clone(), CHAIN, touch_only, with_pin.clone(), wallet.owners.clone()).is_err());
    let verified = wallet.keys[0].assert(&hash, FLAG_UP | FLAG_UV);
    assert!(api::sign_user_operation(op, CHAIN, verified, with_pin, wallet.owners).is_ok());

    // Registering with a PIN requires the key to have verified it.
    let key = Key::from_seed(9);
    let id = hex::encode(&key.credential_id);
    assert!(api::verify_registration(hex::encode(&key.attestation(FLAG_UP)), id.clone(), RP_ID.into(), true).is_err());
    let registration =
        api::verify_registration(hex::encode(&key.attestation(FLAG_UP | FLAG_UV)), id, RP_ID.into(), true);
    assert!(registration.unwrap().user_verified);
}

/// F6 (medium): synced passkeys are accepted as owners. Registration doesn't check the backup-eligible flag (or
/// attestation), so an iCloud/Google-synced passkey is indistinguishable from a YubiKey, which breaks "a hardware
/// key signs every transaction": the passkey lives wherever the cloud account does.
#[test]
fn finding_f6_synced_passkeys_are_rejected_at_registration() {
    let key = Key::from_seed(9);
    let synced = key.attestation(FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS);
    assert!(
        api::verify_registration(hex::encode(&synced), hex::encode(&key.credential_id), RP_ID.into(), false).is_err()
    );
}

/// F7 (low, defence in depth): the RP ID hash and origin aren't checked. Authenticators scope credentials by RP
/// ID and webauthn-sol ignores it too, so this needs a misbehaving platform to matter, but the core could pin the
/// expected RP ID(s) cheaply.
#[test]
fn finding_f7_assertions_from_another_rp_are_refused() {
    let wallet = Wallet::new(&[1]);
    let op = wallet.send_eth();
    let hash = hex::decode(&api::user_operation_hash(op.clone(), CHAIN).unwrap()).unwrap();
    let json = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://evil.example\"}}",
        webauthn::base64url(&hash)
    );
    let other_rp = wallet.keys[0].assert_raw(json.as_bytes(), &rp_auth_data(b"evil.example", FLAG_UP));
    assert!(api::sign_user_operation(op, CHAIN, other_rp, wallet.owner_keys, wallet.owners).is_err());
}

/// F8 (low): `owner_keys` from the app aren't checked against the wallet record. A wrong index/key pairing for an
/// initial owner produces a signature the account rejects onchain (a confusing failure, not a loss).
#[test]
fn finding_f8_owner_index_must_match_the_wallet_record() {
    let wallet = Wallet::new(&[1, 2]);
    let challenge = api::message_challenge("hi".into(), wallet.address.clone(), CHAIN).unwrap();
    let assertion = wallet.keys[1].assert(&hex::decode(&challenge.challenge).unwrap(), FLAG_UP);
    // Key 1 claims index 0, which belongs to key 0 in the wallet record.
    let wrong = vec![OwnerKey { owner_index: 0, ..wallet.owner_keys[1].clone() }];
    assert!(
        api::sign_message("hi".into(), wallet.address.clone(), CHAIN, assertion, wrong, true, wallet.owners).is_err()
    );
}

/// F9 (low): the review doesn't say which wallet (`sender`) or network it's for. Harmless for one wallet on one
/// chain; misleading once the apps hold several.
#[test]
fn finding_f9_review_names_the_sending_wallet() {
    let wallet = Wallet::new(&[1]);
    let review = api::review_user_operation(wallet.send_eth(), CHAIN, vec![], vec![]).unwrap();
    assert!(review_text(&review).contains(&wallet.address), "{}", review_text(&review));
}

/// F10 (low): `,` is always a decimal separator, so "1,000" (one thousand in en-GB/en-US) parses as 1.
#[test]
fn finding_f10_ambiguous_comma_is_refused() {
    // "1,000" of a 6-decimal token used to parse as 0xf4240 base units: one token, not a thousand.
    assert!(api::parse_units("1,000".into(), 6).is_err());
}

/// F11 (low): CBOR maps with duplicate keys are accepted (first wins). CTAP2 requires canonical CBOR without
/// duplicates; a parser that accepts them can disagree with another parser about which key was registered.
#[test]
fn finding_f11_duplicate_cose_labels_are_refused() {
    let key = Key::from_seed(3);
    let other = Key::from_seed(4);
    let p = key.signing.verifying_key().to_encoded_point(false);
    let q = other.signing.verifying_key().to_encoded_point(false);
    let cose = cose_key(
        p.x().unwrap(),
        p.y().unwrap(),
        &[(cbor_int(-2), cbor_bytes(q.x().unwrap())), (cbor_int(-3), cbor_bytes(q.y().unwrap()))],
    );
    let object = attestation_object(&cose, &key.credential_id, FLAG_UP);
    assert!(
        api::verify_registration(hex::encode(&object), hex::encode(&key.credential_id), RP_ID.into(), false).is_err()
    );
}

/// F12 (info): only `type(uint256).max` reads "Unlimited". Approvals of 2^255 and similar are effectively unlimited
/// but show as a 78-digit amount.
#[test]
fn finding_f12_huge_approvals_read_as_unlimited() {
    let wallet = Wallet::new(&[1]);
    let data = abi::encode_call(
        "approve(address,uint256)",
        &[abi::Token::Address(address(ATTACKER)), abi::Token::Uint(U256::from(1) << 255)],
    );
    let op = wallet.op(vec![raw_call("0x036CbD53842c5426634e7929541eC2318f3dCF7e", "0x0", &data)], true);
    let review = api::review_user_operation(op, CHAIN, vec![], vec![]).unwrap();
    assert!(review_text(&review).contains("Unlimited"), "{}", review_text(&review));
}
