//! Describes a user operation for the review screen, working only from the operation's own bytes.
//!
//! Every line passes through [`sanitize`], so text from calldata or the app (token symbols, string arguments)
//! can't fake extra lines or reorder characters.

use crate::abi::{self, Decoder};
use crate::address::checksum;
use crate::error::{invalid, Result};
use crate::function_call;
use crate::hex;
use crate::records::{KnownContract, ReviewDetail, Token};
use crate::smart_wallet::{self, Call, SelfCall};
use crate::units;
use crate::user_operation::UserOperation;
use ruint::aliases::U256;

/// Longest value shown, in characters. Longer text (a long string argument, say) is cut with "…".
const MAX_TEXT: usize = 200;

fn row(label: impl AsRef<str>, value: impl AsRef<str>) -> ReviewDetail {
    ReviewDetail { label: sanitize(label.as_ref()), value: sanitize(value.as_ref()), monospaced: false }
}

fn mono(label: impl AsRef<str>, value: impl AsRef<str>) -> ReviewDetail {
    ReviewDetail { label: sanitize(label.as_ref()), value: sanitize(value.as_ref()), monospaced: true }
}

/// Makes text safe to show as one line: control characters (newlines included), bidi overrides and invisible
/// characters are shown as visible `\u{…}` escapes, and long text is cut.
pub fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(MAX_TEXT * 4));
    for (count, c) in text.chars().enumerate() {
        if count == MAX_TEXT {
            out.push('…');
            break;
        }
        if c.is_control() || is_invisible_or_bidi(c) {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// Format controls that change how text is ordered or spaced without being visible.
fn is_invisible_or_bidi(c: char) -> bool {
    matches!(c,
        '\u{00ad}' | '\u{034f}' | '\u{061c}' | '\u{115f}' | '\u{1160}' | '\u{17b4}' | '\u{17b5}' | '\u{180e}'
        | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{3164}' | '\u{feff}'
        | '\u{ffa0}' | '\u{fff9}'..='\u{fffb}' | '\u{e0000}'..='\u{e007f}')
}

fn eth(value: U256) -> String {
    format!("{} ETH", units::format(value, 18, 18))
}

/// Everything the review screen lists: the sending wallet and network, every call, and who pays for gas.
/// `tokens` names known ERC-20s; `function_signatures` can name a contract call's function (marked unverified,
/// since a 4-byte selector match proves nothing about what the function does).
pub fn describe(
    op: &UserOperation,
    chain_id: u64,
    tokens: &[Token],
    function_signatures: &[String],
    known_paymasters: &[KnownContract],
) -> Result<Vec<ReviewDetail>> {
    let calls = smart_wallet::decode_call_data(&op.call_data)?;
    let network = crate::chains::all().into_iter().find(|c| c.id == chain_id).map(|c| c.name);
    let mut details = vec![
        mono("From", checksum(&op.sender)),
        row("Network", network.unwrap_or_else(|| format!("Chain {chain_id}"))),
    ];
    for (index, call) in calls.iter().enumerate() {
        let (summary, lines) = describe_call(call, op.sender, tokens, function_signatures)?;
        if calls.len() > 1 {
            details.push(row(format!("Call {} of {}", index + 1, calls.len()), summary));
        }
        details.extend(lines);
    }
    if let Some(paymaster) = paymaster(op)? {
        match known_paymasters.iter().find(|k| crate::address::parse(&k.address).ok() == Some(paymaster)) {
            Some(known) => details.push(mono("Gas sponsored by", format!("{} ({})", known.name, checksum(&paymaster)))),
            None => {
                details.push(mono("Gas paid by", format!("Paymaster {}", checksum(&paymaster))));
                details.push(row(
                    "Paymaster",
                    "Not a known sponsor. It can charge this wallet through token allowances you've given it.",
                ));
            }
        }
    }
    Ok(details)
}

/// The paymaster address at the start of `paymasterAndData`, if any.
pub fn paymaster(op: &UserOperation) -> Result<Option<[u8; 20]>> {
    match op.paymaster_and_data.len() {
        0 => Ok(None),
        1..=19 => Err(invalid("paymasterAndData is too short to name a paymaster")),
        _ => Ok(Some(op.paymaster_and_data[..20].try_into().expect("20 bytes"))),
    }
}

/// A one-line summary and the detail lines for one call. Fails for self-calls the core refuses.
fn describe_call(
    call: &Call,
    sender: [u8; 20],
    tokens: &[Token],
    function_signatures: &[String],
) -> Result<(String, Vec<ReviewDetail>)> {
    let target = checksum(&call.target);
    let mut lines = Vec::new();

    if call.data.is_empty() {
        if call.value.is_zero() {
            return Ok(("Empty call".into(), vec![row("Call", "Empty (no data, no ETH)"), mono("To", target)]));
        }
        return Ok(("Send ETH".into(), vec![row("Send", eth(call.value)), mono("To", target)]));
    }

    let selector: [u8; 4] = call.data.get(..4).and_then(|s| s.try_into().ok()).unwrap_or_default();
    let args = Decoder::new(call.data.get(4..).unwrap_or_default());
    let token = tokens.iter().find(|t| crate::address::parse(&t.address).ok() == Some(call.target));
    let token_amount = |amount: U256| match token {
        Some(t) => format!("{} {}", units::format(amount, t.decimals, t.decimals), t.symbol),
        None => format!("{amount} base units of an unknown token"),
    };
    let static_args = |count: usize| call.data.len() == 4 + 32 * count;

    let summary = if call.target == sender {
        match smart_wallet::classify_self_call(&call.data)? {
            SelfCall::AddOwnerPublicKey(key) => {
                lines.push(mono("Add owner key", format!("P-256 {}", hex::encode(&key.owner_bytes()))));
                lines.push(row("Effect", "The new key can sign for this wallet on this network"));
                "Add owner key".to_string()
            }
            SelfCall::RemoveOwnerAtIndex { index, owner } => {
                let kind = if owner.len() == 64 { "P-256" } else { "address" };
                lines.push(mono(format!("Remove owner #{index}"), format!("{kind} {}", hex::encode(&owner))));
                lines.push(row("Effect", "That key can no longer sign for this wallet on this network"));
                "Remove owner".to_string()
            }
        }
    } else if selector == abi::selector("transfer(address,uint256)") && static_args(2) {
        match (args.address(0), args.uint(32)) {
            (Ok(to), Ok(amount)) => {
                lines.push(row("Send", token_amount(amount)));
                lines.push(mono("To", checksum(&to)));
                lines.push(mono("Token contract", target.clone()));
                format!("Send {}", token.map(|t| t.symbol.as_str()).unwrap_or("tokens"))
            }
            _ => contract_call(&mut lines, call, &target, function_signatures),
        }
    } else if selector == abi::selector("approve(address,uint256)") && static_args(2) {
        match (args.address(0), args.uint(32)) {
            (Ok(spender), Ok(amount)) => {
                // No real token has 2^128 base units in circulation, so anything that large is unlimited in effect.
                let unlimited = amount >= U256::from(1) << 128;
                lines.push(row("Approve", if unlimited { "Unlimited".into() } else { token_amount(amount) }));
                lines.push(mono("Spender", checksum(&spender)));
                lines.push(mono("Token contract", target.clone()));
                format!("Approve {}", token.map(|t| t.symbol.as_str()).unwrap_or("tokens"))
            }
            _ => contract_call(&mut lines, call, &target, function_signatures),
        }
    } else {
        contract_call(&mut lines, call, &target, function_signatures)
    };

    if !call.value.is_zero() {
        lines.push(row("Also sends", eth(call.value)));
    }
    Ok((summary, lines))
}

/// A call to some other contract. A supplied signature names the function only if it's the sole match for the
/// selector, and the name is marked unverified: selectors collide (`burn(uint256)` and
/// `collate_propagate_storage(bytes16)` share one), so a match proves nothing about what the function does.
fn contract_call(lines: &mut Vec<ReviewDetail>, call: &Call, target: &str, function_signatures: &[String]) -> String {
    lines.push(mono("Contract", target));
    let selector = call.data.get(..4).unwrap_or_default();
    let mut matching: Vec<function_call::Signature> = function_signatures
        .iter()
        .filter_map(|text| function_call::parse_signature(text).ok())
        .filter(|signature| selector == &signature.selector()[..])
        .collect();
    matching.sort_by_key(|signature| signature.canonical());
    matching.dedup_by_key(|signature| signature.canonical());
    if matching.len() > 1 {
        lines.push(mono("Function", format!("Unknown ({}): several names match this selector", hex::encode(selector))));
        lines.push(row("Calldata", format!("{} bytes", call.data.len())));
        return "Contract call".into();
    }
    let decoded = matching.first().and_then(|signature| {
        let values = abi::decode_values(&signature.types, &call.data[4..]).ok()?;
        Some((signature, values))
    });
    match decoded {
        Some((signature, values)) => {
            lines.push(mono("Function (unverified)", signature.canonical()));
            for (index, (kind, value)) in signature.types.iter().zip(values).enumerate() {
                lines.push(mono(format!("Argument {} ({kind})", index + 1), value));
            }
            format!("Call {}", signature.name)
        }
        None => {
            lines.push(mono("Function", format!("Unknown ({})", hex::encode(selector))));
            lines.push(row("Calldata", format!("{} bytes", call.data.len())));
            "Contract call".into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Token as Abi;

    fn op(calls: &[Call]) -> UserOperation {
        UserOperation { sender: [0xaa; 20], call_data: smart_wallet::call_data(calls).unwrap(), ..Default::default() }
    }

    fn usdc() -> Token {
        Token {
            address: "0x036CbD53842c5426634e7929541eC2318f3dCF7e".into(),
            symbol: "USDC".into(),
            name: "USD Coin".into(),
            decimals: 6,
        }
    }

    /// The call lines, after the "From" and "Network" lines every review starts with.
    fn describe_calls(op: &UserOperation, tokens: &[Token], signatures: &[String]) -> Vec<ReviewDetail> {
        let details = describe(op, 84532, tokens, signatures, &[]).unwrap();
        assert_eq!((details[0].label.as_str(), details[1].label.as_str()), ("From", "Network"));
        details[2..].to_vec()
    }

    fn labels(details: &[ReviewDetail]) -> Vec<(String, String)> {
        details.iter().map(|d| (d.label.clone(), d.value.clone())).collect()
    }

    #[test]
    fn names_the_wallet_and_network() {
        let details =
            describe(&op(&[Call { target: [1; 20], value: U256::from(1), data: vec![] }]), 8453, &[], &[], &[])
                .unwrap();
        assert_eq!(details[0].value, checksum(&[0xaa; 20]));
        assert_eq!(details[1].value, "Base");
        let unknown_chain =
            describe(&op(&[Call { target: [1; 20], value: U256::ZERO, data: vec![] }]), 7, &[], &[], &[]);
        assert_eq!(unknown_chain.unwrap()[1].value, "Chain 7");
    }

    #[test]
    fn eth_transfer() {
        let to = crate::address::parse("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap();
        let details = describe_calls(
            &op(&[Call { target: to, value: U256::from(1_500_000_000_000_000_000u128), data: vec![] }]),
            &[],
            &[],
        );
        assert_eq!(
            labels(&details),
            vec![("Send".into(), "1.5 ETH".into()), ("To".into(), "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".into())]
        );
    }

    #[test]
    fn token_transfer_uses_known_decimals_and_shows_contract() {
        let token = crate::address::parse(&usdc().address).unwrap();
        let data = abi::encode_call(
            "transfer(address,uint256)",
            &[Abi::Address([0x11; 20]), Abi::Uint(U256::from(1_234_567))],
        );
        let details =
            describe_calls(&op(&[Call { target: token, value: U256::ZERO, data: data.clone() }]), &[usdc()], &[]);
        assert_eq!(details[0].value, "1.234567 USDC");
        assert_eq!(details[2].label, "Token contract");
        // Unknown token: raw units, never a guessed symbol.
        let details = describe_calls(&op(&[Call { target: token, value: U256::ZERO, data }]), &[], &[]);
        assert_eq!(details[0].value, "1234567 base units of an unknown token");
    }

    #[test]
    fn empty_call_says_so() {
        let details = describe_calls(&op(&[Call { target: [0x55; 20], value: U256::ZERO, data: vec![] }]), &[], &[]);
        assert_eq!(details[0].value, "Empty (no data, no ETH)");
        assert_eq!(details[1].label, "To");
    }

    #[test]
    fn huge_approvals_are_unlimited() {
        for amount in [U256::MAX, U256::from(1) << 255, U256::from(1) << 128] {
            let data = abi::encode_call("approve(address,uint256)", &[Abi::Address([0x22; 20]), Abi::Uint(amount)]);
            let details = describe_calls(&op(&[Call { target: [0x33; 20], value: U256::ZERO, data }]), &[], &[]);
            assert_eq!(details[0].value, "Unlimited");
        }
        let data =
            abi::encode_call("approve(address,uint256)", &[Abi::Address([0x22; 20]), Abi::Uint(U256::from(5_000_000))]);
        let details = describe_calls(&op(&[Call { target: [0x33; 20], value: U256::ZERO, data }]), &[], &[]);
        assert_eq!(details[0].value, "5000000 base units of an unknown token");
    }

    #[test]
    fn contract_call_names_are_unverified() {
        let data = abi::encode_call("mint(address,uint256)", &[Abi::Address([0x22; 20]), Abi::Uint(U256::from(3))]);
        let call = Call { target: [0x33; 20], value: U256::from(10), data };
        let unknown = describe_calls(&op(std::slice::from_ref(&call)), &[], &[]);
        assert_eq!(unknown[1].value, "Unknown (0x40c10f19)");
        assert_eq!(unknown.last().unwrap().label, "Also sends");
        // A signature that doesn't match the selector is ignored.
        let wrong = describe_calls(&op(std::slice::from_ref(&call)), &[], &["burn(address,uint256)".into()]);
        assert_eq!(wrong[1].value, "Unknown (0x40c10f19)");
        let named = describe_calls(&op(&[call]), &[], &["mint(address to, uint256 amount)".into()]);
        assert_eq!(
            labels(&named)[1..4],
            [
                ("Function (unverified)".into(), "mint(address,uint256)".into()),
                ("Argument 1 (address)".into(), "0x2222222222222222222222222222222222222222".into()),
                ("Argument 2 (uint256)".into(), "0x3".into()),
            ]
        );
    }

    #[test]
    fn colliding_names_show_neither() {
        // burn(uint256) and collate_propagate_storage(bytes16) share the selector 0x42966c68.
        let data = abi::encode_call("burn(uint256)", &[Abi::Uint(U256::from(1) << 200)]);
        let call = Call { target: [0x33; 20], value: U256::ZERO, data };
        let signatures = ["burn(uint256)".to_string(), "collate_propagate_storage(bytes16)".to_string()];
        let details = describe_calls(&op(&[call]), &[], &signatures);
        assert!(details[1].value.contains("several names match"), "{:?}", details[1]);
    }

    #[test]
    fn owner_changes_and_batches() {
        let key = crate::webauthn::tests::public_key(&crate::webauthn::tests::test_key(1));
        let add = smart_wallet::add_owner_public_key_call([0xaa; 20], &key);
        let pay = Call { target: [0x44; 20], value: U256::from(1), data: vec![] };
        let details = describe_calls(&op(&[add, pay]), &[], &[]);
        assert_eq!(details[0].label, "Call 1 of 2");
        assert_eq!(details[0].value, "Add owner key");
        assert_eq!(details[1].value, format!("P-256 {}", hex::encode(&key.owner_bytes())));
        assert!(details.iter().any(|d| d.label == "Call 2 of 2" && d.value == "Send ETH"));

        let remove = abi::encode_call(
            smart_wallet::REMOVE_OWNER_AT_INDEX,
            &[Abi::Uint(U256::from(1)), Abi::Bytes(key.owner_bytes().to_vec())],
        );
        let details = describe_calls(&op(&[Call { target: [0xaa; 20], value: U256::ZERO, data: remove }]), &[], &[]);
        assert_eq!(details[0].label, "Remove owner #1");
    }

    #[test]
    fn dangerous_self_calls_are_refused() {
        let takeover = abi::encode_call("addOwnerAddress(address)", &[Abi::Address([0xba; 20])]);
        let ops = [op(&[Call { target: [0xaa; 20], value: U256::ZERO, data: takeover }])];
        assert!(describe(&ops[0], 84532, &[], &[], &[]).is_err());
    }

    #[test]
    fn paymaster_is_named_and_unknown_ones_are_flagged() {
        let mut with_paymaster = op(&[Call { target: [1; 20], value: U256::from(1), data: vec![] }]);
        with_paymaster.paymaster_and_data = [vec![0x77; 20], vec![1, 2, 3]].concat();
        let details = describe(&with_paymaster, 84532, &[], &[], &[]).unwrap();
        let text = labels(&details).iter().map(|(l, v)| format!("{l}: {v}\n")).collect::<String>();
        assert!(text.contains(&format!("Gas paid by: Paymaster {}", checksum(&[0x77; 20]))), "{text}");
        assert!(text.contains("Not a known sponsor"), "{text}");

        let known = KnownContract { address: checksum(&[0x77; 20]), name: "Test Sponsor".into() };
        let details = describe(&with_paymaster, 84532, &[], &[], &[known]).unwrap();
        assert!(details.iter().any(|d| d.label == "Gas sponsored by" && d.value.starts_with("Test Sponsor")));
        assert!(!details.iter().any(|d| d.value.contains("Not a known sponsor")));

        with_paymaster.paymaster_and_data = vec![1, 2, 3];
        assert!(describe(&with_paymaster, 84532, &[], &[], &[]).is_err(), "too short to name a paymaster");
    }

    #[test]
    fn text_is_sanitized() {
        assert_eq!(sanitize("ok\nSend: 0 ETH"), "ok\\u{a}Send: 0 ETH");
        assert_eq!(sanitize("USDC\u{202e}"), "USDC\\u{202e}");
        assert_eq!(sanitize("a\u{200b}b\tc"), "a\\u{200b}b\\u{9}c");
        assert_eq!(sanitize("plain 0xAbC… text"), "plain 0xAbC… text");
        let long = "x".repeat(500);
        assert_eq!(sanitize(&long).chars().count(), MAX_TEXT + 1);

        let token = Token { symbol: "USDC\u{202e}\n".into(), ..usdc() };
        let data = abi::encode_call("transfer(address,uint256)", &[Abi::Address([0x11; 20]), Abi::Uint(U256::from(1))]);
        let target = crate::address::parse(&usdc().address).unwrap();
        let details = describe_calls(&op(&[Call { target, value: U256::ZERO, data }]), &[token], &[]);
        assert_eq!(details[0].value, "0.000001 USDC\\u{202e}\\u{a}");
    }
}
