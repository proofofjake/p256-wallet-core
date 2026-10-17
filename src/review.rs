//! Describes a user operation for the review screen, working only from the operation's own bytes.

use crate::abi::{self, Decoder};
use crate::address::checksum;
use crate::error::Result;
use crate::function_call;
use crate::hex;
use crate::records::{ReviewDetail, Token};
use crate::smart_wallet::{self, Call};
use crate::units;
use crate::user_operation::UserOperation;
use ruint::aliases::U256;

fn row(label: impl Into<String>, value: impl Into<String>) -> ReviewDetail {
    ReviewDetail { label: label.into(), value: value.into(), monospaced: false }
}

fn mono(label: impl Into<String>, value: impl Into<String>) -> ReviewDetail {
    ReviewDetail { label: label.into(), value: value.into(), monospaced: true }
}

fn eth(value: U256) -> String {
    format!("{} ETH", units::format(value, 18, 18))
}

/// Review lines for every call in `op`. `tokens` names known ERC-20s; `function_signatures` lets a contract call show
/// its function and arguments, used only when a signature's selector matches the calldata.
pub fn describe(op: &UserOperation, tokens: &[Token], function_signatures: &[String]) -> Result<Vec<ReviewDetail>> {
    let calls = smart_wallet::decode_call_data(&op.call_data)?;
    let mut details = Vec::new();
    for (index, call) in calls.iter().enumerate() {
        let lines = describe_call(call, op.sender, tokens, function_signatures);
        if calls.len() > 1 {
            details.push(row(format!("Call {} of {}", index + 1, calls.len()), lines.0));
        }
        details.extend(lines.1);
    }
    Ok(details)
}

/// A one-line summary and the detail lines for one call.
fn describe_call(
    call: &Call,
    sender: [u8; 20],
    tokens: &[Token],
    function_signatures: &[String],
) -> (String, Vec<ReviewDetail>) {
    let target = checksum(&call.target);
    let mut lines = Vec::new();

    if call.data.is_empty() {
        if call.value.is_zero() {
            return ("Empty call".into(), vec![row("Call", "Empty (no data, no ETH)"), mono("To", target)]);
        }
        return ("Send ETH".into(), vec![row("Send", eth(call.value)), mono("To", target)]);
    }

    let selector: [u8; 4] = call.data.get(..4).and_then(|s| s.try_into().ok()).unwrap_or_default();
    let args = Decoder::new(call.data.get(4..).unwrap_or_default());
    let token = tokens.iter().find(|t| crate::address::parse(&t.address).ok() == Some(call.target));
    let token_amount = |amount: U256| match token {
        Some(t) => format!("{} {}", units::format(amount, t.decimals, t.decimals), t.symbol),
        None => format!("{amount} base units of an unknown token"),
    };
    let static_args = |count: usize| call.data.len() == 4 + 32 * count;

    let summary = if call.target == sender
        && selector == abi::selector(smart_wallet::ADD_OWNER_PUBLIC_KEY)
        && static_args(2)
    {
        let x = args.word(0).map(|w| hex::encode(&w)).unwrap_or_default();
        lines.push(mono("Add owner key", format!("P-256 {}…", &x[..18.min(x.len())])));
        lines.push(row("Effect", "The new key can sign for this wallet on this network"));
        "Add owner key".to_string()
    } else if call.target == sender {
        lines.push(mono("Wallet setting", hex::encode(&selector)));
        lines.push(row("Effect", "Changes this wallet's own configuration"));
        "Change wallet settings".to_string()
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
                lines.push(row("Approve", if amount == U256::MAX { "Unlimited".into() } else { token_amount(amount) }));
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
    (summary, lines)
}

fn contract_call(lines: &mut Vec<ReviewDetail>, call: &Call, target: &str, function_signatures: &[String]) -> String {
    lines.push(mono("Contract", target));
    let matching = function_signatures
        .iter()
        .filter_map(|text| function_call::parse_signature(text).ok())
        .find(|signature| call.data.get(..4) == Some(&signature.selector()[..]));
    let decoded = matching.as_ref().and_then(|signature| {
        let values = abi::decode_values(&signature.types, &call.data[4..]).ok()?;
        Some((signature, values))
    });
    match decoded {
        Some((signature, values)) => {
            lines.push(mono("Function", signature.canonical()));
            for (index, (kind, value)) in signature.types.iter().zip(values).enumerate() {
                lines.push(mono(format!("Argument {} ({kind})", index + 1), value));
            }
            format!("Call {}", signature.name)
        }
        None => {
            lines.push(mono("Function", format!("Unknown ({})", hex::encode(call.data.get(..4).unwrap_or_default()))));
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

    fn labels(details: &[ReviewDetail]) -> Vec<(String, String)> {
        details.iter().map(|d| (d.label.clone(), d.value.clone())).collect()
    }

    #[test]
    fn eth_transfer() {
        let to = crate::address::parse("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap();
        let details = describe(
            &op(&[Call { target: to, value: U256::from(1_500_000_000_000_000_000u128), data: vec![] }]),
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(
            labels(&details),
            vec![("Send".into(), "1.5 ETH".into()), ("To".into(), "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".into()),]
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
            describe(&op(&[Call { target: token, value: U256::ZERO, data: data.clone() }]), &[usdc()], &[]).unwrap();
        assert_eq!(details[0].value, "1.234567 USDC");
        assert_eq!(details[2].label, "Token contract");
        // Unknown token: raw units, never a guessed symbol.
        let details = describe(&op(&[Call { target: token, value: U256::ZERO, data }]), &[], &[]).unwrap();
        assert_eq!(details[0].value, "1234567 base units of an unknown token");
    }

    #[test]
    fn empty_call_says_so() {
        let details = describe(&op(&[Call { target: [0x55; 20], value: U256::ZERO, data: vec![] }]), &[], &[]).unwrap();
        assert_eq!(details[0].value, "Empty (no data, no ETH)");
        assert_eq!(details[1].label, "To");
    }

    #[test]
    fn unlimited_approval() {
        let data = abi::encode_call("approve(address,uint256)", &[Abi::Address([0x22; 20]), Abi::Uint(U256::MAX)]);
        let details = describe(&op(&[Call { target: [0x33; 20], value: U256::ZERO, data }]), &[], &[]).unwrap();
        assert_eq!(details[0].value, "Unlimited");
    }

    #[test]
    fn contract_call_with_and_without_signature() {
        let data = abi::encode_call("mint(address,uint256)", &[Abi::Address([0x22; 20]), Abi::Uint(U256::from(3))]);
        let call = Call { target: [0x33; 20], value: U256::from(10), data };
        let unknown = describe(&op(std::slice::from_ref(&call)), &[], &[]).unwrap();
        assert_eq!(unknown[1].value, "Unknown (0x40c10f19)");
        assert_eq!(unknown.last().unwrap().label, "Also sends");
        // A signature that doesn't match the selector is ignored.
        let wrong = describe(&op(std::slice::from_ref(&call)), &[], &["burn(address,uint256)".into()]).unwrap();
        assert_eq!(wrong[1].value, "Unknown (0x40c10f19)");
        let named = describe(&op(&[call]), &[], &["mint(address to, uint256 amount)".into()]).unwrap();
        assert_eq!(
            labels(&named)[1..4],
            [
                ("Function".into(), "mint(address,uint256)".into()),
                ("Argument 1 (address)".into(), "0x2222222222222222222222222222222222222222".into()),
                ("Argument 2 (uint256)".into(), "0x3".into()),
            ]
        );
    }

    #[test]
    fn owner_changes_and_batches() {
        let key = crate::webauthn::tests::public_key(&crate::webauthn::tests::test_key(1));
        let add = smart_wallet::add_owner_public_key_call([0xaa; 20], &key);
        let pay = Call { target: [0x44; 20], value: U256::from(1), data: vec![] };
        let details = describe(&op(&[add, pay]), &[], &[]).unwrap();
        assert_eq!(details[0].label, "Call 1 of 2");
        assert_eq!(details[0].value, "Add owner key");
        assert!(details[1].value.starts_with("P-256 0x"));
        assert!(details.iter().any(|d| d.label == "Call 2 of 2" && d.value == "Send ETH"));
    }
}
