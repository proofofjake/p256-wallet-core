//! Describes a checked user operation for the review screen, working only from the operation's own bytes.
//!
//! Each call is decoded into a [`CallKind`] first, then rendered. Every line passes through [`sanitize`], so text
//! from calldata or the app (token symbols, string arguments) can't fake extra lines, reorder characters or hide
//! anything.

use crate::abi::{self, Decoder};
use crate::address::checksum;
use crate::error::Result;
use crate::functions::*;
use crate::policy::CheckedOperation;
use crate::records::{ReviewDetail, Token};
use crate::smart_wallet::{self, Call};
use crate::webauthn::PublicKey;
use crate::{function_call, hex, unicode_table, units};
use ruint::aliases::U256;
use std::cmp::Ordering;
use std::fmt::Write;

/// Longest value shown, in characters. Longer text (a long string argument, say) is cut with "…".
const MAX_TEXT: usize = 200;

/// Uniswap's Permit2, at the same address on every chain.
const PERMIT2: [u8; 20] = hex::array("000000000022d473030f116ddee9f6b43ac78ba3");

fn row(label: impl AsRef<str>, value: impl AsRef<str>) -> ReviewDetail {
    ReviewDetail { label: sanitize(label.as_ref()), value: sanitize(value.as_ref()), monospaced: false }
}

fn mono(label: impl AsRef<str>, value: impl AsRef<str>) -> ReviewDetail {
    ReviewDetail { label: sanitize(label.as_ref()), value: sanitize(value.as_ref()), monospaced: true }
}

/// Makes text safe to show as one line. Only letters, marks, numbers, punctuation, symbols and the ASCII space are
/// shown as themselves (`unicode_table`, generated from the Unicode Character Database); everything else, such as
/// control, format, invisible and unassigned characters, is shown as a visible `\u{…}` escape. Long text is cut.
pub fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(MAX_TEXT * 4));
    for (count, c) in text.chars().enumerate() {
        if count == MAX_TEXT {
            out.push('…');
            break;
        }
        if is_shown(c) {
            out.push(c);
        } else {
            write!(out, "\\u{{{:x}}}", c as u32).expect("writing to a String");
        }
    }
    out
}

fn is_shown(c: char) -> bool {
    let code = c as u32;
    unicode_table::SHOWN
        .binary_search_by(|&(first, last)| {
            if last < code {
                Ordering::Less
            } else if first > code {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        })
        .is_ok()
}

/// What one call does, decoded before anything is formatted. Token calls are recognized by selector and exact shape
/// (canonical encoding, values in range); anything that doesn't decode cleanly is a plain contract call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallKind {
    /// No data and no ETH.
    Empty,
    /// ETH and nothing else.
    SendEth,
    /// The wallet adds an owner key. `policy::check_operation` lets through only the key the app just registered.
    AddOwner(PublicKey),
    /// ERC-20 `transfer`.
    Transfer { to: [u8; 20], amount: U256 },
    /// ERC-20 `approve`, or ERC-721 `approve` of one item: they share a selector.
    Approve { spender: [u8; 20], amount: U256 },
    /// `increaseAllowance`, from OpenZeppelin's ERC-20.
    IncreaseAllowance { spender: [u8; 20], amount: U256 },
    /// ERC-20 `transferFrom` (an amount) or ERC-721 `transferFrom` (an item ID): they share a selector.
    TransferFrom { from: [u8; 20], to: [u8; 20], amount: U256 },
    /// ERC-721 `safeTransferFrom` of one item, with or without data for the receiver.
    SafeTransferFrom { from: [u8; 20], to: [u8; 20], id: U256, data: Vec<u8> },
    /// ERC-1155 `safeTransferFrom`: `amount` of item `id`.
    SafeTransferFrom1155 { from: [u8; 20], to: [u8; 20], id: U256, amount: U256, data: Vec<u8> },
    /// ERC-721 / ERC-1155 `setApprovalForAll`: every item in the collection, including ones received later.
    SetApprovalForAll { operator: [u8; 20], approved: bool },
    /// Permit2 `approve`: lets `spender` move the wallet's `token` through Permit2 until `expiration`.
    Permit2Approve { token: [u8; 20], spender: [u8; 20], amount: U256, expiration: u64 },
    /// Any other call.
    Contract,
}

/// What `call` does. Fails only for a self-call the core refuses (see `smart_wallet::decode_self_call`).
pub fn decode_call(call: &Call, sender: [u8; 20]) -> Result<CallKind> {
    if call.data.is_empty() {
        return Ok(if call.value.is_zero() { CallKind::Empty } else { CallKind::SendEth });
    }
    if call.target == sender {
        return Ok(CallKind::AddOwner(smart_wallet::decode_self_call(&call.data)?));
    }
    Ok(decode_token_call(&call.data).unwrap_or(CallKind::Contract))
}

fn decode_token_call(data: &[u8]) -> Option<CallKind> {
    let selector = data.get(..4)?;
    let args = &data[4..];
    let decoder = Decoder::new(args);
    let is = |signature: &str| selector == abi::selector(signature);
    let words = |count: usize| args.len() == 32 * count;
    let address = |index: usize| decoder.address(32 * index).ok();
    let uint = |index: usize| decoder.uint(32 * index).ok();
    Some(if is(TRANSFER) && words(2) {
        CallKind::Transfer { to: address(0)?, amount: uint(1)? }
    } else if is(APPROVE) && words(2) {
        CallKind::Approve { spender: address(0)?, amount: uint(1)? }
    } else if is(INCREASE_ALLOWANCE) && words(2) {
        CallKind::IncreaseAllowance { spender: address(0)?, amount: uint(1)? }
    } else if is(TRANSFER_FROM) && words(3) {
        CallKind::TransferFrom { from: address(0)?, to: address(1)?, amount: uint(2)? }
    } else if is(SAFE_TRANSFER_FROM) && words(3) {
        CallKind::SafeTransferFrom { from: address(0)?, to: address(1)?, id: uint(2)?, data: vec![] }
    } else if is(SAFE_TRANSFER_FROM_WITH_DATA) {
        let data = trailing_bytes(args, 3)?;
        CallKind::SafeTransferFrom { from: address(0)?, to: address(1)?, id: uint(2)?, data }
    } else if is(SAFE_TRANSFER_FROM_ERC1155) {
        let data = trailing_bytes(args, 4)?;
        CallKind::SafeTransferFrom1155 { from: address(0)?, to: address(1)?, id: uint(2)?, amount: uint(3)?, data }
    } else if is(SET_APPROVAL_FOR_ALL) && words(2) {
        CallKind::SetApprovalForAll { operator: address(0)?, approved: decoder.bool(32).ok()? }
    } else if is(PERMIT2_APPROVE) && words(4) {
        CallKind::Permit2Approve {
            token: address(0)?,
            spender: address(1)?,
            amount: decoder.uint_bits(64, 160).ok()?,
            expiration: decoder.uint_bits(96, 48).ok()?.to(),
        }
    } else {
        return None;
    })
}

/// The `bytes` after `static_words` static arguments, in canonical form: its offset points right after the head, and
/// the encoding ends with its zero padding. Anything else could carry data the review doesn't show.
fn trailing_bytes(args: &[u8], static_words: usize) -> Option<Vec<u8>> {
    let decoder = Decoder::new(args);
    let head = 32 * static_words;
    if decoder.usize(head).ok()? != head + 32 {
        return None;
    }
    let bytes = decoder.bytes(head, 0).ok()?;
    let end = head + 64 + bytes.len();
    let padded = head + 64 + bytes.len().div_ceil(32) * 32;
    (args.len() == padded && args[end..].iter().all(|&b| b == 0)).then_some(bytes)
}

/// Everything the review screen lists: the sending wallet and network, every call, and who pays for gas.
/// `tokens` names known ERC-20s; `function_signatures` can name a contract call's function (marked unverified,
/// since a 4-byte selector match proves nothing about what the function does).
pub fn describe(
    checked: &CheckedOperation,
    tokens: &[Token],
    function_signatures: &[String],
) -> Result<Vec<ReviewDetail>> {
    let sender = checked.op.sender;
    let network = checked.chain.map_or_else(|| format!("Chain {}", checked.chain_id), |c| c.name.to_string());
    let mut details = vec![mono("From", checksum(&sender)), row("Network", network)];
    let count = checked.calls.len();
    for (index, call) in checked.calls.iter().enumerate() {
        let kind = decode_call(call, sender)?;
        let (summary, lines) = render(&kind, call, sender, tokens, function_signatures);
        if count > 1 {
            details.push(row(format!("Call {} of {count}", index + 1), summary));
        }
        details.extend(lines);
    }
    if let Some(paymaster) = checked.paymaster {
        match checked.sponsor() {
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

fn eth(value: U256) -> String {
    format!("{} ETH", units::format(value, 18, 18))
}

fn find_token(tokens: &[Token], address: [u8; 20]) -> Option<&Token> {
    tokens.iter().find(|t| crate::address::parse(&t.address).ok() == Some(address))
}

/// An amount of a known token, or raw base units, never a guessed symbol.
fn token_amount(token: Option<&Token>, amount: U256) -> String {
    match token {
        Some(t) => format!("{} {}", units::format(amount, t.decimals, t.decimals), t.symbol),
        None => format!("{amount} base units of an unknown token"),
    }
}

/// For calls ERC-20 and ERC-721 share: an amount of a known token, or a number that could be either.
fn amount_or_item(token: Option<&Token>, amount: U256) -> String {
    match token {
        Some(_) => token_amount(token, amount),
        None => format!("{amount} (base units of an unknown token, or an NFT's item ID)"),
    }
}

/// An allowance. No real token has 2^128 base units in circulation, so anything that large is unlimited in effect.
fn allowance(token: Option<&Token>, amount: U256, item_or_amount: bool) -> String {
    if amount >= U256::from(1) << 128 {
        "Unlimited".into()
    } else if item_or_amount {
        amount_or_item(token, amount)
    } else {
        token_amount(token, amount)
    }
}

/// An address in a call, marked when it's the sending wallet.
fn party(address: [u8; 20], sender: [u8; 20]) -> String {
    if address == sender {
        format!("{} (this wallet)", checksum(&address))
    } else {
        checksum(&address)
    }
}

/// A one-line summary and the detail lines for one call.
fn render(
    kind: &CallKind,
    call: &Call,
    sender: [u8; 20],
    tokens: &[Token],
    function_signatures: &[String],
) -> (String, Vec<ReviewDetail>) {
    let target = checksum(&call.target);
    let token = find_token(tokens, call.target);
    let symbol = |fallback: &'static str| token.map_or(fallback, |t| t.symbol.as_str()).to_string();
    let mut lines = Vec::new();
    let summary = match kind {
        CallKind::Empty => {
            return ("Empty call".into(), vec![row("Call", "Empty (no data, no ETH)"), mono("To", target)])
        }
        CallKind::SendEth => return ("Send ETH".into(), vec![row("Send", eth(call.value)), mono("To", target)]),
        CallKind::AddOwner(key) => {
            lines.push(mono("Add owner key", format!("P-256 {}", hex::encode(&key.owner_bytes()))));
            lines.push(row("Effect", "The key you just registered can sign for this wallet on this network"));
            "Add owner key".into()
        }
        CallKind::Transfer { to, amount } => {
            lines.push(row("Send", token_amount(token, *amount)));
            lines.push(mono("To", checksum(to)));
            lines.push(mono("Token contract", &target));
            format!("Send {}", symbol("tokens"))
        }
        CallKind::Approve { spender, amount } => {
            lines.push(row("Approve", allowance(token, *amount, true)));
            lines.push(mono("Spender", checksum(spender)));
            lines.push(mono("Token contract", &target));
            format!("Approve {}", symbol("tokens"))
        }
        CallKind::IncreaseAllowance { spender, amount } => {
            lines.push(row("Increase allowance by", allowance(token, *amount, false)));
            lines.push(mono("Spender", checksum(spender)));
            lines.push(mono("Token contract", &target));
            format!("Increase {} allowance", symbol("token"))
        }
        CallKind::TransferFrom { from, to, amount } => {
            lines.push(row("Transfer", amount_or_item(token, *amount)));
            lines.push(mono("From", party(*from, sender)));
            lines.push(mono("To", party(*to, sender)));
            lines.push(mono("Token contract", &target));
            format!("Transfer {}", symbol("tokens or an NFT"))
        }
        CallKind::SafeTransferFrom { from, to, id, data } => {
            lines.push(row("Send NFT", format!("Item #{id}")));
            lines.push(mono("From", party(*from, sender)));
            lines.push(mono("To", party(*to, sender)));
            lines.push(mono("Collection", &target));
            if !data.is_empty() {
                lines.push(row("Data for the receiver", format!("{} bytes", data.len())));
            }
            "Send an NFT".into()
        }
        CallKind::SafeTransferFrom1155 { from, to, id, amount, data } => {
            lines.push(row("Send", format!("{amount} of item #{id}")));
            lines.push(mono("From", party(*from, sender)));
            lines.push(mono("To", party(*to, sender)));
            lines.push(mono("Collection", &target));
            if !data.is_empty() {
                lines.push(row("Data for the receiver", format!("{} bytes", data.len())));
            }
            "Send NFTs".into()
        }
        CallKind::SetApprovalForAll { operator, approved: true } => {
            lines.push(row("Approve", "ALL items in this collection, including ones received later"));
            lines.push(mono("Operator", checksum(operator)));
            lines.push(mono("Collection", &target));
            "Approve all items in a collection".into()
        }
        CallKind::SetApprovalForAll { operator, approved: false } => {
            lines.push(row("Revoke", "Approval for all items in this collection"));
            lines.push(mono("Operator", checksum(operator)));
            lines.push(mono("Collection", &target));
            "Revoke approval for all items".into()
        }
        CallKind::Permit2Approve { token: permitted, spender, amount, expiration } => {
            let permitted_token = find_token(tokens, *permitted);
            lines.push(row("Permit2 allowance", allowance(permitted_token, *amount, false)));
            lines.push(mono("Token", checksum(permitted)));
            lines.push(mono("Spender", checksum(spender)));
            lines.push(row("Expires", expiry(*expiration)));
            let contract = if call.target == PERMIT2 { format!("Permit2 ({target})") } else { target.clone() };
            lines.push(mono("Contract", contract));
            format!("Permit2 approval for {}", permitted_token.map_or("tokens", |t| t.symbol.as_str()))
        }
        CallKind::Contract => contract_call(&mut lines, call, &target, function_signatures),
    };
    if !call.value.is_zero() {
        lines.push(row("Also sends", eth(call.value)));
    }
    (summary, lines)
}

/// A Permit2 expiration. Zero means the end of the block the transaction runs in.
fn expiry(timestamp: u64) -> String {
    const LAST_SECOND_OF_9999: u64 = 253_402_300_799;
    if timestamp == 0 {
        return "At the end of this transaction's block".into();
    }
    if timestamp > LAST_SECOND_OF_9999 {
        return "Never (after the year 9999)".into();
    }
    let (year, month, day) = civil_date(timestamp / 86_400);
    let seconds = timestamp % 86_400;
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02} UTC", seconds / 3600, seconds % 3600 / 60)
}

/// The proleptic Gregorian date `days` after 1970-01-01 (Howard Hinnant's `civil_from_days`).
fn civil_date(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 { shifted_month + 3 } else { shifted_month - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// A call to some other contract. A supplied signature names the function only if it's the sole match for the
/// selector, and the name is marked unverified, in the summary too: selectors collide (`burn(uint256)` and
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
            format!("Call {} (unverified)", signature.name)
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
    use crate::policy;
    use crate::user_operation::UserOperation;

    const SENDER: [u8; 20] = [0xaa; 20];

    fn checked(calls: &[Call], chain_id: u64) -> CheckedOperation {
        let op =
            UserOperation { sender: SENDER, call_data: smart_wallet::call_data(calls).unwrap(), ..Default::default() };
        let new_owner =
            calls.iter().find(|c| c.target == SENDER).and_then(|c| smart_wallet::decode_self_call(&c.data).ok());
        policy::check_operation(op, chain_id, new_owner.as_ref()).unwrap()
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
    fn describe_calls(calls: &[Call], tokens: &[Token], signatures: &[String]) -> Vec<ReviewDetail> {
        let details = describe(&checked(calls, 84532), tokens, signatures).unwrap();
        assert_eq!((details[0].label.as_str(), details[1].label.as_str()), ("From", "Network"));
        details[2..].to_vec()
    }

    fn labels(details: &[ReviewDetail]) -> Vec<(String, String)> {
        details.iter().map(|d| (d.label.clone(), d.value.clone())).collect()
    }

    fn text(details: &[ReviewDetail]) -> String {
        details.iter().map(|d| format!("{}: {}\n", d.label, d.value)).collect()
    }

    fn token_call(signature: &str, args: &[Abi]) -> Call {
        Call { target: [0x33; 20], value: U256::ZERO, data: abi::encode_call(signature, args) }
    }

    #[test]
    fn names_the_wallet_and_network() {
        let send = [Call { target: [1; 20], value: U256::from(1), data: vec![] }];
        let details = describe(&checked(&send, 8453), &[], &[]).unwrap();
        assert_eq!(details[0].value, checksum(&SENDER));
        assert_eq!(details[1].value, "Base");
        assert_eq!(describe(&checked(&send, 7), &[], &[]).unwrap()[1].value, "Chain 7");
    }

    #[test]
    fn eth_transfer() {
        let to = crate::address::parse("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap();
        let details = describe_calls(
            &[Call { target: to, value: U256::from(1_500_000_000_000_000_000u128), data: vec![] }],
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
        let data = abi::encode_call(TRANSFER, &[Abi::Address([0x11; 20]), Abi::Uint(U256::from(1_234_567))]);
        let details = describe_calls(&[Call { target: token, value: U256::ZERO, data: data.clone() }], &[usdc()], &[]);
        assert_eq!(details[0].value, "1.234567 USDC");
        assert_eq!(details[2].label, "Token contract");
        // Unknown token: raw units, never a guessed symbol.
        let details = describe_calls(&[Call { target: token, value: U256::ZERO, data }], &[], &[]);
        assert_eq!(details[0].value, "1234567 base units of an unknown token");
    }

    #[test]
    fn empty_call_says_so() {
        let details = describe_calls(&[Call { target: [0x55; 20], value: U256::ZERO, data: vec![] }], &[], &[]);
        assert_eq!(details[0].value, "Empty (no data, no ETH)");
        assert_eq!(details[1].label, "To");
    }

    #[test]
    fn huge_approvals_are_unlimited() {
        for amount in [U256::MAX, U256::from(1) << 255, U256::from(1) << 128] {
            let details =
                describe_calls(&[token_call(APPROVE, &[Abi::Address([0x22; 20]), Abi::Uint(amount)])], &[], &[]);
            assert_eq!(details[0].value, "Unlimited");
            let details = describe_calls(
                &[token_call(INCREASE_ALLOWANCE, &[Abi::Address([0x22; 20]), Abi::Uint(amount)])],
                &[],
                &[],
            );
            assert_eq!(labels(&details)[0], ("Increase allowance by".into(), "Unlimited".into()));
        }
        let details = describe_calls(
            &[token_call(APPROVE, &[Abi::Address([0x22; 20]), Abi::Uint(U256::from(5_000_000))])],
            &[],
            &[],
        );
        assert_eq!(details[0].value, "5000000 (base units of an unknown token, or an NFT's item ID)");
    }

    #[test]
    fn nft_and_allowance_calls_are_spelled_out() {
        let attacker = Abi::Address([0xba; 20]);
        let wallet = Abi::Address(SENDER);
        let all = describe_calls(&[token_call(SET_APPROVAL_FOR_ALL, &[attacker.clone(), Abi::Bool(true)])], &[], &[]);
        assert!(text(&all).contains("Approve: ALL items in this collection"), "{}", text(&all));
        assert!(text(&all).contains(&checksum(&[0xba; 20])));
        let revoke =
            describe_calls(&[token_call(SET_APPROVAL_FOR_ALL, &[attacker.clone(), Abi::Bool(false)])], &[], &[]);
        assert_eq!(revoke[0].label, "Revoke");

        let pull = describe_calls(
            &[token_call(TRANSFER_FROM, &[wallet.clone(), attacker.clone(), Abi::Uint(U256::from(7))])],
            &[],
            &[],
        );
        assert!(text(&pull).contains(&format!("From: {} (this wallet)", checksum(&SENDER))), "{}", text(&pull));

        let nft = describe_calls(
            &[token_call(
                SAFE_TRANSFER_FROM_WITH_DATA,
                &[wallet.clone(), attacker.clone(), Abi::Uint(U256::from(9)), Abi::Bytes(vec![1; 40])],
            )],
            &[],
            &[],
        );
        assert_eq!(labels(&nft)[0], ("Send NFT".into(), "Item #9".into()));
        assert!(text(&nft).contains("Data for the receiver: 40 bytes"));
        let items = describe_calls(
            &[token_call(
                SAFE_TRANSFER_FROM_ERC1155,
                &[wallet, attacker.clone(), Abi::Uint(U256::from(9)), Abi::Uint(U256::from(3)), Abi::Bytes(vec![])],
            )],
            &[],
            &[],
        );
        assert_eq!(labels(&items)[0], ("Send".into(), "3 of item #9".into()));

        let usdc_address = crate::address::parse(&usdc().address).unwrap();
        let mut permit = token_call(
            PERMIT2_APPROVE,
            &[
                Abi::Address(usdc_address),
                attacker,
                Abi::Uint((U256::from(1) << 160) - U256::from(1)),
                Abi::Uint(U256::from(1_700_000_000)),
            ],
        );
        permit.target = PERMIT2;
        let permit = text(&describe_calls(&[permit], &[usdc()], &[]));
        for expected in [
            "Permit2 allowance: Unlimited",
            "Expires: 2023-11-14 22:13 UTC",
            "Contract: Permit2 (0x000000000022D473030F116dDEE9F6B43aC78BA3)",
        ] {
            assert!(permit.contains(expected), "{expected} in\n{permit}");
        }
    }

    #[test]
    fn non_canonical_token_calls_are_plain_contract_calls() {
        // A bool that isn't 0 or 1, an amount too big for uint160, and bytes with an unusual offset.
        let mut bad_bool = token_call(SET_APPROVAL_FOR_ALL, &[Abi::Address([0xba; 20]), Abi::Uint(U256::from(2))]);
        let mut too_big = token_call(
            PERMIT2_APPROVE,
            &[Abi::Address([1; 20]), Abi::Address([2; 20]), Abi::Uint(U256::from(1) << 160), Abi::Uint(U256::ZERO)],
        );
        let mut data = token_call(
            SAFE_TRANSFER_FROM_WITH_DATA,
            &[Abi::Address(SENDER), Abi::Address([2; 20]), Abi::Uint(U256::from(1)), Abi::Bytes(vec![5; 3])],
        );
        data.data.extend_from_slice(&[0; 32]); // trailing word the canonical encoding doesn't have
        for call in [&mut bad_bool, &mut too_big, &mut data] {
            let details = describe_calls(std::slice::from_ref(call), &[], &[]);
            assert!(details[1].value.starts_with("Unknown ("), "{:?}", details);
        }
    }

    #[test]
    fn permit2_expiry() {
        assert_eq!(expiry(0), "At the end of this transaction's block");
        assert_eq!(expiry(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(expiry(253_402_300_799), "9999-12-31 23:59 UTC");
        assert_eq!(expiry((1 << 48) - 1), "Never (after the year 9999)");
    }

    #[test]
    fn contract_call_names_are_unverified() {
        let data = abi::encode_call("mint(address,uint256)", &[Abi::Address([0x22; 20]), Abi::Uint(U256::from(3))]);
        let call = Call { target: [0x33; 20], value: U256::from(10), data };
        let unknown = describe_calls(std::slice::from_ref(&call), &[], &[]);
        assert_eq!(unknown[1].value, "Unknown (0x40c10f19)");
        assert_eq!(unknown.last().unwrap().label, "Also sends");
        // A signature that doesn't match the selector is ignored.
        let wrong = describe_calls(std::slice::from_ref(&call), &[], &["burn(address,uint256)".into()]);
        assert_eq!(wrong[1].value, "Unknown (0x40c10f19)");
        let named = describe_calls(std::slice::from_ref(&call), &[], &["mint(address to, uint256 amount)".into()]);
        assert_eq!(
            labels(&named)[1..4],
            [
                ("Function (unverified)".into(), "mint(address,uint256)".into()),
                ("Argument 1 (address)".into(), "0x2222222222222222222222222222222222222222".into()),
                ("Argument 2 (uint256)".into(), "0x3".into()),
            ]
        );
        // In a batch, the summary row is marked too.
        let batch = describe_calls(&[call.clone(), call], &[], &["mint(address,uint256)".into()]);
        assert_eq!(labels(&batch)[0], ("Call 1 of 2".into(), "Call mint (unverified)".into()));
    }

    #[test]
    fn colliding_names_show_neither() {
        // burn(uint256) and collate_propagate_storage(bytes16) share the selector 0x42966c68.
        let data = abi::encode_call("burn(uint256)", &[Abi::Uint(U256::from(1) << 200)]);
        let call = Call { target: [0x33; 20], value: U256::ZERO, data };
        let signatures = ["burn(uint256)".to_string(), "collate_propagate_storage(bytes16)".to_string()];
        let details = describe_calls(&[call], &[], &signatures);
        assert!(details[1].value.contains("several names match"), "{:?}", details[1]);
    }

    #[test]
    fn adding_the_new_owner_key() {
        let key = crate::webauthn::tests::public_key(&crate::webauthn::tests::test_key(1));
        let add = smart_wallet::add_owner_public_key_call(SENDER, &key);
        let details = describe_calls(&[add], &[], &[]);
        assert_eq!(details[0].label, "Add owner key");
        assert_eq!(details[0].value, format!("P-256 {}", hex::encode(&key.owner_bytes())));
        assert!(details[1].value.starts_with("The key you just registered"));
    }

    #[test]
    fn paymaster_is_named_and_unknown_ones_are_flagged() {
        let mut with_paymaster = checked(&[Call { target: [1; 20], value: U256::from(1), data: vec![] }], 84532);
        with_paymaster.paymaster = Some([0x77; 20]);
        let details = text(&describe(&with_paymaster, &[], &[]).unwrap());
        assert!(details.contains(&format!("Gas paid by: Paymaster {}", checksum(&[0x77; 20]))), "{details}");
        assert!(details.contains("Not a known sponsor"), "{details}");

        static SPONSORED: crate::chains::Chain = crate::chains::Chain {
            id: 84532,
            name: "Test",
            is_testnet: true,
            rpc_url: "",
            default_bundler_url: "",
            explorer_url: "",
            blockscout_url: None,
            known_tokens: &[],
            verification_gas_buffer: 0,
            known_paymasters: &[crate::chains::KnownPaymaster { address: [0x77; 20], name: "Test Sponsor" }],
        };
        with_paymaster.chain = Some(&SPONSORED);
        let details = text(&describe(&with_paymaster, &[], &[]).unwrap());
        assert!(details.contains("Gas sponsored by: Test Sponsor"), "{details}");
        assert!(!details.contains("Not a known sponsor"), "{details}");
    }

    #[test]
    fn text_is_sanitized() {
        assert_eq!(sanitize("ok\nSend: 0 ETH"), "ok\\u{a}Send: 0 ETH");
        assert_eq!(sanitize("USDC\u{202e}"), "USDC\\u{202e}");
        assert_eq!(sanitize("a\u{200b}b\tc"), "a\\u{200b}b\\u{9}c");
        assert_eq!(sanitize("plain 0xAbC… text"), "plain 0xAbC… text");
        assert_eq!(sanitize("Ünïcödé 日本 €5 😀"), "Ünïcödé 日本 €5 😀");
        let long = "x".repeat(500);
        assert_eq!(sanitize(&long).chars().count(), MAX_TEXT + 1);

        let token = Token { symbol: "USDC\u{202e}\n".into(), ..usdc() };
        let data = abi::encode_call(TRANSFER, &[Abi::Address([0x11; 20]), Abi::Uint(U256::from(1))]);
        let target = crate::address::parse(&usdc().address).unwrap();
        let details = describe_calls(&[Call { target, value: U256::ZERO, data }], &[token], &[]);
        assert_eq!(details[0].value, "0.000001 USDC\\u{202e}\\u{a}");
    }

    #[test]
    fn invisible_characters_are_escaped() {
        // The classes the second review found passing through the old deny-list, plus spaces other than ASCII's.
        for c in [
            '\u{fe00}',
            '\u{fe0f}',
            '\u{e0100}',
            '\u{e01ef}',
            '\u{180b}',
            '\u{180f}',
            '\u{206a}',
            '\u{206f}',
            '\u{600}',
            '\u{605}',
            '\u{110bd}',
            '\u{13430}',
            '\u{1bca0}',
            '\u{a0}',
            '\u{2007}',
            '\u{3000}',
            '\u{3164}',
            '\u{2800}',
            '\u{e000}',
            '\u{10ffff}',
        ] {
            assert!(!is_shown(c), "U+{:04X}", c as u32);
            assert_eq!(sanitize(&c.to_string()), format!("\\u{{{:x}}}", c as u32));
        }
        // Everything std calls a control character is escaped; printable ASCII is shown.
        for c in (0..=0x10ffffu32).filter_map(char::from_u32).filter(|c| c.is_control()) {
            assert!(!is_shown(c), "U+{:04X}", c as u32);
        }
        assert!((' '..='~').all(is_shown));
        // The table is sorted and its ranges don't touch.
        assert!(unicode_table::SHOWN.windows(2).all(|pair| pair[0].1 + 1 < pair[1].0));
        assert!(unicode_table::SHOWN.iter().all(|(first, last)| first <= last));
    }
}
