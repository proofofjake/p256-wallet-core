//! Differential testing against Foundry's `cast` (alloy's ABI codec), an independent implementation.
//!
//! The review is only honest if the core decodes `execute`/`executeBatch` calldata the way the account will. This
//! encodes random call sets with both and compares bytes, then mutates the calldata and decodes it with both:
//!
//! - both decode, different calls: **failure** (the review would describe something else than what runs);
//! - only the core decodes: reported (alloy and Solidity reject some encodings the core accepts, or vice versa;
//!   each case needs a look, but the transaction would revert rather than do something unreviewed);
//! - only cast decodes: fine (the core is stricter).
//!
//! ```sh
//! CORE_DIFFERENTIAL=1 cargo test --release --test differential -- --nocapture
//! ```
//! `DIFF_CASES` sets the number of random call sets (default 120; each also gets 3 mutations).

mod common;

use common::Rng;
use p256_wallet_core::functions::{EXECUTE, EXECUTE_BATCH};
use p256_wallet_core::smart_wallet::{call_data, decode_call_data, Call};
use p256_wallet_core::{address, hex};
use ruint::aliases::U256;
use std::process::Command;

fn enabled() -> bool {
    let on = std::env::var("CORE_DIFFERENTIAL").is_ok() && Command::new("cast").arg("--version").output().is_ok();
    if !on {
        eprintln!("skipped: set CORE_DIFFERENTIAL=1 (needs Foundry's cast on PATH)");
    }
    on
}

fn cast(args: &[&str]) -> Result<String, String> {
    let out = Command::new("cast").args(args).output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn random_calls(rng: &mut Rng) -> Vec<Call> {
    (0..1 + rng.below(4))
        .map(|_| {
            let target: [u8; 20] = rng.bytes(20).try_into().unwrap();
            let value = match rng.below(3) {
                0 => U256::ZERO,
                1 => U256::from(rng.next()),
                _ => U256::from_limbs([rng.next(), rng.next(), rng.next(), rng.next()]),
            };
            let len = *rng.pick(&[0, 1, 4, 31, 32, 33, 68, 100]);
            Call { target, value, data: rng.bytes(len) }
        })
        .collect()
}

fn cast_encode(calls: &[Call]) -> String {
    let tuple = |c: &Call| format!("({},{},{})", address::checksum(&c.target), c.value, hex::encode(&c.data));
    if let [call] = calls {
        let (t, v, d) = (address::checksum(&call.target), call.value.to_string(), hex::encode(&call.data));
        cast(&["calldata", EXECUTE, &t, &v, &d]).unwrap()
    } else {
        let list = format!("[{}]", calls.iter().map(tuple).collect::<Vec<_>>().join(","));
        cast(&["calldata", EXECUTE_BATCH, &list]).unwrap()
    }
}

/// `(target, value, data)` lowercase strings, from cast's decoded output.
fn cast_decode(data: &[u8]) -> Result<Vec<(String, String, String)>, String> {
    let hex = hex::encode(data);
    let first_value = |text: &str| text.split_whitespace().next().unwrap_or("").to_string();
    if data.get(..4) == Some(&p256_wallet_core::abi::selector(EXECUTE)[..]) {
        let out = cast(&["calldata-decode", EXECUTE, &hex])?;
        let lines: Vec<&str> = out.lines().collect();
        if lines.len() != 3 {
            return Err(format!("unexpected output: {out}"));
        }
        return Ok(vec![(lines[0].to_lowercase(), first_value(lines[1]), lines[2].to_lowercase())]);
    }
    let out = cast(&["calldata-decode", EXECUTE_BATCH, &hex])?;
    let inner = out.trim().trim_start_matches('[').trim_end_matches(']');
    if inner.is_empty() {
        return Ok(vec![]);
    }
    inner
        .split("), (")
        .map(|tuple| {
            let parts: Vec<&str> = tuple.trim_matches(|c| c == '(' || c == ')').splitn(3, ", ").collect();
            match parts[..] {
                [t, v, d] => Ok((t.to_lowercase(), first_value(v), d.to_lowercase())),
                _ => Err(format!("unexpected tuple: {tuple}")),
            }
        })
        .collect()
}

fn core_view(calls: &[Call]) -> Vec<(String, String, String)> {
    calls.iter().map(|c| (hex::encode(&c.target), c.value.to_string(), hex::encode(&c.data))).collect()
}

#[test]
fn account_calldata_matches_cast() {
    if !enabled() {
        return;
    }
    let cases: usize = std::env::var("DIFF_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(120);
    let mut rng = Rng(0xd1ff);
    let (mut agreed, mut core_only, mut cast_only, mut both_reject) = (0, Vec::new(), 0, 0);
    let mut mismatches = Vec::new();
    for _ in 0..cases {
        let calls = random_calls(&mut rng);
        let ours = call_data(&calls).unwrap();
        assert_eq!(hex::encode(&ours), cast_encode(&calls), "encodings differ for {calls:?}");

        for _ in 0..3 {
            let mutated = rng.mutate(&ours);
            match (decode_call_data(&mutated), cast_decode(&mutated)) {
                (Ok(a), Ok(b)) => {
                    if core_view(&a) == b {
                        agreed += 1;
                    } else {
                        mismatches.push(format!(
                            "{}\n  core: {:?}\n  cast: {:?}",
                            hex::encode(&mutated),
                            core_view(&a),
                            b
                        ));
                    }
                }
                (Ok(_), Err(e)) => {
                    core_only.push(format!("{} ({})", hex::encode(&mutated), e.lines().last().unwrap_or("")))
                }
                (Err(_), Ok(_)) => cast_only += 1,
                (Err(_), Err(_)) => both_reject += 1,
            }
        }
    }
    eprintln!("mutations: {agreed} decoded identically, {both_reject} rejected by both, {cast_only} rejected only by the core (stricter), {} accepted only by the core", core_only.len());
    for case in core_only.iter().take(5) {
        eprintln!("  core-only: {}", &case[..case.len().min(220)]);
    }
    assert!(mismatches.is_empty(), "core and cast decode the same calldata differently:\n{}", mismatches.join("\n"));
}
