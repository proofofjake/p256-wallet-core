//! Converts between decimal amounts people type and read, and integer base units.

use crate::error::{invalid, Result};
use ruint::aliases::U256;

/// Parses `"1.5"` with 18 decimals into `1500000000000000000`. Fails on malformed input, more fractional digits
/// than `decimals`, or overflow, so an amount is never silently rounded.
///
/// A single `,` is accepted as a decimal separator (`"1,5"`), except where it reads as a thousands separator:
/// `"1,000"` is refused rather than guessed, as are amounts with both `,` and `.` or several commas.
pub fn parse(text: &str, decimals: u8) -> Result<U256> {
    let error = || invalid(format!("Invalid amount: {text}"));
    let trimmed = text.trim();
    let commas = trimmed.matches(',').count();
    if commas > 1 || (commas == 1 && trimmed.contains('.')) {
        return Err(invalid(format!("Ambiguous amount {trimmed}: use a dot for decimals and no thousands separators")));
    }
    if let Some((_, after)) = trimmed.split_once(',') {
        if after.len() == 3 && after.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid(format!(
                "Ambiguous amount {trimmed}: use a dot for decimals and no thousands separators"
            )));
        }
    }
    let normalized = trimmed.replace(',', ".");
    let (whole, fraction) = match normalized.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (normalized.as_str(), ""),
    };
    let all_digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if (whole.is_empty() && fraction.is_empty()) || !all_digits(whole) || !all_digits(fraction) {
        return Err(error());
    }
    if fraction.len() > decimals as usize {
        return Err(invalid(format!("Too many decimal places (max {decimals}): {text}")));
    }
    let digits = format!("{whole}{fraction}{}", "0".repeat(decimals as usize - fraction.len()));
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Ok(U256::ZERO);
    }
    U256::from_str_radix(digits, 10).map_err(|_| invalid(format!("Amount is too large: {text}")))
}

/// Formats base units for display with thousands separators, truncating (never rounding up) to
/// `max_fraction_digits`. A nonzero amount too small to show reads `<0.000001`, never `0`.
pub fn format(value: U256, decimals: u8, max_fraction_digits: u8) -> String {
    let (whole, fraction) = split(value, decimals);
    let shown = fraction[..fraction.len().min(max_fraction_digits as usize)].trim_end_matches('0');
    let whole_text = group_thousands(&whole);
    if shown.is_empty() {
        if whole == "0" && value != U256::ZERO {
            return format!("<0.{}1", "0".repeat((max_fraction_digits as usize).saturating_sub(1)));
        }
        return whole_text;
    }
    format!("{whole_text}.{shown}")
}

/// Full precision, no grouping: what to prefill an amount field with.
pub fn format_plain(value: U256, decimals: u8) -> String {
    let (whole, fraction) = split(value, decimals);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        whole
    } else {
        format!("{whole}.{fraction}")
    }
}

/// Whole and fractional digit strings. Works on the decimal string, so any `decimals` value is safe.
fn split(value: U256, decimals: u8) -> (String, String) {
    let digits = value.to_string();
    let decimals = decimals as usize;
    let padded = format!("{}{digits}", "0".repeat((decimals + 1).saturating_sub(digits.len())));
    let (whole, fraction) = padded.split_at(padded.len() - decimals);
    (whole.to_string(), fraction.to_string())
}

fn group_thousands(digits: &str) -> String {
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, char) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(text: &str) -> U256 {
        U256::from_str_radix(text, 10).unwrap()
    }

    #[test]
    fn parses() {
        assert_eq!(parse("1.5", 18).unwrap(), u("1500000000000000000"));
        assert_eq!(parse("0.000001", 6).unwrap(), U256::from(1));
        assert_eq!(parse(".5", 6).unwrap(), U256::from(500_000));
        assert_eq!(parse("5.", 6).unwrap(), U256::from(5_000_000));
        assert_eq!(parse("1,5", 6).unwrap(), U256::from(1_500_000));
        assert_eq!(parse("10", 0).unwrap(), U256::from(10));
        assert_eq!(parse("0", 18).unwrap(), U256::ZERO);
        assert_eq!(parse(" 2 ", 0).unwrap(), U256::from(2));
        // A comma that reads as a thousands separator is refused, not guessed.
        for ambiguous in ["1,000", "1,000.5", "1.000,5", "1,000,000", "12,345"] {
            assert!(parse(ambiguous, 6).is_err(), "{ambiguous}");
        }
        assert_eq!(parse("1,50", 6).unwrap(), U256::from(1_500_000));
        assert_eq!(parse("1,5000", 6).unwrap(), U256::from(1_500_000));
        for bad in ["0.0000001", "1.2.3", "abc", "", ".", "-1", "1e5", "1 000"] {
            assert!(parse(bad, 6).is_err(), "{bad}");
        }
        assert!(parse(&"9".repeat(78), 0).is_err());
        assert!(parse("1", 78).is_err()); // 10^78 > 2^256
    }

    #[test]
    fn formats() {
        assert_eq!(format(u("1234567890000000000000"), 18, 6), "1,234.56789");
        assert_eq!(format(U256::from(1_500_000), 6, 6), "1.5");
        assert_eq!(format(U256::from(1), 18, 6), "<0.000001");
        assert_eq!(format(U256::ZERO, 18, 6), "0");
        assert_eq!(format(U256::from(999), 0, 6), "999");
        assert_eq!(format(U256::from(1000), 0, 6), "1,000");
        assert_eq!(format(u("123456789"), 0, 6), "123,456,789");
        assert_eq!(format(U256::from(1_999_999), 6, 2), "1.99"); // truncates, never rounds up
        assert_eq!(format_plain(u("1000000000000000001"), 18), "1.000000000000000001");
        assert_eq!(format_plain(U256::from(1_500_000), 6), "1.5");
        assert_eq!(format_plain(U256::from(7), 0), "7");
        // Absurd decimals from a token contract must not panic.
        assert_eq!(format(U256::MAX, 255, 6), "<0.000001");
        assert!(format_plain(U256::from(1), 255).starts_with("0.000"));
    }
}
