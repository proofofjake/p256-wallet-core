//! Hex strings, the format every byte string and number crosses the binding boundary in.

use crate::error::{invalid, Result};
use ruint::aliases::U256;

/// Lowercase hex with a `0x` prefix.
pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Parses an even-length hex string, with or without a `0x` prefix. `0x` alone is empty.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    let digits = strip_prefix(text);
    if digits.len() % 2 != 0 {
        return Err(invalid(format!("Hex has an odd number of digits: {}", abbreviate(text))));
    }
    digits.as_bytes().chunks(2).map(|pair| Ok(nibble(pair[0], text)? << 4 | nibble(pair[1], text)?)).collect()
}

/// Parses hex that must be exactly `N` bytes long.
pub fn decode_fixed<const N: usize>(text: &str, what: &str) -> Result<[u8; N]> {
    let bytes = decode(text)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| invalid(format!("{what} must be {N} bytes, got {}", bytes.len())))
}

/// Parses a number: a JSON-RPC hex quantity (`0x1a`) or plain decimal digits (`26`).
pub fn parse_quantity(text: &str) -> Result<U256> {
    let error = || invalid(format!("Not a valid number: {}", abbreviate(text)));
    if let Some(digits) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(error());
        }
        U256::from_str_radix(digits, 16).map_err(|_| error())
    } else {
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(error());
        }
        U256::from_str_radix(text, 10).map_err(|_| error())
    }
}

/// JSON-RPC hex quantity: `0x` followed by the shortest hex form (`0x0` for zero).
pub fn quantity(value: U256) -> String {
    format!("{value:#x}")
}

fn strip_prefix(text: &str) -> &str {
    text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text)
}

fn nibble(char: u8, text: &str) -> Result<u8> {
    match char {
        b'0'..=b'9' => Ok(char - b'0'),
        b'a'..=b'f' => Ok(char - b'a' + 10),
        b'A'..=b'F' => Ok(char - b'A' + 10),
        _ => Err(invalid(format!("Not valid hex: {}", abbreviate(text)))),
    }
}

/// Keeps error messages readable when the input is a long blob.
pub(crate) fn abbreviate(text: &str) -> String {
    if text.chars().count() <= 24 {
        text.to_string()
    } else {
        format!("{}…", text.chars().take(20).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        assert_eq!(encode(&[0x00, 0xab, 0xff]), "0x00abff");
        assert_eq!(decode("0x00abFF").unwrap(), vec![0x00, 0xab, 0xff]);
        assert_eq!(decode("00abff").unwrap(), vec![0x00, 0xab, 0xff]);
        assert_eq!(decode("0x").unwrap(), Vec::<u8>::new());
        assert!(decode("0xabc").is_err());
        assert!(decode("0xzz").is_err());
        assert!(decode_fixed::<2>("0x0102", "x").is_ok());
        assert!(decode_fixed::<2>("0x010203", "x").is_err());
    }

    #[test]
    fn quantities() {
        assert_eq!(quantity(U256::ZERO), "0x0");
        assert_eq!(quantity(U256::from(1_000_000_000_000_000_000u128)), "0xde0b6b3a7640000");
        assert_eq!(parse_quantity("0xde0b6b3a7640000").unwrap(), U256::from(10u128.pow(18)));
        assert_eq!(parse_quantity("1000000000000000000").unwrap(), U256::from(10u128.pow(18)));
        assert_eq!(parse_quantity(&format!("0x{}", "f".repeat(64))).unwrap(), U256::MAX);
        assert_eq!(
            parse_quantity("115792089237316195423570985008687907853269984665640564039457584007913129639935").unwrap(),
            U256::MAX
        );
        // 2^256 overflows.
        assert!(
            parse_quantity("115792089237316195423570985008687907853269984665640564039457584007913129639936").is_err()
        );
        assert!(parse_quantity(&format!("0x1{}", "0".repeat(64))).is_err());
        for bad in ["", "0x", "-1", "1.5", "0x0g", " 1"] {
            assert!(parse_quantity(bad).is_err(), "{bad}");
        }
    }
}
