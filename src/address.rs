//! Ethereum addresses with EIP-55 checksums.

use crate::error::{invalid, Result};
use crate::hash::keccak256;
use crate::hex::{abbreviate, decode, encode};

/// Parses a `0x`-prefixed address. Mixed-case input must carry a valid EIP-55 checksum, so a mistyped address
/// is caught; all-lowercase or all-uppercase input is accepted as unchecksummed.
pub fn parse(text: &str) -> Result<[u8; 20]> {
    let error = || invalid(format!("Not a valid address: {}", abbreviate(text)));
    let body = text.strip_prefix("0x").ok_or_else(error)?;
    if body.len() != 40 {
        return Err(error());
    }
    let bytes: [u8; 20] = decode(body).map_err(|_| error())?.try_into().map_err(|_| error())?;
    let is_mixed_case = body.bytes().any(|b| b.is_ascii_lowercase()) && body.bytes().any(|b| b.is_ascii_uppercase());
    if is_mixed_case && checksum(&bytes) != text {
        return Err(invalid(format!("Address checksum doesn't match (check for a typo): {text}")));
    }
    Ok(bytes)
}

/// EIP-55 mixed-case encoding.
pub fn checksum(address: &[u8; 20]) -> String {
    let lower = &encode(address)[2..];
    let hash = keccak256(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (index, char) in lower.chars().enumerate() {
        let nibble = (hash[index / 2] >> (if index % 2 == 0 { 4 } else { 0 })) & 0x0f;
        out.push(if char.is_ascii_alphabetic() && nibble >= 8 { char.to_ascii_uppercase() } else { char });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip55_vectors() {
        for checksummed in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ] {
            let bytes = parse(&checksummed.to_lowercase()).unwrap();
            assert_eq!(checksum(&bytes), checksummed);
            assert_eq!(parse(checksummed).unwrap(), bytes);
        }
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD").is_err()); // last char case flipped
        assert!(parse("0x1234").is_err());
        assert!(parse("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").is_err());
        assert!(parse(" 0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").is_err());
        assert!(parse("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaeg").is_err());
    }
}
