//! Encodes calls written as `transfer(address to, uint256 amount)` plus string arguments, for the contract call
//! screen. Supports address, bool, string, bytes, uintN, intN and bytesN; arrays and tuples need raw calldata.

use crate::abi::{self, Token};
use crate::error::{invalid, Result};
use crate::hex;
use ruint::aliases::U256;

/// A parsed function signature with parameter names dropped and types canonicalized (`uint` → `uint256`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub name: String,
    pub types: Vec<String>,
}

impl Signature {
    /// `transfer(address,uint256)`, the form selectors are computed from.
    pub fn canonical(&self) -> String {
        format!("{}({})", self.name, self.types.join(","))
    }

    pub fn selector(&self) -> [u8; 4] {
        abi::selector(&self.canonical())
    }
}

pub fn parse_signature(text: &str) -> Result<Signature> {
    let error = || invalid(format!("Invalid function signature: {text}"));
    let trimmed = text.trim();
    let trimmed = trimmed.strip_prefix("function ").unwrap_or(trimmed).trim();
    let (name, rest) = trimmed.split_once('(').ok_or_else(error)?;
    let name = name.trim();
    // Allow trailing modifiers such as `view returns (uint256)` by cutting at the first closing paren.
    let (inner, _) = rest.split_once(')').ok_or_else(error)?;
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(error());
    }
    if inner.contains('(') || inner.contains('[') {
        return Err(invalid("Arrays and tuples aren't supported here. Use raw calldata."));
    }
    let types = if inner.trim().is_empty() {
        Vec::new()
    } else {
        inner
            .split(',')
            .map(|param| canonical_type(param.split_whitespace().next().unwrap_or("")))
            .collect::<Result<_>>()?
    };
    Ok(Signature { name: name.to_string(), types })
}

/// Validates an elementary type and returns its canonical spelling.
pub fn canonical_type(kind: &str) -> Result<String> {
    let unsupported = || invalid(format!("Unsupported type: {kind}"));
    let sized = |prefix: &str, max: usize, step: usize| -> Option<bool> {
        let size: usize = kind.strip_prefix(prefix)?.parse().ok()?;
        Some(size >= step && size <= max && size % step == 0)
    };
    Ok(match kind {
        "address" | "bool" | "string" | "bytes" => kind.to_string(),
        "uint" => "uint256".into(),
        "int" => "int256".into(),
        _ if kind.starts_with("uint") && kind.len() > 4 => {
            if sized("uint", 256, 8) != Some(true) || kind.as_bytes()[4] == b'0' {
                return Err(unsupported());
            }
            kind.to_string()
        }
        _ if kind.starts_with("int") && kind.len() > 3 => {
            if sized("int", 256, 8) != Some(true) || kind.as_bytes()[3] == b'0' {
                return Err(unsupported());
            }
            kind.to_string()
        }
        _ if kind.starts_with("bytes") && kind.len() > 5 => {
            if sized("bytes", 32, 1) != Some(true) || kind.as_bytes()[5] == b'0' {
                return Err(unsupported());
            }
            kind.to_string()
        }
        _ => return Err(unsupported()),
    })
}

/// Returns the parsed signature and the calldata (selector plus encoded arguments).
pub fn encode(signature: &str, arguments: &[String]) -> Result<(Signature, Vec<u8>)> {
    let parsed = parse_signature(signature)?;
    if parsed.types.len() != arguments.len() {
        return Err(invalid(format!("Expected {} arguments, got {}", parsed.types.len(), arguments.len())));
    }
    let tokens =
        parsed.types.iter().zip(arguments).map(|(kind, text)| token(kind, text.trim())).collect::<Result<Vec<_>>>()?;
    let data = abi::encode_call(&parsed.canonical(), &tokens);
    Ok((parsed, data))
}

fn token(kind: &str, text: &str) -> Result<Token> {
    let bad = || invalid(format!("Invalid {kind}: {}", hex::abbreviate(text)));
    Ok(match kind {
        "address" => Token::Address(crate::address::parse(text)?),
        "bool" => match text.to_ascii_lowercase().as_str() {
            "true" | "1" => Token::Bool(true),
            "false" | "0" => Token::Bool(false),
            _ => return Err(bad()),
        },
        "string" => Token::String(text.to_string()),
        "bytes" => Token::Bytes(hex::decode(text).map_err(|_| bad())?),
        _ if kind.starts_with("uint") => {
            let bits: usize = kind[4..].parse().expect("canonical type");
            let value = hex::parse_quantity(text).map_err(|_| bad())?;
            if value.bit_len() > bits {
                return Err(bad());
            }
            Token::Uint(value)
        }
        _ if kind.starts_with("int") => {
            let bits: usize = kind[3..].parse().expect("canonical type");
            let (negative, magnitude) = match text.strip_prefix('-') {
                Some(rest) => (true, rest),
                None => (false, text),
            };
            let magnitude = hex::parse_quantity(magnitude).map_err(|_| bad())?;
            // intN holds -2^(N-1) ..= 2^(N-1) - 1.
            let limit = U256::from(1) << (bits - 1);
            if (negative && magnitude > limit) || (!negative && magnitude >= limit) {
                return Err(bad());
            }
            Token::Uint(if negative { magnitude.wrapping_neg() } else { magnitude })
        }
        _ if kind.starts_with("bytes") => {
            let size: usize = kind[5..].parse().expect("canonical type");
            let bytes = hex::decode(text).map_err(|_| bad())?;
            if bytes.len() != size {
                return Err(bad());
            }
            Token::FixedBytes(bytes)
        }
        _ => return Err(invalid(format!("Unsupported type: {kind}"))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::encode as to_hex;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn transfer_with_parameter_names() {
        let (signature, data) = encode(
            "transfer(address to, uint amount)",
            &args(&["0x036CbD53842c5426634e7929541eC2318f3dCF7e", "1500000"]),
        )
        .unwrap();
        assert_eq!(signature.canonical(), "transfer(address,uint256)");
        assert_eq!(to_hex(&data), "0xa9059cbb000000000000000000000000036cbd53842c5426634e7929541ec2318f3dcf7e000000000000000000000000000000000000000000000000000000000016e360");
    }

    #[test]
    fn mixed_types() {
        // cast calldata "foo(bool,bytes4,string,uint8)" true 0xdeadbeef hello 255
        let (_, data) =
            encode("foo(bool,bytes4,string,uint8)", &args(&["true", "0xdeadbeef", "hello", "255"])).unwrap();
        assert_eq!(to_hex(&data), "0xf13264560000000000000000000000000000000000000000000000000000000000000001deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000000000000000000000000568656c6c6f000000000000000000000000000000000000000000000000000000");
    }

    #[test]
    fn signed_integers() {
        // cast calldata "f(int8,int256)" -- -128 -1
        let (_, data) = encode("f(int8,int256)", &args(&["-128", "-1"])).unwrap();
        assert_eq!(to_hex(&data), "0x0c6bf2b8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assert!(encode("f(int8)", &args(&["128"])).is_err());
        assert!(encode("f(int8)", &args(&["-129"])).is_err());
        assert!(encode("f(int8)", &args(&["127"])).is_ok());
    }

    #[test]
    fn rejections() {
        assert!(encode("f(uint8)", &args(&["256"])).is_err());
        assert!(encode("f(uint256[])", &args(&["1"])).is_err());
        assert!(encode("f((uint256,bool))", &args(&["1"])).is_err());
        assert!(encode("f(uint7)", &args(&["1"])).is_err());
        assert!(encode("f(bytes33)", &args(&["0x00"])).is_err());
        assert!(encode("f(bytes2)", &args(&["0x00"])).is_err());
        assert!(encode("f(address)", &args(&[])).is_err());
        assert!(encode("no parens", &args(&[])).is_err());
        assert!(encode("f(address)", &args(&["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"])).is_err());
    }

    #[test]
    fn no_arguments_and_modifiers() {
        let (signature, data) = encode("function nextOwnerIndex() view returns (uint256)", &[]).unwrap();
        assert_eq!(signature.canonical(), "nextOwnerIndex()");
        assert_eq!(data.len(), 4);
    }
}
