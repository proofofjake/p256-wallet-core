//! Solidity ABI encoding and decoding for the types this wallet uses. Not a general ABI library: no fixed-size
//! arrays, and decoding covers flat values plus what the account's own calls need.

use crate::error::{invalid, Result};
use crate::hash::keccak256;
use ruint::aliases::U256;

/// A value to ABI-encode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// Any `uintN`, or an `intN` already in two's complement form.
    Uint(U256),
    Address([u8; 20]),
    Bool(bool),
    /// `bytes1`…`bytes32`, right-padded.
    FixedBytes(Vec<u8>),
    Bytes(Vec<u8>),
    String(String),
    /// Dynamic array `T[]`.
    Array(Vec<Token>),
    Tuple(Vec<Token>),
}

impl Token {
    fn is_dynamic(&self) -> bool {
        match self {
            Token::Bytes(_) | Token::String(_) | Token::Array(_) => true,
            Token::Tuple(items) => items.iter().any(Token::is_dynamic),
            _ => false,
        }
    }

    /// Size of the value in the head when it is static.
    fn head_size(&self) -> usize {
        match self {
            Token::Tuple(items) if !self.is_dynamic() => items.iter().map(Token::head_size).sum(),
            _ => 32,
        }
    }
}

/// `abi.encode(tokens...)`.
pub fn encode(tokens: &[Token]) -> Vec<u8> {
    let head_size: usize = tokens.iter().map(Token::head_size).sum();
    let mut head = Vec::with_capacity(head_size);
    let mut tail = Vec::new();
    for token in tokens {
        if token.is_dynamic() {
            head.extend_from_slice(&word(U256::from(head_size + tail.len())));
            tail.extend(encode_token(token));
        } else {
            head.extend(encode_token(token));
        }
    }
    head.extend(tail);
    head
}

/// First four bytes of `keccak256(signature)`.
pub fn selector(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

/// `abi.encodeWithSignature(signature, tokens...)`.
pub fn encode_call(signature: &str, tokens: &[Token]) -> Vec<u8> {
    let mut out = selector(signature).to_vec();
    out.extend(encode(tokens));
    out
}

pub fn word(value: U256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

fn encode_token(token: &Token) -> Vec<u8> {
    match token {
        Token::Uint(value) => word(*value).to_vec(),
        Token::Address(address) => {
            let mut out = vec![0u8; 12];
            out.extend_from_slice(address);
            out
        }
        Token::Bool(flag) => word(U256::from(*flag as u8)).to_vec(),
        Token::FixedBytes(bytes) => {
            assert!(bytes.len() <= 32, "fixed bytes longer than 32");
            let mut out = bytes.clone();
            out.resize(32, 0);
            out
        }
        Token::Bytes(bytes) => encode_dynamic_bytes(bytes),
        Token::String(text) => encode_dynamic_bytes(text.as_bytes()),
        Token::Array(items) => {
            let mut out = word(U256::from(items.len())).to_vec();
            out.extend(encode(items));
            out
        }
        Token::Tuple(items) => encode(items),
    }
}

fn encode_dynamic_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = word(U256::from(bytes.len())).to_vec();
    out.extend_from_slice(bytes);
    out.resize(32 + bytes.len().div_ceil(32) * 32, 0);
    out
}

/// Reads values out of ABI-encoded data. Offsets are in bytes from the start of `data`. Rejects values with dirty
/// padding, as Solidity's decoder does.
pub struct Decoder<'a> {
    data: &'a [u8],
}

impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Decoder { data }
    }

    pub fn word(&self, offset: usize) -> Result<[u8; 32]> {
        let end = offset.checked_add(32).ok_or_else(out_of_bounds)?;
        let slice = self.data.get(offset..end).ok_or_else(out_of_bounds)?;
        Ok(slice.try_into().expect("32-byte slice"))
    }

    pub fn uint(&self, offset: usize) -> Result<U256> {
        Ok(U256::from_be_bytes(self.word(offset)?))
    }

    /// A `uintN` that must fit in `bits`.
    pub fn uint_bits(&self, offset: usize, bits: usize) -> Result<U256> {
        let value = self.uint(offset)?;
        if value.bit_len() > bits {
            return Err(invalid(format!("ABI value doesn't fit in uint{bits}")));
        }
        Ok(value)
    }

    /// A small integer such as an offset, length or index.
    pub fn usize(&self, offset: usize) -> Result<usize> {
        let value = self.uint(offset)?;
        usize::try_from(value).map_err(|_| out_of_bounds())
    }

    pub fn bool(&self, offset: usize) -> Result<bool> {
        match self.uint_bits(offset, 1) {
            Ok(value) => Ok(value == U256::from(1)),
            Err(_) => Err(invalid("ABI bool is not 0 or 1")),
        }
    }

    pub fn address(&self, offset: usize) -> Result<[u8; 20]> {
        let word = self.word(offset)?;
        if word[..12].iter().any(|&b| b != 0) {
            return Err(invalid("ABI address has dirty upper bytes"));
        }
        Ok(word[12..].try_into().expect("20-byte slice"))
    }

    /// `bytesN`, which must be zero-padded on the right.
    pub fn fixed_bytes(&self, offset: usize, size: usize) -> Result<Vec<u8>> {
        let word = self.word(offset)?;
        if word[size..].iter().any(|&b| b != 0) {
            return Err(invalid(format!("ABI bytes{size} has dirty padding")));
        }
        Ok(word[..size].to_vec())
    }

    /// Dynamic `bytes` whose offset word sits at `head`, with the offset relative to `base`.
    pub fn bytes(&self, head: usize, base: usize) -> Result<Vec<u8>> {
        let start = base.checked_add(self.usize(head)?).ok_or_else(out_of_bounds)?;
        let length = self.usize(start)?;
        let begin = start.checked_add(32).ok_or_else(out_of_bounds)?;
        let end = begin.checked_add(length).ok_or_else(out_of_bounds)?;
        Ok(self.data.get(begin..end).ok_or_else(out_of_bounds)?.to_vec())
    }

    pub fn string(&self, head: usize, base: usize) -> Result<String> {
        String::from_utf8(self.bytes(head, base)?).map_err(|_| invalid("ABI string is not valid UTF-8"))
    }
}

fn out_of_bounds() -> crate::error::CoreError {
    invalid("ABI data is too short or has an out-of-range offset")
}

/// Decodes flat return values (`abi.decode(data, (types...))`) into display strings: numbers as hex quantities,
/// addresses checksummed, bytes as hex, strings as text, bools as `true`/`false`.
pub fn decode_values(types: &[String], data: &[u8]) -> Result<Vec<String>> {
    let decoder = Decoder::new(data);
    types
        .iter()
        .enumerate()
        .map(|(index, kind)| {
            let head = index * 32;
            let kind = crate::function_call::canonical_type(kind.trim())?;
            Ok(match kind.as_str() {
                "address" => crate::address::checksum(&decoder.address(head)?),
                "bool" => decoder.bool(head)?.to_string(),
                "string" => decoder.string(head, 0)?,
                "bytes" => crate::hex::encode(&decoder.bytes(head, 0)?),
                other => {
                    if let Some(bits) = other.strip_prefix("uint") {
                        crate::hex::quantity(decoder.uint_bits(head, bits.parse().expect("canonical type"))?)
                    } else if let Some(size) = other.strip_prefix("bytes") {
                        crate::hex::encode(&decoder.fixed_bytes(head, size.parse().expect("canonical type"))?)
                    } else {
                        return Err(invalid(format!("Can't decode {other}")));
                    }
                }
            })
        })
        .collect()
}

/// The text of a Solidity `Error(string)` or `Panic(uint256)` revert, if `data` is one.
pub fn decode_revert_reason(data: &[u8]) -> Option<String> {
    let (selector_bytes, payload) = (data.get(..4)?, data.get(4..)?);
    let decoder = Decoder::new(payload);
    if selector_bytes == selector(crate::functions::ERROR) {
        decoder.string(0, 0).ok()
    } else if selector_bytes == selector(crate::functions::PANIC) {
        let code = decoder.uint(0).ok()?;
        Some(format!("Panic {}", crate::hex::quantity(code)))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::{decode as hex, encode as to_hex};

    #[test]
    fn selectors() {
        assert_eq!(selector("transfer(address,uint256)"), [0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(selector("createAccount(bytes[],uint256)"), [0x3f, 0xfb, 0xa3, 0x6f]);
        assert_eq!(selector("getAddress(bytes[],uint256)"), [0x25, 0x0b, 0x1b, 0x41]);
    }

    #[test]
    fn webauthn_auth_struct() {
        // cast abi-encode "f((bytes,string,uint256,uint256,uint256,uint256))" "(0x0102,abc,23,1,5,6)"
        let encoded = encode(&[Token::Tuple(vec![
            Token::Bytes(vec![1, 2]),
            Token::String("abc".into()),
            Token::Uint(U256::from(23)),
            Token::Uint(U256::from(1)),
            Token::Uint(U256::from(5)),
            Token::Uint(U256::from(6)),
        ])]);
        assert_eq!(to_hex(&encoded), "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000170000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000002010200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000036162630000000000000000000000000000000000000000000000000000000000");
    }

    #[test]
    fn decoder_round_trip() {
        let address = [0x11u8; 20];
        let data = encode(&[Token::Uint(U256::from(42)), Token::Bytes(vec![1, 2, 3]), Token::Address(address)]);
        let decoder = Decoder::new(&data);
        assert_eq!(decoder.uint(0).unwrap(), U256::from(42));
        assert_eq!(decoder.bytes(32, 0).unwrap(), vec![1, 2, 3]);
        assert_eq!(decoder.address(64).unwrap(), address);
        assert!(decoder.word(data.len() - 31).is_err());
    }

    #[test]
    fn decoder_rejects_bad_offsets_and_padding() {
        let mut huge_offset = vec![0u8; 64];
        huge_offset[..32].copy_from_slice(&[0xff; 32]);
        assert!(Decoder::new(&huge_offset).bytes(0, 0).is_err());
        let mut dirty = vec![0u8; 32];
        dirty[0] = 1;
        assert!(Decoder::new(&dirty).address(0).is_err());
        assert!(Decoder::new(&dirty).bool(0).is_err());
    }

    #[test]
    fn decode_values_for_display() {
        let data = encode(&[
            Token::Uint(U256::from(1_500_000)),
            Token::String("USD Coin".into()),
            Token::Address(hex("0x036cbd53842c5426634e7929541ec2318f3dcf7e").unwrap().try_into().unwrap()),
            Token::Bool(true),
        ]);
        let types = ["uint256", "string", "address", "bool"].map(String::from);
        assert_eq!(
            decode_values(&types, &data).unwrap(),
            vec!["0x16e360", "USD Coin", "0x036CbD53842c5426634e7929541eC2318f3dCF7e", "true"]
        );
        assert!(decode_values(&["uint8".to_string()], &encode(&[Token::Uint(U256::from(256))])).is_err());
    }

    #[test]
    fn revert_reasons() {
        // cast calldata "Error(string)" "ERC20: transfer amount exceeds balance"
        let data = hex("0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002645524332303a207472616e7366657220616d6f756e7420657863656564732062616c616e63650000000000000000000000000000000000000000000000000000").unwrap();
        assert_eq!(decode_revert_reason(&data).unwrap(), "ERC20: transfer amount exceeds balance");
        let panic = encode_call("Panic(uint256)", &[Token::Uint(U256::from(0x11))]);
        assert_eq!(decode_revert_reason(&panic).unwrap(), "Panic 0x11");
        assert_eq!(decode_revert_reason(&[1, 2, 3]), None);
    }
}
