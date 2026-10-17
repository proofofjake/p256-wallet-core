//! Minimal CBOR decoder: enough to read WebAuthn attestation objects and COSE keys. Definite lengths only, no
//! floats, bounded nesting.

use crate::error::{invalid, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Unsigned(u64),
    /// Encodes `-1 - n`.
    Negative(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
    Undefined,
}

impl Value {
    pub fn get(&self, key: &Value) -> Option<&Value> {
        match self {
            Value::Map(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn get_text(&self, key: &str) -> Option<&Value> {
        self.get(&Value::Text(key.to_string()))
    }

    /// COSE uses small integer keys, negative ones included.
    pub fn get_int(&self, key: i64) -> Option<&Value> {
        let key = if key >= 0 { Value::Unsigned(key as u64) } else { Value::Negative((-1 - key) as u64) };
        self.get(&key)
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match *self {
            Value::Unsigned(n) => i64::try_from(n).ok(),
            Value::Negative(n) => i64::try_from(n).ok().map(|n| -1 - n),
            _ => None,
        }
    }
}

const MAX_DEPTH: usize = 16;

/// Decodes one item from the start of `data` and returns it with the number of bytes it used.
pub fn decode_prefix(data: &[u8]) -> Result<(Value, usize)> {
    let mut offset = 0;
    let value = item(data, &mut offset, 0)?;
    Ok((value, offset))
}

/// Decodes `data`, which must hold exactly one item.
pub fn decode(data: &[u8]) -> Result<Value> {
    let (value, used) = decode_prefix(data)?;
    if used != data.len() {
        return Err(invalid("CBOR has trailing bytes"));
    }
    Ok(value)
}

fn item(data: &[u8], offset: &mut usize, depth: usize) -> Result<Value> {
    if depth > MAX_DEPTH {
        return Err(invalid("CBOR is nested too deeply"));
    }
    let initial = *data.get(*offset).ok_or_else(truncated)?;
    *offset += 1;
    let (major, info) = (initial >> 5, initial & 0x1f);

    if major == 7 {
        return match info {
            20 => Ok(Value::Bool(false)),
            21 => Ok(Value::Bool(true)),
            22 => Ok(Value::Null),
            23 => Ok(Value::Undefined),
            _ => Err(invalid(format!("Unsupported CBOR simple value {info}"))),
        };
    }

    let argument = read_argument(info, data, offset)?;
    Ok(match major {
        0 => Value::Unsigned(argument),
        1 => Value::Negative(argument),
        2 => Value::Bytes(take(argument, data, offset)?.to_vec()),
        3 => Value::Text(
            String::from_utf8(take(argument, data, offset)?.to_vec()).map_err(|_| invalid("CBOR text is not UTF-8"))?,
        ),
        4 => {
            // Each item takes at least one byte, which bounds the allocation by the input size.
            let count = bounded_count(argument, data, *offset)?;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                items.push(item(data, offset, depth + 1)?);
            }
            Value::Array(items)
        }
        5 => {
            let count = bounded_count(argument, data, *offset)?;
            let mut pairs = Vec::with_capacity(count);
            for _ in 0..count {
                let key = item(data, offset, depth + 1)?;
                let value = item(data, offset, depth + 1)?;
                pairs.push((key, value));
            }
            Value::Map(pairs)
        }
        // Tags: skip the tag number and return the tagged item.
        6 => item(data, offset, depth + 1)?,
        _ => unreachable!("major type is three bits"),
    })
}

fn read_argument(info: u8, data: &[u8], offset: &mut usize) -> Result<u64> {
    match info {
        0..=23 => Ok(info as u64),
        24..=27 => {
            let length = 1usize << (info - 24);
            Ok(take(length as u64, data, offset)?.iter().fold(0u64, |acc, &b| acc << 8 | b as u64))
        }
        _ => Err(invalid("Indefinite-length CBOR isn't supported")),
    }
}

fn take<'a>(count: u64, data: &'a [u8], offset: &mut usize) -> Result<&'a [u8]> {
    let count = usize::try_from(count).map_err(|_| truncated())?;
    let end = offset.checked_add(count).ok_or_else(truncated)?;
    let slice = data.get(*offset..end).ok_or_else(truncated)?;
    *offset = end;
    Ok(slice)
}

fn bounded_count(count: u64, data: &[u8], offset: usize) -> Result<usize> {
    let remaining = data.len().saturating_sub(offset) as u64;
    if count > remaining {
        return Err(truncated());
    }
    Ok(count as usize)
}

fn truncated() -> crate::error::CoreError {
    invalid("CBOR data is truncated")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_basic_items() {
        // {"a": 1, -2: h'0102', "t": [true, null]}
        let data = [0xa3, 0x61, b'a', 0x01, 0x21, 0x42, 0x01, 0x02, 0x61, b't', 0x82, 0xf5, 0xf6];
        let value = decode(&data).unwrap();
        assert_eq!(value.get_text("a").and_then(Value::as_int), Some(1));
        assert_eq!(value.get_int(-2).and_then(Value::as_bytes), Some(&[1u8, 2][..]));
        assert_eq!(value.get_text("t"), Some(&Value::Array(vec![Value::Bool(true), Value::Null])));
    }

    #[test]
    fn rejects_hostile_input() {
        assert!(decode(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err()); // huge array
        assert!(decode(&[0x5a, 0xff, 0xff, 0xff, 0xff]).is_err()); // byte string past the end
        assert!(decode(&[0x9f]).is_err()); // indefinite length
        assert!(decode(&[0x81; 64]).is_err()); // nesting
        assert!(decode(&[0x01, 0x02]).is_err()); // trailing bytes
        assert!(decode(&[]).is_err());
    }
}
