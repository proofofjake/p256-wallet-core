//! Minimal CBOR decoder: enough to read WebAuthn attestation objects and COSE keys. Definite lengths only, no
//! floats, bounded nesting and size.
//!
//! What a security key encodes itself (the COSE key and extension outputs inside authenticator data) is read as
//! CTAP2 canonical CBOR, which authenticators must produce: shortest-form lengths, no tags, and map keys in canonical
//! order, which also rules out duplicates with one comparison per key. The attestation object around it is assembled
//! by the browser or OS, so there only duplicate keys are refused.

use crate::error::{invalid, Result};
use std::cmp::Ordering;

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

/// How strictly to read the encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// CTAP2 canonical, for what an authenticator encodes.
    Canonical,
    /// Any definite-length encoding without duplicate map keys, for what a browser or OS assembles.
    Relaxed,
}

const MAX_DEPTH: usize = 16;
/// Most items one array or map may hold. A COSE key has five entries and an attestation object three, so this is
/// generous, and it keeps the duplicate-key check in relaxed maps cheap.
const MAX_ITEMS: u64 = 32;

/// Decodes one item from the start of `data` and returns it with the number of bytes it used.
pub fn decode_prefix(data: &[u8], form: Form) -> Result<(Value, usize)> {
    let mut reader = Reader { data, offset: 0, form };
    let value = reader.item(0)?;
    Ok((value, reader.offset))
}

/// Decodes `data`, which must hold exactly one item.
pub fn decode(data: &[u8], form: Form) -> Result<Value> {
    let (value, used) = decode_prefix(data, form)?;
    if used != data.len() {
        return Err(invalid("CBOR has trailing bytes"));
    }
    Ok(value)
}

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
    form: Form,
}

impl Reader<'_> {
    fn item(&mut self, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(invalid("CBOR is nested too deeply"));
        }
        let initial = *self.data.get(self.offset).ok_or_else(truncated)?;
        self.offset += 1;
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

        let argument = self.argument(info)?;
        Ok(match major {
            0 => Value::Unsigned(argument),
            1 => Value::Negative(argument),
            2 => Value::Bytes(self.take(argument)?.to_vec()),
            3 => Value::Text(
                String::from_utf8(self.take(argument)?.to_vec()).map_err(|_| invalid("CBOR text is not UTF-8"))?,
            ),
            4 => {
                let count = self.count(argument)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.item(depth + 1)?);
                }
                Value::Array(items)
            }
            5 => {
                let count = self.count(argument)?;
                let mut pairs: Vec<(Value, Value)> = Vec::with_capacity(count);
                let mut previous_key: Option<(usize, usize)> = None;
                for _ in 0..count {
                    let start = self.offset;
                    let key = self.item(depth + 1)?;
                    let encoded = &self.data[start..self.offset];
                    // Two parsers that disagree on a repeated key could disagree on what was registered.
                    let in_order = match (self.form, previous_key) {
                        (Form::Canonical, Some((s, e))) => canonical_order(&self.data[s..e], encoded).is_lt(),
                        (Form::Canonical, None) => true,
                        (Form::Relaxed, _) => !pairs.iter().any(|(existing, _)| *existing == key),
                    };
                    if !in_order {
                        return Err(invalid("CBOR map has a duplicate or out-of-order key"));
                    }
                    previous_key = Some((start, self.offset));
                    let value = self.item(depth + 1)?;
                    pairs.push((key, value));
                }
                Value::Map(pairs)
            }
            // Tags: canonical CTAP2 has none; otherwise skip the tag number and return the tagged item.
            6 if self.form == Form::Canonical => return Err(invalid("CBOR tags aren't allowed here")),
            6 => self.item(depth + 1)?,
            _ => unreachable!("major type is three bits"),
        })
    }

    fn argument(&mut self, info: u8) -> Result<u64> {
        let value = match info {
            0..=23 => return Ok(info as u64),
            24..=27 => {
                let length = 1u64 << (info - 24);
                self.take(length)?.iter().fold(0u64, |acc, &b| acc << 8 | b as u64)
            }
            _ => return Err(invalid("Indefinite-length CBOR isn't supported")),
        };
        // Shortest form: each width is used only for values the next smaller one can't hold.
        let smallest = [24, 0x100, 0x1_0000, 0x1_0000_0000][(info - 24) as usize];
        if self.form == Form::Canonical && value < smallest {
            return Err(invalid("CBOR isn't in canonical (shortest) form"));
        }
        Ok(value)
    }

    fn take(&mut self, count: u64) -> Result<&[u8]> {
        let count = usize::try_from(count).map_err(|_| truncated())?;
        let end = self.offset.checked_add(count).ok_or_else(truncated)?;
        let slice = self.data.get(self.offset..end).ok_or_else(truncated)?;
        self.offset = end;
        Ok(slice)
    }

    /// An array or map's item count, capped at [`MAX_ITEMS`].
    fn count(&self, count: u64) -> Result<usize> {
        if count > MAX_ITEMS {
            return Err(invalid("CBOR array or map has too many items"));
        }
        Ok(count as usize)
    }
}

/// CTAP2's canonical key order: by major type, then encoded length, then encoded bytes.
fn canonical_order(a: &[u8], b: &[u8]) -> Ordering {
    (a[0] >> 5, a.len(), a).cmp(&(b[0] >> 5, b.len(), b))
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
        let value = decode(&data, Form::Relaxed).unwrap();
        assert_eq!(value.get_text("a").and_then(Value::as_int), Some(1));
        assert_eq!(value.get_int(-2).and_then(Value::as_bytes), Some(&[1u8, 2][..]));
        assert_eq!(value.get_text("t"), Some(&Value::Array(vec![Value::Bool(true), Value::Null])));
        // -2 before "a" is canonical; "a" before -2 isn't.
        assert!(decode(&data, Form::Canonical).is_err());
    }

    #[test]
    fn rejects_hostile_input() {
        for form in [Form::Canonical, Form::Relaxed] {
            assert!(decode(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], form).is_err()); // huge array
            assert!(decode(&[0x5a, 0xff, 0xff, 0xff, 0xff], form).is_err()); // byte string past the end
            assert!(decode(&[0x9f], form).is_err()); // indefinite length
            assert!(decode(&[0x81; 64], form).is_err()); // nesting
            assert!(decode(&[0x01, 0x02], form).is_err()); // trailing bytes
            assert!(decode(&[], form).is_err());
            assert!(decode(&[0xa2, 0x01, 0x02, 0x01, 0x03], form).is_err()); // {1: 2, 1: 3}
                                                                             // 33 items, each a valid one-byte integer.
            assert!(decode(&[[0x98, 33].as_slice(), &[0x01; 33]].concat(), form).is_err());
        }
    }

    #[test]
    fn canonical_form() {
        // COSE key order: 1, 3, -1, -2, -3.
        let cose = [0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x40, 0x22, 0x40];
        assert!(decode(&cose, Form::Canonical).is_ok());
        let swapped = [0xa5, 0x03, 0x26, 0x01, 0x02, 0x20, 0x01, 0x21, 0x40, 0x22, 0x40];
        assert!(decode(&swapped, Form::Canonical).is_err());
        assert!(decode(&swapped, Form::Relaxed).is_ok());
        // 1 written in two bytes instead of one.
        assert!(decode(&[0x18, 0x01], Form::Canonical).is_err());
        assert!(decode(&[0x18, 0x01], Form::Relaxed).is_ok());
        assert!(decode(&[0x18, 0x18], Form::Canonical).is_ok());
        assert!(decode(&[0xc2, 0x40], Form::Canonical).is_err(), "tagged");
        // Unsigned keys sort before negative ones regardless of length: {24: 0, -1: 0}.
        assert!(decode(&[0xa2, 0x18, 0x18, 0x00, 0x20, 0x00], Form::Canonical).is_ok());
    }
}
