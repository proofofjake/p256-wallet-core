//! Hash functions, all from RustCrypto.

use sha2::{Digest, Sha256};
use sha3::Keccak256;

pub fn keccak256(data: impl AsRef<[u8]>) -> [u8; 32] {
    Keccak256::digest(data.as_ref()).into()
}

pub fn sha256(data: impl AsRef<[u8]>) -> [u8; 32] {
    Sha256::digest(data.as_ref()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::encode;

    #[test]
    fn keccak_vectors() {
        // Foundry `cast keccak`.
        assert_eq!(encode(&keccak256(b"")), "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
        assert_eq!(encode(&keccak256(b"abc")), "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
        // Rate boundaries (136-byte blocks).
        for (length, expected) in [
            (135, "0x34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446"),
            (136, "0xa6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e"),
            (137, "0xd869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39"),
            (300, "0x5b7e0e47a96f32a88b4f14ca177982790807c40e1a105742ba0fc1babe1ef826"),
        ] {
            assert_eq!(encode(&keccak256(vec![b'a'; length])), expected, "length {length}");
        }
    }

    #[test]
    fn sha256_vector() {
        assert_eq!(encode(&sha256(b"abc")), "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
