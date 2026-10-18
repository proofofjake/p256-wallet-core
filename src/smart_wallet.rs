//! Coinbase Smart Wallet v1 (github.com/coinbase/smart-wallet): addresses, calls and signature formats.
//!
//! Owners are stored as bytes: 32 bytes for an Ethereum address, 64 bytes (`x || y`) for a P-256 key. P-256
//! owners sign WebAuthn assertions, which the account verifies with the RIP-7212 precompile.

use crate::abi::{self, Decoder, Token};
use crate::error::{invalid, Result};
use crate::hash::keccak256;
use crate::webauthn::PublicKey;
use ruint::aliases::U256;

/// `CoinbaseSmartWalletFactory`, deployed at the same address on Base, Base Sepolia and most L2s.
pub const FACTORY: [u8; 20] = hex20("0ba5ed0c6aa8c49038f819e587e2633c4a9f428a");
/// ERC-4337 EntryPoint v0.6, the version Coinbase Smart Wallet v1 targets.
pub const ENTRY_POINT_V06: [u8; 20] = hex20("5ff137d4b0fdcd49dca30c7cf57e578a026d2789");
/// `CoinbaseSmartWallet` implementation the factory clones. Documentation only: the address follows from
/// `INIT_CODE_HASH`.
pub const IMPLEMENTATION: [u8; 20] = hex20("000100abaad02f1cfc8bbe32bd5a564817339e72");
/// `factory.initCodeHash()`: keccak of the ERC-1967 proxy creation code pointing at `IMPLEMENTATION`. Read from the
/// factory on Base and Base Sepolia; the live integration test checks it is still current.
pub const INIT_CODE_HASH: [u8; 32] = hex32("5153041b4b8e36c84ca233b2fb610f85b8831b5e56a365618f507f8784fe034e");
/// Returned by `isValidSignature` when a signature is valid (ERC-1271).
pub const ERC1271_MAGIC_VALUE: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];
/// Suffix marking a signature from an account that isn't deployed yet (ERC-6492).
pub const ERC6492_MAGIC_SUFFIX: [u8; 32] = [
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, //
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
];

pub const EXECUTE: &str = "execute(address,uint256,bytes)";
pub const EXECUTE_BATCH: &str = "executeBatch((address,uint256,bytes)[])";
pub const ADD_OWNER_PUBLIC_KEY: &str = "addOwnerPublicKey(bytes32,bytes32)";
pub const REMOVE_OWNER_AT_INDEX: &str = "removeOwnerAtIndex(uint256,bytes)";
pub const CREATE_ACCOUNT: &str = "createAccount(bytes[],uint256)";

/// One call the account makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub target: [u8; 20],
    pub value: U256,
    pub data: Vec<u8>,
}

fn owners_token(owners: &[Vec<u8>]) -> Token {
    Token::Array(owners.iter().map(|owner| Token::Bytes(owner.clone())).collect())
}

/// Checks owner bytes have one of the two lengths the account accepts.
pub fn validate_owners(owners: &[Vec<u8>]) -> Result<()> {
    if owners.is_empty() {
        return Err(invalid("A wallet needs at least one owner"));
    }
    if let Some(owner) = owners.iter().find(|owner| owner.len() != 32 && owner.len() != 64) {
        return Err(invalid(format!("Owner must be 32 or 64 bytes, got {}", owner.len())));
    }
    Ok(())
}

pub fn create_account_calldata(owners: &[Vec<u8>], nonce: U256) -> Vec<u8> {
    abi::encode_call(CREATE_ACCOUNT, &[owners_token(owners), Token::Uint(nonce)])
}

/// `initCode` for the first user operation: the factory address followed by the `createAccount` call.
pub fn init_code(owners: &[Vec<u8>], nonce: U256) -> Vec<u8> {
    let mut out = FACTORY.to_vec();
    out.extend(create_account_calldata(owners, nonce));
    out
}

/// The inverse of [`init_code`]: the owners and nonce a deployment will create the account with. Fails unless it is
/// a `createAccount` call on [`FACTORY`].
pub fn decode_init_code(init_code: &[u8]) -> Result<(Vec<Vec<u8>>, U256)> {
    let unknown = || invalid("Account deployment doesn't use the Coinbase Smart Wallet factory");
    if init_code.len() < 24 || init_code[..20] != FACTORY || init_code[20..24] != abi::selector(CREATE_ACCOUNT) {
        return Err(unknown());
    }
    let args = Decoder::new(&init_code[24..]);
    let array = args.usize(0)?;
    let count = args.usize(array)?;
    if count > init_code.len() / 32 {
        return Err(invalid("Owner list length is out of range"));
    }
    let items = array + 32;
    let owners = (0..count).map(|index| args.bytes(items + index * 32, items)).collect::<Result<Vec<_>>>()?;
    Ok((owners, args.uint(32)?))
}

/// The counterfactual account address, computed locally: `CREATE2(factory, keccak256(abi.encode(owners, nonce)),
/// INIT_CODE_HASH)`. Same on every chain with the factory. Doing this offline means a lying RPC can't hand out an
/// address the user doesn't control.
pub fn account_address(owners: &[Vec<u8>], nonce: U256) -> [u8; 20] {
    let salt = keccak256(abi::encode(&[owners_token(owners), Token::Uint(nonce)]));
    let mut preimage = Vec::with_capacity(85);
    preimage.push(0xff);
    preimage.extend_from_slice(&FACTORY);
    preimage.extend_from_slice(&salt);
    preimage.extend_from_slice(&INIT_CODE_HASH);
    keccak256(preimage)[12..].try_into().expect("20 bytes")
}

/// Single calls use `execute`, several use `executeBatch`.
pub fn call_data(calls: &[Call]) -> Result<Vec<u8>> {
    match calls {
        [] => Err(invalid("A transaction needs at least one call")),
        [call] => Ok(abi::encode_call(
            EXECUTE,
            &[Token::Address(call.target), Token::Uint(call.value), Token::Bytes(call.data.clone())],
        )),
        calls => Ok(abi::encode_call(
            EXECUTE_BATCH,
            &[Token::Array(
                calls
                    .iter()
                    .map(|call| {
                        Token::Tuple(vec![
                            Token::Address(call.target),
                            Token::Uint(call.value),
                            Token::Bytes(call.data.clone()),
                        ])
                    })
                    .collect(),
            )],
        )),
    }
}

/// The inverse of [`call_data`]: what the account will execute. Fails for anything other than `execute` or
/// `executeBatch`, so the core never signs an account call it can't describe.
pub fn decode_call_data(data: &[u8]) -> Result<Vec<Call>> {
    let unknown = || invalid("Transaction calls an account function this wallet doesn't recognize");
    let selector = data.get(..4).ok_or_else(unknown)?;
    let args = Decoder::new(&data[4..]);
    if selector == abi::selector(EXECUTE) {
        Ok(vec![Call { target: args.address(0)?, value: args.uint(32)?, data: args.bytes(64, 0)? }])
    } else if selector == abi::selector(EXECUTE_BATCH) {
        let array = args.usize(0)?;
        let count = args.usize(array)?;
        let items = array + 32;
        // Each element needs at least a 32-byte offset word.
        if count > data.len() / 32 {
            return Err(invalid("Batch length is out of range"));
        }
        (0..count)
            .map(|index| {
                let tuple = items + args.usize(items + index * 32)?;
                Ok(Call {
                    target: args.address(tuple)?,
                    value: args.uint(tuple + 32)?,
                    data: args.bytes(tuple + 64, tuple)?,
                })
            })
            .collect()
    } else {
        Err(unknown())
    }
}

/// Owner management is `onlyOwner`, which includes the account itself, so it goes through `execute`.
pub fn add_owner_public_key_call(account: [u8; 20], key: &PublicKey) -> Call {
    Call {
        target: account,
        value: U256::ZERO,
        data: abi::encode_call(
            ADD_OWNER_PUBLIC_KEY,
            &[Token::FixedBytes(key.x.to_vec()), Token::FixedBytes(key.y.to_vec())],
        ),
    }
}

/// What a call from the account to itself does. These are the only self-calls the core will sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfCall {
    /// A new P-256 owner.
    AddOwnerPublicKey(PublicKey),
    /// Removes the owner at `index`, which must currently be `owner` (the contract checks).
    RemoveOwnerAtIndex { index: U256, owner: Vec<u8> },
}

/// Classifies a call the account makes to itself. Everything outside [`SelfCall`] is refused, because the account's
/// own functions control who owns it: `addOwnerAddress` hands it to an Ethereum address, `upgradeToAndCall` swaps
/// its code, and `removeLastOwner` leaves it with no way to sign.
pub fn classify_self_call(data: &[u8]) -> Result<SelfCall> {
    let selector: [u8; 4] = data.get(..4).and_then(|s| s.try_into().ok()).unwrap_or_default();
    let args = Decoder::new(&data[4.min(data.len())..]);
    if selector == abi::selector(ADD_OWNER_PUBLIC_KEY) && data.len() == 4 + 64 {
        let key = PublicKey::new(args.word(0)?, args.word(32)?)
            .map_err(|_| invalid("Refused: the new owner isn't a valid P-256 key"))?;
        return Ok(SelfCall::AddOwnerPublicKey(key));
    }
    if selector == abi::selector(REMOVE_OWNER_AT_INDEX) {
        let owner = args.bytes(32, 0)?;
        if owner.len() != 32 && owner.len() != 64 {
            return Err(invalid("Refused: owner to remove must be 32 or 64 bytes"));
        }
        return Ok(SelfCall::RemoveOwnerAtIndex { index: args.uint(0)?, owner });
    }
    let refused = |reason: &str| Err(invalid(format!("Refused: {reason}")));
    if selector == abi::selector("addOwnerAddress(address)") {
        return refused(
            "this wallet only accepts security keys as owners; an Ethereum address owner could take it over",
        );
    }
    if selector == abi::selector("upgradeToAndCall(address,bytes)") {
        return refused("this would replace the wallet's contract code");
    }
    if selector == abi::selector("removeLastOwner(uint256,bytes)") {
        return refused("removing the last owner leaves the wallet with no way to sign");
    }
    refused(&format!(
        "this calls the wallet's own function {}, which can change who controls it",
        crate::hex::encode(&selector)
    ))
}

/// `abi.encode(SignatureWrapper(ownerIndex, signatureData))`, the format `UserOperation.signature` and
/// `isValidSignature` expect.
pub fn wrap_signature(owner_index: u32, signature_data: Vec<u8>) -> Vec<u8> {
    abi::encode(&[Token::Tuple(vec![Token::Uint(U256::from(owner_index)), Token::Bytes(signature_data)])])
}

/// Placeholder signature for gas estimation, the same shape as a real assertion and at least as long, so the
/// bundler's `preVerificationGas` (which prices calldata) covers the real one. It mirrors the longest
/// `clientDataJSON` a browser sends: a long extension origin plus the extra key Chrome sometimes adds to discourage
/// template matching.
pub fn dummy_signature(owner_index: u32) -> Vec<u8> {
    let challenge = [0xffu8; 32];
    let mut authenticator_data = vec![0x49u8; 32];
    authenticator_data.extend_from_slice(&[0x05, 0, 0, 0, 0]);
    let json = format!(
        "{{\"type\":\"webauthn.get\",{},\"origin\":\"chrome-extension://fblccdigbmoojajgljjbpaihhdjdcghn\",\
         \"crossOrigin\":false,\"other_keys_can_be_added_here\":\"do not compare clientDataJSON against a template. \
         See https://goo.gl/yabPex\"}}",
        crate::webauthn::challenge_needle(&challenge)
    );
    let challenge_index = json.find("\"challenge\"").expect("present");
    let type_index = json.find("\"type\"").expect("present");
    let half_n =
        U256::from_str_radix("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8", 16).expect("constant");
    let data = abi::encode(&[Token::Tuple(vec![
        Token::Bytes(authenticator_data),
        Token::String(json),
        Token::Uint(U256::from(challenge_index)),
        Token::Uint(U256::from(type_index)),
        Token::Uint(half_n),
        Token::Uint(half_n),
    ])]);
    wrap_signature(owner_index, data)
}

/// The EIP-712 hash the account actually verifies for ERC-1271, binding a signature to one account and chain so it
/// can't be replayed on another account owned by the same key. Matches `CoinbaseSmartWallet.replaySafeHash`.
pub fn replay_safe_hash(hash: [u8; 32], account: [u8; 20], chain_id: u64) -> [u8; 32] {
    let domain_separator = keccak256(abi::encode(&[
        Token::FixedBytes(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)").to_vec(),
        ),
        Token::FixedBytes(keccak256("Coinbase Smart Wallet").to_vec()),
        Token::FixedBytes(keccak256("1").to_vec()),
        Token::Uint(U256::from(chain_id)),
        Token::Address(account),
    ]));
    let struct_hash = keccak256(abi::encode(&[
        Token::FixedBytes(keccak256("CoinbaseSmartWalletMessage(bytes32 hash)").to_vec()),
        Token::FixedBytes(hash.to_vec()),
    ]));
    let mut preimage = vec![0x19, 0x01];
    preimage.extend_from_slice(&domain_separator);
    preimage.extend_from_slice(&struct_hash);
    keccak256(preimage)
}

/// ERC-6492 wrapping so verifiers can check a signature before the account is deployed: they simulate the factory
/// call, then call `isValidSignature`.
pub fn erc6492_wrap(signature: Vec<u8>, owners: &[Vec<u8>], nonce: U256) -> Vec<u8> {
    let mut out = abi::encode(&[
        Token::Address(FACTORY),
        Token::Bytes(create_account_calldata(owners, nonce)),
        Token::Bytes(signature),
    ]);
    out.extend_from_slice(&ERC6492_MAGIC_SUFFIX);
    out
}

/// EIP-191 `personal_sign` hash.
pub fn personal_message_hash(message: &[u8]) -> [u8; 32] {
    let mut preimage = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
    preimage.extend_from_slice(message);
    keccak256(preimage)
}

const fn hex20(text: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < 20 {
        out[i] = nibble(bytes[2 * i]) << 4 | nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

const fn hex32(text: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(bytes[2 * i]) << 4 | nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(char: u8) -> u8 {
    match char {
        b'0'..=b'9' => char - b'0',
        b'a'..=b'f' => char - b'a' + 10,
        _ => panic!("constant must be lowercase hex"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::{decode as hex, encode as to_hex};

    fn address(text: &str) -> [u8; 20] {
        crate::address::parse(text).unwrap()
    }

    #[test]
    fn constants_match_their_checksummed_forms() {
        assert_eq!(crate::address::checksum(&FACTORY), "0x0BA5ED0c6AA8c49038F819E587E2633c4A9F428a");
        assert_eq!(crate::address::checksum(&ENTRY_POINT_V06), "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789");
        assert_eq!(crate::address::checksum(&IMPLEMENTATION), "0x000100abaad02f1cfC8Bbe32bD5a564817339E72");
    }

    #[test]
    fn create_account() {
        let owners = vec![vec![0x11; 64], vec![0x22; 64]];
        // cast calldata "createAccount(bytes[],uint256)" "[0x11..,0x22..]" 0
        assert_eq!(to_hex(&create_account_calldata(&owners, U256::ZERO)), "0x3ffba36f000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000004011111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000004022222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222");
    }

    #[test]
    fn counterfactual_address_matches_factory() {
        // factory.getAddress([0x11.., 0x22..], 0) on Base Sepolia.
        let owners = vec![vec![0x11; 64], vec![0x22; 64]];
        assert_eq!(
            crate::address::checksum(&account_address(&owners, U256::ZERO)),
            "0x2c12B943Dc11D552Fa5648796BD0e85Ac4ddE92b"
        );
    }

    #[test]
    fn init_code_round_trip() {
        let owners = vec![vec![0x11; 64], vec![0x22; 32]];
        let code = init_code(&owners, U256::from(3));
        assert_eq!(decode_init_code(&code).unwrap(), (owners, U256::from(3)));
        let mut other_factory = code.clone();
        other_factory[0] ^= 1;
        assert!(decode_init_code(&other_factory).is_err());
        assert!(decode_init_code(&code[..60]).is_err());
    }

    #[test]
    fn execute_and_round_trip() {
        let call = Call {
            target: address("0x3333333333333333333333333333333333333333"),
            value: U256::from(10u128.pow(18)),
            data: vec![0xa9, 0x05, 0x9c, 0xbb],
        };
        let data = call_data(std::slice::from_ref(&call)).unwrap();
        assert_eq!(to_hex(&data), "0xb61d27f600000000000000000000000033333333333333333333333333333333333333330000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000004a9059cbb00000000000000000000000000000000000000000000000000000000");
        assert_eq!(decode_call_data(&data).unwrap(), vec![call]);
    }

    #[test]
    fn execute_batch_and_round_trip() {
        let calls = vec![
            Call {
                target: address("0x1111111111111111111111111111111111111111"),
                value: U256::from(1),
                data: vec![0xde, 0xad, 0xbe, 0xef],
            },
            Call { target: address("0x2222222222222222222222222222222222222222"), value: U256::ZERO, data: vec![] },
        ];
        let data = call_data(&calls).unwrap();
        assert_eq!(to_hex(&data), "0x34fcd5be00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000001111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000004deadbeef000000000000000000000000000000000000000000000000000000000000000000000000000000002222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(decode_call_data(&data).unwrap(), calls);
    }

    #[test]
    fn refuses_unknown_account_calls() {
        let key = crate::webauthn::tests::public_key(&crate::webauthn::tests::test_key(1));
        let direct = add_owner_public_key_call([0x44; 20], &key).data; // not wrapped in execute
        assert!(decode_call_data(&direct).is_err());
        assert!(decode_call_data(&[]).is_err());
        let mut truncated = call_data(&[Call { target: [1; 20], value: U256::ZERO, data: vec![1; 40] }]).unwrap();
        truncated.truncate(100);
        assert!(decode_call_data(&truncated).is_err());
    }

    #[test]
    fn self_calls() {
        let key = crate::webauthn::tests::public_key(&crate::webauthn::tests::test_key(1));
        let add = add_owner_public_key_call([0x44; 20], &key).data;
        assert_eq!(classify_self_call(&add).unwrap(), SelfCall::AddOwnerPublicKey(key));
        let remove = abi::encode_call(
            REMOVE_OWNER_AT_INDEX,
            &[Token::Uint(U256::from(2)), Token::Bytes(key.owner_bytes().to_vec())],
        );
        assert!(matches!(classify_self_call(&remove).unwrap(), SelfCall::RemoveOwnerAtIndex { .. }));
        for refused in [
            abi::encode_call("addOwnerAddress(address)", &[Token::Address([0xba; 20])]),
            abi::encode_call("upgradeToAndCall(address,bytes)", &[Token::Address([0xba; 20]), Token::Bytes(vec![])]),
            abi::encode_call("removeLastOwner(uint256,bytes)", &[Token::Uint(U256::ZERO), Token::Bytes(vec![0; 64])]),
            abi::encode_call("someOtherFunction()", &[]),
            abi::encode_call(ADD_OWNER_PUBLIC_KEY, &[Token::FixedBytes(vec![1; 32]), Token::FixedBytes(vec![2; 32])]),
            vec![1, 2],
        ] {
            assert!(classify_self_call(&refused).is_err());
        }
    }

    #[test]
    fn signature_wrapper() {
        // cast abi-encode "f((uint256,bytes))" "(2,0xcafebabe)"
        assert_eq!(to_hex(&wrap_signature(2, vec![0xca, 0xfe, 0xba, 0xbe])), "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000004cafebabe00000000000000000000000000000000000000000000000000000000");
    }

    #[test]
    fn dummy_signature_is_well_formed() {
        let dummy = dummy_signature(1);
        let decoder = Decoder::new(&dummy);
        let base = decoder.usize(0).unwrap();
        assert_eq!(decoder.usize(base).unwrap(), 1);
        assert!(dummy.len() > 300);
    }

    #[test]
    fn message_hashes() {
        assert_eq!(
            to_hex(&personal_message_hash(b"hello world")),
            "0xd9eba16ed0ecae432b71fe008c98cc872bb4cc214d3220a36f365326cf807d68"
        );
        // CoinbaseSmartWallet.replaySafeHash(0xab..ab) for this account on Base Sepolia, read via eth_call.
        let hash: [u8; 32] = hex(&"ab".repeat(32)).unwrap().try_into().unwrap();
        assert_eq!(
            to_hex(&replay_safe_hash(hash, address("0x1234567890123456789012345678901234567890"), 84532)),
            "0x635f6857102c57d2fc12f5a61f2606c6f85d88e0a00999dc0e3663fd2f633a4a"
        );
    }
}
