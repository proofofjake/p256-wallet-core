//! The functions the apps call. Exported to Swift as-is (UniFFI) and wrapped one-to-one for TypeScript (`wasm.rs`).
//!
//! Nothing here does I/O: the apps fetch nonces, gas prices and balances, and pass them in. Every function validates
//! its inputs, and the two signing functions recompute the hash themselves from the operation or message they sign.

use crate::error::{bad_assertion, invalid, Result};
use crate::records::*;
use crate::smart_wallet as wallet;
use crate::user_operation::UserOperation as Op;
use crate::{abi, address, chains, function_call, hex, review, units, webauthn};
use ruint::aliases::U256;
use std::cmp::Ordering;

// MARK: Conversions

fn addr(text: &str) -> Result<[u8; 20]> {
    address::parse(text)
}

fn quantity(text: &str) -> Result<U256> {
    hex::parse_quantity(text)
}

fn bytes(text: &str) -> Result<Vec<u8>> {
    hex::decode(text)
}

fn owners(initial_owners: &[String]) -> Result<Vec<Vec<u8>>> {
    let owners = initial_owners.iter().map(|owner| bytes(owner)).collect::<Result<Vec<_>>>()?;
    wallet::validate_owners(&owners)?;
    Ok(owners)
}

fn public_key(key: &PublicKey) -> Result<webauthn::PublicKey> {
    webauthn::PublicKey::new(hex::decode_fixed(&key.x, "Public key x")?, hex::decode_fixed(&key.y, "Public key y")?)
}

fn public_key_record(key: &webauthn::PublicKey) -> PublicKey {
    PublicKey { x: hex::encode(&key.x), y: hex::encode(&key.y) }
}

fn call(call: &Call) -> Result<wallet::Call> {
    Ok(wallet::Call { target: addr(&call.target)?, value: quantity(&call.value)?, data: bytes(&call.data)? })
}

fn call_record(call: &wallet::Call) -> Call {
    Call { target: address::checksum(&call.target), value: hex::quantity(call.value), data: hex::encode(&call.data) }
}

fn op(op: &UserOperation) -> Result<Op> {
    Ok(Op {
        sender: addr(&op.sender)?,
        nonce: quantity(&op.nonce)?,
        init_code: bytes(&op.init_code)?,
        call_data: bytes(&op.call_data)?,
        call_gas_limit: quantity(&op.call_gas_limit)?,
        verification_gas_limit: quantity(&op.verification_gas_limit)?,
        pre_verification_gas: quantity(&op.pre_verification_gas)?,
        max_fee_per_gas: quantity(&op.max_fee_per_gas)?,
        max_priority_fee_per_gas: quantity(&op.max_priority_fee_per_gas)?,
        paymaster_and_data: bytes(&op.paymaster_and_data)?,
        signature: bytes(&op.signature)?,
    })
}

fn op_record(op: &Op) -> UserOperation {
    UserOperation {
        sender: address::checksum(&op.sender),
        nonce: hex::quantity(op.nonce),
        init_code: hex::encode(&op.init_code),
        call_data: hex::encode(&op.call_data),
        call_gas_limit: hex::quantity(op.call_gas_limit),
        verification_gas_limit: hex::quantity(op.verification_gas_limit),
        pre_verification_gas: hex::quantity(op.pre_verification_gas),
        max_fee_per_gas: hex::quantity(op.max_fee_per_gas),
        max_priority_fee_per_gas: hex::quantity(op.max_priority_fee_per_gas),
        paymaster_and_data: hex::encode(&op.paymaster_and_data),
        signature: hex::encode(&op.signature),
    }
}

fn assertion(assertion: &Assertion) -> Result<webauthn::Assertion> {
    let field = |text: &str, name: &str| {
        hex::decode(text).map_err(|_| bad_assertion(format!("Security key response has a malformed {name}")))
    };
    Ok(webauthn::Assertion {
        credential_id: field(&assertion.credential_id, "credential ID")?,
        authenticator_data: field(&assertion.authenticator_data, "authenticatorData")?,
        client_data_json: field(&assertion.client_data_json, "clientDataJSON")?,
        signature_der: field(&assertion.signature, "signature")?,
    })
}

/// Finds the owner that produced `assertion` and returns its `SignatureWrapper` over `challenge`.
///
/// The owner's index is checked against the wallet record where the record fixes it (the initial owners), so a
/// mismatched key list fails here rather than as an opaque onchain rejection.
fn wrapped_signature(
    assertion_record: &Assertion,
    challenge: &[u8],
    owner_keys: &[OwnerKey],
    initial_owners: &[Vec<u8>],
) -> Result<Vec<u8>> {
    if owner_keys.is_empty() {
        return Err(bad_assertion("This wallet has no keys that can sign on this network"));
    }
    let assertion = assertion(assertion_record)?;
    let owner = owner_keys
        .iter()
        .find(|owner| hex::decode(&owner.credential_id).ok().as_deref() == Some(&assertion.credential_id[..]))
        .ok_or_else(|| bad_assertion("That key isn't an owner of this wallet"))?;
    let key = public_key(&owner.public_key)?;
    if let Some(recorded) = initial_owners.get(owner.owner_index as usize) {
        if recorded[..] != key.owner_bytes()[..] {
            return Err(bad_assertion(format!(
                "This key isn't owner #{} in the wallet record; the key list is out of date",
                owner.owner_index
            )));
        }
    }
    if owner.rp_id.is_empty() {
        return Err(invalid("Owner key has no relying party ID"));
    }
    let expected = webauthn::ExpectedKey {
        public_key: key,
        rp_id: owner.rp_id.clone(),
        require_user_verification: owner.require_user_verification,
    };
    let data = webauthn::signature_data(&assertion, challenge, &expected)?;
    Ok(wallet::wrap_signature(owner.owner_index, data))
}

/// The wallet record's initial owners, checked to produce `account`.
fn record_owners(initial_owners: &[String], account: [u8; 20]) -> Result<Vec<Vec<u8>>> {
    let owners = owners(initial_owners)?;
    if wallet::account_address(&owners, U256::ZERO) != account {
        return Err(invalid("Wallet address doesn't match its owner keys"));
    }
    Ok(owners)
}

/// Refuses operations the core can't fully account for: an account call other than `execute`/`executeBatch`, a
/// call to the wallet itself outside the owner changes it supports, a malformed paymaster, or a deployment that
/// wouldn't create `sender`.
fn check_operation(op: &Op) -> Result<()> {
    for call in wallet::decode_call_data(&op.call_data)? {
        if call.target == op.sender && !call.data.is_empty() {
            wallet::classify_self_call(&call.data)?;
        }
    }
    review::paymaster(op)?;
    if !op.init_code.is_empty() {
        let (owners, nonce) = wallet::decode_init_code(&op.init_code)?;
        if wallet::account_address(&owners, nonce) != op.sender {
            return Err(invalid("Account deployment would create a different address than the sender"));
        }
    }
    Ok(())
}

// MARK: Configuration

/// The core's version, for display and to check the apps run the build that was reviewed.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn chains() -> Vec<ChainConfig> {
    chains::all()
}

/// ERC-4337 EntryPoint v0.6.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn entry_point_address() -> String {
    address::checksum(&wallet::ENTRY_POINT_V06)
}

/// Coinbase Smart Wallet factory.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn factory_address() -> String {
    address::checksum(&wallet::FACTORY)
}

// MARK: Values

/// Validates an address (mixed case must have a correct EIP-55 checksum) and returns it checksummed.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn checksum_address(address: String) -> Result<String> {
    Ok(address::checksum(&addr(&address)?))
}

/// Normalizes a hex quantity or decimal string to a hex quantity.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parse_quantity(text: String) -> Result<String> {
    Ok(hex::quantity(quantity(&text)?))
}

/// -1, 0 or 1 as `a` is less than, equal to or greater than `b`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn compare_quantities(a: String, b: String) -> Result<i8> {
    Ok(match quantity(&a)?.cmp(&quantity(&b)?) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    })
}

/// `"1.5"` with 6 decimals → `0x16e360`. Fails rather than rounding.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parse_units(text: String, decimals: u8) -> Result<String> {
    Ok(hex::quantity(units::parse(&text, decimals)?))
}

/// For display: thousands separators, truncated to `max_fraction_digits`, and `<0.000001` for dust.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn format_units(quantity: String, decimals: u8, max_fraction_digits: u8) -> Result<String> {
    Ok(units::format(self::quantity(&quantity)?, decimals, max_fraction_digits))
}

/// Full precision with no grouping, for prefilling an amount field.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn format_units_plain(quantity: String, decimals: u8) -> Result<String> {
    Ok(units::format_plain(self::quantity(&quantity)?, decimals))
}

/// Encodes `transfer(address to, uint256 amount)` with string arguments. Also used for the apps' own view calls.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn encode_function_call(signature: String, arguments: Vec<String>) -> Result<EncodedFunctionCall> {
    let (parsed, data) = function_call::encode(&signature, &arguments)?;
    Ok(EncodedFunctionCall { name: parsed.name.clone(), signature: parsed.canonical(), data: hex::encode(&data) })
}

/// Decodes flat return data, e.g. `["uint256"]` for `balanceOf`. See `abi::decode_values` for the output format.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn abi_decode(types: Vec<String>, data: String) -> Result<Vec<String>> {
    abi::decode_values(&types, &bytes(&data)?)
}

/// The message of an `Error(string)` or `Panic(uint256)` revert.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn decode_revert_reason(data: String) -> Option<String> {
    abi::decode_revert_reason(&bytes(&data).ok()?)
}

/// Whether an `isValidSignature` result is exactly the ERC-1271 success value: one word, the magic value followed by
/// zero padding.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn is_erc1271_success(result: String) -> bool {
    bytes(&result)
        .map(|b| b.len() == 32 && b[..4] == wallet::ERC1271_MAGIC_VALUE && b[4..].iter().all(|&x| x == 0))
        .unwrap_or(false)
}

// MARK: Keys and accounts

/// Checks a security key registration and returns its public key. Refuses a response for another credential or
/// relying party, a synced passkey (only hardware keys can be owners), and, when the user chose a PIN for this key
/// (`require_user_verification`), a response without PIN verification. Store `require_user_verification` with the
/// key and pass it back in `OwnerKey`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_registration(
    attestation_object: String,
    credential_id: String,
    rp_id: String,
    require_user_verification: bool,
) -> Result<Registration> {
    let registration =
        webauthn::register(&bytes(&attestation_object)?, &bytes(&credential_id)?, &rp_id, require_user_verification)?;
    Ok(Registration {
        public_key: public_key_record(&registration.public_key),
        user_verified: registration.user_verified,
        pin_enforced_by_key: registration.pin_enforced_by_key,
    })
}

/// The 64-byte owner entry for a P-256 key.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn owner_bytes(key: PublicKey) -> Result<String> {
    Ok(hex::encode(&public_key(&key)?.owner_bytes()))
}

/// The wallet address for `initial_owners` (owner bytes, in order), computed locally. Same on every chain.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn account_address(initial_owners: Vec<String>) -> Result<String> {
    Ok(address::checksum(&wallet::account_address(&owners(&initial_owners)?, U256::ZERO)))
}

/// Checks a wallet record restored from a backup file before an app trusts it, and returns its checksummed address.
/// The initial owners must produce `address`, there must be at least one key, every key must be a valid P-256 key
/// with a relying party ID, credential IDs must be unique, and a key claiming an initial owner's index must be that
/// owner. Signing re-checks all of this; checking here turns a damaged or edited file into a clear error up front.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn check_wallet_record(address: String, initial_owners: Vec<String>, keys: Vec<OwnerKey>) -> Result<String> {
    let damaged =
        |detail: &str| invalid(format!("This backup file can't be used: {detail}. It may be damaged or edited."));
    let account = addr(&address).map_err(|_| damaged("its wallet address isn't valid"))?;
    let owners = owners(&initial_owners).map_err(|_| damaged("its owner list isn't valid"))?;
    if wallet::account_address(&owners, U256::ZERO) != account {
        return Err(damaged("its owner keys don't produce its wallet address"));
    }
    if keys.is_empty() {
        return Err(damaged("it has no keys"));
    }
    let mut seen = std::collections::HashSet::new();
    for (position, key) in keys.iter().enumerate() {
        let number = position + 1;
        let public_key =
            public_key(&key.public_key).map_err(|_| damaged(&format!("key {number}'s public key isn't valid")))?;
        let credential =
            bytes(&key.credential_id).map_err(|_| damaged(&format!("key {number}'s credential ID isn't valid")))?;
        if credential.is_empty() || !seen.insert(credential) {
            return Err(damaged(&format!("key {number}'s credential ID is missing or repeated")));
        }
        if key.rp_id.is_empty() {
            return Err(damaged(&format!("key {number} has no relying party ID")));
        }
        if let Some(recorded) = owners.get(key.owner_index as usize) {
            if recorded[..] != public_key.owner_bytes()[..] {
                return Err(damaged(&format!("key {number} doesn't match owner #{} of the wallet", key.owner_index)));
            }
        }
    }
    Ok(address::checksum(&account))
}

// MARK: Calls

/// Sends `amount` of ETH (`token` = nil) or of the ERC-20 at `token`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn transfer_call(token: Option<String>, to: String, amount: String) -> Result<Call> {
    let to = addr(&to)?;
    let amount = quantity(&amount)?;
    Ok(call_record(&match token {
        None => wallet::Call { target: to, value: amount, data: vec![] },
        Some(token) => wallet::Call {
            target: addr(&token)?,
            value: U256::ZERO,
            data: abi::encode_call("transfer(address,uint256)", &[abi::Token::Address(to), abi::Token::Uint(amount)]),
        },
    }))
}

/// Makes `key` an owner of `account`. Owners added this way exist only on the chain where the call runs.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn add_owner_call(account: String, key: PublicKey) -> Result<Call> {
    Ok(call_record(&wallet::add_owner_public_key_call(addr(&account)?, &public_key(&key)?)))
}

// MARK: User operations

/// A user operation for `calls`, ready for gas estimation: `initCode` if the account isn't deployed yet, the
/// `execute`/`executeBatch` call data, and a placeholder signature for `signing_owner_index`. Gas limits are zero.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn build_user_operation(
    sender: String,
    nonce: String,
    deployed: bool,
    initial_owners: Vec<String>,
    calls: Vec<Call>,
    gas_price: GasPrice,
    signing_owner_index: u32,
) -> Result<UserOperation> {
    let sender = addr(&sender)?;
    let owners = record_owners(&initial_owners, sender)?;
    let calls = calls.iter().map(call).collect::<Result<Vec<_>>>()?;
    Ok(op_record(&Op {
        sender,
        nonce: quantity(&nonce)?,
        init_code: if deployed { vec![] } else { wallet::init_code(&owners, U256::ZERO) },
        call_data: wallet::call_data(&calls)?,
        max_fee_per_gas: quantity(&gas_price.max_fee_per_gas)?,
        max_priority_fee_per_gas: quantity(&gas_price.max_priority_fee_per_gas)?,
        signature: wallet::dummy_signature(signing_owner_index),
        ..Op::default()
    }))
}

/// Fees when the bundler doesn't suggest any: `2 * baseFee + tip`, the usual headroom for base fee increases.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn fallback_gas_price(base_fee_per_gas: String, max_priority_fee_per_gas: String) -> Result<GasPrice> {
    let tip = quantity(&max_priority_fee_per_gas)?;
    let max_fee = quantity(&base_fee_per_gas)?
        .checked_mul(U256::from(2))
        .and_then(|fee| fee.checked_add(tip))
        .ok_or_else(|| invalid("Gas price is too large"))?;
    Ok(GasPrice { max_fee_per_gas: hex::quantity(max_fee), max_priority_fee_per_gas: hex::quantity(tip) })
}

/// Sets the gas limits from a bundler estimate, with headroom (see `UserOperation::apply_gas_estimate`).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn apply_gas_estimate(
    op: UserOperation,
    estimate: GasEstimate,
    verification_gas_buffer: u64,
) -> Result<UserOperation> {
    let mut op = self::op(&op)?;
    op.apply_gas_estimate(
        quantity(&estimate.pre_verification_gas)?,
        quantity(&estimate.verification_gas_limit)?,
        quantity(&estimate.call_gas_limit)?,
        verification_gas_buffer,
    )?;
    Ok(op_record(&op))
}

/// Everything the review screen shows, decoded from `op` itself, plus the hash the key will sign.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn review_user_operation(
    op: UserOperation,
    chain_id: u64,
    tokens: Vec<Token>,
    function_signatures: Vec<String>,
) -> Result<OperationReview> {
    let op = self::op(&op)?;
    check_operation(&op)?;
    let calls = wallet::decode_call_data(&op.call_data)?;
    let total_value = calls
        .iter()
        .try_fold(U256::ZERO, |sum, call| sum.checked_add(call.value))
        .ok_or_else(|| invalid("Total value is too large"))?;
    let known_paymasters =
        chains::all().into_iter().find(|c| c.id == chain_id).map(|c| c.known_paymasters).unwrap_or_default();
    let paymaster = review::paymaster(&op)?;
    // With any paymaster, the EntryPoint charges gas to the paymaster's deposit, not the wallet's ETH. Whether it
    // charges the wallet some other way is what `sponsored` and the review's paymaster lines are about.
    let max_gas_cost = if paymaster.is_some() { U256::ZERO } else { op.max_cost()? };
    let sponsored =
        paymaster.is_some_and(|p| known_paymasters.iter().any(|k| address::parse(&k.address).ok() == Some(p)));
    let required_balance = max_gas_cost.checked_add(total_value).ok_or_else(|| invalid("Total cost is too large"))?;
    Ok(OperationReview {
        hash: hex::encode(&op.hash(chain_id)),
        details: review::describe(&op, chain_id, &tokens, &function_signatures, &known_paymasters)?,
        deploys_account: !op.init_code.is_empty(),
        paymaster: paymaster.map(|p| address::checksum(&p)),
        sponsored,
        max_gas_cost: hex::quantity(max_gas_cost),
        total_value: hex::quantity(total_value),
        required_balance: hex::quantity(required_balance),
    })
}

/// `EntryPoint.getUserOpHash(op)`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn user_operation_hash(op: UserOperation, chain_id: u64) -> Result<String> {
    Ok(hex::encode(&self::op(&op)?.hash(chain_id)))
}

/// Attaches a security key's signature to `op`. Recomputes the hash from `op`, checks the assertion signed exactly
/// that with one of `owners` (matching the wallet record's `initial_owners`), and that `op` is one the core can
/// describe; then returns `op` with its signature.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn sign_user_operation(
    op: UserOperation,
    chain_id: u64,
    assertion: Assertion,
    owners: Vec<OwnerKey>,
    initial_owners: Vec<String>,
) -> Result<UserOperation> {
    let mut op = self::op(&op)?;
    check_operation(&op)?;
    let initial = record_owners(&initial_owners, op.sender)?;
    op.signature = wrapped_signature(&assertion, &op.hash(chain_id), &owners, &initial)?;
    Ok(op_record(&op))
}

// MARK: Messages

/// The hashes involved in signing `message` (UTF-8 text, EIP-191) as `account`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn message_challenge(message: String, account: String, chain_id: u64) -> Result<MessageChallenge> {
    let message_hash = wallet::personal_message_hash(message.as_bytes());
    Ok(MessageChallenge {
        message_hash: hex::encode(&message_hash),
        challenge: hex::encode(&wallet::replay_safe_hash(message_hash, addr(&account)?, chain_id)),
    })
}

/// An ERC-1271 signature of `message` by `account`, ERC-6492 wrapped if the account isn't deployed yet (verifiers
/// simulate the deployment first). Recomputes the challenge from `message` and checks the assertion signed it.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn sign_message(
    message: String,
    account: String,
    chain_id: u64,
    assertion: Assertion,
    owners: Vec<OwnerKey>,
    deployed: bool,
    initial_owners: Vec<String>,
) -> Result<SignedMessage> {
    let account_bytes = addr(&account)?;
    let initial = record_owners(&initial_owners, account_bytes)?;
    let message_hash = wallet::personal_message_hash(message.as_bytes());
    let challenge = wallet::replay_safe_hash(message_hash, account_bytes, chain_id);
    let signature = wrapped_signature(&assertion, &challenge, &owners, &initial)?;
    let signature = if deployed { signature } else { wallet::erc6492_wrap(signature, &initial, U256::ZERO) };
    Ok(SignedMessage { message_hash: hex::encode(&message_hash), signature: hex::encode(&signature) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webauthn::tests::{assert_with, public_key as key_of, test_key};
    use crate::webauthn::FLAG_USER_PRESENT;

    fn assertion_record(a: &webauthn::Assertion) -> Assertion {
        Assertion {
            credential_id: hex::encode(&a.credential_id),
            authenticator_data: hex::encode(&a.authenticator_data),
            client_data_json: hex::encode(&a.client_data_json),
            signature: hex::encode(&a.signature_der),
        }
    }

    struct Wallet {
        address: String,
        owners: Vec<String>,
        keys: Vec<OwnerKey>,
    }

    fn wallet(seeds: &[u8]) -> Wallet {
        let keys: Vec<OwnerKey> = seeds
            .iter()
            .enumerate()
            .map(|(index, &seed)| {
                let signing = test_key(seed);
                OwnerKey {
                    credential_id: hex::encode(&assert_with(&signing, &[0; 32], FLAG_USER_PRESENT).credential_id),
                    owner_index: index as u32,
                    public_key: public_key_record(&key_of(&signing)),
                    rp_id: "p256wallet.dev".into(),
                    require_user_verification: false,
                }
            })
            .collect();
        let owners: Vec<String> = keys.iter().map(|k| owner_bytes(k.public_key.clone()).unwrap()).collect();
        Wallet { address: account_address(owners.clone()).unwrap(), owners, keys }
    }

    fn gas() -> GasPrice {
        GasPrice { max_fee_per_gas: "0x3b9aca00".into(), max_priority_fee_per_gas: "0xf4240".into() }
    }

    fn send_eth(wallet: &Wallet) -> UserOperation {
        let call = transfer_call(None, "0x000000000000000000000000000000000000dEaD".into(), "0x1".into()).unwrap();
        build_user_operation(wallet.address.clone(), "0x0".into(), false, wallet.owners.clone(), vec![call], gas(), 0)
            .unwrap()
    }

    #[test]
    fn build_estimate_review_sign() {
        let wallet = wallet(&[1, 2]);
        let op = send_eth(&wallet);
        assert!(op.init_code.starts_with("0x0ba5ed0c"));
        let estimate = GasEstimate {
            pre_verification_gas: "0xc350".into(),
            verification_gas_limit: "0x61a80".into(),
            call_gas_limit: "0x2710".into(),
        };
        let op = apply_gas_estimate(op, estimate, 30_000).unwrap();
        let review = review_user_operation(op.clone(), 84532, vec![], vec![]).unwrap();
        assert!(review.deploys_account && !review.sponsored);
        assert_eq!(review.details[2].value, "0.000000000000000001 ETH");
        assert_eq!(
            compare_quantities(review.required_balance.clone(), review.max_gas_cost.clone()).unwrap(),
            1,
            "required balance includes the value"
        );

        // The backup key (index 1) signs.
        let challenge = hex::decode(&review.hash).unwrap();
        let assertion = assertion_record(&assert_with(&test_key(2), &challenge, FLAG_USER_PRESENT));
        let signed =
            sign_user_operation(op.clone(), 84532, assertion.clone(), wallet.keys.clone(), wallet.owners.clone())
                .unwrap();
        let wrapper = hex::decode(&signed.signature).unwrap();
        let decoder = abi::Decoder::new(&wrapper);
        assert_eq!(decoder.usize(decoder.usize(0).unwrap()).unwrap(), 1, "owner index of the backup key");

        // Same assertion against another chain's hash, or a changed operation, is refused.
        assert!(sign_user_operation(op.clone(), 8453, assertion.clone(), wallet.keys.clone(), wallet.owners.clone())
            .is_err());
        let mut changed = op.clone();
        changed.max_fee_per_gas = "0x1".into();
        assert!(
            sign_user_operation(changed, 84532, assertion.clone(), wallet.keys.clone(), wallet.owners.clone()).is_err()
        );
        // A key that isn't an owner is refused even if its signature is valid.
        let stranger = assertion_record(&assert_with(&test_key(9), &challenge, FLAG_USER_PRESENT));
        assert!(sign_user_operation(op, 84532, stranger, wallet.keys, wallet.owners).is_err());
    }

    #[test]
    fn refuses_mismatched_wallet_records() {
        let wallet = wallet(&[1]);
        let other = self::wallet(&[3]);
        let call = transfer_call(None, other.address.clone(), "0x1".into()).unwrap();
        assert!(build_user_operation(other.address, "0x0".into(), false, wallet.owners, vec![call], gas(), 0).is_err());
    }

    #[test]
    fn refuses_operations_it_cant_describe() {
        let wallet = wallet(&[1]);
        let mut op = send_eth(&wallet);
        // Point the deployment at a different owner set: the account it creates isn't `sender`.
        let other = self::wallet(&[4]);
        op.init_code = hex::encode(&wallet::init_code(&owners(&other.owners).unwrap(), U256::ZERO));
        assert!(review_user_operation(op.clone(), 84532, vec![], vec![]).is_err());
        let challenge = hex::decode(&user_operation_hash(op.clone(), 84532).unwrap()).unwrap();
        let assertion = assertion_record(&assert_with(&test_key(1), &challenge, FLAG_USER_PRESENT));
        assert!(sign_user_operation(op, 84532, assertion, wallet.keys, wallet.owners).is_err());
    }

    #[test]
    fn messages() {
        let wallet = wallet(&[5]);
        let request = message_challenge("hello world".into(), wallet.address.clone(), 84532).unwrap();
        assert_eq!(request.message_hash, "0xd9eba16ed0ecae432b71fe008c98cc872bb4cc214d3220a36f365326cf807d68");
        let assertion =
            assertion_record(&assert_with(&test_key(5), &hex::decode(&request.challenge).unwrap(), FLAG_USER_PRESENT));
        let undeployed = sign_message(
            "hello world".into(),
            wallet.address.clone(),
            84532,
            assertion.clone(),
            wallet.keys.clone(),
            false,
            wallet.owners.clone(),
        )
        .unwrap();
        assert!(undeployed.signature.ends_with(&"6492".repeat(16)));
        let deployed = sign_message(
            "hello world".into(),
            wallet.address.clone(),
            84532,
            assertion.clone(),
            wallet.keys.clone(),
            true,
            wallet.owners.clone(),
        )
        .unwrap();
        assert!(!deployed.signature.ends_with("6492"));
        // The key signed "hello world", not this.
        assert!(sign_message("hello there".into(), wallet.address, 84532, assertion, wallet.keys, true, wallet.owners)
            .is_err());
    }

    #[test]
    fn owner_keys_must_match_the_wallet_record() {
        let wallet = wallet(&[1, 2]);
        let op = send_eth(&wallet);
        let challenge = hex::decode(&user_operation_hash(op.clone(), 84532).unwrap()).unwrap();
        let assertion = assertion_record(&assert_with(&test_key(2), &challenge, FLAG_USER_PRESENT));
        // Key 2 claims index 0, which the record gives to key 1.
        let swapped = vec![OwnerKey { owner_index: 0, ..wallet.keys[1].clone() }];
        assert!(sign_user_operation(op.clone(), 84532, assertion.clone(), swapped, wallet.owners.clone()).is_err());
        // Owners that don't produce the sender are refused too.
        let other = self::wallet(&[3]);
        assert!(sign_user_operation(op, 84532, assertion, wallet.keys, other.owners).is_err());
    }

    #[test]
    fn per_key_pin_and_relying_party() {
        let wallet = wallet(&[1]);
        let op = send_eth(&wallet);
        let challenge = hex::decode(&user_operation_hash(op.clone(), 84532).unwrap()).unwrap();
        let touch = assertion_record(&assert_with(&test_key(1), &challenge, FLAG_USER_PRESENT));
        let pin = assertion_record(&assert_with(&test_key(1), &challenge, FLAG_USER_PRESENT | 0x04));
        let with_pin = vec![OwnerKey { require_user_verification: true, ..wallet.keys[0].clone() }];
        assert!(sign_user_operation(op.clone(), 84532, touch.clone(), with_pin.clone(), wallet.owners.clone()).is_err());
        assert!(sign_user_operation(op.clone(), 84532, pin, with_pin, wallet.owners.clone()).is_ok());
        let other_rp = vec![OwnerKey { rp_id: "fblccdigbmoojajgljjbpaihhdjdcghn".into(), ..wallet.keys[0].clone() }];
        assert!(sign_user_operation(op, 84532, touch, other_rp, wallet.owners).is_err());
    }

    #[test]
    fn refuses_self_calls_outside_the_allowlist() {
        let wallet = wallet(&[1]);
        let takeover = encode_function_call("addOwnerAddress(address)".into(), vec![DEAD_ADDRESS.into()]).unwrap();
        let call = Call { target: wallet.address.clone(), value: "0x0".into(), data: takeover.data };
        let op = build_user_operation(
            wallet.address.clone(),
            "0x0".into(),
            true,
            wallet.owners.clone(),
            vec![call],
            gas(),
            0,
        )
        .unwrap();
        assert!(review_user_operation(op.clone(), 84532, vec![], vec![]).is_err());
        let challenge = hex::decode(&user_operation_hash(op.clone(), 84532).unwrap()).unwrap();
        let assertion = assertion_record(&assert_with(&test_key(1), &challenge, FLAG_USER_PRESENT));
        assert!(sign_user_operation(op, 84532, assertion, wallet.keys, wallet.owners).is_err());
    }

    #[test]
    fn unknown_paymasters_are_named_not_called_sponsored() {
        let wallet = wallet(&[1]);
        let mut op = send_eth(&wallet);
        op.paymaster_and_data = format!("0x{}{}", "77".repeat(20), "ab".repeat(8));
        let review = review_user_operation(op, 84532, vec![], vec![]).unwrap();
        assert_eq!(review.paymaster.as_deref(), Some(address::checksum(&[0x77; 20]).as_str()));
        assert!(!review.sponsored);
        assert_eq!(review.max_gas_cost, "0x0", "the paymaster's deposit pays the gas, not the wallet's ETH");
        assert!(review.details.iter().any(|d| d.value.contains("Not a known sponsor")));
    }

    const DEAD_ADDRESS: &str = "0x000000000000000000000000000000000000dEaD";

    #[test]
    fn wallet_records_from_backups() {
        let wallet = wallet(&[1, 2]);
        let lowercase = wallet.address.to_lowercase();
        assert_eq!(check_wallet_record(lowercase, wallet.owners.clone(), wallet.keys.clone()).unwrap(), wallet.address);

        let other = self::wallet(&[3]);
        let refused = [
            ("other owners", check_wallet_record(wallet.address.clone(), other.owners.clone(), wallet.keys.clone())),
            ("no keys", check_wallet_record(wallet.address.clone(), wallet.owners.clone(), vec![])),
            (
                "swapped keys",
                check_wallet_record(
                    wallet.address.clone(),
                    wallet.owners.clone(),
                    vec![OwnerKey { owner_index: 1, ..wallet.keys[0].clone() }],
                ),
            ),
            (
                "repeated credential",
                check_wallet_record(
                    wallet.address.clone(),
                    wallet.owners.clone(),
                    vec![wallet.keys[0].clone(), OwnerKey { owner_index: 5, ..wallet.keys[0].clone() }],
                ),
            ),
            (
                "no relying party",
                check_wallet_record(
                    wallet.address.clone(),
                    wallet.owners.clone(),
                    vec![OwnerKey { rp_id: String::new(), ..wallet.keys[0].clone() }],
                ),
            ),
            ("bad address", check_wallet_record("0x1234".into(), wallet.owners.clone(), wallet.keys.clone())),
        ];
        for (case, result) in refused {
            let message = result.expect_err(case).to_string();
            assert!(message.starts_with("This backup file can't be used"), "{case}: {message}");
        }
        // A key added after setup (index past the initial owners) is accepted.
        let added = OwnerKey { owner_index: 2, ..other.keys[0].clone() };
        let mut keys = wallet.keys.clone();
        keys.push(added);
        assert!(check_wallet_record(wallet.address.clone(), wallet.owners.clone(), keys).is_ok());
    }

    #[test]
    fn values() {
        assert_eq!(parse_units("1.5".into(), 6).unwrap(), "0x16e360");
        assert_eq!(format_units("0x16e360".into(), 6, 6).unwrap(), "1.5");
        assert_eq!(parse_quantity("1000".into()).unwrap(), "0x3e8");
        assert_eq!(compare_quantities("0x2".into(), "1".into()).unwrap(), 1);
        assert_eq!(
            checksum_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed".into()).unwrap(),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
        assert!(is_erc1271_success(format!("0x1626ba7e{}", "0".repeat(56))));
        assert!(!is_erc1271_success("0xffffffff".into()));
        assert!(!is_erc1271_success(format!("0x1626ba7e{}01", "0".repeat(54))), "non-zero padding");
        assert!(!is_erc1271_success(format!("0x1626ba7e{}", "0".repeat(120))), "more than one word");
        assert_eq!(fallback_gas_price("0x10".into(), "0x1".into()).unwrap().max_fee_per_gas, "0x21");
        let token = transfer_call(
            Some("0x036CbD53842c5426634e7929541eC2318f3dCF7e".into()),
            "0x000000000000000000000000000000000000dEaD".into(),
            "0x16e360".into(),
        )
        .unwrap();
        assert_eq!(token.value, "0x0");
        assert!(token.data.starts_with("0xa9059cbb"));
    }
}
