//! What the core agrees to sign. Every rule that can refuse an operation, an owner key or a wallet record lives here.
//! Review and signing both go through [`check_operation`], so they can't apply different policies.

use crate::chains::{self, Chain, KnownPaymaster};
use crate::error::{bad_assertion, invalid, wont_sign, Result};
use crate::records::{Assertion, OwnerKey};
use crate::smart_wallet::{self as wallet, Call};
use crate::user_operation::UserOperation;
use crate::{convert, hex, webauthn};
use ruint::aliases::U256;
use std::collections::HashSet;

/// A user operation that passed [`check_operation`], with what was decoded along the way.
pub struct CheckedOperation {
    pub op: UserOperation,
    pub chain_id: u64,
    /// `None` for a chain the core doesn't know: it can still be reviewed and signed, but no paymaster is a sponsor.
    pub chain: Option<&'static Chain>,
    /// What the account will execute, in order.
    pub calls: Vec<Call>,
    pub paymaster: Option<[u8; 20]>,
}

impl CheckedOperation {
    pub fn deploys_account(&self) -> bool {
        !self.op.init_code.is_empty()
    }

    /// The paymaster, if it's one of the chain's known sponsors.
    pub fn sponsor(&self) -> Option<&'static KnownPaymaster> {
        self.chain?.known_paymaster(self.paymaster?)
    }

    /// ETH sent by the calls.
    pub fn total_value(&self) -> Result<U256> {
        self.calls
            .iter()
            .try_fold(U256::ZERO, |sum, call| sum.checked_add(call.value))
            .ok_or_else(|| invalid("Total value is too large"))
    }
}

/// Decodes `op` and refuses anything the core can't fully account for:
/// - an account call other than `execute` / `executeBatch`;
/// - a call from the wallet to itself, except adding `new_owner` (the key the app just registered) as the only call
///   in the operation. Anyone can make a P-256 key in software, so adding any other key is a takeover;
/// - a malformed paymaster;
/// - a deployment that wouldn't create `sender` from the Coinbase factory.
pub fn check_operation(
    op: UserOperation,
    chain_id: u64,
    new_owner: Option<&webauthn::PublicKey>,
) -> Result<CheckedOperation> {
    let calls = wallet::decode_call_data(&op.call_data)?;
    for call in &calls {
        if call.target == op.sender && !call.data.is_empty() {
            let key = wallet::decode_self_call(&call.data)?;
            if new_owner != Some(&key) {
                return Err(wont_sign(
                    "it adds an owner key that wasn't just registered in this app. Another owner could take the \
                     wallet over.",
                ));
            }
            if calls.len() != 1 {
                return Err(wont_sign("adding an owner key must be the only call in its transaction."));
            }
        }
    }
    let paymaster = paymaster(&op)?;
    if !op.init_code.is_empty() {
        let (owners, nonce) = wallet::decode_init_code(&op.init_code)?;
        if wallet::account_address(&owners, nonce) != op.sender {
            return Err(wont_sign("the account deployment would create a different address than the sender."));
        }
    }
    Ok(CheckedOperation { chain: chains::by_id(chain_id), op, chain_id, calls, paymaster })
}

/// The paymaster address at the start of `paymasterAndData`, if any.
fn paymaster(op: &UserOperation) -> Result<Option<[u8; 20]>> {
    match op.paymaster_and_data.len() {
        0 => Ok(None),
        1..=19 => Err(invalid("paymasterAndData is too short to name a paymaster")),
        _ => Ok(Some(op.paymaster_and_data[..20].try_into().expect("20 bytes"))),
    }
}

/// The wallet record's initial owners, checked to produce `account`.
pub fn record_owners(initial_owners: &[String], account: [u8; 20]) -> Result<Vec<Vec<u8>>> {
    let owners = convert::owners(initial_owners)?;
    if wallet::account_address(&owners, U256::ZERO) != account {
        return Err(invalid("Wallet address doesn't match its owner keys"));
    }
    Ok(owners)
}

/// An owner key that passed [`check_owner_key`].
pub struct Owner {
    pub credential_id: Vec<u8>,
    pub index: u32,
    pub added_on_chain_id: Option<u64>,
    pub expected: webauthn::ExpectedKey,
}

/// The rules for one owner key, shared by signing and [`check_wallet_record`]. On failure, returns what's wrong as
/// a phrase to follow "This key" or "Key 2":
/// - its public key, credential ID and relying party must be valid;
/// - an index below the initial owner count must hold that initial owner's key, which owns the account on every
///   chain, so it can't be recorded as added on one;
/// - a higher index is an owner added later, which must record the chain it was added on.
pub fn check_owner_key(key: &OwnerKey, initial_owners: &[Vec<u8>]) -> std::result::Result<Owner, String> {
    let public_key = convert::public_key(&key.public_key).map_err(|_| "has an invalid public key".to_string())?;
    let credential_id = hex::decode(&key.credential_id)
        .ok()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| "has a missing or invalid credential ID".to_string())?;
    if key.rp_id.is_empty() {
        return Err("has no relying party ID".into());
    }
    let index = key.owner_index;
    match (initial_owners.get(index as usize), key.added_on_chain_id) {
        (Some(owner), _) if owner[..] != public_key.owner_bytes()[..] => {
            return Err(format!("isn't owner #{index} of the wallet"));
        }
        (Some(_), Some(_)) => return Err(format!("is initial owner #{index} but is recorded as added later")),
        (None, None) => return Err(format!("claims owner #{index}, an owner added later, but not the network")),
        _ => {}
    }
    Ok(Owner {
        credential_id,
        index,
        added_on_chain_id: key.added_on_chain_id,
        expected: webauthn::ExpectedKey {
            public_key,
            rp_id: key.rp_id.clone(),
            require_user_verification: key.require_user_verification,
        },
    })
}

/// Finds the owner that produced `assertion`, checks it against the wallet record and that it owns the account on
/// `chain_id`, and returns its `SignatureWrapper` over `challenge`.
pub fn wrapped_signature(
    assertion: &Assertion,
    challenge: &[u8],
    owner_keys: &[OwnerKey],
    initial_owners: &[Vec<u8>],
    chain_id: u64,
) -> Result<Vec<u8>> {
    if owner_keys.is_empty() {
        return Err(bad_assertion("This wallet has no keys that can sign on this network"));
    }
    let assertion = convert::assertion(assertion)?;
    let key = owner_keys
        .iter()
        .find(|key| hex::decode(&key.credential_id).ok().as_deref() == Some(&assertion.credential_id[..]))
        .ok_or_else(|| bad_assertion("That key isn't an owner of this wallet"))?;
    let owner = check_owner_key(key, initial_owners)
        .map_err(|problem| bad_assertion(format!("This key {problem}; the wallet's key list is out of date")))?;
    if let Some(added) = owner.added_on_chain_id.filter(|&added| added != chain_id) {
        let network = chains::by_id(added).map_or_else(|| format!("chain {added}"), |chain| chain.name.to_string());
        return Err(bad_assertion(format!("This key was added on {network}, so it can't sign on this network")));
    }
    let data = webauthn::signature_data(&assertion, challenge, &owner.expected)?;
    Ok(wallet::wrap_signature(owner.index, data))
}

/// Checks a wallet record restored from a backup file and returns its address. The initial owners must produce
/// `address`, there must be at least one key, every key must pass [`check_owner_key`], credential IDs must be
/// unique, and no two keys may hold the same owner index on the same chain. (Owners added later hold an index on
/// their own chain only, so two such keys can share an index on different chains.)
pub fn check_wallet_record(address: &str, initial_owners: &[String], keys: &[OwnerKey]) -> Result<[u8; 20]> {
    let damaged =
        |detail: &str| invalid(format!("This backup file can't be used: {detail}. It may be damaged or edited."));
    let account = convert::addr(address).map_err(|_| damaged("its wallet address isn't valid"))?;
    let owners = record_owners(initial_owners, account)
        .map_err(|_| damaged("its owner keys don't produce its wallet address"))?;
    if keys.is_empty() {
        return Err(damaged("it has no keys"));
    }
    let mut credentials = HashSet::new();
    let mut slots = HashSet::new();
    for (position, key) in keys.iter().enumerate() {
        let number = position + 1;
        let owner = check_owner_key(key, &owners).map_err(|problem| damaged(&format!("key {number} {problem}")))?;
        if !credentials.insert(owner.credential_id) {
            return Err(damaged(&format!("key {number} repeats another key's credential ID")));
        }
        if !slots.insert((owner.index, owner.added_on_chain_id)) {
            return Err(damaged(&format!("key {number} claims owner #{}, which another key holds", owner.index)));
        }
    }
    Ok(account)
}
