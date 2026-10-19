//! Conversions between the records that cross the binding boundary (hex strings) and the core's internal types.
//! Each one validates as it converts.

use crate::error::{bad_assertion, Result};
use crate::records::{Assertion, Call, PublicKey, UserOperation};
use crate::smart_wallet as wallet;
use crate::user_operation::UserOperation as Op;
use crate::{address, hex, webauthn};
use ruint::aliases::U256;

pub fn addr(text: &str) -> Result<[u8; 20]> {
    address::parse(text)
}

pub fn quantity(text: &str) -> Result<U256> {
    hex::parse_quantity(text)
}

pub fn bytes(text: &str) -> Result<Vec<u8>> {
    hex::decode(text)
}

/// Owner bytes in order, each 32 (address) or 64 (P-256 key) bytes.
pub fn owners(initial_owners: &[String]) -> Result<Vec<Vec<u8>>> {
    let owners = initial_owners.iter().map(|owner| bytes(owner)).collect::<Result<Vec<_>>>()?;
    wallet::validate_owners(&owners)?;
    Ok(owners)
}

pub fn public_key(key: &PublicKey) -> Result<webauthn::PublicKey> {
    webauthn::PublicKey::new(hex::decode_fixed(&key.x, "Public key x")?, hex::decode_fixed(&key.y, "Public key y")?)
}

pub fn public_key_record(key: &webauthn::PublicKey) -> PublicKey {
    PublicKey { x: hex::encode(&key.x), y: hex::encode(&key.y) }
}

pub fn call(call: &Call) -> Result<wallet::Call> {
    Ok(wallet::Call { target: addr(&call.target)?, value: quantity(&call.value)?, data: bytes(&call.data)? })
}

pub fn call_record(call: &wallet::Call) -> Call {
    Call { target: address::checksum(&call.target), value: hex::quantity(call.value), data: hex::encode(&call.data) }
}

pub fn op(op: &UserOperation) -> Result<Op> {
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

pub fn op_record(op: &Op) -> UserOperation {
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

pub fn assertion(assertion: &Assertion) -> Result<webauthn::Assertion> {
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
