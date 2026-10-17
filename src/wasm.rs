//! TypeScript bindings: one wrapper per `api` function, converting records to and from plain JS objects
//! (camelCase fields, same shapes as the Swift records). No logic lives here. Chain IDs are `u32` because
//! wasm-bindgen maps `u64` parameters to `BigInt`.

use crate::api;
use crate::error::CoreError;
use crate::records::*;
use serde::{de::DeserializeOwned, Serialize};
use wasm_bindgen::prelude::*;

fn error(error: CoreError) -> JsError {
    JsError::new(&error.to_string())
}

fn to_js<T: Serialize>(value: crate::error::Result<T>) -> Result<JsValue, JsError> {
    serde_wasm_bindgen::to_value(&value.map_err(error)?).map_err(|e| JsError::new(&e.to_string()))
}

fn from_js<T: DeserializeOwned>(value: JsValue, what: &str) -> Result<T, JsError> {
    serde_wasm_bindgen::from_value(value).map_err(|e| JsError::new(&format!("Invalid {what}: {e}")))
}

fn string(value: crate::error::Result<String>) -> Result<String, JsError> {
    value.map_err(error)
}

#[wasm_bindgen(js_name = coreVersion)]
pub fn core_version() -> String {
    api::core_version()
}

#[wasm_bindgen]
pub fn chains() -> Result<JsValue, JsError> {
    to_js(Ok(api::chains()))
}

#[wasm_bindgen(js_name = entryPointAddress)]
pub fn entry_point_address() -> String {
    api::entry_point_address()
}

#[wasm_bindgen(js_name = factoryAddress)]
pub fn factory_address() -> String {
    api::factory_address()
}

#[wasm_bindgen(js_name = checksumAddress)]
pub fn checksum_address(address: String) -> Result<String, JsError> {
    string(api::checksum_address(address))
}

#[wasm_bindgen(js_name = parseQuantity)]
pub fn parse_quantity(text: String) -> Result<String, JsError> {
    string(api::parse_quantity(text))
}

#[wasm_bindgen(js_name = compareQuantities)]
pub fn compare_quantities(a: String, b: String) -> Result<i8, JsError> {
    api::compare_quantities(a, b).map_err(error)
}

#[wasm_bindgen(js_name = parseUnits)]
pub fn parse_units(text: String, decimals: u8) -> Result<String, JsError> {
    string(api::parse_units(text, decimals))
}

#[wasm_bindgen(js_name = formatUnits)]
pub fn format_units(quantity: String, decimals: u8, max_fraction_digits: u8) -> Result<String, JsError> {
    string(api::format_units(quantity, decimals, max_fraction_digits))
}

#[wasm_bindgen(js_name = formatUnitsPlain)]
pub fn format_units_plain(quantity: String, decimals: u8) -> Result<String, JsError> {
    string(api::format_units_plain(quantity, decimals))
}

#[wasm_bindgen(js_name = encodeFunctionCall)]
pub fn encode_function_call(signature: String, arguments: Vec<String>) -> Result<JsValue, JsError> {
    to_js(api::encode_function_call(signature, arguments))
}

#[wasm_bindgen(js_name = abiDecode)]
pub fn abi_decode(types: Vec<String>, data: String) -> Result<Vec<String>, JsError> {
    api::abi_decode(types, data).map_err(error)
}

#[wasm_bindgen(js_name = decodeRevertReason)]
pub fn decode_revert_reason(data: String) -> Option<String> {
    api::decode_revert_reason(data)
}

#[wasm_bindgen(js_name = isErc1271Success)]
pub fn is_erc1271_success(result: String) -> bool {
    api::is_erc1271_success(result)
}

#[wasm_bindgen(js_name = publicKeyFromAttestationObject)]
pub fn public_key_from_attestation_object(
    attestation_object: String,
    credential_id: String,
) -> Result<JsValue, JsError> {
    to_js(api::public_key_from_attestation_object(attestation_object, credential_id))
}

#[wasm_bindgen(js_name = ownerBytes)]
pub fn owner_bytes(key: JsValue) -> Result<String, JsError> {
    string(api::owner_bytes(from_js::<PublicKey>(key, "public key")?))
}

#[wasm_bindgen(js_name = accountAddress)]
pub fn account_address(initial_owners: Vec<String>) -> Result<String, JsError> {
    string(api::account_address(initial_owners))
}

#[wasm_bindgen(js_name = transferCall)]
pub fn transfer_call(token: Option<String>, to: String, amount: String) -> Result<JsValue, JsError> {
    to_js(api::transfer_call(token, to, amount))
}

#[wasm_bindgen(js_name = addOwnerCall)]
pub fn add_owner_call(account: String, key: JsValue) -> Result<JsValue, JsError> {
    to_js(api::add_owner_call(account, from_js(key, "public key")?))
}

#[wasm_bindgen(js_name = buildUserOperation)]
pub fn build_user_operation(
    sender: String,
    nonce: String,
    deployed: bool,
    initial_owners: Vec<String>,
    calls: JsValue,
    gas_price: JsValue,
    signing_owner_index: u32,
) -> Result<JsValue, JsError> {
    to_js(api::build_user_operation(
        sender,
        nonce,
        deployed,
        initial_owners,
        from_js(calls, "calls")?,
        from_js(gas_price, "gas price")?,
        signing_owner_index,
    ))
}

#[wasm_bindgen(js_name = fallbackGasPrice)]
pub fn fallback_gas_price(base_fee_per_gas: String, max_priority_fee_per_gas: String) -> Result<JsValue, JsError> {
    to_js(api::fallback_gas_price(base_fee_per_gas, max_priority_fee_per_gas))
}

#[wasm_bindgen(js_name = applyGasEstimate)]
pub fn apply_gas_estimate(op: JsValue, estimate: JsValue, verification_gas_buffer: u32) -> Result<JsValue, JsError> {
    to_js(api::apply_gas_estimate(
        from_js(op, "user operation")?,
        from_js(estimate, "gas estimate")?,
        verification_gas_buffer.into(),
    ))
}

#[wasm_bindgen(js_name = reviewUserOperation)]
pub fn review_user_operation(
    op: JsValue,
    chain_id: u32,
    tokens: JsValue,
    function_signatures: Vec<String>,
) -> Result<JsValue, JsError> {
    to_js(api::review_user_operation(
        from_js(op, "user operation")?,
        chain_id.into(),
        from_js(tokens, "tokens")?,
        function_signatures,
    ))
}

#[wasm_bindgen(js_name = userOperationHash)]
pub fn user_operation_hash(op: JsValue, chain_id: u32) -> Result<String, JsError> {
    string(api::user_operation_hash(from_js(op, "user operation")?, chain_id.into()))
}

#[wasm_bindgen(js_name = signUserOperation)]
pub fn sign_user_operation(
    op: JsValue,
    chain_id: u32,
    assertion: JsValue,
    owners: JsValue,
) -> Result<JsValue, JsError> {
    to_js(api::sign_user_operation(
        from_js(op, "user operation")?,
        chain_id.into(),
        from_js(assertion, "assertion")?,
        from_js(owners, "owners")?,
    ))
}

#[wasm_bindgen(js_name = messageChallenge)]
pub fn message_challenge(message: String, account: String, chain_id: u32) -> Result<JsValue, JsError> {
    to_js(api::message_challenge(message, account, chain_id.into()))
}

#[wasm_bindgen(js_name = signMessage)]
#[allow(clippy::too_many_arguments)]
pub fn sign_message(
    message: String,
    account: String,
    chain_id: u32,
    assertion: JsValue,
    owners: JsValue,
    deployed: bool,
    initial_owners: Vec<String>,
) -> Result<JsValue, JsError> {
    to_js(api::sign_message(
        message,
        account,
        chain_id.into(),
        from_js(assertion, "assertion")?,
        from_js(owners, "owners")?,
        deployed,
        initial_owners,
    ))
}
