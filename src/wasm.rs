//! TypeScript bindings: one generated wrapper per `api` function. Every argument and result crosses as a plain JS
//! value converted with serde (records as camelCase objects, the same shapes as the Swift records), so adding an API
//! function means adding one line to `export!`. No logic lives here.
//!
//! Errors are thrown as a JS `Error` whose `kind` is `invalidInput`, `invalidAssertion` or `refused`, matching
//! `CoreError`.

use crate::api;
use crate::error::CoreError;
use serde::{de::DeserializeOwned, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    /// JavaScript's `Error`, given a `kind` property.
    #[wasm_bindgen(js_name = Error)]
    type JsErrorWithKind;
    #[wasm_bindgen(constructor, js_class = "Error")]
    fn new(message: &str) -> JsErrorWithKind;
    #[wasm_bindgen(method, setter = kind, js_class = "Error")]
    fn set_kind(this: &JsErrorWithKind, kind: &str);
}

fn error(kind: &str, message: &str) -> JsValue {
    let error = JsErrorWithKind::new(message);
    error.set_kind(kind);
    error.into()
}

fn core_error(error: CoreError) -> JsValue {
    let kind = match error {
        CoreError::InvalidInput(_) => "invalidInput",
        CoreError::InvalidAssertion(_) => "invalidAssertion",
        CoreError::Refused(_) => "refused",
    };
    self::error(kind, &error.to_string())
}

fn from_js<T: DeserializeOwned>(value: JsValue, name: &str) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value)
        .map_err(|e| error("invalidInput", &format!("Invalid {}: {e}", name.replace('_', " "))))
}

/// What an `api` function returns: a `Result`, or a plain value for the few that can't fail.
trait Output {
    type Value: Serialize;
    fn into_result(self) -> crate::Result<Self::Value>;
}

impl<T: Serialize> Output for crate::Result<T> {
    type Value = T;
    fn into_result(self) -> crate::Result<T> {
        self
    }
}

macro_rules! infallible {
    ($($type:ty),*) => {$(
        impl Output for $type {
            type Value = $type;
            fn into_result(self) -> crate::Result<$type> {
                Ok(self)
            }
        }
    )*};
}

infallible!(String, bool, Option<String>, Vec<crate::records::ChainConfig>);

fn to_js(output: impl Output) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(&output.into_result().map_err(core_error)?)
        .map_err(|e| error("invalidInput", &e.to_string()))
}

macro_rules! export {
    ($($js_name:ident => $name:ident($($argument:ident),*);)*) => {$(
        #[wasm_bindgen(js_name = $js_name)]
        #[allow(clippy::too_many_arguments)]
        pub fn $name($($argument: JsValue),*) -> Result<JsValue, JsValue> {
            to_js(api::$name($(from_js($argument, stringify!($argument))?),*))
        }
    )*};
}

export! {
    coreVersion => core_version();
    chains => chains();
    entryPointAddress => entry_point_address();
    factoryAddress => factory_address();

    checksumAddress => checksum_address(address);
    parseQuantity => parse_quantity(text);
    compareQuantities => compare_quantities(a, b);
    parseUnits => parse_units(text, decimals);
    formatUnits => format_units(quantity, decimals, max_fraction_digits);
    formatUnitsPlain => format_units_plain(quantity, decimals);
    encodeFunctionCall => encode_function_call(signature, arguments);
    abiDecode => abi_decode(types, data);
    decodeRevertReason => decode_revert_reason(data);
    isErc1271Success => is_erc1271_success(result);

    verifyRegistration => verify_registration(attestation_object, credential_id, rp_id, require_user_verification);
    ownerBytes => owner_bytes(public_key);
    accountAddress => account_address(initial_owners);
    checkWalletRecord => check_wallet_record(address, initial_owners, keys);

    transferCall => transfer_call(token, to, amount);
    addOwnerCall => add_owner_call(account, public_key);

    buildUserOperation => build_user_operation(sender, nonce, deployed, initial_owners, calls, gas_price, signing_owner_index);
    fallbackGasPrice => fallback_gas_price(base_fee_per_gas, max_priority_fee_per_gas);
    applyGasEstimate => apply_gas_estimate(user_operation, estimate, verification_gas_buffer);
    reviewUserOperation => review_user_operation(user_operation, chain_id, tokens, function_signatures, new_owner);
    userOperationHash => user_operation_hash(user_operation, chain_id);
    signUserOperation => sign_user_operation(user_operation, chain_id, assertion, owners, initial_owners, new_owner);

    messageChallenge => message_challenge(message, account, chain_id);
    signMessage => sign_message(message, account, chain_id, assertion, owners, deployed, initial_owners);
}
