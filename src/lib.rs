//! Signing core for P256 Wallet.
//!
//! Decides what gets signed: builds Coinbase Smart Wallet v1 user operations (ERC-4337 EntryPoint v0.6), describes
//! them for review, and turns WebAuthn assertions from P-256 security keys into signatures the account accepts. It
//! does no I/O; the iOS app and browser extension handle networking, storage, UI and the key prompt.
//!
//! Start reading at [`api`], the whole surface the apps use, then [`policy`], every rule that can refuse something.
//! See README.md for the review guide.

pub mod abi;
pub mod address;
pub mod api;
pub mod cbor;
pub mod chains;
mod convert;
pub mod error;
pub mod function_call;
pub mod functions;
pub mod hash;
pub mod hex;
pub mod policy;
pub mod records;
pub mod review;
pub mod smart_wallet;
pub mod unicode_table;
pub mod units;
pub mod user_operation;
pub mod webauthn;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use error::{CoreError, Result};

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!("p256_wallet_core");
