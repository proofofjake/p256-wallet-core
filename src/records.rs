//! Plain data types that cross the binding boundary, identical in Swift and TypeScript.
//!
//! Byte strings are `0x` hex, numbers are JSON-RPC hex quantities (`0x1a`) unless noted, and addresses come back
//! EIP-55 checksummed. `UserOperation` therefore serializes to exactly the JSON bundlers expect.

macro_rules! record {
    ($(#[$meta:meta])* pub struct $name:ident { $($(#[$field_meta:meta])* pub $field:ident: $type:ty,)* }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
        #[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize), serde(rename_all = "camelCase"))]
        pub struct $name { $($(#[$field_meta])* pub $field: $type,)* }
    };
}

record! {
    /// A P-256 public key: 32-byte `x` and `y` coordinates.
    pub struct PublicKey {
        pub x: String,
        pub y: String,
    }
}

record! {
    /// One call the account makes: `target.call{value}(data)`.
    pub struct Call {
        pub target: String,
        pub value: String,
        pub data: String,
    }
}

record! {
    /// ERC-4337 v0.6 user operation, in the JSON-RPC shape bundlers use.
    pub struct UserOperation {
        pub sender: String,
        pub nonce: String,
        pub init_code: String,
        pub call_data: String,
        pub call_gas_limit: String,
        pub verification_gas_limit: String,
        pub pre_verification_gas: String,
        pub max_fee_per_gas: String,
        pub max_priority_fee_per_gas: String,
        pub paymaster_and_data: String,
        pub signature: String,
    }
}

record! {
    pub struct GasPrice {
        pub max_fee_per_gas: String,
        pub max_priority_fee_per_gas: String,
    }
}

record! {
    /// A bundler's `eth_estimateUserOperationGas` result.
    pub struct GasEstimate {
        pub pre_verification_gas: String,
        pub verification_gas_limit: String,
        pub call_gas_limit: String,
    }
}

record! {
    /// What a security key returns when asked to sign, every field exactly as the authenticator produced it.
    pub struct Assertion {
        pub credential_id: String,
        pub authenticator_data: String,
        pub client_data_json: String,
        /// ASN.1 DER-encoded ECDSA signature.
        pub signature: String,
    }
}

record! {
    /// A key that owns the account. `owner_index` is its position in the account's owner list.
    pub struct OwnerKey {
        pub credential_id: String,
        pub owner_index: u32,
        pub public_key: PublicKey,
        /// The WebAuthn relying party ID the key was registered under. Assertions for any other are refused.
        pub rp_id: String,
        /// The key was registered with a PIN. Since v0.3.0 that means the key enforces the PIN itself (`credProtect`
        /// level 3). Signing also refuses a response without user verification, as defence in depth, but this flag
        /// alone can't protect a key: anyone who can edit the stored record can clear it.
        pub require_user_verification: bool,
        /// For an owner added after the wallet was created, the chain it was added on: it's an owner there only.
        /// `None` for the initial owners, which own the account on every chain.
        pub added_on_chain_id: Option<u64>,
    }
}

record! {
    /// A security key registration, checked by `verify_registration`.
    pub struct Registration {
        pub public_key: PublicKey,
        /// The key verified its PIN (or biometric) while registering.
        pub user_verified: bool,
        /// The key itself will refuse to sign without its PIN (`credProtect` level 3), whatever an app asks for.
        /// Always true when the registration required a PIN.
        pub pin_enforced_by_key: bool,
    }
}

record! {
    /// A contract the core recognizes by address, such as a gas sponsor.
    pub struct KnownContract {
        pub address: String,
        pub name: String,
    }
}

record! {
    pub struct Token {
        pub address: String,
        pub symbol: String,
        pub name: String,
        pub decimals: u8,
    }
}

record! {
    /// A supported network. Contract addresses are the same on all of them (see `entry_point_address` and
    /// `factory_address`).
    pub struct ChainConfig {
        pub id: u64,
        pub name: String,
        pub is_testnet: bool,
        pub rpc_url: String,
        pub default_bundler_url: String,
        pub explorer_url: String,
        /// Blockscout instance used to list every ERC-20 an address holds, without an API key.
        pub blockscout_url: Option<String>,
        /// Checked over RPC when the indexer is unavailable.
        pub known_tokens: Vec<Token>,
        /// Verification gas added to the bundler's estimate (see `apply_gas_estimate`). Chains without the
        /// RIP-7212 precompile need far more.
        pub verification_gas_buffer: u64,
        /// Paymasters reviewed as pure sponsors: they pay gas and charge the wallet nothing. Any other paymaster is
        /// named in the review with a warning, because it may charge the wallet's tokens.
        pub known_paymasters: Vec<KnownContract>,
    }
}

record! {
    pub struct EncodedFunctionCall {
        /// Function name, e.g. `transfer`.
        pub name: String,
        /// Canonical signature, e.g. `transfer(address,uint256)`.
        pub signature: String,
        /// Selector plus encoded arguments.
        pub data: String,
    }
}

record! {
    /// One line of the review screen.
    pub struct ReviewDetail {
        pub label: String,
        pub value: String,
        /// Addresses, hashes and other values best shown in a fixed-width font.
        pub monospaced: bool,
    }
}

record! {
    /// What a user operation will do, decoded from the operation itself. Review screens show `details` as-is, so
    /// what the user approves is what the core will sign.
    pub struct OperationReview {
        /// The user operation hash: the challenge the security key signs.
        pub hash: String,
        pub details: Vec<ReviewDetail>,
        /// Whether this operation deploys the account (its first transaction).
        pub deploys_account: bool,
        /// The paymaster, if one pays the gas. The review's details name it too.
        pub paymaster: Option<String>,
        /// The paymaster is a known sponsor (see `ChainConfig::known_paymasters`) that charges the wallet nothing.
        pub sponsored: bool,
        /// Most the account can pay in gas, in wei. Zero when a paymaster pays (though an unknown paymaster may
        /// charge tokens instead; the details say so). The actual cost is usually far lower.
        pub max_gas_cost: String,
        /// ETH sent by the calls, in wei.
        pub total_value: String,
        /// ETH the account must hold for this to go through: `max_gas_cost + total_value`.
        pub required_balance: String,
    }
}

record! {
    /// What signing a message involves: the EIP-191 hash dapps verify, and the account-specific hash the key signs.
    pub struct MessageChallenge {
        pub message_hash: String,
        /// `replaySafeHash(message_hash)`, the challenge the security key signs.
        pub challenge: String,
    }
}

record! {
    pub struct SignedMessage {
        pub message_hash: String,
        /// For `isValidSignature(message_hash, signature)`, or ERC-6492 wrapped if the account isn't deployed.
        pub signature: String,
    }
}
