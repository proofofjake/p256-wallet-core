use std::fmt;

/// Every failure the core reports. Messages are written to be shown to the user as-is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
#[cfg_attr(feature = "uniffi", uniffi(flat_error))]
pub enum CoreError {
    /// Malformed input: bad hex, address, amount, ABI data, function signature, user operation or wallet record.
    InvalidInput(String),
    /// A security key response that can't be used: wrong format, wrong challenge, unknown key, or a signature
    /// that doesn't verify against the key's registered public key.
    InvalidAssertion(String),
    /// A well-formed request the core won't carry out: a transaction that could hand over or lock the wallet, or
    /// that it can't describe faithfully, and keys it won't accept as owners (synced passkeys, or a PIN the key
    /// won't enforce). Apps can show these as "the wallet won't sign this" rather than as an error in the input.
    Refused(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::InvalidInput(message) | CoreError::InvalidAssertion(message) | CoreError::Refused(message) => {
                f.write_str(message)
            }
        }
    }
}

impl std::error::Error for CoreError {}

pub type Result<T> = std::result::Result<T, CoreError>;

pub(crate) fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::InvalidInput(message.into())
}

pub(crate) fn bad_assertion(message: impl Into<String>) -> CoreError {
    CoreError::InvalidAssertion(message.into())
}

pub(crate) fn refused(message: impl Into<String>) -> CoreError {
    CoreError::Refused(message.into())
}

/// A refused operation: "This wallet won't sign this: `reason`".
pub(crate) fn wont_sign(reason: &str) -> CoreError {
    refused(format!("This wallet won't sign this: {reason}"))
}
