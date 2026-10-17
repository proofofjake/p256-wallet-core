use std::fmt;

/// Every failure the core reports. Messages are written to be shown to the user as-is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
#[cfg_attr(feature = "uniffi", uniffi(flat_error))]
pub enum CoreError {
    /// Malformed input: bad hex, address, amount, ABI data, function signature or user operation.
    InvalidInput(String),
    /// A security key response that can't be used: wrong format, wrong challenge, unknown key, or a signature
    /// that doesn't verify against the key's registered public key.
    InvalidAssertion(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::InvalidInput(message) | CoreError::InvalidAssertion(message) => f.write_str(message),
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
