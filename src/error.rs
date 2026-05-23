//! Error type, modeled on libdatachannel's negative-return-code convention.

use thiserror::Error;

/// Errors returned by libdatachannel operations.
#[derive(Debug, Error)]
pub enum Error {
    /// An argument was invalid (matches `RTC_ERR_INVALID`).
    #[error("invalid argument")]
    InvalidArg,
    /// A runtime/internal failure (matches `RTC_ERR_FAILURE`).
    #[error("runtime error")]
    Runtime,
    /// The requested operation is not available in the current state
    /// (matches `RTC_ERR_NOT_AVAIL`).
    #[error("not available")]
    NotAvailable,
    /// A caller-supplied buffer was too small (matches `RTC_ERR_TOO_SMALL`).
    #[error("buffer too small")]
    TooSmall,
    /// Catch-all for unexpected return codes.
    #[error("unknown error")]
    Unknown,
    /// A string passed across the FFI boundary was malformed.
    #[error("bad string: {0}")]
    BadString(String),
}

impl From<std::ffi::NulError> for Error {
    fn from(e: std::ffi::NulError) -> Self {
        Self::BadString(e.to_string())
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self::BadString(e.to_string())
    }
}

/// Convenience `Result` alias.
pub type Result<T> = std::result::Result<T, Error>;
