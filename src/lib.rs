use core::fmt;

pub mod edilithium;
pub mod silithium;

/// Errors returned by the Silithium family of signature schemes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The encoded signature does not have the expected length.
    InvalidLength { expected: usize, actual: usize },
    /// The system random number generator failed.
    Rng,
    /// The ML-DSA signing operation failed.
    Signing,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidLength { expected, actual } => write!(
                f,
                "invalid signature length: expected {expected} bytes, got {actual}"
            ),
            Error::Rng => f.write_str("random number generator failure"),
            Error::Signing => f.write_str("ML-DSA signing failure"),
        }
    }
}

impl core::error::Error for Error {}

impl From<getrandom::Error> for Error {
    fn from(_: getrandom::Error) -> Self {
        Error::Rng
    }
}
