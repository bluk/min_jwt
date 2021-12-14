//! Error type.

use core::convert::From;
use core::fmt::{self, Debug, Display};
use core::result;
use std::error;

/// Result type with crate [Error].
pub type Result<T> = result::Result<T, Error>;

/// Represents all possible errors from this crate.
pub struct Error {
    err: Box<ErrorImpl>,
}

impl Error {
    pub(crate) fn malformed_jwt() -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::MalformedJwt,
            }),
        }
    }

    /// If the error is due to the JWT being malformed.
    pub fn is_malformed_jwt(&self) -> bool {
        matches!(self.err.code, ErrorCode::MalformedJwt)
    }

    #[cfg(any(
        feature = "p256",
        feature = "ring",
        feature = "rsa",
        feature = "web_crypto"
    ))]
    pub(crate) fn invalid_signature() -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::InvalidSignature,
            }),
        }
    }
    /// If the error is due to an invalid signature.
    pub fn is_invalid_signature(&self) -> bool {
        matches!(self.err.code, ErrorCode::InvalidSignature)
    }

    /// If the error is due to a part not being correctly base64 encoded.
    pub fn is_base64_decode_error(&self) -> bool {
        matches!(self.err.code, ErrorCode::Base64Decode(_))
    }

    pub(crate) fn key_rejected() -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::KeyRejected,
            }),
        }
    }

    /// If the error is due to an invalid key.
    pub fn is_key_rejected(&self) -> bool {
        matches!(self.err.code, ErrorCode::KeyRejected)
    }

    pub(crate) fn unsupported_algorithm() -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::UnsupportedAlgorithm,
            }),
        }
    }

    /// If the error is due to an unsupported algorithm.
    pub fn is_unsupported_algorithm(&self) -> bool {
        matches!(self.err.code, ErrorCode::UnsupportedAlgorithm)
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self.err.code {
            ErrorCode::Base64Decode(_) => "base64 decode error",
            ErrorCode::InvalidSignature => "invalid signature",
            ErrorCode::KeyRejected => "key rejected",
            ErrorCode::MalformedJwt => "malformed jwt",
            ErrorCode::Unspecified => "unspecified error",
            ErrorCode::UnsupportedAlgorithm => "unsupported algorithm",
        }
    }

    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self.err.code {
            ErrorCode::Base64Decode(ref err) => Some(err),
            ErrorCode::InvalidSignature => None,
            ErrorCode::KeyRejected => None,
            ErrorCode::MalformedJwt => None,
            ErrorCode::Unspecified => None,
            ErrorCode::UnsupportedAlgorithm => None,
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&*self.err, f)
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error({:?})", self.err.code.to_string(),)
    }
}

#[cfg(feature = "ring")]
impl From<ring::error::KeyRejected> for Error {
    fn from(_: ring::error::KeyRejected) -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::KeyRejected,
            }),
        }
    }
}

#[cfg(feature = "ring")]
impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::Unspecified,
            }),
        }
    }
}

impl From<base64::DecodeError> for Error {
    fn from(error: base64::DecodeError) -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::Base64Decode(error),
            }),
        }
    }
}

#[derive(Debug)]
struct ErrorImpl {
    code: ErrorCode,
}

impl Display for ErrorImpl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.code, f)
    }
}

#[derive(Debug)]
pub(crate) enum ErrorCode {
    Base64Decode(base64::DecodeError),
    InvalidSignature,
    KeyRejected,
    MalformedJwt,
    Unspecified,
    UnsupportedAlgorithm,
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ErrorCode::Base64Decode(ref error) => Display::fmt(error, f),
            ErrorCode::InvalidSignature => f.write_str("invalid signature"),
            ErrorCode::KeyRejected => f.write_str("invalid signature"),
            ErrorCode::MalformedJwt => f.write_str("malformed jwt"),
            ErrorCode::Unspecified => f.write_str("unspecified error"),
            ErrorCode::UnsupportedAlgorithm => f.write_str("unsupported algorithm"),
        }
    }
}
