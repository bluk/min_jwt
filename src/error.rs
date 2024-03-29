//! Error type.

use core::convert::From;
use core::fmt::{self, Debug, Display};
use core::result;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::boxed::Box;

#[cfg(feature = "std")]
use std::boxed::Box;

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
    #[must_use]
    pub fn is_malformed_jwt(&self) -> bool {
        matches!(self.err.code, ErrorCode::MalformedJwt)
    }

    #[cfg(any(feature = "p256", feature = "ring", feature = "rsa",))]
    #[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "ring")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
    pub(crate) fn invalid_signature() -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::InvalidSignature,
            }),
        }
    }
    /// If the error is due to an invalid signature.
    #[must_use]
    pub fn is_invalid_signature(&self) -> bool {
        matches!(self.err.code, ErrorCode::InvalidSignature)
    }

    /// If the error is due to a part not being correctly base64 encoded.
    #[must_use]
    pub fn is_base64_decode_error(&self) -> bool {
        matches!(self.err.code, ErrorCode::Base64Decode(_))
    }

    /// If the error is due to an invalid key.
    #[must_use]
    pub fn is_key_rejected(&self) -> bool {
        matches!(self.err.code, ErrorCode::KeyRejected)
    }

    #[must_use]
    pub(crate) fn unspecified() -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::Unspecified,
            }),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.err.code {
            ErrorCode::Base64Decode(ref err) => Some(err),
            ErrorCode::InvalidSignature
            | ErrorCode::KeyRejected
            | ErrorCode::MalformedJwt
            | ErrorCode::Unspecified => None,
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&*self.err, f)
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error({:?})", self.err.code)
    }
}

#[cfg(feature = "ring")]
#[cfg_attr(docsrs, doc(cfg(feature = "ring")))]
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
#[cfg_attr(docsrs, doc(cfg(feature = "ring")))]
impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::Unspecified,
            }),
        }
    }
}

impl From<base64ct::Error> for Error {
    fn from(error: base64ct::Error) -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::Base64Decode(error),
            }),
        }
    }
}

impl From<base64ct::InvalidLengthError> for Error {
    fn from(_: base64ct::InvalidLengthError) -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::Base64Decode(base64ct::Error::InvalidLength),
            }),
        }
    }
}

impl From<base64ct::InvalidEncodingError> for Error {
    fn from(_: base64ct::InvalidEncodingError) -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::Base64Decode(base64ct::Error::InvalidEncoding),
            }),
        }
    }
}

#[derive(Debug)]
struct ErrorImpl {
    code: ErrorCode,
}

impl Display for ErrorImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.code, f)
    }
}

#[derive(Debug)]
pub(crate) enum ErrorCode {
    Base64Decode(base64ct::Error),
    #[allow(dead_code)]
    InvalidSignature,
    #[allow(dead_code)]
    KeyRejected,
    MalformedJwt,
    #[allow(dead_code)]
    Unspecified,
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCode::Base64Decode(ref error) => Display::fmt(error, f),
            ErrorCode::InvalidSignature | ErrorCode::KeyRejected => {
                f.write_str("invalid signature")
            }
            ErrorCode::MalformedJwt => f.write_str("malformed jwt"),
            ErrorCode::Unspecified => f.write_str("unspecified error"),
        }
    }
}
