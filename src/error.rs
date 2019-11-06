use std::convert::From;
use std::error;
use std::fmt::{self, Debug, Display};
use std::result;

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
        match self.err.code {
            ErrorCode::MalformedJwt => true,
            _ => false,
        }
    }

    pub(crate) fn invalid_signature() -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::InvalidSignature,
            }),
        }
    }

    /// If the error is due to an invalid signature.
    pub fn is_invalid_signature(&self) -> bool {
        match self.err.code {
            ErrorCode::InvalidSignature => true,
            _ => false,
        }
    }

    /// If the error is due to a part not being correctly base64 encoded.
    pub fn is_base64_decode_error(&self) -> bool {
        match self.err.code {
            ErrorCode::Base64(_) => true,
            _ => false,
        }
    }

    /// If the error is due to a cryptography error.
    pub fn is_crypto_error(&self) -> bool {
        match self.err.code {
            ErrorCode::RingUnspecified(_) => true,
            _ => false,
        }
    }

    /// If the error is due to an invalid signing key.
    pub fn is_key_rejected(&self) -> bool {
        match self.err.code {
            ErrorCode::RingKeyRejected(_) => true,
            _ => false,
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self.err.code {
            ErrorCode::Base64(_) => "base64 decode error",
            ErrorCode::InvalidSignature => "invalid signature",
            ErrorCode::MalformedJwt => "malformed jwt",
            ErrorCode::RingUnspecified(_) => "cryptography error",
            ErrorCode::RingKeyRejected(_) => "key rejected",
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match self.err.code {
            ErrorCode::Base64(ref err) => Some(err),
            ErrorCode::InvalidSignature
            | ErrorCode::MalformedJwt
            | ErrorCode::RingKeyRejected(_)
            | ErrorCode::RingUnspecified(_) => None,
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

impl From<ring::error::KeyRejected> for Error {
    fn from(error: ring::error::KeyRejected) -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::RingKeyRejected(error),
            }),
        }
    }
}

impl From<ring::error::Unspecified> for Error {
    fn from(error: ring::error::Unspecified) -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::RingUnspecified(error),
            }),
        }
    }
}

impl From<base64::DecodeError> for Error {
    fn from(error: base64::DecodeError) -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::Base64(error),
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
    // TODO: Should also have a reference to the str which did not decode
    Base64(base64::DecodeError),
    InvalidSignature,
    MalformedJwt,
    RingKeyRejected(ring::error::KeyRejected),
    RingUnspecified(ring::error::Unspecified),
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ErrorCode::Base64(ref error) => Display::fmt(error, f),
            ErrorCode::InvalidSignature => f.write_str("invalid signature"),
            ErrorCode::MalformedJwt => f.write_str("malformed jwt"),
            ErrorCode::RingKeyRejected(ref error) => Display::fmt(error, f),
            ErrorCode::RingUnspecified(ref error) => Display::fmt(error, f),
        }
    }
}
