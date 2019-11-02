use std::convert::From;
use std::error;
use std::fmt::{self, Debug, Display};
use std::result;

use crate::verifier::UnverifiedJWT;

pub type Result<'a, T> = result::Result<T, Error<'a>>;

pub struct Error<'a> {
    err: Box<ErrorImpl<'a>>,
}

impl<'a> Error<'a> {
    pub(crate) fn malformed_jwt() -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::MalformedJwt,
            }),
        }
    }

    pub(crate) fn invalid_signature(unverified_jwt: UnverifiedJWT<'a>) -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::InvalidSignature(unverified_jwt),
            }),
        }
    }
}

impl<'a> error::Error for Error<'a> {
    fn description(&self) -> &str {
        match self.err.code {
            ErrorCode::Base64(_) => "base64 decode error",
            ErrorCode::InvalidSignature(_) => "invalid signature",
            ErrorCode::MalformedJwt => "malformed jwt",
            ErrorCode::RingUnspecified(_) => "cryptography error",
            ErrorCode::SerdeJson(ref err) => error::Error::description(err),
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match self.err.code {
            ErrorCode::Base64(ref err) => Some(err),
            ErrorCode::SerdeJson(ref err) => Some(err),
            ErrorCode::InvalidSignature(_)
            | ErrorCode::MalformedJwt
            | ErrorCode::RingUnspecified(_) => None,
        }
    }
}

impl<'a> Display for Error<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&*self.err, f)
    }
}

impl<'a> Debug for Error<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error({:?})", self.err.code.to_string(),)
    }
}

impl<'a> From<ring::error::Unspecified> for Error<'a> {
    fn from(error: ring::error::Unspecified) -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::RingUnspecified(error),
            }),
        }
    }
}

impl<'a> From<serde_json::Error> for Error<'a> {
    fn from(error: serde_json::Error) -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::SerdeJson(error),
            }),
        }
    }
}

impl<'a> From<base64::DecodeError> for Error<'a> {
    fn from(error: base64::DecodeError) -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::Base64(error),
            }),
        }
    }
}

#[derive(Debug)]
struct ErrorImpl<'a> {
    code: ErrorCode<'a>,
}

impl<'a> Display for ErrorImpl<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.code, f)
    }
}

#[derive(Debug)]
pub(crate) enum ErrorCode<'a> {
    // TODO: Should also have a reference to the str which did not decode
    Base64(base64::DecodeError),
    InvalidSignature(UnverifiedJWT<'a>),
    MalformedJwt,
    RingUnspecified(ring::error::Unspecified),
    SerdeJson(serde_json::Error),
}

impl<'a> Display for ErrorCode<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ErrorCode::Base64(ref error) => Display::fmt(error, f),
            ErrorCode::InvalidSignature(_) => f.write_str("invalid signature"),
            ErrorCode::MalformedJwt => f.write_str("malformed jwt"),
            ErrorCode::SerdeJson(ref error) => Display::fmt(error, f),
            ErrorCode::RingUnspecified(ref error) => Display::fmt(error, f),
        }
    }
}
