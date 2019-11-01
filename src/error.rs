use std::convert::From;
use std::error;
use std::fmt::{self, Debug, Display};
use std::result;

pub type Result<T> = result::Result<T, Error>;

pub struct Error {
    err: Box<ErrorImpl>,
}

impl Error {}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self.err.code {
            ErrorCode::RingUnspecified(_) => "cryptography error",
            ErrorCode::SerdeJson(ref err) => error::Error::description(err),
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match self.err.code {
            ErrorCode::RingUnspecified(_) => None,
            ErrorCode::SerdeJson(ref err) => Some(err),
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

impl From<ring::error::Unspecified> for Error {
    fn from(error: ring::error::Unspecified) -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::RingUnspecified(error),
            }),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::SerdeJson(error),
            }),
        }
    }
}

struct ErrorImpl {
    code: ErrorCode,
}

impl Display for ErrorImpl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.code, f)
    }
}

enum ErrorCode {
    RingUnspecified(ring::error::Unspecified),
    SerdeJson(serde_json::Error),
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ErrorCode::SerdeJson(ref error) => Display::fmt(error, f),
            ErrorCode::RingUnspecified(ref error) => Display::fmt(error, f),
        }
    }
}
