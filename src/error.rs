use std::convert::From;
use std::error;
use std::fmt;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    // err: Box<ErrorImpl>,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("jwt error")
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "JWT error"
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

impl From<ring::error::KeyRejected> for Error {
    fn from(_other: ring::error::KeyRejected) -> Self {
        Error {}
    }
}

impl From<ring::error::Unspecified> for Error {
    fn from(_other: ring::error::Unspecified) -> Self {
        Error {}
    }
}

impl From<serde_json::Error> for Error {
    fn from(_other: serde_json::Error) -> Self {
        Error {}
    }
}
