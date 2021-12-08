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
        matches!(self.err.code, ErrorCode::MalformedJwt)
    }

    #[cfg(any(feature = "ring", feature = "web_crypto"))]
    pub(crate) fn invalid_signature() -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::InvalidSignature,
            }),
        }
    }

    /// If the error is due to an invalid signature.
    pub fn is_invalid_signature(&self) -> bool {
        #[cfg(any(feature = "ring", feature = "web_crypto"))]
        {
            matches!(self.err.code, ErrorCode::InvalidSignature)
        }
        #[cfg(not(any(feature = "ring", feature = "web_crypto")))]
        {
            false
        }
    }

    /// If the error is due to a part not being correctly base64 encoded.
    pub fn is_base64_decode_error(&self) -> bool {
        matches!(self.err.code, ErrorCode::Base64(_))
    }

    /// If the error is due to a cryptography error.
    pub fn is_crypto_error(&self) -> bool {
        #[cfg(feature = "ring")]
        {
            matches!(self.err.code, ErrorCode::RingUnspecified(_))
        }
        #[cfg(not(any(feature = "ring")))]
        {
            false
        }
    }

    #[cfg(feature = "web_crypto")]
    pub(crate) fn key_rejected(value: wasm_bindgen::JsValue) -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::WebCryptoKeyRejected(value),
            }),
        }
    }

    /// If the error is due to an invalid key.
    pub fn is_key_rejected(&self) -> bool {
        #[cfg(all(feature = "ring", not(feature = "web_crypto")))]
        {
            matches!(self.err.code, ErrorCode::RingKeyRejected(_))
        }
        #[cfg(all(feature = "web_crypto", not(feature = "ring")))]
        {
            matches!(self.err.code, ErrorCode::WebCryptoKeyRejected(_))
        }
        #[cfg(all(feature = "web_crypto", feature = "ring"))]
        {
            matches!(self.err.code, ErrorCode::RingKeyRejected(_))
                || matches!(self.err.code, ErrorCode::WebCryptoKeyRejected(_))
        }
        #[cfg(not(any(feature = "ring", feature = "web_crypto")))]
        {
            false
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self.err.code {
            ErrorCode::Base64(_) => "base64 decode error",
            #[cfg(any(feature = "ring", feature = "web_crypto"))]
            ErrorCode::InvalidSignature => "invalid signature",
            ErrorCode::MalformedJwt => "malformed jwt",
            #[cfg(feature = "ring")]
            ErrorCode::RingUnspecified(_) => "cryptography error",
            #[cfg(feature = "ring")]
            ErrorCode::RingKeyRejected(_) => "key rejected",
            #[cfg(feature = "web_crypto")]
            ErrorCode::WebCryptoKeyRejected(_) => "key rejected",
        }
    }

    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self.err.code {
            ErrorCode::Base64(ref err) => Some(err),
            ErrorCode::MalformedJwt => None,
            #[cfg(any(feature = "ring", feature = "web_crypto"))]
            ErrorCode::InvalidSignature => None,
            #[cfg(feature = "ring")]
            ErrorCode::RingKeyRejected(_) | ErrorCode::RingUnspecified(_) => None,
            #[cfg(feature = "web_crypto")]
            ErrorCode::WebCryptoKeyRejected(_) => None,
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
    fn from(error: ring::error::KeyRejected) -> Self {
        Error {
            err: Box::new(ErrorImpl {
                code: ErrorCode::RingKeyRejected(error),
            }),
        }
    }
}

#[cfg(feature = "ring")]
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
    #[cfg(any(feature = "ring", feature = "web_crypto"))]
    InvalidSignature,
    MalformedJwt,
    #[cfg(feature = "ring")]
    RingKeyRejected(ring::error::KeyRejected),
    #[cfg(feature = "ring")]
    RingUnspecified(ring::error::Unspecified),
    #[cfg(feature = "web_crypto")]
    WebCryptoKeyRejected(wasm_bindgen::JsValue),
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ErrorCode::Base64(ref error) => Display::fmt(error, f),
            #[cfg(any(feature = "ring", feature = "web_crypto"))]
            ErrorCode::InvalidSignature => f.write_str("invalid signature"),
            ErrorCode::MalformedJwt => f.write_str("malformed jwt"),
            #[cfg(feature = "ring")]
            ErrorCode::RingKeyRejected(ref error) => Display::fmt(error, f),
            #[cfg(feature = "ring")]
            ErrorCode::RingUnspecified(ref error) => Display::fmt(error, f),
            #[cfg(feature = "web_crypto")]
            ErrorCode::WebCryptoKeyRejected(ref error) => {
                if let Some(error) = error.as_string() {
                    Display::fmt(&error, f)
                } else {
                    f.write_str("key rejected")
                }
            }
        }
    }
}
