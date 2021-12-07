//! PKCS8 Keys.
//!
//! Keys in PEM/DER format.

use super::Algorithm;

/// A key used to sign, verify, or encrypt data.
#[derive(Clone, Debug)]
pub struct Pkcs8Key<'a> {
    pub(crate) algorithm: Algorithm,
    pub(crate) data: &'a [u8],
}

impl<'a> Pkcs8Key<'a> {
    pub fn with_rs256_key(data: &'a [u8]) -> Self {
        Self {
            algorithm: Algorithm::Rs256,
            data,
        }
    }

    pub fn with_es256_key(data: &'a [u8]) -> Self {
        Self {
            algorithm: Algorithm::Es256,
            data,
        }
    }
}
