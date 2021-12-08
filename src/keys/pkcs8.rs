//! PKCS8 Keys.
//!
//! Keys in PEM format.

use crate::Algorithm;

/// A key used to sign, verify, or encrypt data.
#[derive(Clone, Debug)]
pub struct Pkcs8Key {
    pub(crate) algorithm: Algorithm,
    pub(crate) data: Vec<u8>,
}

impl Pkcs8Key {
    pub fn with_rs256_pem(data: Vec<u8>) -> Self {
        Self {
            algorithm: Algorithm::Rs256,
            data,
        }
    }

    pub fn with_es256_pem(data: Vec<u8>) -> Self {
        Self {
            algorithm: Algorithm::Es256,
            data,
        }
    }
}

/// A key used to sign, verify, or encrypt data with the key ID.
#[derive(Clone, Debug)]
pub struct Pkcs8KeyWithId {
    pub(crate) key: Pkcs8Key,
    pub(crate) kid: String,
}

impl Pkcs8KeyWithId {
    pub fn with_key_and_id(key: Pkcs8Key, kid: String) -> Self {
        Self { key, kid }
    }
}
