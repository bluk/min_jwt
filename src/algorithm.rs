//! Algorithms used to sign the JWT.
//!
//! The algorithms listed here are not comprehensive. The types are used to
//! represent various properties of the algorithms.

/// A marker trait for an Algorithm.
pub trait Algorithm: private::Private {}

/// ECDSA using P-256 and SHA-256.
#[derive(Debug)]
pub struct Es256;

impl private::Private for Es256 {}
impl Algorithm for Es256 {}

/// HMAC using SHA-256.
#[derive(Debug)]
pub struct Hs256;

impl private::Private for Hs256 {}
impl Algorithm for Hs256 {}

/// RSASSA-PKCS-v1_5 using SHA-256.
#[derive(Debug)]
pub struct Rs256;

impl private::Private for Rs256 {}
impl Algorithm for Rs256 {}

mod private {
    pub trait Private {}

    impl<T> Private for &T where T: Private {}
}
