//! Sign JWTs using various signature algorithms.
//!
//! The [encode_and_sign](super::encode_and_sign) and
//! [serialize_encode_and_sign](super::serialize_encode_and_sign) functions sign
//! JWTs.
//!
//! Both functions require a [Signer] which abstracts the implementation and
//! necessary parameters for signing the encoded data. This crate either directly
//! implements the `Signer` trait on the foreign types or it creates a wrapping
//! type which implements the `Signer` trait.
//!
//! Find the implementations on foreign types and implementators listed under
//! the [Signer]'s documentation to discover what is available.
//!
//! See the implementation modules for specific examples.

use crate::error::Result;

/// A signature which can be represented by bytes.
pub trait Signature: AsRef<[u8]> + private::Private {}

impl private::Private for Vec<u8> {}
impl Signature for Vec<u8> {}

// impl private::Private for &[u8] {}
// impl Signature for &[u8] {}

// impl private::Private for String {}
// impl Signature for String {}

// impl private::Private for &str {}
// impl Signature for &str {}

/// A type which can sign a byte buffer.
///
/// In some cases, the trait is directly implemented on a signing key type which
/// can directly generate a signature.
///
/// In other cases, a new type composed of multiple fields may be needed because
/// the signing key's sign method may require more parameters (e.g. a random
/// number generator).
pub trait Signer: private::Private {
    type Signature: Signature;

    /// Returns a signature from a byte buffer.
    fn sign(&self, bytes: &[u8]) -> Result<Self::Signature>;
}

impl<T> Signer for &T
where
    T: Signer,
{
    type Signature = T::Signature;

    fn sign(&self, bytes: &[u8]) -> Result<Self::Signature> {
        T::sign(self, bytes)
    }
}

mod private {
    pub trait Private {}

    impl<T> Private for &T where T: Private {}
}

#[cfg(feature = "p256")]
pub mod p256;
#[cfg(feature = "ring")]
pub mod ring;
#[cfg(feature = "rsa")]
pub mod rsa;
