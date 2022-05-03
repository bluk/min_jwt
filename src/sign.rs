//! Sign JWTs using various signature algorithms.
//!
//! The [`encode_and_sign`](super::encode_and_sign) and
//! [`serialize_encode_and_sign`](super::serialize_encode_and_sign) functions sign
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

/// A signature which can be represented by bytes.
pub trait Signature: AsRef<[u8]> {}

impl Signature for Vec<u8> {}

impl Signature for &[u8] {}

impl Signature for String {}

impl Signature for &str {}

/// A type which can sign a byte buffer.
///
/// In some cases, the trait is directly implemented on a signing key type which
/// can directly generate a signature.
///
/// In other cases, a new type composed of multiple fields may be needed because
/// the signing key's sign method may require more parameters (e.g. a random
/// number generator).
pub trait Signer {
    /// Returned signature type which implmenets the [Signature] trait.
    type Signature: Signature;

    /// Returns an error.
    type Error;

    /// Returns a signature from a byte buffer.
    ///
    /// # Errors
    ///
    /// Returns an error dependent on the signer.
    fn sign(&self, bytes: &[u8]) -> Result<Self::Signature, Self::Error>;
}

impl<T> Signer for &T
where
    T: Signer,
{
    type Signature = T::Signature;

    type Error = T::Error;

    fn sign(&self, bytes: &[u8]) -> Result<Self::Signature, Self::Error> {
        T::sign(self, bytes)
    }
}

#[cfg(feature = "p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
pub mod p256;
#[cfg(feature = "ring")]
#[cfg_attr(docsrs, doc(cfg(feature = "ring")))]
pub mod ring;
#[cfg(feature = "rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
pub mod rsa;
