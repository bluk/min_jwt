//! Verify various types of signatures for a JWT.
//!
//! The [verify](super::verify()) function verifies JWTs.
//!
//! The function requires a [Verifier] which abstracts the implementation and
//! necessary parameters for verifying the signed data. This crate either
//! directly implements the `Verifier` trait on the foreign types or it creates
//! a wrapping type which implements the `Verifier` trait.
//!
//! Find the implementations on foreign types and implementators listed under
//! the [Verifier]'s documentation to discover what is available.
//!
//! See the implementation modules for specific examples.

use crate::error::Result;

/// A type which can verify a signature of a given message.
///
/// In some cases, the trait is directly implemented on a verifying key type which
/// can directly verify a signature.
///
/// In other cases, a new type composed of multiple fields may be needed because
/// the verifying key's verify method may require more parameters.
pub trait Verifier: private::Private {
    fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
    where
        M: AsRef<[u8]>,
        S: AsRef<[u8]>;
}

impl<T> Verifier for &T
where
    T: Verifier,
{
    fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
    where
        M: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        T::verify(self, message, signature)
    }
}

mod private {
    pub trait Private {}

    impl<T> Private for &T where T: Private {}
}

#[cfg(feature = "p256")]
pub mod p256;
#[cfg(feature = "rsa")]
pub mod rsa;

/// Ring implementation of signers and verifiers.
///
/// [Ring][ring] is a library for crytography operations which many Rust libraries depend on.
///
/// [ring]: https://github.com/briansmith/ring
#[cfg(feature = "ring")]
mod ring {
    use crate::error::{Error, Result};

    impl<B> super::Verifier for ::ring::signature::UnparsedPublicKey<B>
    where
        B: AsRef<[u8]>,
    {
        fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
        where
            M: AsRef<[u8]>,
            S: AsRef<[u8]>,
        {
            ::ring::signature::UnparsedPublicKey::verify(self, message.as_ref(), signature.as_ref())
                .map_err(|_| Error::invalid_signature())
        }
    }

    impl<B> super::private::Private for ::ring::signature::UnparsedPublicKey<B> where B: AsRef<[u8]> {}

    impl super::Verifier for ::ring::hmac::Key {
        fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
        where
            M: AsRef<[u8]>,
            S: AsRef<[u8]>,
        {
            ::ring::hmac::verify(self, message.as_ref(), signature.as_ref())
                .map_err(|_| Error::invalid_signature())
        }
    }

    impl super::private::Private for ::ring::hmac::Key {}
}

#[cfg(feature = "web_crypto")]
pub mod web_crypto;
