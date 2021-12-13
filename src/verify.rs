//! Verify various types of signatures for a JWT.
//!
//! See the tests for how to verify a specific signing algorithm.

use crate::error::Result;

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
mod p256 {
    use crate::error::{Error, Result};

    impl super::Verifier for ::p256::ecdsa::VerifyingKey {
        fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
        where
            M: AsRef<[u8]>,
            S: AsRef<[u8]>,
        {
            let signature = ::p256::ecdsa::signature::Signature::from_bytes(signature.as_ref())
                .map_err(|_| Error::invalid_signature())?;
            ::p256::ecdsa::signature::Verifier::verify(self, message.as_ref(), &signature)
                .map_err(|_| Error::invalid_signature())
        }
    }

    impl super::private::Private for ::p256::ecdsa::VerifyingKey {}
}

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
