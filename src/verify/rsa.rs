//! `rsa` crate Verifier implementation.
//!
//! # Supported Algorithms
//!
//! | Algorithm | Type | Wrapper Type |
//! | --------- | ---- | ------------ |
//! | rs256     | [`::rsa::RsaPublicKey`] | [`RsaPublicKeyVerifier`] |
//!
//! Note that you will also need the `sha2` feature enabled.
//!
//! # Examples
//!
//! ## PKCS8
//!
//! The `pem` feature on the `rsa` dependency must be enabled.
//!
//! ```
//! # #[cfg(all(feature = "rsa", feature = "sha2"))]
//! # fn try_main() -> Result<(), min_jwt::error::Error> {
//! # let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.BV5tgihZQo_CCSJuwSmespFnUPVcE1tZ52td6wYfB6j-YuKanRuHD4hJZPO-fN2GYe492aU4FDFVqVqC3cZcv5sZgkZolPgAhXVlQymw___vmvcodWv7xLjZBr4INpzb4FPUkaNhAd1LvF28CXHx0aNvoyyOo4i_AR1ZYBk6CbsCrVj7XxdsVmP3VBpXLSFKcit0FrWBs_sP0-g2qQDIKZ5w9HNiv4H3fU5NZ_TNKRKIQkwMJ1hvI_JbacIZ9uk2oYZ6LwV_NMeh0EqIwRg1EsH6TcdXhzLRozVa1fbej9hd2-AOGxZTba3LQtBAEKbyEATd7N5mqtEsRvcTHzXJmw";
//! use ::rsa::pkcs8::FromPublicKey;
//!
//! let public_key =
//! "-----BEGIN PUBLIC KEY-----
//! MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyfEiSb2ElqylyAfWkbV0
//! JmKwzaYH2JtWi05dELrGpSI+OM2mNmFnpxZVUUx77GWASD+u/EbDpB7TxoL8wW6r
//! SFuduTIb63uhqeilkj6VhpPXVLpZg6m8korAXPGaN5BBMTyBAbpWk9e72z5gOGaF
//! GI4xOv0v3N0MX2h9uXJvhPTpOdKn6jXEflUFF89OWGEh/3JnyZbX5p8+F8BAuseb
//! 8gfpqT2Ct6KT5GrNiA7dPwjN7XFvVnvyYgR7+QXTVNRMrcrEUoJbR4DG+QVeyIRh
//! 0JGqXtm901cviPBRbicIMn2f8qfs15XMSeHWrgel21Cv1wQh3I4xy+soZuZZ2i/p
//! zwIDAQAB
//! -----END PUBLIC KEY-----";
//!
//! let public_key = ::rsa::RsaPublicKey::from_public_key_pem(public_key).unwrap();
//!
//! let verifier = min_jwt::verify::rsa::RsaPublicKeyVerifier::with_rs256(public_key);
//! let result = min_jwt::verify(jwt, &verifier)?;
//!
//! let header = result.decode_header();
//! let claims = result.decode_claims();
//! # Ok::<(), min_jwt::Error>(())
//! # }
//! # fn main() {
//! #   #[cfg(all(feature = "rsa", feature = "sha2"))]
//! #   try_main().unwrap();
//! # }
//! ```

use crate::{
    algorithm::Algorithm,
    error::{Error, Result},
};
use core::marker::PhantomData;

/// Types which can verify a signature.
pub trait PublicKey {
    fn verify<M, S>(&self, message: M, signature: S, padding: ::rsa::PaddingScheme) -> Result<()>
    where
        M: AsRef<[u8]>,
        S: AsRef<[u8]>;
}

impl<T> PublicKey for &T
where
    T: PublicKey,
{
    fn verify<M, S>(&self, message: M, signature: S, padding: ::rsa::PaddingScheme) -> Result<()>
    where
        M: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        T::verify(self, message, signature, padding)
    }
}

impl PublicKey for ::rsa::RsaPublicKey {
    fn verify<M, S>(&self, message: M, signature: S, padding: ::rsa::PaddingScheme) -> Result<()>
    where
        M: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        ::rsa::PublicKey::verify(self, padding, message.as_ref(), signature.as_ref())
            .map_err(|_| Error::invalid_signature())
    }
}

/// A wrapper type which holds the key and algorithm.
#[derive(Debug)]
pub struct RsaPublicKeyVerifier<K, A>
where
    K: PublicKey,
    A: Algorithm,
{
    key: K,
    alg: PhantomData<A>,
}

impl<K, A> RsaPublicKeyVerifier<K, A>
where
    K: PublicKey,
    A: Algorithm,
{
    pub fn into_inner(self) -> K {
        self.key
    }
}

#[cfg(feature = "sha2")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha2")))]
impl<K> RsaPublicKeyVerifier<K, crate::algorithm::Rs256>
where
    K: PublicKey,
{
    pub fn with_rs256(key: K) -> Self {
        Self {
            key,
            alg: PhantomData::default(),
        }
    }
}

#[cfg(feature = "sha2")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha2")))]
impl<K> super::Verifier for RsaPublicKeyVerifier<K, crate::algorithm::Rs256>
where
    K: PublicKey,
{
    fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
    where
        M: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        use sha2::{Digest, Sha256};

        self.key.verify(
            Sha256::digest(message),
            signature,
            ::rsa::PaddingScheme::new_pkcs1v15_sign(Some(::rsa::Hash::SHA2_256)),
        )
    }
}
