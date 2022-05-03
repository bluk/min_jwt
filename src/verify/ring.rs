//! `ring` crate Verifier implementation.
//!
//! # Supported Algorithms
//!
//! | Algorithm | Type | Wrapper Type |
//! | --------- | ---- | ------------ |
//! | es256     | [`::ring::signature::UnparsedPublicKey`]   |`EcdsaKeyVerifier`er] |
//! | hs256     | [`::ring::hmac::Key`]                      | [`HmacKeyVerifier`]  |
//! | rs256     | [`::ring::signature::UnparsedPublicKey`]   | [`RsaKeyVerifier`]   |
//!
//! # Examples
//!
//! ## ES256 PKCS8
//!
//! ```
//! # #[cfg(all(feature="p256", feature="ring"))]
//! # fn try_main() -> Result<(), min_jwt::error::Error> {
//! # fn convert_pkcs8_pem_to_spk(public_key: &str) -> impl AsRef<[u8]> {
//! #   use ::p256::pkcs8::{DecodePublicKey, EncodePublicKey};
//! #   let public_key = ::p256::PublicKey::from_public_key_pem(&public_key).unwrap();
//! #   let mut public_key = public_key.to_public_key_der().unwrap().as_ref().to_vec();
//! #   // This is a hack to get the correct format.
//! #   let public_key = public_key.split_off(26);
//! #   public_key
//! # }
//! # let jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.t2IAtoWoX5iMaIXJmOELc_LY-B8YxlsgkCsEKso_qvYgg0DR6_Q1pZO6SVeOTLFhgDFku9l_cIoL1A6js5rhjw";
//! let public_key =
//! "-----BEGIN PUBLIC KEY-----
//! MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEerEk+zqoG1oYBLD3ohuz0tzIlU7X
//! zFG1098HcCOu0CmVAsp8ZLYXqYD3ts6+j0CV/I2yfzwx/ojBrm+Z/pSQnA==
//! -----END PUBLIC KEY-----";
//!
//! // Convert the PKCS8 PEM to SPK.
//! // Note that ring requires SPK (not SPKI) keys for ECDSA_P256_SHA256 public keys.
//! // See https://github.com/briansmith/ring/issues/881
//! let public_key = convert_pkcs8_pem_to_spk(public_key);
//!
//! let public_key = ::ring::signature::UnparsedPublicKey::new(
//!   &::ring::signature::ECDSA_P256_SHA256_FIXED,
//!   public_key,
//! );
//!
//! let verifier = min_jwt::verify::ring::EcdsaKeyVerifier::with_es256(&public_key);
//! let verified_jwt = min_jwt::verify(jwt, &verifier)?;
//!
//! let header = verified_jwt.decode_header();
//! let claims = verified_jwt.decode_claims();
//! # Ok::<(), min_jwt::Error>(())
//! # }
//! # fn main() {
//! #   #[cfg(all(feature="p256", feature="ring"))]
//! #   try_main().unwrap();
//! # }
//! ```
//!
//! ## HS256
//!
//! ```
//! # let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.tAzkR2NyvqGKrIras8IDsoczvrYWD0gAM3E6H5qGZVg";
//! # let encoded_hmac_key: &str =
//! # "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
//! # let hmac_key_bytes = ::base64::decode_config(encoded_hmac_key, base64::URL_SAFE_NO_PAD).unwrap();
//! let hmac_key = ::ring::hmac::Key::new(::ring::hmac::HMAC_SHA256, &hmac_key_bytes);
//!
//! let verifier = min_jwt::verify::ring::HmacKeyVerifier::with_hs256(hmac_key);
//! let verified_jwt = min_jwt::verify(jwt, &verifier)?;
//!
//! let header = verified_jwt.decode_header();
//! let claims = verified_jwt.decode_claims();
//! # Ok::<(), min_jwt::Error>(())
//! ```
//!
//! ## RS256 PKCS8
//!
//! ```
//! # let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.BV5tgihZQo_CCSJuwSmespFnUPVcE1tZ52td6wYfB6j-YuKanRuHD4hJZPO-fN2GYe492aU4FDFVqVqC3cZcv5sZgkZolPgAhXVlQymw___vmvcodWv7xLjZBr4INpzb4FPUkaNhAd1LvF28CXHx0aNvoyyOo4i_AR1ZYBk6CbsCrVj7XxdsVmP3VBpXLSFKcit0FrWBs_sP0-g2qQDIKZ5w9HNiv4H3fU5NZ_TNKRKIQkwMJ1hvI_JbacIZ9uk2oYZ6LwV_NMeh0EqIwRg1EsH6TcdXhzLRozVa1fbej9hd2-AOGxZTba3LQtBAEKbyEATd7N5mqtEsRvcTHzXJmw";
//! # fn convert_pkcs8_pem_to_pkcs1_der(public_key: &str) -> impl AsRef<[u8]> {
//! #   use rsa::{pkcs8::{FromPublicKey, ToPublicKey}, pkcs1::ToRsaPublicKey};
//! #   let public_key = ::rsa::RsaPublicKey::from_public_key_pem(&public_key).unwrap();
//! #   public_key.to_pkcs1_der().unwrap()
//! # }
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
//! // Convert the PKCS8 PEM to PKCS1 DER for RSA public keys.
//! let public_key = convert_pkcs8_pem_to_pkcs1_der(public_key);
//!
//! let public_key = ::ring::signature::UnparsedPublicKey::new(
//!   &::ring::signature::RSA_PKCS1_2048_8192_SHA256,
//!   public_key,
//! );
//!
//! let verifier = min_jwt::verify::ring::RsaKeyVerifier::with_rs256(public_key);
//! let verified_jwt = min_jwt::verify(jwt, &verifier)?;
//!
//! let header = verified_jwt.decode_header();
//! let claims = verified_jwt.decode_claims();
//! # Ok::<(), min_jwt::Error>(())
//! ```
use crate::{
    algorithm::{Algorithm, Es256, Hs256, Rs256},
    error::{Error, Result},
};
use core::marker::PhantomData;

mod private {
    pub trait Private {}

    impl<T> Private for &T where T: Private {}
}

impl<B> private::Private for ::ring::signature::UnparsedPublicKey<B> where B: AsRef<[u8]> {}

macro_rules! key_verifier {
    ($verifier_name:ident, $key_name:ident) => {
        pub trait $key_name: private::Private {
            fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
            where
                M: AsRef<[u8]>,
                S: AsRef<[u8]>;
        }

        impl<T> $key_name for &T
        where
            T: $key_name,
        {
            fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
            where
                M: AsRef<[u8]>,
                S: AsRef<[u8]>,
            {
                T::verify(self, message, signature)
            }
        }

        impl<B> $key_name for ::ring::signature::UnparsedPublicKey<B>
        where
            B: AsRef<[u8]>,
        {
            fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
            where
                M: AsRef<[u8]>,
                S: AsRef<[u8]>,
            {
                ::ring::signature::UnparsedPublicKey::verify(
                    self,
                    message.as_ref(),
                    signature.as_ref(),
                )
                .map_err(|_| Error::invalid_signature())
            }
        }

        impl<K, A> $verifier_name<K, A>
        where
            K: $key_name,
            A: Algorithm,
        {
            pub fn into_inner(self) -> K {
                self.key
            }
        }

        impl<K, A> super::Verifier for $verifier_name<K, A>
        where
            K: $key_name,
            A: Algorithm,
        {
            fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
            where
                M: AsRef<[u8]>,
                S: AsRef<[u8]>,
            {
                self.key.verify(message, signature)
            }
        }

        impl<K, A> super::private::Private for $verifier_name<K, A>
        where
            K: $key_name,
            A: Algorithm,
        {
        }
    };
}

key_verifier!(EcdsaKeyVerifier, EcdsaKey);

/// Wrapper for [`::ring::signature::UnparsedPublicKey`].
///
/// # Examples
///
/// ## ES256 PKCS8
///
/// ```
/// # fn convert_pkcs8_pem_to_spk(public_key: &str) -> impl AsRef<[u8]> {
/// #   use ::p256::pkcs8::{DecodePublicKey, EncodePublicKey};
/// #   let public_key = ::p256::PublicKey::from_public_key_pem(&public_key).unwrap();
/// #   let mut public_key = public_key.to_public_key_der().unwrap().as_ref().to_vec();
/// #   // This is a hack to get the correct format.
/// #   let public_key = public_key.split_off(26);
/// #   public_key
/// # }
/// # let jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.t2IAtoWoX5iMaIXJmOELc_LY-B8YxlsgkCsEKso_qvYgg0DR6_Q1pZO6SVeOTLFhgDFku9l_cIoL1A6js5rhjw";
/// let public_key =
/// "-----BEGIN PUBLIC KEY-----
/// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEerEk+zqoG1oYBLD3ohuz0tzIlU7X
/// zFG1098HcCOu0CmVAsp8ZLYXqYD3ts6+j0CV/I2yfzwx/ojBrm+Z/pSQnA==
/// -----END PUBLIC KEY-----";
///
/// // Convert the PKCS8 PEM to SPK.
/// // Note that ring requires SPK (not SPKI) keys for ECDSA_P256_SHA256 public keys.
/// // See https://github.com/briansmith/ring/issues/881
/// let public_key = convert_pkcs8_pem_to_spk(public_key);
///
/// let public_key = ::ring::signature::UnparsedPublicKey::new(
///   &::ring::signature::ECDSA_P256_SHA256_FIXED,
///   public_key,
/// );
///
/// let verifier = min_jwt::verify::ring::EcdsaKeyVerifier::with_es256(&public_key);
/// let verified_jwt = min_jwt::verify(jwt, &verifier)?;
///
/// let header = verified_jwt.decode_header();
/// let claims = verified_jwt.decode_claims();
/// # Ok::<(), min_jwt::Error>(())
/// ```
pub struct EcdsaKeyVerifier<K, A>
where
    K: EcdsaKey,
    A: Algorithm,
{
    key: K,
    algorithm: PhantomData<A>,
}

impl<K> EcdsaKeyVerifier<K, Es256>
where
    K: EcdsaKey,
{
    pub fn with_es256(key: K) -> EcdsaKeyVerifier<K, Es256> {
        Self {
            key,
            algorithm: PhantomData::default(),
        }
    }
}

key_verifier!(RsaKeyVerifier, RsaKey);

/// Wrapper for [`::ring::signature::UnparsedPublicKey`].
///
/// # Examples
///
/// ## RS256 PKCS8
///
/// ```
/// # let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.BV5tgihZQo_CCSJuwSmespFnUPVcE1tZ52td6wYfB6j-YuKanRuHD4hJZPO-fN2GYe492aU4FDFVqVqC3cZcv5sZgkZolPgAhXVlQymw___vmvcodWv7xLjZBr4INpzb4FPUkaNhAd1LvF28CXHx0aNvoyyOo4i_AR1ZYBk6CbsCrVj7XxdsVmP3VBpXLSFKcit0FrWBs_sP0-g2qQDIKZ5w9HNiv4H3fU5NZ_TNKRKIQkwMJ1hvI_JbacIZ9uk2oYZ6LwV_NMeh0EqIwRg1EsH6TcdXhzLRozVa1fbej9hd2-AOGxZTba3LQtBAEKbyEATd7N5mqtEsRvcTHzXJmw";
/// # fn convert_pkcs8_pem_to_pkcs1_der(public_key: &str) -> impl AsRef<[u8]> {
/// #   use rsa::{pkcs8::{FromPublicKey, ToPublicKey}, pkcs1::ToRsaPublicKey};
/// #   let public_key = ::rsa::RsaPublicKey::from_public_key_pem(&public_key).unwrap();
/// #   public_key.to_pkcs1_der().unwrap()
/// # }
/// let public_key =
/// "-----BEGIN PUBLIC KEY-----
/// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyfEiSb2ElqylyAfWkbV0
/// JmKwzaYH2JtWi05dELrGpSI+OM2mNmFnpxZVUUx77GWASD+u/EbDpB7TxoL8wW6r
/// SFuduTIb63uhqeilkj6VhpPXVLpZg6m8korAXPGaN5BBMTyBAbpWk9e72z5gOGaF
/// GI4xOv0v3N0MX2h9uXJvhPTpOdKn6jXEflUFF89OWGEh/3JnyZbX5p8+F8BAuseb
/// 8gfpqT2Ct6KT5GrNiA7dPwjN7XFvVnvyYgR7+QXTVNRMrcrEUoJbR4DG+QVeyIRh
/// 0JGqXtm901cviPBRbicIMn2f8qfs15XMSeHWrgel21Cv1wQh3I4xy+soZuZZ2i/p
/// zwIDAQAB
/// -----END PUBLIC KEY-----";
///
/// // Convert the PKCS8 PEM to PKCS1 DER for RSA public keys.
/// let public_key = convert_pkcs8_pem_to_pkcs1_der(public_key);
///
/// let public_key = ::ring::signature::UnparsedPublicKey::new(
///   &::ring::signature::RSA_PKCS1_2048_8192_SHA256,
///   public_key,
/// );
///
/// let verifier = min_jwt::verify::ring::RsaKeyVerifier::with_rs256(public_key);
/// let verified_jwt = min_jwt::verify(jwt, &verifier)?;
///
/// let header = verified_jwt.decode_header();
/// let claims = verified_jwt.decode_claims();
/// # Ok::<(), min_jwt::Error>(())
/// ```
pub struct RsaKeyVerifier<K, A>
where
    K: RsaKey,
    A: Algorithm,
{
    key: K,
    algorithm: PhantomData<A>,
}

impl<K> RsaKeyVerifier<K, Rs256>
where
    K: RsaKey,
{
    pub fn with_rs256(key: K) -> RsaKeyVerifier<K, Rs256> {
        Self {
            key,
            algorithm: PhantomData::default(),
        }
    }
}

pub trait HmacKey: private::Private {
    fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
    where
        M: AsRef<[u8]>,
        S: AsRef<[u8]>;
}

impl<T> HmacKey for &T
where
    T: HmacKey,
{
    fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
    where
        M: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        T::verify(self, message, signature)
    }
}

impl HmacKey for ::ring::hmac::Key {
    fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
    where
        M: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        ::ring::hmac::verify(self, message.as_ref(), signature.as_ref())
            .map_err(|_| Error::invalid_signature())
    }
}
impl private::Private for ::ring::hmac::Key {}

/// Wrapper for [`::ring::hmac::Key`].
///
/// # Examples
///
/// ## HS256
///
/// ```
/// # let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.tAzkR2NyvqGKrIras8IDsoczvrYWD0gAM3E6H5qGZVg";
/// # let encoded_hmac_key: &str =
/// # "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
/// # let hmac_key_bytes = ::base64::decode_config(encoded_hmac_key, base64::URL_SAFE_NO_PAD).unwrap();
/// let hmac_key = ::ring::hmac::Key::new(::ring::hmac::HMAC_SHA256, &hmac_key_bytes);
///
/// let verifier = min_jwt::verify::ring::HmacKeyVerifier::with_hs256(hmac_key);
/// let verified_jwt = min_jwt::verify(jwt, &verifier)?;
///
/// let header = verified_jwt.decode_header();
/// let claims = verified_jwt.decode_claims();
/// # Ok::<(), min_jwt::Error>(())
/// ```
pub struct HmacKeyVerifier<K, A>
where
    K: HmacKey,
    A: Algorithm,
{
    key: K,
    algorithm: PhantomData<A>,
}

impl<K, A> HmacKeyVerifier<K, A>
where
    K: HmacKey,
    A: Algorithm,
{
    pub fn into_inner(self) -> K {
        self.key
    }
}

impl<K, A> super::Verifier for HmacKeyVerifier<K, A>
where
    K: HmacKey,
    A: Algorithm,
{
    fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
    where
        M: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        self.key.verify(message, signature)
    }
}

impl<K, A> super::private::Private for HmacKeyVerifier<K, A>
where
    K: HmacKey,
    A: Algorithm,
{
}

impl<K> HmacKeyVerifier<K, Hs256>
where
    K: HmacKey,
{
    pub fn with_hs256(key: K) -> HmacKeyVerifier<K, Hs256> {
        Self {
            key,
            algorithm: PhantomData::default(),
        }
    }
}
