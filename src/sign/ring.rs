//! `ring` crate Signer implementation.
//!
//! # Supported Algorithms
//!
//! | Algorithm | Type | Wrapper Type |
//! | --------- | ---- | ------------ |
//! | es256     | [::ring::signature::EcdsaKeyPair] | [EcdsaKeyPairSigner] |
//! | hs256     | [::ring::hmac::Key]               | [HmacKeySigner] |
//! | rs256     | [::ring::signature::RsaKeyPair]   | [RsaKeyPairSigner] |
//!
//! # Examples
//!
//! ## ES256 PKCS8
//!
//! ```
//! # let header = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
//! # let claims = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\",\"iat\":1516239022}";
//! # fn convert_pkcs8_pem_to_der(private_key: &str) -> impl AsRef<[u8]> {
//! #   use ::p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
//! #   let secret_key = ::p256::SecretKey::from_pkcs8_pem(&private_key).unwrap();
//! #   secret_key.to_pkcs8_der().unwrap()
//! # }
//! let private_key =
//! "-----BEGIN PRIVATE KEY-----
//! MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8UmkmK0KO64KCDRZ
//! b4RCAHRZ0AfRWBn3Pv6hTv1VR9mhRANCAAR6sST7OqgbWhgEsPeiG7PS3MiVTtfM
//! UbXT3wdwI67QKZUCynxkthepgPe2zr6PQJX8jbJ/PDH+iMGub5n+lJCc
//! -----END PRIVATE KEY-----";
//!
//! // Convert the PKCS8 PEM to DER
//! let private_key = convert_pkcs8_pem_to_der(private_key);
//!
//! let private_key = ::ring::signature::EcdsaKeyPair::from_pkcs8(
//!   &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
//!   private_key.as_ref(),
//! ).unwrap();
//! let secure_random = ::ring::rand::SystemRandom::new();
//!
//! let signer = min_jwt::sign::ring::EcdsaKeyPairSigner::with_es256(
//!   private_key,
//!   secure_random
//! );
//! let jwt = min_jwt::encode_and_sign(header, claims, &signer)?;
//! # use ::p256::pkcs8::DecodePublicKey;
//! # let public_key =
//! # "-----BEGIN PUBLIC KEY-----
//! # MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEerEk+zqoG1oYBLD3ohuz0tzIlU7X
//! # zFG1098HcCOu0CmVAsp8ZLYXqYD3ts6+j0CV/I2yfzwx/ojBrm+Z/pSQnA==
//! # -----END PUBLIC KEY-----";
//! #
//! # let public_key = ::p256::PublicKey::from_public_key_pem(public_key).unwrap();
//! # let verifying_key = ::p256::ecdsa::VerifyingKey::from(public_key);
//! #
//! # let result = min_jwt::verify(&jwt, &verifying_key)?;
//! # Ok::<(), min_jwt::Error>(())
//! ```
//!
//! ## HS256
//!
//! ```
//! # let header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
//! # let claims = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\",\"iat\":1516239022}";
//! # let encoded_hmac_key: &str =
//! # "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
//! # let hmac_key_bytes = ::base64::decode_config(encoded_hmac_key, base64::URL_SAFE_NO_PAD).unwrap();
//! let hmac_key = ::ring::hmac::Key::new(::ring::hmac::HMAC_SHA256, &hmac_key_bytes);
//!
//! let signer = min_jwt::sign::ring::HmacKeySigner::with_hs256(hmac_key);
//! let jwt = min_jwt::encode_and_sign(header, claims, &signer)?;
//! # assert_eq!("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.tAzkR2NyvqGKrIras8IDsoczvrYWD0gAM3E6H5qGZVg", jwt);
//! # Ok::<(), min_jwt::Error>(())
//! ```
//!
//! ## RS256 PKCS8
//!
//! ```
//! # let header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
//! # let claims = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\",\"iat\":1516239022}";
//! # fn convert_pkcs8_pem_to_der(private_key: &str) -> impl AsRef<[u8]> {
//! #   use rsa::pkcs8::{ToPrivateKey, FromPrivateKey};
//! #   let private_key = ::rsa::RsaPrivateKey::from_pkcs8_pem(&private_key).unwrap();
//! #   private_key.to_pkcs8_der().unwrap()
//! # }
//! let private_key =
//! "-----BEGIN PRIVATE KEY-----
//! MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJ8SJJvYSWrKXI
//! B9aRtXQmYrDNpgfYm1aLTl0QusalIj44zaY2YWenFlVRTHvsZYBIP678RsOkHtPG
//! gvzBbqtIW525Mhvre6Gp6KWSPpWGk9dUulmDqbySisBc8Zo3kEExPIEBulaT17vb
//! PmA4ZoUYjjE6/S/c3QxfaH25cm+E9Ok50qfqNcR+VQUXz05YYSH/cmfJltfmnz4X
//! wEC6x5vyB+mpPYK3opPkas2IDt0/CM3tcW9We/JiBHv5BdNU1EytysRSgltHgMb5
//! BV7IhGHQkape2b3TVy+I8FFuJwgyfZ/yp+zXlcxJ4dauB6XbUK/XBCHcjjHL6yhm
//! 5lnaL+nPAgMBAAECggEAbv/LIAs68PMvILcmOuspT9wZYMBtOaOQu3u0bfisLaKX
//! 3vMy9Fsv9UiyVsCasULNc2kFzwc6jGCheVEQi2ZAYcJx/JTNge9v2gvVzn/2AoYK
//! 6ziO8W8ABvCbcbsfUIFLRDwEkSWSZytCx+0OSJIZgHjQGKOIhnc+UMcHrEJ5h/N4
//! teVo/6JOJkvBJOKCIQKt8Y1tjmjX7cNjhYP5+1SgkwyDJqm2G0l2BRgttWvgDeQ2
//! ACibNYOIWj71Gmtup4gVqYwWxNgcIFkrz24dxe4yI53ieLHBk4bOJenJ+OeEKQjY
//! boN4lDqQgCiwjowe8B+vbSpvmHiTwsPm7ASpZN6eSQKBgQDirgvjnHL81rmrXqod
//! Msod/Yn4SD8Jc9TC3e1L8wh6LBSnj/SVdziUOo+NOHoJ9mcTDKjAAfDgmKHbAoKJ
//! RDP1BuHX0uyIkdC5AIoLkm9QAf3qKPNwrRMwKqWw0qbbiY6FAIbcKF/YFETjDB8V
//! CBVQGvuPJlsp8lipdv8/tlQkzQKBgQDkD/NgIRRmgO0sIxtSI5KwJfT6VyJc1NLm
//! jp25c9IfEWSZdzhywXN9qomKkCs34tBkexlKx01Oph7Jdepntry3sVu4m08QK9NC
//! Z97i++TYCCeIBZoLwolRPO8IFqAq803h3QCENDAZnP+Fl7Z7dgZa443Z9n3C/755
//! OVhSMWOpCwKBgQDMVR+aeTid+eE8PQUTdOkEx7tK97T7DFLJpct2HwmRN5MWyIkt
//! Al8aHv+vyS0ZNegMH+kty5IaovujtEt++N/tC9sg9Z0KLob7fSTy8Xktod4E6g0n
//! kJwvWwIotnp6gzDZa3QlmK9s1DiUgiSyjKrJnskMbQLYeQC7Ie1MvUp0MQKBgQCy
//! +1WsRqnE/D+mGPMzFlnjxhYpdcKxChFuAdUEm0H3QeYqjqcNYIbrw6/nv9c7J9UW
//! Vol1503jgHm+77yDoqUeoKF0EucMsOg+QFhq2PczF8s2c/b+bbDowaJyPZd7vbCM
//! pq3mEzMAlvbt+C+tWuYH5HgJ6+ms5JqudnO7JamqGwKBgGcDDTdxmOm4YX5G1wiE
//! Lafrn9dXK31D7quBNl2j6p3hV+vhIYitwSP/VbZgTG4q9CpuFD7TMn2wycKzFmFq
//! urcMnLLy5lKPBVegcd9144Z11WDzraFESvBRqfSWEVTTLXDBDo0XfHQPnCSpfPlN
//! 4eEjZ7+NQEVHHG2ZVHFCcMBv
//! -----END PRIVATE KEY-----";
//!
//! // Convert the PKCS8 PEM to DER
//! let private_key = convert_pkcs8_pem_to_der(private_key);
//!
//! let private_key = ::ring::signature::RsaKeyPair::from_pkcs8(
//!   private_key.as_ref()
//! ).unwrap();
//! let secure_random = ::ring::rand::SystemRandom::new();
//!
//! let signer = min_jwt::sign::ring::RsaKeyPairSigner::with_rs256(
//!   private_key,
//!   secure_random
//! );
//! let jwt = min_jwt::encode_and_sign(header, claims, &signer)?;
//! # assert_eq!("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.BV5tgihZQo_CCSJuwSmespFnUPVcE1tZ52td6wYfB6j-YuKanRuHD4hJZPO-fN2GYe492aU4FDFVqVqC3cZcv5sZgkZolPgAhXVlQymw___vmvcodWv7xLjZBr4INpzb4FPUkaNhAd1LvF28CXHx0aNvoyyOo4i_AR1ZYBk6CbsCrVj7XxdsVmP3VBpXLSFKcit0FrWBs_sP0-g2qQDIKZ5w9HNiv4H3fU5NZ_TNKRKIQkwMJ1hvI_JbacIZ9uk2oYZ6LwV_NMeh0EqIwRg1EsH6TcdXhzLRozVa1fbej9hd2-AOGxZTba3LQtBAEKbyEATd7N5mqtEsRvcTHzXJmw", jwt);
//! # Ok::<(), min_jwt::Error>(())
//! ```

use super::Signature;
use crate::{
    algorithm::{Algorithm, Es256, Hs256, Rs256},
    error::{Error, Result},
};
use ::ring::rand::SecureRandom;
use core::marker::PhantomData;
use ring::signature::EcdsaKeyPair;

impl Signature for ::ring::signature::Signature {}
impl super::private::Private for ::ring::signature::Signature {}
impl Signature for ::ring::hmac::Tag {}
impl super::private::Private for ::ring::hmac::Tag {}

mod private {
    pub trait Private {}
    impl<T> Private for &T where T: Private {}
}

pub trait EcdsaKey: private::Private {
    type Signature: Signature;

    fn sign<B>(&self, secure_random: &dyn SecureRandom, bytes: B) -> Result<Self::Signature>
    where
        B: AsRef<[u8]>;
}

impl<T> EcdsaKey for &T
where
    T: EcdsaKey,
{
    type Signature = T::Signature;

    fn sign<B>(&self, secure_random: &dyn SecureRandom, bytes: B) -> Result<Self::Signature>
    where
        B: AsRef<[u8]>,
    {
        T::sign(self, secure_random, bytes)
    }
}

impl private::Private for ::ring::signature::EcdsaKeyPair {}

impl EcdsaKey for ::ring::signature::EcdsaKeyPair {
    type Signature = ::ring::signature::Signature;

    fn sign<B>(&self, secure_random: &dyn SecureRandom, bytes: B) -> Result<Self::Signature>
    where
        B: AsRef<[u8]>,
    {
        EcdsaKeyPair::sign(self, secure_random, bytes.as_ref()).map_err(|_| todo!())
    }
}

/// Wrapper for [::ring::signature::EcdsaKeyPair].
///
/// # Examples
///
/// ## ES256 PKCS8
///
/// ```
/// # let header = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
/// # let claims = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\",\"iat\":1516239022}";
/// # fn convert_pkcs8_pem_to_der(private_key: &str) -> impl AsRef<[u8]> {
/// #   use ::p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
/// #   let secret_key = ::p256::SecretKey::from_pkcs8_pem(&private_key).unwrap();
/// #   secret_key.to_pkcs8_der().unwrap()
/// # }
/// let private_key =
/// "-----BEGIN PRIVATE KEY-----
/// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8UmkmK0KO64KCDRZ
/// b4RCAHRZ0AfRWBn3Pv6hTv1VR9mhRANCAAR6sST7OqgbWhgEsPeiG7PS3MiVTtfM
/// UbXT3wdwI67QKZUCynxkthepgPe2zr6PQJX8jbJ/PDH+iMGub5n+lJCc
/// -----END PRIVATE KEY-----";
///
/// // Convert the PKCS8 PEM to DER
/// let private_key = convert_pkcs8_pem_to_der(private_key);
///
/// let private_key = ::ring::signature::EcdsaKeyPair::from_pkcs8(
///   &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
///   private_key.as_ref(),
/// ).unwrap();
/// let secure_random = ::ring::rand::SystemRandom::new();
///
/// let signer = min_jwt::sign::ring::EcdsaKeyPairSigner::with_es256(
///   private_key,
///   secure_random
/// );
/// let jwt = min_jwt::encode_and_sign(header, claims, &signer)?;
/// # use ::p256::pkcs8::DecodePublicKey;
/// # let public_key =
/// # "-----BEGIN PUBLIC KEY-----
/// # MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEerEk+zqoG1oYBLD3ohuz0tzIlU7X
/// # zFG1098HcCOu0CmVAsp8ZLYXqYD3ts6+j0CV/I2yfzwx/ojBrm+Z/pSQnA==
/// # -----END PUBLIC KEY-----";
/// #
/// # let public_key = ::p256::PublicKey::from_public_key_pem(public_key).unwrap();
/// # let verifying_key = ::p256::ecdsa::VerifyingKey::from(public_key);
/// #
/// # let result = min_jwt::verify(&jwt, &verifying_key)?;
/// # Ok::<(), min_jwt::Error>(())
/// ```
#[derive(Debug)]
pub struct EcdsaKeyPairSigner<K, R, A>
where
    K: EcdsaKey,
    R: SecureRandom,
    A: Algorithm,
{
    key_pair: K,
    secure_random: R,
    algorithm: PhantomData<A>,
}

impl<K, R, A> super::private::Private for EcdsaKeyPairSigner<K, R, A>
where
    K: EcdsaKey,
    R: SecureRandom,
    A: Algorithm,
{
}

impl<K, R, A> EcdsaKeyPairSigner<K, R, A>
where
    K: EcdsaKey,
    R: SecureRandom,
    A: Algorithm,
{
    pub fn into_inner(self) -> (K, R) {
        (self.key_pair, self.secure_random)
    }
}

impl<K, R> EcdsaKeyPairSigner<K, R, Es256>
where
    K: EcdsaKey,
    R: SecureRandom,
{
    pub fn with_es256(key_pair: K, secure_random: R) -> EcdsaKeyPairSigner<K, R, Es256> {
        Self {
            key_pair,
            secure_random,
            algorithm: PhantomData::default(),
        }
    }
}

impl<K, R, A> super::Signer for EcdsaKeyPairSigner<K, R, A>
where
    K: EcdsaKey,
    R: SecureRandom,
    A: Algorithm,
{
    type Signature = K::Signature;

    fn sign(&self, bytes: &[u8]) -> Result<Self::Signature> {
        self.key_pair.sign(&self.secure_random, bytes)
    }
}

pub trait HmacKey: private::Private {
    type Signature: Signature;

    fn sign<B>(&self, bytes: B) -> Result<Self::Signature>
    where
        B: AsRef<[u8]>;
}

impl<T> HmacKey for &T
where
    T: HmacKey,
{
    type Signature = T::Signature;

    fn sign<B>(&self, bytes: B) -> Result<Self::Signature>
    where
        B: AsRef<[u8]>,
    {
        T::sign(self, bytes)
    }
}

impl HmacKey for ::ring::hmac::Key {
    type Signature = ::ring::hmac::Tag;

    fn sign<B>(&self, bytes: B) -> Result<Self::Signature>
    where
        B: AsRef<[u8]>,
    {
        Ok(::ring::hmac::sign(self, bytes.as_ref()))
    }
}
impl private::Private for ::ring::hmac::Key {}

/// Wrapper for [::ring::hmac::Key].
///
/// # Examples
///
/// ## HS256
/// ```
/// # let header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
/// # let claims = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\",\"iat\":1516239022}";
/// # let encoded_hmac_key: &str =
/// # "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
/// # let hmac_key_bytes = ::base64::decode_config(encoded_hmac_key, base64::URL_SAFE_NO_PAD).unwrap();
/// let hmac_key = ::ring::hmac::Key::new(::ring::hmac::HMAC_SHA256, &hmac_key_bytes);
///
/// let signer = min_jwt::sign::ring::HmacKeySigner::with_hs256(hmac_key);
/// let jwt = min_jwt::encode_and_sign(header, claims, &signer);
/// # Ok::<(), min_jwt::Error>(())
/// ```
pub struct HmacKeySigner<K, A>
where
    K: HmacKey,
    A: Algorithm,
{
    key: K,
    algorithm: PhantomData<A>,
}

impl<K, A> super::private::Private for HmacKeySigner<K, A>
where
    K: HmacKey,
    A: Algorithm,
{
}

impl<K, A> HmacKeySigner<K, A>
where
    K: HmacKey,
    A: Algorithm,
{
    pub fn into_inner(self) -> K {
        self.key
    }
}

impl<K, A> super::Signer for HmacKeySigner<K, A>
where
    K: HmacKey,
    A: Algorithm,
{
    type Signature = K::Signature;

    fn sign(&self, bytes: &[u8]) -> Result<Self::Signature> {
        self.key.sign(bytes)
    }
}

impl<K> HmacKeySigner<K, Hs256>
where
    K: HmacKey,
{
    pub fn with_hs256(key: K) -> HmacKeySigner<K, Hs256> {
        Self {
            key,
            algorithm: PhantomData::default(),
        }
    }
}

pub trait RsaKey: private::Private {
    type Signature: Signature;

    fn sign<B>(&self, secure_random: &dyn SecureRandom, bytes: B) -> Result<Self::Signature>
    where
        B: AsRef<[u8]>;
}

impl<T> RsaKey for &T
where
    T: RsaKey,
{
    type Signature = T::Signature;

    fn sign<B>(&self, secure_random: &dyn SecureRandom, bytes: B) -> Result<Self::Signature>
    where
        B: AsRef<[u8]>,
    {
        T::sign(self, secure_random, bytes)
    }
}

impl RsaKey for ::ring::signature::RsaKeyPair {
    type Signature = Vec<u8>;

    fn sign<B>(&self, secure_random: &dyn SecureRandom, bytes: B) -> Result<Self::Signature>
    where
        B: AsRef<[u8]>,
    {
        let mut signature = vec![0; self.public_modulus_len()];
        ::ring::signature::RsaKeyPair::sign(
            self,
            &ring::signature::RSA_PKCS1_SHA256,
            secure_random,
            bytes.as_ref(),
            &mut signature,
        )
        .map_err(|_| Error::invalid_signature())?;
        Ok(signature)
    }
}
impl private::Private for ::ring::signature::RsaKeyPair {}

/// Wrapper for [::ring::signature::RsaKeyPair].
///
/// # Examples
///
/// ## RS256 PKCS8
///
/// ```
/// # let header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
/// # let claims = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\",\"iat\":1516239022}";
/// # fn convert_pkcs8_pem_to_der(private_key: &str) -> impl AsRef<[u8]> {
/// #   use rsa::pkcs8::{ToPrivateKey, FromPrivateKey};
/// #   let private_key = ::rsa::RsaPrivateKey::from_pkcs8_pem(&private_key).unwrap();
/// #   private_key.to_pkcs8_der().unwrap()
/// # }
/// let private_key =
/// "-----BEGIN PRIVATE KEY-----
/// MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJ8SJJvYSWrKXI
/// B9aRtXQmYrDNpgfYm1aLTl0QusalIj44zaY2YWenFlVRTHvsZYBIP678RsOkHtPG
/// gvzBbqtIW525Mhvre6Gp6KWSPpWGk9dUulmDqbySisBc8Zo3kEExPIEBulaT17vb
/// PmA4ZoUYjjE6/S/c3QxfaH25cm+E9Ok50qfqNcR+VQUXz05YYSH/cmfJltfmnz4X
/// wEC6x5vyB+mpPYK3opPkas2IDt0/CM3tcW9We/JiBHv5BdNU1EytysRSgltHgMb5
/// BV7IhGHQkape2b3TVy+I8FFuJwgyfZ/yp+zXlcxJ4dauB6XbUK/XBCHcjjHL6yhm
/// 5lnaL+nPAgMBAAECggEAbv/LIAs68PMvILcmOuspT9wZYMBtOaOQu3u0bfisLaKX
/// 3vMy9Fsv9UiyVsCasULNc2kFzwc6jGCheVEQi2ZAYcJx/JTNge9v2gvVzn/2AoYK
/// 6ziO8W8ABvCbcbsfUIFLRDwEkSWSZytCx+0OSJIZgHjQGKOIhnc+UMcHrEJ5h/N4
/// teVo/6JOJkvBJOKCIQKt8Y1tjmjX7cNjhYP5+1SgkwyDJqm2G0l2BRgttWvgDeQ2
/// ACibNYOIWj71Gmtup4gVqYwWxNgcIFkrz24dxe4yI53ieLHBk4bOJenJ+OeEKQjY
/// boN4lDqQgCiwjowe8B+vbSpvmHiTwsPm7ASpZN6eSQKBgQDirgvjnHL81rmrXqod
/// Msod/Yn4SD8Jc9TC3e1L8wh6LBSnj/SVdziUOo+NOHoJ9mcTDKjAAfDgmKHbAoKJ
/// RDP1BuHX0uyIkdC5AIoLkm9QAf3qKPNwrRMwKqWw0qbbiY6FAIbcKF/YFETjDB8V
/// CBVQGvuPJlsp8lipdv8/tlQkzQKBgQDkD/NgIRRmgO0sIxtSI5KwJfT6VyJc1NLm
/// jp25c9IfEWSZdzhywXN9qomKkCs34tBkexlKx01Oph7Jdepntry3sVu4m08QK9NC
/// Z97i++TYCCeIBZoLwolRPO8IFqAq803h3QCENDAZnP+Fl7Z7dgZa443Z9n3C/755
/// OVhSMWOpCwKBgQDMVR+aeTid+eE8PQUTdOkEx7tK97T7DFLJpct2HwmRN5MWyIkt
/// Al8aHv+vyS0ZNegMH+kty5IaovujtEt++N/tC9sg9Z0KLob7fSTy8Xktod4E6g0n
/// kJwvWwIotnp6gzDZa3QlmK9s1DiUgiSyjKrJnskMbQLYeQC7Ie1MvUp0MQKBgQCy
/// +1WsRqnE/D+mGPMzFlnjxhYpdcKxChFuAdUEm0H3QeYqjqcNYIbrw6/nv9c7J9UW
/// Vol1503jgHm+77yDoqUeoKF0EucMsOg+QFhq2PczF8s2c/b+bbDowaJyPZd7vbCM
/// pq3mEzMAlvbt+C+tWuYH5HgJ6+ms5JqudnO7JamqGwKBgGcDDTdxmOm4YX5G1wiE
/// Lafrn9dXK31D7quBNl2j6p3hV+vhIYitwSP/VbZgTG4q9CpuFD7TMn2wycKzFmFq
/// urcMnLLy5lKPBVegcd9144Z11WDzraFESvBRqfSWEVTTLXDBDo0XfHQPnCSpfPlN
/// 4eEjZ7+NQEVHHG2ZVHFCcMBv
/// -----END PRIVATE KEY-----";
///
/// // Convert the PKCS8 PEM to DER
/// let private_key = convert_pkcs8_pem_to_der(private_key);
///
/// let private_key = ::ring::signature::RsaKeyPair::from_pkcs8(
///   private_key.as_ref()
/// ).unwrap();
/// let secure_random = ::ring::rand::SystemRandom::new();
///
/// let signer = min_jwt::sign::ring::RsaKeyPairSigner::with_rs256(
///   private_key,
///   secure_random
/// );
/// let jwt = min_jwt::encode_and_sign(header, claims, &signer)?;
/// # assert_eq!("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.BV5tgihZQo_CCSJuwSmespFnUPVcE1tZ52td6wYfB6j-YuKanRuHD4hJZPO-fN2GYe492aU4FDFVqVqC3cZcv5sZgkZolPgAhXVlQymw___vmvcodWv7xLjZBr4INpzb4FPUkaNhAd1LvF28CXHx0aNvoyyOo4i_AR1ZYBk6CbsCrVj7XxdsVmP3VBpXLSFKcit0FrWBs_sP0-g2qQDIKZ5w9HNiv4H3fU5NZ_TNKRKIQkwMJ1hvI_JbacIZ9uk2oYZ6LwV_NMeh0EqIwRg1EsH6TcdXhzLRozVa1fbej9hd2-AOGxZTba3LQtBAEKbyEATd7N5mqtEsRvcTHzXJmw", jwt);
/// # Ok::<(), min_jwt::Error>(())
/// ```
#[derive(Debug)]
pub struct RsaKeyPairSigner<K, R, A>
where
    K: RsaKey,
    R: SecureRandom,
    A: Algorithm,
{
    key_pair: K,
    secure_random: R,
    alg: PhantomData<A>,
}

impl<K, R, A> super::private::Private for RsaKeyPairSigner<K, R, A>
where
    K: RsaKey,
    R: SecureRandom,
    A: Algorithm,
{
}

impl<K, R, A> RsaKeyPairSigner<K, R, A>
where
    K: RsaKey,
    R: SecureRandom,
    A: Algorithm,
{
    pub fn into_inner(self) -> (K, R) {
        (self.key_pair, self.secure_random)
    }
}

impl<K, R, A> super::Signer for RsaKeyPairSigner<K, R, A>
where
    K: RsaKey,
    R: SecureRandom,
    A: Algorithm,
{
    type Signature = K::Signature;

    fn sign(&self, bytes: &[u8]) -> Result<Self::Signature> {
        self.key_pair.sign(&self.secure_random, bytes)
    }
}

impl<K, R> RsaKeyPairSigner<K, R, Rs256>
where
    K: RsaKey,
    R: SecureRandom,
{
    /// Signs header and claims parts with an RSA key.
    pub fn with_rs256(key_pair: K, secure_random: R) -> RsaKeyPairSigner<K, R, Rs256> {
        Self {
            key_pair,
            secure_random,
            alg: PhantomData::<Rs256>::default(),
        }
    }
}
