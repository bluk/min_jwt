//! `ring` crate Signer implementation.
//!
//! # Supported Algorithms
//!
//! | Algorithm | Type | Wrapper Type |
//! | --------- | ---- | ------------ |
//! | rs256     | [::ring::signature::RsaKeyPair] | [RsaKeyPairSigner] |
//!
//! # Examples
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
//! // The private key must be formatted without extra spaces or new lines.
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
//! // Convert the PKCS8 PEM data to PKCS8 DER formatting
//! let private_key = convert_pkcs8_pem_to_der(private_key);
//!
//! let private_key = ::ring::signature::RsaKeyPair::from_pkcs8(private_key.as_ref()).unwrap();
//! let secure_random = ::ring::rand::SystemRandom::new();
//! let signer = min_jwt::sign::ring::RsaKeyPairSigner::with_rs256(private_key, secure_random);
//! let jwt = min_jwt::encode_and_sign(header, claims, &signer)?;
//! # assert_eq!("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.BV5tgihZQo_CCSJuwSmespFnUPVcE1tZ52td6wYfB6j-YuKanRuHD4hJZPO-fN2GYe492aU4FDFVqVqC3cZcv5sZgkZolPgAhXVlQymw___vmvcodWv7xLjZBr4INpzb4FPUkaNhAd1LvF28CXHx0aNvoyyOo4i_AR1ZYBk6CbsCrVj7XxdsVmP3VBpXLSFKcit0FrWBs_sP0-g2qQDIKZ5w9HNiv4H3fU5NZ_TNKRKIQkwMJ1hvI_JbacIZ9uk2oYZ6LwV_NMeh0EqIwRg1EsH6TcdXhzLRozVa1fbej9hd2-AOGxZTba3LQtBAEKbyEATd7N5mqtEsRvcTHzXJmw", jwt);
//! # Ok::<(), min_jwt::Error>(())
//! ```
use crate::{
    algorithm::{Algorithm, Rs256},
    error::{Error, Result},
};
use core::marker::PhantomData;
use ring::rand::SecureRandom;

impl super::Signature for ::ring::signature::Signature {}
impl super::private::Private for ::ring::signature::Signature {}
impl super::Signature for ::ring::hmac::Tag {}
impl super::private::Private for ::ring::hmac::Tag {}

#[derive(Debug)]
pub struct EcdsaKeyPairSigner<R>
where
    R: SecureRandom,
{
    key_pair: ::ring::signature::EcdsaKeyPair,
    secure_random: R,
}

impl<R> super::private::Private for EcdsaKeyPairSigner<R> where R: SecureRandom {}

impl<R> EcdsaKeyPairSigner<R>
where
    R: SecureRandom,
{
    /// Signs header and claims parts with an ECDSA key.
    ///
    /// ```
    /// # use min_jwt::Error;
    /// #
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::sign::ring::EcdsaKeyPairSigner;
    /// use ring::{rand::SystemRandom};
    ///
    /// let sys_rand = SystemRandom::new();
    ///
    /// let header = String::from("{\"alg\":\"ES256\",\"typ\":\"JWT\"}");
    /// let claims = String::from("{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true,\"iat\":1516239022}");
    ///
    /// // Normally the key's bytes are read from a file or another data store
    /// // and should not be randomly generated on every invocation
    /// let pkcs8_bytes = ::ring::signature::EcdsaKeyPair::generate_pkcs8(
    ///   &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
    ///   &sys_rand
    /// )?;
    /// let key_pair = ::ring::signature::EcdsaKeyPair::from_pkcs8(
    ///   &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
    ///   pkcs8_bytes.as_ref()
    /// )?;
    ///
    /// let signing_key = EcdsaKeyPairSigner::with_key_pair_and_random(key_pair, sys_rand);
    ///
    /// /* the header and claims could be serialized by Serde */
    /// /* in the end, the serialized JSON should be referenced as either &str or &[u8] */
    ///
    /// let jwt = min_jwt::encode_and_sign(&header, &claims, &signing_key)?;
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn with_key_pair_and_random(
        key_pair: ::ring::signature::EcdsaKeyPair,
        secure_random: R,
    ) -> EcdsaKeyPairSigner<R> {
        Self {
            key_pair,
            secure_random,
        }
    }

    pub fn into_inner(self) -> (::ring::signature::EcdsaKeyPair, R) {
        (self.key_pair, self.secure_random)
    }
}

impl<R> super::Signer for EcdsaKeyPairSigner<R>
where
    R: SecureRandom,
{
    type Signature = ring::signature::Signature;

    fn sign(&self, bytes: &[u8]) -> Result<Self::Signature> {
        self.key_pair
            .sign(&self.secure_random, bytes)
            .map_err(|_| todo!())
    }
}

impl super::private::Private for ::ring::hmac::Key {}

impl super::Signer for ::ring::hmac::Key {
    type Signature = ::ring::hmac::Tag;

    fn sign(&self, bytes: &[u8]) -> Result<Self::Signature> {
        Ok(::ring::hmac::sign(self, bytes))
    }
}

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
/// // The private key must be formatted without extra spaces or new lines.
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
/// // Convert the PKCS8 PEM data to PKCS8 DER formatting
/// let private_key = convert_pkcs8_pem_to_der(private_key);
///
/// let private_key = ::ring::signature::RsaKeyPair::from_pkcs8(private_key.as_ref()).unwrap();
/// let secure_random = ::ring::rand::SystemRandom::new();
/// let signer = min_jwt::sign::ring::RsaKeyPairSigner::with_rs256(private_key, secure_random);
/// let jwt = min_jwt::encode_and_sign(header, claims, &signer)?;
/// # assert_eq!("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.BV5tgihZQo_CCSJuwSmespFnUPVcE1tZ52td6wYfB6j-YuKanRuHD4hJZPO-fN2GYe492aU4FDFVqVqC3cZcv5sZgkZolPgAhXVlQymw___vmvcodWv7xLjZBr4INpzb4FPUkaNhAd1LvF28CXHx0aNvoyyOo4i_AR1ZYBk6CbsCrVj7XxdsVmP3VBpXLSFKcit0FrWBs_sP0-g2qQDIKZ5w9HNiv4H3fU5NZ_TNKRKIQkwMJ1hvI_JbacIZ9uk2oYZ6LwV_NMeh0EqIwRg1EsH6TcdXhzLRozVa1fbej9hd2-AOGxZTba3LQtBAEKbyEATd7N5mqtEsRvcTHzXJmw", jwt);
/// # Ok::<(), min_jwt::Error>(())
/// ```
#[derive(Debug)]
pub struct RsaKeyPairSigner<R, A>
where
    R: SecureRandom,
    A: Algorithm,
{
    key_pair: ::ring::signature::RsaKeyPair,
    secure_random: R,
    alg: PhantomData<A>,
}

impl<R, A> super::private::Private for RsaKeyPairSigner<R, A>
where
    R: SecureRandom,
    A: Algorithm,
{
}

impl<R, A> RsaKeyPairSigner<R, A>
where
    R: SecureRandom,
    A: Algorithm,
{
    pub fn into_inner(self) -> (::ring::signature::RsaKeyPair, R) {
        (self.key_pair, self.secure_random)
    }
}

macro_rules! rsa_impl {
    ($alg:ty, $alg_str:expr, $ring_alg:expr) => {
        impl<R> super::Signer for RsaKeyPairSigner<R, $alg>
        where
            R: SecureRandom,
        {
            type Signature = Vec<u8>;

            fn sign(&self, bytes: &[u8]) -> Result<Self::Signature> {
                let mut signature = vec![0; self.key_pair.public_modulus_len()];
                self.key_pair
                    .sign(&$ring_alg, &self.secure_random, bytes, &mut signature)
                    .map_err(|_| Error::invalid_signature())?;
                Ok(signature)
            }
        }
    };
}

rsa_impl!(Rs256, "RS256", ring::signature::RSA_PKCS1_SHA256);

impl<R> RsaKeyPairSigner<R, Rs256>
where
    R: SecureRandom,
{
    /// Signs header and claims parts with an RSA key.
    pub fn with_rs256(
        key_pair: ::ring::signature::RsaKeyPair,
        secure_random: R,
    ) -> RsaKeyPairSigner<R, Rs256> {
        Self {
            key_pair,
            secure_random,
            alg: PhantomData::<Rs256>::default(),
        }
    }
}
