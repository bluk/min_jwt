//! `rsa` crate Signer implementation.
//!
//! # Supported Algorithms
//!
//! | Algorithm | Type | Wrapper Type |
//! | --------- | ---- | ------------ |
//! | rs256     | [::rsa::RsaPrivateKey] | [RsaPrivateKeySigner] |
//!
//! Note that you will also need the `sha2` feature enabled.
//!
//! # Examples
//!
//! ## PKCS8
//!
//! The `pem` feature on the `rsa` dependency must be enabled.
//!
//! See the [::rsa::pkcs8::FromPrivateKey] trait for more methods.
//!
//! ```
//! # let header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
//! # let claims = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\",\"iat\":1516239022}";
//! use rsa::pkcs8::FromPrivateKey;
//!
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
//! let private_key = ::rsa::RsaPrivateKey::from_pkcs8_pem(&private_key).unwrap();
//! let signer = min_jwt::sign::rsa::RsaPrivateKeySigner::with_rs256(&private_key);
//! let jwt = min_jwt::encode_and_sign(header, claims, &signer)?;
//! # assert_eq!("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.BV5tgihZQo_CCSJuwSmespFnUPVcE1tZ52td6wYfB6j-YuKanRuHD4hJZPO-fN2GYe492aU4FDFVqVqC3cZcv5sZgkZolPgAhXVlQymw___vmvcodWv7xLjZBr4INpzb4FPUkaNhAd1LvF28CXHx0aNvoyyOo4i_AR1ZYBk6CbsCrVj7XxdsVmP3VBpXLSFKcit0FrWBs_sP0-g2qQDIKZ5w9HNiv4H3fU5NZ_TNKRKIQkwMJ1hvI_JbacIZ9uk2oYZ6LwV_NMeh0EqIwRg1EsH6TcdXhzLRozVa1fbej9hd2-AOGxZTba3LQtBAEKbyEATd7N5mqtEsRvcTHzXJmw", jwt);
//! # Ok::<(), min_jwt::Error>(())
//! ```
use core::marker::PhantomData;

use crate::{algorithm::Algorithm, error::Result};

use super::Signature;

/// Types which can sign a digest.
pub trait PrivateKey: private::Private {
    type Signature: Signature;

    fn sign<B>(&self, padding: ::rsa::PaddingScheme, bytes: B) -> Result<Self::Signature>
    where
        B: AsRef<[u8]>;
}

mod private {
    pub trait Private {}
    impl<T> Private for &T where T: Private {}
}

impl<T> PrivateKey for &T
where
    T: PrivateKey,
{
    type Signature = T::Signature;

    fn sign<B>(&self, padding: ::rsa::PaddingScheme, bytes: B) -> Result<Self::Signature>
    where
        B: AsRef<[u8]>,
    {
        T::sign(self, padding, bytes)
    }
}

impl PrivateKey for ::rsa::RsaPrivateKey {
    type Signature = Vec<u8>;

    fn sign<B>(&self, padding: ::rsa::PaddingScheme, bytes: B) -> Result<Self::Signature>
    where
        B: AsRef<[u8]>,
    {
        ::rsa::RsaPrivateKey::sign(self, padding, bytes.as_ref()).map_err(|_| todo!())
    }
}

impl private::Private for ::rsa::RsaPrivateKey {}

/// Wrapper for [::rsa::RsaPrivateKey].
///
/// # Examples
///
/// ## PKCS8
///
/// ```
/// # let header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
/// # let claims = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\",\"iat\":1516239022}";
/// use rsa::pkcs8::FromPrivateKey;
///
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
/// let private_key = ::rsa::RsaPrivateKey::from_pkcs8_pem(&private_key).unwrap();
/// let signer = min_jwt::sign::rsa::RsaPrivateKeySigner::with_rs256(&private_key);
/// let jwt = min_jwt::encode_and_sign(header, claims, &signer)?;
/// # assert_eq!("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.BV5tgihZQo_CCSJuwSmespFnUPVcE1tZ52td6wYfB6j-YuKanRuHD4hJZPO-fN2GYe492aU4FDFVqVqC3cZcv5sZgkZolPgAhXVlQymw___vmvcodWv7xLjZBr4INpzb4FPUkaNhAd1LvF28CXHx0aNvoyyOo4i_AR1ZYBk6CbsCrVj7XxdsVmP3VBpXLSFKcit0FrWBs_sP0-g2qQDIKZ5w9HNiv4H3fU5NZ_TNKRKIQkwMJ1hvI_JbacIZ9uk2oYZ6LwV_NMeh0EqIwRg1EsH6TcdXhzLRozVa1fbej9hd2-AOGxZTba3LQtBAEKbyEATd7N5mqtEsRvcTHzXJmw", jwt);
/// # Ok::<(), min_jwt::Error>(())
/// ```
#[derive(Debug)]
pub struct RsaPrivateKeySigner<K, A>
where
    K: PrivateKey,
    A: Algorithm,
{
    key: K,
    alg: PhantomData<A>,
}

impl<K, A> super::private::Private for RsaPrivateKeySigner<K, A>
where
    K: PrivateKey,
    A: Algorithm,
{
}

impl<K, A> RsaPrivateKeySigner<K, A>
where
    K: PrivateKey,
    A: Algorithm,
{
    pub fn into_inner(self) -> K {
        self.key
    }
}

#[cfg(feature = "sha2")]
impl<K> RsaPrivateKeySigner<K, crate::algorithm::Rs256>
where
    K: PrivateKey,
{
    pub fn with_rs256(key: K) -> Self {
        Self {
            key,
            alg: PhantomData::default(),
        }
    }
}

#[cfg(feature = "sha2")]
impl<K> super::Signer for RsaPrivateKeySigner<K, crate::algorithm::Rs256>
where
    K: PrivateKey,
{
    type Signature = K::Signature;

    fn sign(&self, bytes: &[u8]) -> Result<Self::Signature> {
        use sha2::{Digest, Sha256};

        self.key.sign(
            ::rsa::PaddingScheme::new_pkcs1v15_sign(Some(::rsa::Hash::SHA2_256)),
            Sha256::digest(bytes),
        )
    }
}
