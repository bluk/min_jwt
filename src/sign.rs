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

impl private::Private for &[u8] {}
impl Signature for &[u8] {}

impl private::Private for String {}
impl Signature for String {}

impl private::Private for &str {}
impl Signature for &str {}

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

#[cfg(feature = "web_crypto")]
pub mod web_crypto {
    use js_sys::Uint8Array;
    use web_sys::{CryptoKey, SubtleCrypto};

    use crate::{
        error::Error,
        keys::jwk::{Jwk, USAGE_SIGN},
        web_crypto::WebCryptoAlgorithm,
        Algorithm,
    };

    /// A key used to sign JWTs.
    #[derive(Debug)]
    pub struct Signer<'a> {
        subtle_crypto: &'a SubtleCrypto,
        algorithm: Algorithm,
        crypto_key: CryptoKey,
    }

    impl<'a> Signer<'a> {
        /// Imports a JWK via the `SubtleCrypto` API.
        pub async fn with_jwk<'b>(
            subtle_crypto: &'a SubtleCrypto,
            jwk: &Jwk,
        ) -> Result<Signer<'a>, Error> {
            if let Some(usage) = jwk.r#use.as_deref() {
                if usage != USAGE_SIGN {
                    return Err(Error::key_rejected());
                }
            }

            let algorithm = jwk.algorithm().map_err(|_| Error::key_rejected())?;
            let crypto_key = crate::web_crypto::import_jwk(
                subtle_crypto,
                jwk,
                algorithm,
                crate::web_crypto::KeyUsage::Sign,
            )
            .await?;
            Ok(Signer {
                subtle_crypto,
                crypto_key,
                algorithm,
            })
        }

        /// Returns the algorithm of the underlying key.
        pub fn algorithm(&self) -> Algorithm {
            self.algorithm
        }

        /// Serializes the types to JSON, base64 encodes the JSON, constructs the signing input, signs the data, and then
        /// returns the JWT.
        ///
        /// # Errors
        ///
        /// The function may return an error variant because the key pair is invalid.
        #[cfg(all(feature = "serde", feature = "serde_json"))]
        #[inline]
        pub async fn encode_and_sign<H, C>(&self, header: H, claims: C) -> Result<String, Error>
        where
            H: crate::Header + serde::Serialize,
            C: crate::Claims + serde::Serialize,
        {
            let header = serde_json::to_vec(&header).unwrap();
            let claims = serde_json::to_vec(&claims).unwrap();
            self.encode_and_sign_json(header, claims).await
        }

        /// Base64 encodes the JSON, constructs the signing input, signs the data, and then
        /// returns the JWT.
        ///
        /// # Errors
        ///
        /// The function may return an error variant because the key pair is invalid.
        #[inline]
        pub async fn encode_and_sign_json<H, C>(
            &self,
            header: H,
            claims: C,
        ) -> Result<String, Error>
        where
            H: AsRef<[u8]>,
            C: AsRef<[u8]>,
        {
            let encoded_header = base64::encode_config(header, base64::URL_SAFE_NO_PAD);
            let encoded_claims = base64::encode_config(claims, base64::URL_SAFE_NO_PAD);
            let data_to_sign = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");

            let signed_data_promise = self
                .subtle_crypto
                .sign_with_object_and_u8_array(
                    &self.algorithm.sign_algorithm(),
                    &self.crypto_key,
                    &mut data_to_sign.clone().into_bytes(),
                )
                .map_err(|_| Error::key_rejected())?;
            let signed_data_array_buffer =
                wasm_bindgen_futures::JsFuture::from(signed_data_promise)
                    .await
                    .map_err(|_| Error::key_rejected())?;
            let signature = base64::encode_config(
                &Uint8Array::new(&signed_data_array_buffer).to_vec(),
                base64::URL_SAFE_NO_PAD,
            );

            let signature = base64::encode_config(&signature, base64::URL_SAFE_NO_PAD);

            Ok([data_to_sign, signature].join("."))
        }
    }
}
