//! Signs a JWT.

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use web_sys::{CryptoKey, SubtleCrypto};

use crate::{
    error::Error,
    keys::{
        jwk::{Jwk, USAGE_SIGN},
        pkcs8::Pkcs8Key,
    },
    Algorithm,
};

use super::WebCryptoAlgorithm;

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
                return Err(Error::key_rejected(JsValue::from_str("invalid usage")));
            }
        }

        let algorithm = jwk
            .algorithm()
            .map_err(|_| Error::key_rejected(JsValue::from_str("unknown alg")))?;
        let crypto_key =
            super::import_jwk(subtle_crypto, jwk, algorithm, super::KeyUsage::Sign).await?;
        Ok(Signer {
            subtle_crypto,
            crypto_key,
            algorithm,
        })
    }

    /// Imports a Pkcs8 key via the `SubtleCrypto` API.
    pub async fn with_pkcs8<'b>(
        subtle_crypto: &'a SubtleCrypto,
        pkcs8: &Pkcs8Key,
    ) -> Result<Signer<'a>, Error> {
        let crypto_key = super::import_pkcs8(subtle_crypto, pkcs8, super::KeyUsage::Sign).await?;
        Ok(Signer {
            subtle_crypto,
            crypto_key,
            algorithm: pkcs8.algorithm,
        })
    }

    /// Returns the algorithm of the underlying key.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Base64 encodes the JSON, constructs the signing input, signs the data, and then
    /// returns the JWT.
    ///
    /// # Errors
    ///
    /// The function may return an error variant because the key pair is invalid.
    #[inline]
    pub async fn encode_and_sign_json_str(
        &self,
        header: &str,
        claims: &str,
    ) -> Result<String, Error> {
        self.encode_and_sign_json_bytes(header.as_bytes(), claims.as_bytes())
            .await
    }

    /// Base64 encodes the JSON, constructs the signing input, signs the data, and then
    /// returns the JWT.
    ///
    /// # Errors
    ///
    /// The function may return an error variant because the key pair is invalid.
    #[inline]
    pub async fn encode_and_sign_json_bytes(
        &self,
        header: &[u8],
        claims: &[u8],
    ) -> Result<String, Error> {
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
            .map_err(Error::key_rejected)?;
        let signed_data_array_buffer = wasm_bindgen_futures::JsFuture::from(signed_data_promise)
            .await
            .map_err(Error::key_rejected)?;
        let signature = base64::encode_config(
            &Uint8Array::new(&signed_data_array_buffer).to_vec(),
            base64::URL_SAFE_NO_PAD,
        );

        let signature = base64::encode_config(&signature, base64::URL_SAFE_NO_PAD);

        Ok([data_to_sign, signature].join("."))
    }
}
