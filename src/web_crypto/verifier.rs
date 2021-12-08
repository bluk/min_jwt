//! Verify various types of signatures for a JWT.

use wasm_bindgen::prelude::*;
use web_sys::{CryptoKey, SubtleCrypto};

use crate::{
    error::Error,
    keys::jwk::{Jwk, USAGE_SIGN},
    Algorithm, SignatureVerifiedJwt, UnverifiedJwt,
};

use super::WebCryptoAlgorithm;

/// A key used to verify JWT signatures.
#[derive(Debug)]
pub struct VerifyingKey<'a> {
    subtle_crypto: &'a SubtleCrypto,
    algorithm: Algorithm,
    crypto_key: CryptoKey,
}

impl<'a> VerifyingKey<'a> {
    /// Returns the algorithm of the underlying key.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Attempts to verify signed data with a base64 decoded signature.
    ///
    /// This function is available for debugging purposes.
    ///
    /// # Errors
    ///
    /// If the public key or signature is invalid, the function will return an error variant.
    pub async fn verify_data_with_decoded_signature(
        &self,
        signed_data: &mut [u8],
        decoded_signature: &mut [u8],
    ) -> Result<(), Error> {
        let verify_promise = self
            .subtle_crypto
            .verify_with_object_and_u8_array_and_u8_array(
                &self.algorithm.verify_algorithm(),
                &self.crypto_key,
                decoded_signature,
                signed_data,
            )
            .map_err(|_| Error::invalid_signature())?;
        let value = wasm_bindgen_futures::JsFuture::from(verify_promise)
            .await
            .map_err(|_| Error::invalid_signature())?;
        if value.as_bool() == Some(true) {
            Ok(())
        } else {
            Err(Error::invalid_signature())
        }
    }

    /// Attempts to verify a JWT's signature.
    ///
    /// # Errors
    ///
    /// If the public key or signature is invalid, the function will return an error variant.
    pub async fn verify<'b>(
        &self,
        unverified_jwt: &'b UnverifiedJwt<'b>,
    ) -> Result<SignatureVerifiedJwt<'b>, Error> {
        let mut signed_data = unverified_jwt.signed_data().as_bytes().to_vec();
        let mut decoded_signature = unverified_jwt.decode_signature()?;

        self.verify_data_with_decoded_signature(&mut signed_data, &mut decoded_signature)
            .await
            .map(|_| SignatureVerifiedJwt { unverified_jwt })
    }
}

/// Imports a JWK key via the `SubtleCrypto` API.
pub async fn import_jwk_key<'a, 'b>(
    subtle_crypto: &'a SubtleCrypto,
    jwk: &Jwk,
) -> Result<VerifyingKey<'a>, Error> {
    if let Some(usage) = jwk.r#use.as_deref() {
        if usage != USAGE_SIGN {
            return Err(Error::key_rejected(JsValue::from_str("invalid usage")));
        }
    }

    let algorithm = jwk
        .algorithm()
        .map_err(|_| Error::key_rejected(JsValue::from_str("unknown alg")))?;
    let crypto_key =
        super::import_jwk_key(subtle_crypto, jwk, algorithm, super::KeyUsages::Verify).await?;
    Ok(VerifyingKey {
        subtle_crypto,
        crypto_key,
        algorithm,
    })
}
