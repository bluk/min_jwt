//! Web Crypto API implementation of signers and verifiers.
//!
//! [Web Crypto API][web_crypto] is an API available in JavaScript/browser environments.
//!
//! [web_crypto]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API

use js_sys::{Array, Object};
use serde::Serialize;
use std::iter::FromIterator;
use wasm_bindgen::prelude::*;
use web_sys::{CryptoKey, SubtleCrypto};

use crate::{error::Error, keys::jwk::Jwk, Algorithm};

pub mod verifier;

pub(crate) enum KeyUsage {
    Sign,
    Verify,
}

impl KeyUsage {
    #[inline]
    fn import_usage(&self) -> Array {
        match self {
            Self::Sign => Array::from_iter([JsValue::from_str("sign")].iter()),
            Self::Verify => Array::from_iter([JsValue::from_str("verify")].iter()),
        }
    }
}

fn jwk_data_object(jwk: &Jwk) -> Object {
    let js_value = JsValue::from_serde(jwk).unwrap();
    Object::from(js_value)
}

pub(crate) trait WebCryptoAlgorithm {
    fn import_algorithm(&self) -> Object;

    fn sign_algorithm(&self) -> Object;

    fn verify_algorithm(&self) -> Object;
}

#[cfg(feature = "serde_json")]
impl WebCryptoAlgorithm for super::Algorithm {
    fn import_algorithm(&self) -> Object {
        // TODO: Avoid use of serde

        match self {
            Self::Es256 => {
                #[derive(Serialize)]
                #[serde(rename_all = "camelCase")]
                struct ImportEcKeyType<'a> {
                    name: &'a str,
                    named_curve: &'a str,
                }

                let key_type = ImportEcKeyType {
                    name: "ECDSA",
                    named_curve: "P-256",
                };
                let key_type_js_value = JsValue::from_serde(&key_type).unwrap();
                Object::from(key_type_js_value)
            }
            Self::Rs256 => {
                #[derive(Serialize)]
                #[serde(rename_all = "camelCase")]
                struct ImportRsaPkcs1Type<'a> {
                    name: &'a str,
                    hash: &'a str,
                }

                let key_type = ImportRsaPkcs1Type {
                    name: "RSASSA-PKCS1-v1_5",
                    hash: "SHA-256",
                };
                let key_type_js_value = JsValue::from_serde(&key_type).unwrap();
                Object::from(key_type_js_value)
            }
        }
    }

    fn sign_algorithm(&self) -> Object {
        // TODO: Avoid use of serde

        match self {
            Self::Es256 => {
                #[derive(Serialize)]
                #[serde(rename_all = "camelCase")]
                struct VerifyEcdsaParamsType<'a> {
                    name: &'a str,
                    hash: &'a str,
                }

                let key_type = VerifyEcdsaParamsType {
                    name: "ECDSA",
                    hash: "SHA-256",
                };
                let key_type_js_value = JsValue::from_serde(&key_type).unwrap();
                Object::from(key_type_js_value)
            }
            Self::Rs256 => {
                todo!()
            }
        }
    }

    fn verify_algorithm(&self) -> Object {
        // TODO: Avoid use of serde

        match self {
            Self::Es256 => {
                #[derive(Serialize)]
                #[serde(rename_all = "camelCase")]
                struct VerifyEcdsaParamsType<'a> {
                    name: &'a str,
                    hash: &'a str,
                }

                let key_type = VerifyEcdsaParamsType {
                    name: "ECDSA",
                    hash: "SHA-256",
                };
                let key_type_js_value = JsValue::from_serde(&key_type).unwrap();
                Object::from(key_type_js_value)
            }
            Self::Rs256 => {
                #[derive(Serialize)]
                #[serde(rename_all = "camelCase")]
                struct VerifyRsaPkcs1Type<'a> {
                    name: &'a str,
                }

                let key_type = VerifyRsaPkcs1Type {
                    name: "RSASSA-PKCS1-v1_5",
                };
                let key_type_js_value = JsValue::from_serde(&key_type).unwrap();
                Object::from(key_type_js_value)
            }
        }
    }
}

pub(crate) async fn import_jwk<'a, 'b>(
    subtle_crypto: &'a SubtleCrypto,
    jwk: &'b Jwk,
    algorithm: Algorithm,
    key_usages: KeyUsage,
) -> Result<CryptoKey, Error> {
    debug_assert_eq!(algorithm, jwk.algorithm().unwrap());
    let import_key_promise = subtle_crypto
        .import_key_with_object(
            "jwk",
            &jwk_data_object(jwk),
            &algorithm.import_algorithm(),
            false,
            &key_usages.import_usage(),
        )
        .map_err(Error::key_rejected)?;
    Ok(CryptoKey::from(
        wasm_bindgen_futures::JsFuture::from(import_key_promise)
            .await
            .map_err(Error::key_rejected)?,
    ))
}
