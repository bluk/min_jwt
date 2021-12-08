//! Web Crypto API implementation of signers and verifiers.
//!
//! [Web Crypto API][web_crypto] is an API available in JavaScript/browser environments.
//!
//! [web_crypto]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API

use js_sys::{Array, Object, Uint8Array};
use serde::Serialize;
use std::iter::FromIterator;
use wasm_bindgen::prelude::*;
use web_sys::{CryptoKey, SubtleCrypto};

use crate::{
    error::Error,
    keys::{jwk::Jwk, pkcs8::Pkcs8Key},
    Algorithm,
};

pub mod verifier;

enum KeyUsages {
    Verify,
}

impl KeyUsages {
    #[inline]
    fn import_usage(&self) -> Array {
        match self {
            Self::Verify => Array::from_iter([JsValue::from_str("verify")].iter()),
        }
    }
}

fn pkcs8_data_object(bytes: &[u8]) -> Object {
    use regex::Regex;

    let header_re = Regex::new(r"-+BEGIN.+-+").unwrap();
    let footer_re = Regex::new(r"-+END.+-+").unwrap();

    let key_data = String::from_utf8(bytes.to_vec())
        .expect("PKCS8 formatted data can be converted to UTF-8 string")
        .lines()
        .filter(|line| !header_re.is_match(line) && !footer_re.is_match(line))
        .collect::<Vec<&str>>()
        .join("");
    // TODO: Use JavaScript window.atob() instead of base64?
    let b64_decoded_key =
        base64::decode_config(&key_data[..], base64::STANDARD).expect("base64::decode failed");
    Object::from(Uint8Array::from(b64_decoded_key.as_slice()).buffer())
}

fn jwk_data_object(jwk: &Jwk) -> Object {
    let js_value = JsValue::from_serde(jwk).unwrap();
    Object::from(js_value)
}

trait WebCryptoAlgorithm {
    fn import_algorithm(&self) -> Object;

    fn verify_algorithm(&self) -> Object;
}

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

async fn import_jwk_key<'a, 'b>(
    subtle_crypto: &'a SubtleCrypto,
    jwk: &'b Jwk,
    algorithm: Algorithm,
    key_usages: KeyUsages,
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

async fn import_pkcs8_key<'a, 'b>(
    subtle_crypto: &'a SubtleCrypto,
    pkcs8_key: &'b Pkcs8Key<'b>,
    key_usages: KeyUsages,
) -> Result<CryptoKey, Error> {
    let import_key_promise = subtle_crypto
        .import_key_with_object(
            "pkcs8",
            &pkcs8_data_object(pkcs8_key.data),
            &pkcs8_key.algorithm.import_algorithm(),
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
