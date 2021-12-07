//! JSON Web Keys.
//!
//! Keys described in a standard JSON format.
//!
//! See [RFC 7517][rfc_7517].
//!
//! [rfc_7517]: https://tools.ietf.org/html/rfc7517

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{Algorithm, ParseAlgorithmError};

/// A JSON Web Key.
///
/// See [RFC 7517][rfc_7517].
///
/// [rfc_7517]: https://tools.ietf.org/html/rfc7517
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Jwk {
    pub kty: String,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub r#use: Option<String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub alg: Option<String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub kid: Option<String>,

    // EC
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub crv: Option<String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub x: Option<String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub y: Option<String>,

    // RSA
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub e: Option<String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub n: Option<String>,
}

impl Jwk {
    pub(crate) fn algorithm(&self) -> Result<Algorithm, ParseAlgorithmError> {
        use core::str::FromStr;

        if let Some(alg) = self.alg.as_ref() {
            Algorithm::from_str(alg)
        } else {
            Err(ParseAlgorithmError::UnknownAlgorithm)
        }
    }
}

/// A JSON Web Key set.
///
/// See [RFC 7517][rfc_7517].
///
/// [rfc_7517]: https://tools.ietf.org/html/rfc7517
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    pub fn signing_keys(&self) -> impl Iterator<Item = &Jwk> {
        self.keys
            .iter()
            .filter(|&key| key.r#use.as_deref() == Some("sig"))
    }
}
