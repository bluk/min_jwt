//! JSON Web Keys.
//!
//! Keys described in a standard JSON format.
//!
//! See [RFC 7517][rfc_7517].
//!
//! [rfc_7517]: https://tools.ietf.org/html/rfc7517

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{Algorithm, Error, Header, UnverifiedJwt};

pub(crate) const USAGE_SIGN: &str = "sig";

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

    // RSA Private
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub d: Option<String>,

    // RSA Primes
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub p: Option<String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub q: Option<String>,

    // RSA Exponents
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub dp: Option<String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub dq: Option<String>,
    // RSA Co-efficient
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub qi: Option<String>,
}

impl Jwk {
    pub(crate) fn algorithm(&self) -> Result<Algorithm, Error> {
        use core::str::FromStr;

        if let Some(alg) = self.alg.as_ref() {
            Algorithm::from_str(alg)
        } else {
            Err(Error::unknown_algorithm())
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
    /// Returns all of the keys used for signing.
    pub fn signing_keys(&self) -> impl Iterator<Item = &Jwk> {
        self.keys
            .iter()
            .filter(|&key| key.r#use.as_deref() == Some(USAGE_SIGN))
    }

    /// Uses a JWT's header's algorithm and key id values to find a JWK.
    #[cfg(feature = "serde_json")]
    pub fn find_signing_key(&self, jwt: &UnverifiedJwt) -> Option<&Jwk> {
        let header = jwt.decode_header().ok()?;
        let header = serde_json::from_slice::<Header>(&header).ok()?;
        let alg = header.alg;
        let kid = header.kid;

        self.signing_keys().find(|&jwk| {
            alg.is_some() && jwk.alg.as_deref() == alg && kid.is_some() && jwk.kid.as_deref() == kid
        })
    }
}
