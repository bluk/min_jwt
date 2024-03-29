//! `p256` crate Verifier implementation.
//!
//! # Supported Algorithms
//!
//! | Algorithm | Type | Wrapper Type |
//! | --------- | ---- | ------------ |
//! | es256     | [`::p256::ecdsa::VerifyingKey`] | N/A |
//!
//! # Examples
//!
//! ## PKCS8
//!
//! The `pem` feature on the `p256` dependency must be enabled.
//!
//! ```
//! # let jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.t2IAtoWoX5iMaIXJmOELc_LY-B8YxlsgkCsEKso_qvYgg0DR6_Q1pZO6SVeOTLFhgDFku9l_cIoL1A6js5rhjw";
//! use ::p256::pkcs8::DecodePublicKey;
//!
//! let public_key =
//! "-----BEGIN PUBLIC KEY-----
//! MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEerEk+zqoG1oYBLD3ohuz0tzIlU7X
//! zFG1098HcCOu0CmVAsp8ZLYXqYD3ts6+j0CV/I2yfzwx/ojBrm+Z/pSQnA==
//! -----END PUBLIC KEY-----";
//!
//! let public_key = ::p256::PublicKey::from_public_key_pem(public_key).unwrap();
//! let verifying_key = ::p256::ecdsa::VerifyingKey::from(public_key);
//!
//! let verified_jwt = min_jwt::verify(jwt, &verifying_key)?;
//!
//! let header = verified_jwt.decode_header();
//! let claims = verified_jwt.decode_claims();
//! # Ok::<(), min_jwt::Error>(())
//! ```
//!
//! ## JWK
//!
//! The `jwk` feature on the `p256` dependency must be enabled.
//!
//! ```
//! # let jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.t2IAtoWoX5iMaIXJmOELc_LY-B8YxlsgkCsEKso_qvYgg0DR6_Q1pZO6SVeOTLFhgDFku9l_cIoL1A6js5rhjw";
//!
//! let jwk = r#"
//! {
//!     "kty": "EC",
//!     "crv": "P-256",
//!     "x": "erEk-zqoG1oYBLD3ohuz0tzIlU7XzFG1098HcCOu0Ck",
//!     "y": "lQLKfGS2F6mA97bOvo9AlfyNsn88Mf6Iwa5vmf6UkJw"
//! }
//! "#;
//!
//! let public_key = ::p256::PublicKey::from_jwk_str(jwk).unwrap();
//! let verifying_key = ::p256::ecdsa::VerifyingKey::from(public_key);
//!
//! let verified_jwt = min_jwt::verify(jwt, &verifying_key)?;
//!
//! let header = verified_jwt.decode_header();
//! let claims = verified_jwt.decode_claims();
//! # Ok::<(), min_jwt::Error>(())
//! ```

use crate::error::{Error, Result};

impl super::Verifier for ::p256::ecdsa::VerifyingKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let signature = ::p256::ecdsa::Signature::try_from(signature)
            .map_err(|_| Error::invalid_signature())?;
        ::p256::ecdsa::signature::Verifier::verify(self, message, &signature)
            .map_err(|_| Error::invalid_signature())
    }
}
