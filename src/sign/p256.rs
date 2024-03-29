//! `p256` crate Signer implementation.
//!
//! # Supported Algorithms
//!
//! | Algorithm | Type | Wrapper Type |
//! | --------- | ---- | ------------ |
//! | es256     | [`::p256::ecdsa::Signature`] | N/A |
//!
//! # Examples
//!
//! ## PKCS8
//!
//! The `pem` feature on the `p256` dependency must be enabled.
//!
//! ```
//! # let header = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
//! # let claims = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\",\"iat\":1516239022}";
//! use ::p256::pkcs8::DecodePrivateKey;
//!
//! let private_key =
//! "-----BEGIN PRIVATE KEY-----
//! MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8UmkmK0KO64KCDRZ
//! b4RCAHRZ0AfRWBn3Pv6hTv1VR9mhRANCAAR6sST7OqgbWhgEsPeiG7PS3MiVTtfM
//! UbXT3wdwI67QKZUCynxkthepgPe2zr6PQJX8jbJ/PDH+iMGub5n+lJCc
//! -----END PRIVATE KEY-----";
//!
//! let secret_key = ::p256::SecretKey::from_pkcs8_pem(&private_key).unwrap();
//! let signing_key = ::p256::ecdsa::SigningKey::from(secret_key);
//!
//! let jwt = min_jwt::encode_and_sign(header.as_bytes(), claims.as_bytes(), &signing_key)?;
//! # assert_eq!("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.t2IAtoWoX5iMaIXJmOELc_LY-B8YxlsgkCsEKso_qvYgg0DR6_Q1pZO6SVeOTLFhgDFku9l_cIoL1A6js5rhjw", jwt);
//! # Ok::<(), min_jwt::Error>(())
//! ```
//!
//! ## JWK
//!
//! The `jwk` feature on the `p256` dependency must be enabled.
//!
//! ```
//! # let header = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
//! # let claims = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\",\"iat\":1516239022}";
//! let jwk = r#"
//! {
//!     "kty": "EC",
//!     "crv": "P-256",
//!     "x": "erEk-zqoG1oYBLD3ohuz0tzIlU7XzFG1098HcCOu0Ck",
//!     "y": "lQLKfGS2F6mA97bOvo9AlfyNsn88Mf6Iwa5vmf6UkJw",
//!     "d": "8UmkmK0KO64KCDRZb4RCAHRZ0AfRWBn3Pv6hTv1VR9k"
//! }
//! "#;
//!
//! let secret_key = ::p256::SecretKey::from_jwk_str(jwk).unwrap();
//! let signing_key = ::p256::ecdsa::SigningKey::from(secret_key);
//!
//! let jwt = min_jwt::encode_and_sign(header.as_bytes(), claims.as_bytes(), &signing_key)?;
//! # assert_eq!("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.t2IAtoWoX5iMaIXJmOELc_LY-B8YxlsgkCsEKso_qvYgg0DR6_Q1pZO6SVeOTLFhgDFku9l_cIoL1A6js5rhjw", jwt);
//! # Ok::<(), min_jwt::Error>(())
//! ```

/// An ECDSA P-256 signature.
#[derive(Debug)]
pub struct Signature([u8; 64]);

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl super::Signature for Signature {}

impl super::Signer for ::p256::ecdsa::SigningKey {
    type Signature = Signature;

    type Error = ();

    fn sign(&self, bytes: &[u8]) -> Result<Self::Signature, Self::Error> {
        let signature: ::p256::ecdsa::Signature =
            ::p256::ecdsa::signature::Signer::sign(self, bytes);
        let signature_bytes = signature.to_bytes();
        let mut bytes: [u8; 64] = [0; 64];
        bytes.copy_from_slice(&signature_bytes);
        Ok(Signature(bytes))
    }
}
