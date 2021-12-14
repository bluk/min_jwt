//! # Minimal JWT
//!
//! JSON Web Tokens are a method for representing claims between two parties.
//!
//! They are used in authentication flows with a third party provider (e.g.
//! Sign in with...) amongst other scenarios.
//!
//! This crate provides functionality to sign and verify the signatures of
//! JWTs.
//!
//! ## Cryptography Features/Dependencies
//!
//! This crate depends on other crates for all cryptographic operations.
//! Find a supported crypto crate below which supports the algorithms required.
//!
//! | Dependent Crate(s)       | Algorithm(s) Supported | Feature(s)
//! | ------------------       | ---------------------- | ----------
//! | [p256][p256]             | ES256                  | p256
//! | [ring][ring]             | ES256, HS256, RS256    | ring
//! | [rsa][rsa], [sha2][sha2] | RS256                  | rsa, sha2
//!
//! For instance, if you need `ES256` support, you may choose to use the `p256`
//! crate and/or the `ring` crate.  Suppose you chose the `p256` crate. In your
//! crate, depend on this crate and the relevant dependent crate in your
//! `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! min_jwt = { version = "0.2.0", features = [ "p256", "serde", "serde_json"] }
//! p256 = { version = "0.9.0", features = [ "ecdsa", "jwk", "pem"] }
//! ```
//!
//! Be sure to enable the relevant features as well.
//!
//! When choosing a cryptography implementation, you may want to consider
//! compatibility with your environment, the ability to import the signing and
//! verifying keys in the given formats, and the security properties of the
//! code (e.g. an audited implementation, resistence to timing attacks, etc.).
//!
//! ## Usage
//!
//! The [encode_and_sign] and [verify][fn@verify] functions are the primary functions for this crate.
//!
//! To use the functions, construct the cryptography crate's key. The
//! cryptography crate may provide methods to import a key in PKCS8 PEM, PKCS8
//! DER, JSON Web Key (JWK), and other formats.
//!
//! Then, use the key as either a [sign::Signer] or [verify::Verifier]
//! parameter. The key may need to be wrapped in a provided type.
//! See the [sign] or [verify][mod@verify] modules for more documentation and examples.
//!
//! ## Examples
//!
//! # Sign using ES256 with `p256` crate
//!
//! ```
//! # let header = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
//! # let claims = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\",\"iat\":1516239022}";
//! use p256::elliptic_curve::pkcs8::FromPrivateKey;
//!
//! // The private key must be formatted without extra spaces or new lines.
//! let private_key =
//! "-----BEGIN PRIVATE KEY-----
//! MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8UmkmK0KO64KCDRZ
//! b4RCAHRZ0AfRWBn3Pv6hTv1VR9mhRANCAAR6sST7OqgbWhgEsPeiG7PS3MiVTtfM
//! UbXT3wdwI67QKZUCynxkthepgPe2zr6PQJX8jbJ/PDH+iMGub5n+lJCc
//! -----END PRIVATE KEY-----";
//!
//! let secret_key = ::p256::SecretKey::from_pkcs8_pem(&private_key).unwrap();
//! let signing_key = ::p256::ecdsa::SigningKey::from(secret_key);
//! let jwt = min_jwt::encode_and_sign(header, claims, &signing_key)?;
//! # Ok::<(), min_jwt::Error>(())
//! ```
//!
//! [p256]: https://github.com/RustCrypto/elliptic-curves
//! [ring]: https://github.com/briansmith/ring
//! [rsa]: https://github.com/RustCrypto/RSA
//! [rust_crypto]: https://github.com/RustCrypto
//! [sha2]: https://github.com/RustCrypto/hashes

pub use error::Error;

pub mod algorithm;
mod error;
pub mod keys;
pub mod sign;
pub mod time;
pub mod verify;
#[cfg(feature = "web_crypto")]
pub mod web_crypto;

use error::Result;

/// Represents an unverified JSON Web Token.
///
/// An unverified JWT token may or may not contain valid data. The type attempts basic parsing of
/// the JWT and provides methods to attempt to get the decoded contents.
///
/// After constructing an instance of this type, a developer could decode the header to determine
/// what to do with the JWT.
///
/// ```
/// # use min_jwt::Error;
/// #
/// # fn try_main() -> Result<(), Error> {
/// use min_jwt::UnverifiedJwt;
///
/// let jwt_str = String::from("\
/// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
/// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
/// ");
/// let unverified_jwt = UnverifiedJwt::with_str(&jwt_str)?;
///
/// /* if need to read the header */
/// let decoded_header = unverified_jwt.decode_header()?;
///
/// assert_eq!(String::from_utf8(decoded_header).unwrap(), "{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
///
/// /* use Serde or other library to deserialize the decoded header into a custom type */
///
/// /* check the header to determine the algorithm used to sign the JWT */
///
/// /* use a verifier from the min_jwt::verifier package to verify the JWT signature */
///
/// #   Ok(())
/// # }
/// # fn main() {
/// #   try_main().unwrap();
/// # }
/// ```
#[derive(Debug)]
pub struct UnverifiedJwt<'a> {
    /// The encoded header part.
    header: &'a str,
    /// The encoded claims part.
    claims: &'a str,
    /// The encoded header part + "." + encoded claims part.
    signed_data: &'a str,
    /// The encoded signature.
    signature: &'a str,
}

#[derive(Debug)]
struct SplitJwt<'a> {
    header: &'a str,
    claims: &'a str,
    signed_data: &'a str,
    signature: &'a str,
}

impl<'a> core::convert::TryFrom<&'a str> for UnverifiedJwt<'a> {
    type Error = crate::error::Error;

    fn try_from(value: &'a str) -> Result<Self> {
        let split_jwt = Self::split(value)?;
        Ok(UnverifiedJwt {
            header: split_jwt.header,
            claims: split_jwt.claims,
            signed_data: split_jwt.signed_data,
            signature: split_jwt.signature,
        })
    }
}

impl<'a> UnverifiedJwt<'a> {
    /// Attempts to construct an `UnverifiedJwt`.
    ///
    /// Only basic parsing is done with this method, so, even if an `UnverifiedJwt` is successfully
    /// returned, the JWT may contain invalid data (e.g any of the parts may not be correctly
    /// base64 encoded).
    ///
    /// # Errors
    ///
    /// The function may return an error variant because the string slice is an invalid JWT string.
    ///
    /// ```
    /// # use min_jwt::Error;
    /// #
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    ///
    /// let jwt_str = String::from("\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ");
    /// let unverified_jwt = UnverifiedJwt::with_str(&jwt_str)?;
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn with_str(jwt: &str) -> Result<UnverifiedJwt> {
        let split_jwt = Self::split(jwt)?;
        Ok(UnverifiedJwt {
            header: split_jwt.header,
            claims: split_jwt.claims,
            signed_data: split_jwt.signed_data,
            signature: split_jwt.signature,
        })
    }

    /// Decodes the header part by parsing the JWT for the header and base64 decoding the header.
    ///
    /// # Errors
    ///
    /// If the header part is not correctly base64 encoded, the function will return an error variant.
    ///
    /// ```
    /// # use min_jwt::Error;
    /// #
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    ///
    /// let jwt_str = String::from("\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ");
    /// let unverified_jwt = UnverifiedJwt::with_str(&jwt_str)?;
    ///
    /// let decoded_header = unverified_jwt.decode_header()?;
    ///
    /// assert_eq!(String::from_utf8(decoded_header).unwrap(), "{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    ///
    /// /* use Serde or other library to deserialize the decoded header */
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn decode_header(&self) -> Result<Vec<u8>> {
        Ok(base64::decode_config(
            &self.header,
            base64::URL_SAFE_NO_PAD,
        )?)
    }

    // Currently not pub. Should a SignatureVerifiedJwt be required before looking at the claims?
    /// Decodes the claims part by parsing the JWT for the claims and base64 decoding the claims.
    ///
    /// # Errors
    ///
    /// If the claims part is not correctly base64 encoded, the function will return an error variant.
    fn decode_claims(&self) -> Result<Vec<u8>> {
        Ok(base64::decode_config(
            &self.claims,
            base64::URL_SAFE_NO_PAD,
        )?)
    }

    /// Decodes the signature part by parsing the JWT for the signature and base64 decoding the
    /// signature.
    ///
    /// # Errors
    ///
    /// If the signature part is not correctly base64 encoded, the function will return an error variant.
    ///
    /// ```
    /// # use min_jwt::Error;
    /// #
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    ///
    /// let jwt_str = String::from("\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ");
    /// let unverified_jwt = UnverifiedJwt::with_str(&jwt_str)?;
    ///
    /// let decoded_signature = unverified_jwt.decode_signature()?;
    ///
    /// /* use a cryptography library to verify the signed data with the decoded signature */
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn decode_signature(&self) -> Result<Vec<u8>> {
        Ok(base64::decode_config(
            &self.signature,
            base64::URL_SAFE_NO_PAD,
        )?)
    }

    /// Returns the signed data.
    ///
    /// The signed data is the encoded header + "." + encoded claims.
    ///
    /// ```
    /// # use min_jwt::Error;
    /// #
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    ///
    /// let jwt_str = String::from("\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ");
    /// let unverified_jwt = UnverifiedJwt::with_str(&jwt_str)?;
    ///
    /// assert_eq!("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", unverified_jwt.signed_data());
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn signed_data(&self) -> &'a str {
        self.signed_data
    }

    /// Returns the encoded header part.
    ///
    /// Practically, the `decode_header` method is more useful since the returned data from this
    /// method is still base64 encoded.
    ///
    /// The encoded header is available for debugging purposes.
    ///
    /// ```
    /// # use min_jwt::Error;
    /// #
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    ///
    /// let jwt_str = String::from("\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ");
    /// let unverified_jwt = UnverifiedJwt::with_str(&jwt_str)?;
    ///
    /// assert_eq!("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", unverified_jwt.encoded_header());
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn encoded_header(&self) -> &'a str {
        self.header
    }

    /// Returns the encoded signature part.
    ///
    /// Practically, the `decode_signature` method is more useful since the returned data from this
    /// method is still base64 encoded.
    ///
    /// The encoded signature is available for debugging purposes.
    ///
    /// ```
    /// # use min_jwt::Error;
    /// #
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    ///
    /// let jwt_str = String::from("\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ");
    /// let unverified_jwt = UnverifiedJwt::with_str(&jwt_str)?;
    ///
    /// assert_eq!("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", unverified_jwt.encoded_signature());
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn encoded_signature(&self) -> &'a str {
        self.signature
    }

    fn split(jwt: &str) -> Result<SplitJwt<'_>> {
        let mut parts = jwt.rsplitn(2, '.');
        let (signature, signed_data) = match (parts.next(), parts.next()) {
            (Some(signature), Some(signed_data)) => (signature, signed_data),
            _ => return Err(Error::malformed_jwt()),
        };

        let mut parts = signed_data.rsplitn(3, '.');
        let (claims, header) = match (parts.next(), parts.next(), parts.next()) {
            (Some(claims), Some(header), None) => (claims, header),
            _ => return Err(Error::malformed_jwt()),
        };

        Ok(SplitJwt {
            header,
            claims,
            signed_data,
            signature,
        })
    }
}

/// Represents a JSON Web Token which has had its signature verified.
///
/// A signature verified JWT contains signed data which was verified with the included
/// signature. The signed data is the encoded header + "." + encoded claims.
///
/// ```
/// # use min_jwt::Error;
/// #
/// # #[cfg(feature = "ring")]
/// # fn try_main() -> Result<(), Error> {
/// use min_jwt::UnverifiedJwt;
/// use ring::hmac;
///
/// let jwt_str = String::from("\
/// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
/// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
/// ");
/// let unverified_jwt = UnverifiedJwt::with_str(&jwt_str)?;
///
/// let hmac_key_bytes = String::from("your-256-bit-secret").into_bytes();
/// let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);
///
/// let signature_verified_jwt = min_jwt::verify(&unverified_jwt, &hmac_key)?;
///
/// let decoded_claims = signature_verified_jwt.decode_claims()?;
///
/// /* validate claims */
/// #   Ok(())
/// # }
/// # fn main() {
/// #   #[cfg(feature = "ring")]
/// #   try_main().unwrap();
/// # }
/// ```
#[derive(Debug)]
pub struct SignatureVerifiedJwt<'a> {
    unverified_jwt: &'a UnverifiedJwt<'a>,
}

impl<'a> SignatureVerifiedJwt<'a> {
    /// Decodes the header part by parsing the JWT for the header and base64 decoding the header.
    ///
    /// # Errors
    ///
    /// If the header part is not correctly base64 encoded, the function will return an error variant.
    ///
    /// ```
    /// # use min_jwt::Error;
    /// #
    /// # #[cfg(feature = "ring")]
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    /// use ring::hmac;
    ///
    /// let jwt_str = String::from("\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ");
    /// let unverified_jwt = UnverifiedJwt::with_str(&jwt_str)?;
    ///
    /// let hmac_key_bytes = String::from("your-256-bit-secret").into_bytes();
    /// let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);
    ///
    /// let signature_verified_jwt = min_jwt::verify(&unverified_jwt, &hmac_key)?;
    ///
    /// let decoded_header = signature_verified_jwt.decode_header()?;
    ///
    /// assert_eq!(String::from_utf8(decoded_header).unwrap(), "{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   #[cfg(feature = "ring")]
    /// #   try_main().unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn decode_header(&self) -> Result<Vec<u8>> {
        self.unverified_jwt.decode_header()
    }

    /// Decodes the claims part by parsing the JWT for the claims and base64 decoding the claims.
    ///
    /// # Errors
    ///
    /// If the claims part is not correctly base64 encoded, the function will return an error variant.
    ///
    /// ```
    /// # use min_jwt::Error;
    /// #
    /// # #[cfg(feature = "ring")]
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    /// use ring::hmac;
    ///
    /// let jwt_str = String::from("\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ");
    /// let unverified_jwt = UnverifiedJwt::with_str(&jwt_str)?;
    ///
    /// let hmac_key_bytes = String::from("your-256-bit-secret").into_bytes();
    /// let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);
    ///
    /// let signature_verified_jwt = min_jwt::verify(&unverified_jwt, &hmac_key)?;
    ///
    /// let decoded_claims = signature_verified_jwt.decode_claims()?;
    ///
    /// assert_eq!(String::from_utf8(decoded_claims).unwrap(), "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}");
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   #[cfg(feature = "ring")]
    /// #   try_main().unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn decode_claims(&self) -> Result<Vec<u8>> {
        self.unverified_jwt.decode_claims()
    }

    /// Decodes the signature part by parsing the JWT for the signature and base64 decoding the
    /// signature.
    ///
    /// # Errors
    ///
    /// If the signature part is not correctly base64 encoded, the function will return an error variant.
    ///
    /// ```
    /// # use min_jwt::Error;
    /// #
    /// # #[cfg(feature = "ring")]
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    /// use ring::hmac;
    ///
    /// let jwt_str = String::from("\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ");
    /// let unverified_jwt = UnverifiedJwt::with_str(&jwt_str)?;
    ///
    /// let hmac_key_bytes = String::from("your-256-bit-secret").into_bytes();
    /// let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);
    ///
    /// let signature_verified_jwt = min_jwt::verify(&unverified_jwt, &hmac_key)?;
    ///
    /// let decoded_signature = signature_verified_jwt.decode_signature()?;
    ///
    /// /* use a cryptography library to verify the signed data with the decoded signature */
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   #[cfg(feature = "ring")]
    /// #   try_main().unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn decode_signature(&self) -> Result<Vec<u8>> {
        self.unverified_jwt.decode_signature()
    }

    /// Returns the signed data.
    ///
    /// The signed data is the encoded header + "." + encoded claims.
    ///
    /// ```
    /// # use min_jwt::Error;
    /// #
    /// # #[cfg(feature = "ring")]
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    /// use ring::hmac;
    ///
    /// let jwt_str = String::from("\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ");
    /// let unverified_jwt = UnverifiedJwt::with_str(&jwt_str)?;
    ///
    /// let hmac_key_bytes = String::from("your-256-bit-secret").into_bytes();
    /// let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);
    ///
    /// let signature_verified_jwt = min_jwt::verify(&unverified_jwt, &hmac_key)?;
    ///
    /// assert_eq!("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", signature_verified_jwt .signed_data());
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   #[cfg(feature = "ring")]
    /// #   try_main().unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn signed_data(&self) -> &'a str {
        self.unverified_jwt.signed_data()
    }

    /// Returns the encoded header part.
    ///
    /// Practically, the `decode_header` method is more useful since the returned data from this
    /// method is still base64 encoded.
    ///
    /// The encoded header is available for debugging purposes.
    ///
    /// ```
    /// # use min_jwt::Error;
    /// #
    /// # #[cfg(feature = "ring")]
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    /// use ring::hmac;
    ///
    /// let jwt_str = String::from("\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ");
    /// let unverified_jwt = UnverifiedJwt::with_str(&jwt_str)?;
    ///
    /// let hmac_key_bytes = String::from("your-256-bit-secret").into_bytes();
    /// let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);
    ///
    /// let signature_verified_jwt = min_jwt::verify(&unverified_jwt, &hmac_key)?;
    ///
    /// assert_eq!("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", signature_verified_jwt.encoded_header());
    ///
    /// /* use a cryptography library to verify the signed data with the decoded signature */
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   #[cfg(feature = "ring")]
    /// #   try_main().unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn encoded_header(&self) -> &'a str {
        self.unverified_jwt.encoded_header()
    }

    /// Returns the encoded claims part.
    ///
    /// Practically, the `decode_claims` method is more useful since the returned data from this
    /// method is still base64 encoded.
    ///
    /// The encoded claims is available for debugging purposes.
    ///
    ///
    /// ```
    /// # use min_jwt::Error;
    /// #
    /// # #[cfg(feature = "ring")]
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    /// use ring::hmac;
    ///
    /// let jwt_str = String::from("\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ");
    /// let unverified_jwt = UnverifiedJwt::with_str(&jwt_str)?;
    ///
    /// let hmac_key_bytes = String::from("your-256-bit-secret").into_bytes();
    /// let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);
    ///
    /// let signature_verified_jwt = min_jwt::verify(&unverified_jwt, &hmac_key)?;
    ///
    /// assert_eq!("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", signature_verified_jwt.encoded_claims());
    ///
    /// /* use a cryptography library to verify the signed data with the decoded signature */
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   #[cfg(feature = "ring")]
    /// #   try_main().unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn encoded_claims(&self) -> &'a str {
        self.unverified_jwt.claims
    }

    /// Returns the encoded signature part.
    ///
    /// Practically, the `decode_signature` method is more useful since the returned data from this
    /// method is still base64 encoded.
    ///
    /// The encoded signature is available for debugging purposes.
    ///
    /// ```
    /// # use min_jwt::Error;
    /// #
    /// # #[cfg(feature = "ring")]
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    /// use ring::hmac;
    ///
    /// let jwt_str = String::from("\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ");
    /// let unverified_jwt = UnverifiedJwt::with_str(&jwt_str)?;
    ///
    /// let hmac_key_bytes = String::from("your-256-bit-secret").into_bytes();
    /// let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);
    ///
    /// let signature_verified_jwt = min_jwt::verify(&unverified_jwt, &hmac_key)?;
    ///
    /// assert_eq!("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", signature_verified_jwt.encoded_signature());
    ///
    /// /* use a cryptography library to verify the signed data with the decoded signature */
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   #[cfg(feature = "ring")]
    /// #   try_main().unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn encoded_signature(&self) -> &'a str {
        self.unverified_jwt.encoded_signature()
    }
}

/// Algorithm used to sign the JWT.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Algorithm {
    Es256,
    Rs256,
}

impl core::str::FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        match s {
            "ES256" => Ok(Algorithm::Es256),
            "RS256" => Ok(Algorithm::Rs256),
            _ => Err(Error::unsupported_algorithm()),
        }
    }
}

/// A marker trait for a JWT's header.
pub trait Header {}

/// A marker trait for a JWT's claims.
pub trait Claims {}

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Contains the algorithm and the key ID used to sign the JWT.
///
/// The `BasicHeader` type is intended to be used for generic algorithms which
/// only require common information in JWTs. If more specific fields need to be
/// deserialized, a custom application specific type would be required to
/// deserialize all of the fields.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub struct BasicHeader<'a> {
    /// The signing algorithm.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub alg: Option<&'a str>,
    /// The key ID.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub kid: Option<&'a str>,
    /// The type of token.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub typ: Option<&'a str>,
}

impl<'a> Header for BasicHeader<'a> {}

/// Contains the issuer ID, when the token was issued, and when the token
/// expires.
///
/// The `BasicClaims` type is intended to be used for generic algorithms which
/// only require common information in JWTs. For most applications, a custom
/// application specific type would be required to deserialize all of the
/// fields.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub struct BasicClaims<'a> {
    /// The issuer of the token.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub iss: Option<&'a str>,
    /// When the token was issued as the number of seconds since the Unix epoch.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub iat: Option<u64>,
    /// When the token should expire as the number of seconds since the Unix epoch.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub exp: Option<u64>,
    /// The intended audience.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub aud: Option<&'a str>,
    /// The subject.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub sub: Option<&'a str>,
}

impl<'a> Claims for BasicClaims<'a> {}

trait DecodeJwk {}

trait EncodeJwk {}

/// Serializes the types to JSON, base64 encodes the JSON, constructs the
/// signing input, signs the data, and then returns the JWT.
///
/// # Errors
///
/// The function may return an error variant because the key pair is invalid.
#[cfg(all(feature = "serde", feature = "serde_json"))]
pub fn serialize_encode_and_sign<H, C, S>(header: H, claims: C, signing_key: S) -> Result<String>
where
    H: crate::Header + serde::Serialize,
    C: crate::Claims + serde::Serialize,
    S: sign::Signer,
{
    let header = serde_json::to_vec(&header).unwrap();
    let claims = serde_json::to_vec(&claims).unwrap();
    encode_and_sign(header, claims, signing_key)
}

/// Base64 encodes byte representations of the header and claims, constructs the
/// signing input, signs the data, and then returns the JWT.
///
/// # Errors
///
/// The function may return an error variant because the key pair is invalid.
pub fn encode_and_sign<H, C, S>(header: H, claims: C, signing_key: S) -> Result<String>
where
    H: AsRef<[u8]>,
    C: AsRef<[u8]>,
    S: sign::Signer,
{
    let encoded_header = base64::encode_config(header, base64::URL_SAFE_NO_PAD);
    let encoded_claims = base64::encode_config(claims, base64::URL_SAFE_NO_PAD);
    let data_to_sign = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");

    let signature = signing_key.sign(data_to_sign.as_bytes())?;
    let signature = signature.as_ref();
    let signature = base64::encode_config(&signature, base64::URL_SAFE_NO_PAD);

    Ok([data_to_sign, signature].join("."))
}

/// Attempts to verify a JWT's signature.
///
/// # Errors
///
/// If the public key or signature is invalid, the function will return an error variant.
pub fn verify<'a, I, V>(unverified_jwt: I, verifying_key: V) -> Result<SignatureVerifiedJwt<'a>>
where
    I: core::convert::Into<&'a UnverifiedJwt<'a>>,
    V: verify::Verifier,
{
    let unverified_jwt = unverified_jwt.into();
    let signed_data = unverified_jwt.signed_data().as_bytes();
    let decoded_signature = unverified_jwt.decode_signature()?;

    verifying_key
        .verify(signed_data, decoded_signature)
        .map(|_| SignatureVerifiedJwt { unverified_jwt })
}

#[cfg(test)]
mod tests {
    use super::{SplitJwt, UnverifiedJwt};

    pub(crate) fn jwt_claims_str() -> String {
        String::from(
            "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true,\"iat\":1516239022}",
        )
    }

    #[test]
    fn split_unverified_jwt_normal_parts() {
        let jwt = String::from("abc.defg.vwxyz");
        let SplitJwt {
            header,
            claims,
            signed_data,
            signature,
        } = UnverifiedJwt::split(&jwt).unwrap();

        assert_eq!("abc", header);
        assert_eq!("defg", claims);
        assert_eq!("abc.defg", signed_data);
        assert_eq!("vwxyz", signature);
    }

    #[test]
    fn with_str_unverified_jwt_normal_parts() {
        let jwt = String::from("abc.defg.vwxyz");
        let unverified_jwt = UnverifiedJwt::with_str(&jwt).unwrap();

        assert_eq!("abc", unverified_jwt.encoded_header());
        assert_eq!("abc.defg", unverified_jwt.signed_data());
        assert_eq!("vwxyz", unverified_jwt.encoded_signature());
    }

    #[test]
    fn split_unverified_jwt_no_data_in_parts() {
        let jwt = String::from("..");
        let SplitJwt {
            header,
            claims,
            signed_data,
            signature,
        } = UnverifiedJwt::split(&jwt).unwrap();

        assert_eq!("", header);
        assert_eq!("", claims);
        assert_eq!(".", signed_data);
        assert_eq!("", signature);
    }

    #[test]
    fn with_str_unverified_jwt_no_data_in_parts() {
        let jwt = String::from("..");
        let unverified_jwt = UnverifiedJwt::with_str(&jwt).unwrap();

        assert_eq!("", unverified_jwt.encoded_header());
        assert_eq!(".", unverified_jwt.signed_data());
        assert_eq!("", unverified_jwt.encoded_signature());
    }

    #[test]
    fn split_unverified_jwt_too_many_parts() {
        let jwt = String::from("abc.defg.lmnop.vwxyz");
        let error = UnverifiedJwt::split(&jwt).unwrap_err();
        assert!(error.is_malformed_jwt())
    }

    #[test]
    fn with_str_unverified_jwt_too_many_parts() {
        let jwt = String::from("abc.defg.lmnop.vwxyz");
        let error = UnverifiedJwt::with_str(&jwt).unwrap_err();
        assert!(error.is_malformed_jwt())
    }

    #[test]
    fn split_unverified_jwt_too_few_parts() {
        let jwt = String::from("abc.defg");
        let error = UnverifiedJwt::split(&jwt).unwrap_err();
        assert!(error.is_malformed_jwt())
    }

    #[test]
    fn with_str_unverified_jwt_too_few_parts() {
        let jwt = String::from("abc.defg");
        let error = UnverifiedJwt::with_str(&jwt).unwrap_err();
        assert!(error.is_malformed_jwt())
    }
}

#[cfg(feature = "p256")]
mod p256;

#[cfg(feature = "ring")]
mod ring;

#[cfg(feature = "rsa")]
mod rsa;
