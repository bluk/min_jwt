//! # Minimal JWT
//!
//! JSON Web Tokens are a method for representing claims between two parties.
//!
//! JWTs are useful in some scenarios, but there are many use cases where JWTs are not ideal. If
//! you search on the Internet, you can find many articles and comments which may help you decide
//! if JWTs are appropriate for your use case.
//!
//! This crate currently provides basic functionality to sign and verify the signatures of JWTs.

#[cfg(any(feature = "ring"))]
pub mod ring;

pub use error::Error;

mod error;
pub mod keys;

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
/// # #[cfg(any(feature = "ring"))]
/// # fn try_main() -> Result<(), Error> {
/// use min_jwt::UnverifiedJwt;
/// use min_jwt::ring::verifier::HmacVerifier;
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
/// let hmac_verifier = HmacVerifier::with_key(hmac_key);
///
/// let signature_verified_jwt = hmac_verifier.verify(&unverified_jwt)?;
///
/// let decoded_claims = signature_verified_jwt.decode_claims()?;
///
/// /* validate claims */
/// #   Ok(())
/// # }
/// # fn main() {
/// #   #[cfg(any(feature = "ring"))]
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
    /// # #[cfg(any(feature = "ring"))]
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    /// use min_jwt::ring::verifier::HmacVerifier;
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
    /// let hmac_verifier = HmacVerifier::with_key(hmac_key);
    ///
    /// let signature_verified_jwt = hmac_verifier.verify(&unverified_jwt)?;
    ///
    /// let decoded_header = signature_verified_jwt.decode_header()?;
    ///
    /// assert_eq!(String::from_utf8(decoded_header).unwrap(), "{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   #[cfg(any(feature = "ring"))]
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
    /// # #[cfg(any(feature = "ring"))]
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    /// use min_jwt::ring::verifier::HmacVerifier;
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
    /// let hmac_verifier = HmacVerifier::with_key(hmac_key);
    ///
    /// let signature_verified_jwt = hmac_verifier.verify(&unverified_jwt)?;
    ///
    /// let decoded_claims = signature_verified_jwt.decode_claims()?;
    ///
    /// assert_eq!(String::from_utf8(decoded_claims).unwrap(), "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}");
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   #[cfg(any(feature = "ring"))]
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
    /// # #[cfg(any(feature = "ring"))]
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    /// use min_jwt::ring::verifier::HmacVerifier;
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
    /// let hmac_verifier = HmacVerifier::with_key(hmac_key);
    ///
    /// let signature_verified_jwt = hmac_verifier.verify(&unverified_jwt)?;
    ///
    /// let decoded_signature = signature_verified_jwt.decode_signature()?;
    ///
    /// /* use a cryptography library to verify the signed data with the decoded signature */
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   #[cfg(any(feature = "ring"))]
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
    /// # #[cfg(any(feature = "ring"))]
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    /// use min_jwt::ring::verifier::HmacVerifier;
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
    /// let hmac_verifier = HmacVerifier::with_key(hmac_key);
    ///
    /// let signature_verified_jwt = hmac_verifier.verify(&unverified_jwt)?;
    ///
    /// assert_eq!("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", signature_verified_jwt .signed_data());
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   #[cfg(any(feature = "ring"))]
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
    /// # #[cfg(any(feature = "ring"))]
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    /// use min_jwt::ring::verifier::HmacVerifier;
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
    /// let hmac_verifier = HmacVerifier::with_key(hmac_key);
    ///
    /// let signature_verified_jwt = hmac_verifier.verify(&unverified_jwt)?;
    ///
    /// assert_eq!("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", signature_verified_jwt.encoded_header());
    ///
    /// /* use a cryptography library to verify the signed data with the decoded signature */
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   #[cfg(any(feature = "ring"))]
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
    /// # #[cfg(any(feature = "ring"))]
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    /// use min_jwt::ring::verifier::HmacVerifier;
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
    /// let hmac_verifier = HmacVerifier::with_key(hmac_key);
    ///
    /// let signature_verified_jwt = hmac_verifier.verify(&unverified_jwt)?;
    ///
    /// assert_eq!("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", signature_verified_jwt.encoded_claims());
    ///
    /// /* use a cryptography library to verify the signed data with the decoded signature */
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   #[cfg(any(feature = "ring"))]
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
    /// # #[cfg(any(feature = "ring"))]
    /// # fn try_main() -> Result<(), Error> {
    /// use min_jwt::UnverifiedJwt;
    /// use min_jwt::ring::verifier::HmacVerifier;
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
    /// let hmac_verifier = HmacVerifier::with_key(hmac_key);
    ///
    /// let signature_verified_jwt = hmac_verifier.verify(&unverified_jwt)?;
    ///
    /// assert_eq!("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", signature_verified_jwt.encoded_signature());
    ///
    /// /* use a cryptography library to verify the signed data with the decoded signature */
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   #[cfg(any(feature = "ring"))]
    /// #   try_main().unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn encoded_signature(&self) -> &'a str {
        self.unverified_jwt.encoded_signature()
    }
}

/// The key ID.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId<'a>(pub &'a str);

/// Algorithm used to sign the JWT.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Algorithm {
    Es256,
    Rs256,
}

// impl Algorithm {
//     fn as_str(&self) -> &str {
//         match self {
//             Algorithm::Es256 => "ES256",
//             Algorithm::Rs256 => "RS256",
//         }
//     }
// }

/// Errors for when parsing a str into an algorithm.
#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum ParseAlgorithmError {
    UnknownAlgorithm,
}

impl std::error::Error for ParseAlgorithmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::fmt::Display for ParseAlgorithmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownAlgorithm => f.write_str("unknown algorithm"),
        }
    }
}

impl core::str::FromStr for Algorithm {
    type Err = ParseAlgorithmError;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        match s {
            "ES256" => Ok(Algorithm::Es256),
            "RS256" => Ok(Algorithm::Rs256),
            _ => Err(ParseAlgorithmError::UnknownAlgorithm),
        }
    }
}

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Contains the algorithm and the key ID used to sign the JWT.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Header<'a> {
    alg: &'a str,
    kid: &'a str,
}

impl<'a> Header<'a> {
    /// Returns the signing algorithm.
    pub fn alg(&self) -> &str {
        self.alg
    }

    /// Returns the key ID.
    pub fn kid(&self) -> &str {
        self.kid
    }

    pub(crate) fn key_id(&self) -> KeyId<'_> {
        KeyId(self.kid)
    }
}

/// Contains the issuer ID, when the token was issued, and when the token expires.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Claims<'a> {
    pub iss: &'a str,
    pub iat: u64,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub exp: Option<u64>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub aud: Option<&'a str>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub sub: Option<&'a str>,
}

impl<'a> Claims<'a> {
    /// Returns the issuer of the token (usually the team ID).
    pub fn iss(&self) -> &str {
        self.iss
    }

    /// Returns when the token was issued as the number of seconds since the Unix epoch.
    pub fn iat(&self) -> u64 {
        self.iat
    }

    /// Returns when the token should expire as the number of seconds since the Unix epoch.
    pub fn exp(&self) -> Option<u64> {
        self.exp
    }

    /// Returns the intended audience.
    pub fn aud(&self) -> Option<&str> {
        self.aud
    }

    /// Returns the subject.
    pub fn sub(&self) -> Option<&str> {
        self.sub
    }
}

#[cfg(test)]
mod tests {
    use super::{SplitJwt, UnverifiedJwt};

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
