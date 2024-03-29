#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(
    rust_2018_idioms,
    missing_docs,
    missing_debug_implementations,
    unused_lifetimes,
    unused_qualifications
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

use base64ct::{Base64UrlUnpadded, Encoding};
use core::convert::TryFrom;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::{string::String, vec, vec::Vec};

#[cfg(feature = "std")]
use std::{string::String, vec, vec::Vec};

pub use error::Error;

pub mod algorithm;
pub mod error;
pub mod sign;
pub mod time;
pub mod verify;

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
/// # fn try_main() -> Result<(), min_jwt::error::Error> {
/// use min_jwt::UnverifiedJwt;
///
/// let jwt = "\
/// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
/// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
/// ";
/// let unverified_jwt = UnverifiedJwt::with_str(jwt)?;
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

impl<'a> TryFrom<&'a str> for UnverifiedJwt<'a> {
    type Error = Error;

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
    /// let jwt = "\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ";
    /// let unverified_jwt = UnverifiedJwt::with_str(jwt)?;
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    pub fn with_str(jwt: &str) -> Result<UnverifiedJwt<'_>> {
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
    /// let jwt = "\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ";
    /// let unverified_jwt = UnverifiedJwt::with_str(&jwt)?;
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
        Ok(Base64UrlUnpadded::decode_vec(self.header)?)
    }

    // Currently not pub. Should a SignatureVerifiedJwt be required before looking at the claims?
    /// Decodes the claims part by parsing the JWT for the claims and base64 decoding the claims.
    ///
    /// # Errors
    ///
    /// If the claims part is not correctly base64 encoded, the function will return an error variant.
    fn decode_claims(&self) -> Result<Vec<u8>> {
        Ok(Base64UrlUnpadded::decode_vec(self.claims)?)
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
    /// let jwt = "\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ";
    /// let unverified_jwt = UnverifiedJwt::with_str(&jwt)?;
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
        Ok(Base64UrlUnpadded::decode_vec(self.signature)?)
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
    /// let jwt = "\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ";
    /// let unverified_jwt = UnverifiedJwt::with_str(&jwt)?;
    ///
    /// assert_eq!("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", unverified_jwt.signed_data());
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    #[must_use]
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
    /// let jwt = "\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ";
    /// let unverified_jwt = UnverifiedJwt::with_str(&jwt)?;
    ///
    /// assert_eq!("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", unverified_jwt.encoded_header());
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    #[must_use]
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
    /// let jwt = "\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ";
    /// let unverified_jwt = UnverifiedJwt::with_str(&jwt)?;
    ///
    /// assert_eq!("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", unverified_jwt.encoded_signature());
    ///
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    #[must_use]
    pub fn encoded_signature(&self) -> &'a str {
        self.signature
    }

    fn split(jwt: &str) -> Result<SplitJwt<'_>> {
        let mut parts = jwt.rsplitn(2, '.');

        let signature = parts.next().ok_or_else(Error::malformed_jwt)?;
        let signed_data = parts.next().ok_or_else(Error::malformed_jwt)?;

        if parts.next().is_some() {
            return Err(Error::malformed_jwt());
        }

        let mut parts = signed_data.rsplitn(3, '.');

        let claims = parts.next().ok_or_else(Error::malformed_jwt)?;
        let header = parts.next().ok_or_else(Error::malformed_jwt)?;

        if parts.next().is_some() {
            return Err(Error::malformed_jwt());
        }

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
/// use ring::hmac;
///
/// let jwt = "\
/// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
/// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
/// ";
///
/// let hmac_key_bytes = String::from("your-256-bit-secret").into_bytes();
/// let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);
///
/// let verifier = min_jwt::verify::ring::HmacKeyVerifier::with_hs256(&hmac_key);
/// let signature_verified_jwt = min_jwt::verify(jwt, &verifier)?;
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
    unverified_jwt: UnverifiedJwt<'a>,
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
    /// use ring::hmac;
    ///
    /// let jwt = "\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ";
    ///
    /// let hmac_key_bytes = String::from("your-256-bit-secret").into_bytes();
    /// let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);
    ///
    /// let verifier = min_jwt::verify::ring::HmacKeyVerifier::with_hs256(&hmac_key);
    /// let signature_verified_jwt = min_jwt::verify(jwt, &verifier)?;
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
    /// use ring::hmac;
    ///
    /// let jwt = "\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ";
    ///
    /// let hmac_key_bytes = String::from("your-256-bit-secret").into_bytes();
    /// let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);
    ///
    /// let verifier = min_jwt::verify::ring::HmacKeyVerifier::with_hs256(&hmac_key);
    /// let signature_verified_jwt = min_jwt::verify(jwt, &verifier)?;
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
    /// use ring::hmac;
    ///
    /// let jwt = "\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ";
    ///
    /// let hmac_key_bytes = String::from("your-256-bit-secret").into_bytes();
    /// let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);
    ///
    /// let verifier = min_jwt::verify::ring::HmacKeyVerifier::with_hs256(&hmac_key);
    /// let signature_verified_jwt = min_jwt::verify(jwt, &verifier)?;
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
    /// use ring::hmac;
    ///
    /// let jwt = "\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ";
    ///
    /// let hmac_key_bytes = String::from("your-256-bit-secret").into_bytes();
    /// let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);
    ///
    /// let verifier = min_jwt::verify::ring::HmacKeyVerifier::with_hs256(&hmac_key);
    /// let signature_verified_jwt = min_jwt::verify(jwt, &verifier)?;
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
    #[must_use]
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
    /// use ring::hmac;
    ///
    /// let jwt = "\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ";
    ///
    /// let hmac_key_bytes = String::from("your-256-bit-secret").into_bytes();
    /// let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);
    ///
    /// let verifier = min_jwt::verify::ring::HmacKeyVerifier::with_hs256(&hmac_key);
    /// let signature_verified_jwt = min_jwt::verify(jwt, &verifier)?;
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
    #[must_use]
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
    /// use ring::hmac;
    ///
    /// let jwt = "\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ";
    ///
    /// let hmac_key_bytes = String::from("your-256-bit-secret").into_bytes();
    /// let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);
    ///
    /// let verifier = min_jwt::verify::ring::HmacKeyVerifier::with_hs256(&hmac_key);
    /// let signature_verified_jwt = min_jwt::verify(jwt, &verifier)?;
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
    #[must_use]
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
    /// use ring::hmac;
    ///
    /// let jwt = "\
    /// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva\
    /// G4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\
    /// ";
    ///
    /// let hmac_key_bytes = String::from("your-256-bit-secret").into_bytes();
    /// let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key_bytes);
    ///
    /// let verifier = min_jwt::verify::ring::HmacKeyVerifier::with_hs256(&hmac_key);
    /// let signature_verified_jwt = min_jwt::verify(jwt, &verifier)?;
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
    #[must_use]
    pub fn encoded_signature(&self) -> &'a str {
        self.unverified_jwt.encoded_signature()
    }
}

/// A marker trait for a JWT's header.
pub trait Header {}

/// A marker trait for a JWT's claims.
pub trait Claims {}

#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Contains the algorithm and the key ID used to sign the JWT.
///
/// The `BasicHeader` type is intended to be used for generic algorithms which
/// only require common information in JWTs. If more specific fields need to be
/// deserialized, a custom application specific type would be required to
/// deserialize all of the fields.
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// Serializes the types to JSON, base64 encodes the JSON, constructs the
/// signing input, signs the data, and then returns the JWT.
///
/// # Errors
///
/// The function may return an error variant because the key pair is invalid.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
#[cfg_attr(docsrs, doc(cfg(feature = "serde_json")))]
#[cfg(all(feature = "serde", feature = "serde_json"))]
pub fn serialize_encode_and_sign<H, C, S>(header: &H, claims: &C, signing_key: S) -> Result<String>
where
    H: Header + Serialize,
    C: Claims + Serialize,
    S: sign::Signer,
{
    let header = serde_json::to_vec(&header).map_err(|_| Error::unspecified())?;
    let claims = serde_json::to_vec(&claims).map_err(|_| Error::unspecified())?;
    encode_and_sign(&header, &claims, signing_key)
}

/// Base64 encodes byte representations of the header and claims, constructs the
/// signing input, signs the data, and then returns the JWT.
///
/// # Errors
///
/// The function may return an error variant because the key pair is invalid.
pub fn encode_and_sign<S>(header: &[u8], claims: &[u8], signing_key: S) -> Result<String>
where
    S: sign::Signer,
{
    let encoded_header_len = Base64UrlUnpadded::encoded_len(header);
    let signed_data_len = encoded_header_len + Base64UrlUnpadded::encoded_len(claims) + 1;

    let mut output = vec![0; signed_data_len];

    Base64UrlUnpadded::encode(header, &mut output[..encoded_header_len])?;
    output[encoded_header_len] = b'.';
    Base64UrlUnpadded::encode(claims, &mut output[encoded_header_len + 1..])?;

    let signature = signing_key
        .sign(&output)
        .map_err(|_| Error::unspecified())?;
    let signature = signature.as_ref();

    let final_len = signed_data_len + 1 + Base64UrlUnpadded::encoded_len(signature);

    output.reserve_exact(final_len);
    output.resize(final_len, 0);
    output[signed_data_len] = b'.';

    Base64UrlUnpadded::encode(signature, &mut output[signed_data_len + 1..])?;

    Ok(String::from_utf8(output).map_err(|_| base64ct::InvalidEncodingError)?)
}

/// Attempts to verify a JWT's signature.
///
/// # Errors
///
/// If the public key or signature is invalid, the function will return an error variant.
pub fn verify<V>(unverified_jwt: &str, verifying_key: V) -> Result<SignatureVerifiedJwt<'_>>
where
    V: verify::Verifier,
{
    let unverified_jwt = UnverifiedJwt::with_str(unverified_jwt)?;
    let signed_data = unverified_jwt.signed_data().as_bytes();
    let decoded_signature = unverified_jwt.decode_signature()?;

    verifying_key
        .verify(signed_data, &decoded_signature)
        .map(|_| SignatureVerifiedJwt { unverified_jwt })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(feature = "ring", feature = "p256"))]
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
        assert!(error.is_malformed_jwt());
    }

    #[test]
    fn with_str_unverified_jwt_too_many_parts() {
        let jwt = String::from("abc.defg.lmnop.vwxyz");
        let error = UnverifiedJwt::with_str(&jwt).unwrap_err();
        assert!(error.is_malformed_jwt());
    }

    #[test]
    fn split_unverified_jwt_too_few_parts() {
        let jwt = String::from("abc.defg");
        let error = UnverifiedJwt::split(&jwt).unwrap_err();
        assert!(error.is_malformed_jwt());
    }

    #[test]
    fn with_str_unverified_jwt_too_few_parts() {
        let jwt = String::from("abc.defg");
        let error = UnverifiedJwt::with_str(&jwt).unwrap_err();
        assert!(error.is_malformed_jwt());
    }
}

#[cfg(feature = "p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
mod p256;
#[cfg(feature = "ring")]
#[cfg_attr(docsrs, doc(cfg(feature = "ring")))]
mod ring;
#[cfg(feature = "rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
mod rsa;
