//! Sign JWTs using various signature algorithms.
//!
//! See the tests for how to use a specific signing algorithm.

use base64;
use ring::{
    hmac,
    rand::SecureRandom,
    signature::{EcdsaKeyPair, RsaKeyPair},
};

use crate::error::Result;

/// Signs header and claims parts with an ECDSA key.
///
/// ```
/// # use min_jwt::Error;
/// #
/// # fn try_main() -> Result<(), Error> {
/// use min_jwt::ring::signer::EcdsaSigner;
/// use ring::{signature::EcdsaKeyPair, rand::SystemRandom};
///
/// let sys_rand = SystemRandom::new();
///
/// let header = String::from("{\"alg\":\"ES256\",\"typ\":\"JWT\"}");
/// let claims = String::from("{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true,\"iat\":1516239022}");
///
/// // Normally the key's bytes are read from a file or another data store
/// // and should not be randomly generated on every invocation
/// let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(
///   &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
///   &sys_rand
/// )?;
/// let key_pair = EcdsaKeyPair::from_pkcs8(
///   &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
///   pkcs8_bytes.as_ref()
/// )?;
///
/// let signer = EcdsaSigner::with_key_pair(key_pair, &sys_rand);
///
/// /* the header and claims could be serialized by Serde */
/// /* in the end, the serialized JSON should be referenced as either &str or &[u8] */
///
/// let jwt = signer.encode_and_sign_json_str(&header, &claims)?;
///
/// #   Ok(())
/// # }
/// # fn main() {
/// #   try_main().unwrap();
/// # }
/// ```
pub struct EcdsaSigner<'a, T>
where
    T: SecureRandom,
{
    key_pair: EcdsaKeyPair,
    secure_random: &'a T,
}

impl<'a, T> EcdsaSigner<'a, T>
where
    T: SecureRandom,
{
    /// Instantiates a new signer with the given ECDSA key pair and random number generator.
    pub fn with_key_pair(key_pair: EcdsaKeyPair, secure_random: &'a T) -> EcdsaSigner<'a, T> {
        EcdsaSigner {
            key_pair,
            secure_random,
        }
    }

    /// Base64 encodes the JSON, constructs the signing input, signs the data, and then
    /// returns the JWT.
    ///
    /// # Errors
    ///
    /// The function may return an error variant because the key pair is invalid.
    #[inline]
    pub fn encode_and_sign_json_str(&self, header: &str, claims: &str) -> Result<String> {
        self.encode_and_sign_json_bytes(header.as_bytes(), claims.as_bytes())
    }

    /// Base64 encodes the JSON, constructs the signing input, signs the data, and then
    /// returns the JWT.
    ///
    /// # Errors
    ///
    /// The function may return an error variant because the key pair is invalid.
    #[inline]
    pub fn encode_and_sign_json_bytes(&self, header: &[u8], claims: &[u8]) -> Result<String> {
        let encoded_header = base64::encode_config(header, base64::URL_SAFE_NO_PAD);
        let encoded_claims = base64::encode_config(claims, base64::URL_SAFE_NO_PAD);
        let data_to_sign = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");

        let signature = self
            .key_pair
            .sign(self.secure_random, data_to_sign.as_bytes())?;
        let signature = base64::encode_config(&signature, base64::URL_SAFE_NO_PAD);

        Ok([data_to_sign, signature].join("."))
    }
}

/// Signs header and claims parts with a HMAC secret key.
///
/// ```
/// # use min_jwt::Error;
/// #
/// # fn try_main() -> Result<(), Error> {
/// use min_jwt::ring::signer::HmacSigner;
/// use ring::hmac::{Key, self};
///
/// let header = String::from("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
/// let claims = String::from("{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true,\"iat\":1516239022}");
///
/// let hmac_key = String::from("your-secret-key");
/// let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key.as_bytes());
/// let hmac_signer = HmacSigner::with_key(hmac_key);
///
/// /* the header and claims could be serialized by Serde */
/// /* in the end, the serialized JSON should be referenced as either &str or &[u8] */
///
/// let jwt = hmac_signer .encode_and_sign_json_str(&header, &claims)?;
///
/// #   Ok(())
/// # }
/// # fn main() {
/// #   try_main().unwrap();
/// # }
/// ```
pub struct HmacSigner {
    key: hmac::Key,
}

impl HmacSigner {
    /// Instantiates a new signer with the given HMAC key.
    pub fn with_key(key: hmac::Key) -> Self {
        HmacSigner { key }
    }

    /// Base64 encodes the JSON, constructs the signing input, signs the data, and then
    /// returns the JWT.
    #[inline]
    pub fn encode_and_sign_json_str(&self, header: &str, claims: &str) -> Result<String> {
        self.encode_and_sign_json_bytes(header.as_bytes(), claims.as_bytes())
    }

    /// Base64 encodes the JSON, constructs the signing input, signs the data, and then
    /// returns the JWT.
    #[inline]
    pub fn encode_and_sign_json_bytes(&self, header: &[u8], claims: &[u8]) -> Result<String> {
        let encoded_header = base64::encode_config(header, base64::URL_SAFE_NO_PAD);
        let encoded_claims = base64::encode_config(claims, base64::URL_SAFE_NO_PAD);
        let data_to_sign = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");

        let signature = hmac::sign(&self.key, data_to_sign.as_bytes());
        let signature = base64::encode_config(&signature, base64::URL_SAFE_NO_PAD);

        Ok([data_to_sign, signature].join("."))
    }
}

/// Signs header and claims parts with an RSA key.
pub struct RsaSigner<'a, T>
where
    T: SecureRandom,
{
    alg: &'static dyn ring::signature::RsaEncoding,
    key_pair: RsaKeyPair,
    secure_random: &'a T,
}

impl<'a, T> RsaSigner<'a, T>
where
    T: SecureRandom,
{
    pub fn new(
        alg: &'static dyn ring::signature::RsaEncoding,
        key_pair: RsaKeyPair,
        secure_random: &'a T,
    ) -> RsaSigner<'a, T> {
        RsaSigner {
            alg,
            key_pair,
            secure_random,
        }
    }

    // pub fn with_rs256_der(bytes: &[u8]) -> Result<RSASigner> {
    //     Ok(Self::new(
    //         &ring::signature::RSA_PKCS1_SHA256,
    //         ring::signature::RsaKeyPair::from_der(bytes)?,
    //     ))
    // }
    //
    // pub fn with_rs384_der(bytes: &[u8]) -> Result<RSASigner> {
    //     Ok(Self::new(
    //         &ring::signature::RSA_PKCS1_SHA384,
    //         ring::signature::RsaKeyPair::from_der(bytes)?,
    //     ))
    // }
    //
    // pub fn with_rs512_der(bytes: &[u8]) -> Result<RSASigner> {
    //     Ok(Self::new(
    //         &ring::signature::RSA_PKCS1_SHA512,
    //         ring::signature::RsaKeyPair::from_der(bytes)?,
    //     ))
    // }
    //
    // pub fn with_ps256_der(bytes: &[u8]) -> Result<RSASigner> {
    //     Ok(Self::new(
    //         &ring::signature::RSA_PSS_SHA256,
    //         ring::signature::RsaKeyPair::from_der(bytes)?,
    //     ))
    // }
    //
    // pub fn with_ps384_der(bytes: &[u8]) -> Result<RSASigner> {
    //     Ok(Self::new(
    //         &ring::signature::RSA_PSS_SHA384,
    //         ring::signature::RsaKeyPair::from_der(bytes)?,
    //     ))
    // }
    //
    // pub fn with_ps512_der(bytes: &[u8]) -> Result<RSASigner> {
    //     Ok(Self::new(
    //         &ring::signature::RSA_PSS_SHA512,
    //         ring::signature::RsaKeyPair::from_der(bytes)?,
    //     ))
    // }
    //
    // pub fn with_rs256_pkcs8(bytes: &[u8]) -> Result<RSASigner> {
    //     Ok(Self::new(
    //         &ring::signature::RSA_PKCS1_SHA256,
    //         ring::signature::RsaKeyPair::from_pkcs8(bytes)?,
    //     ))
    // }
    //
    // pub fn with_rs384_pkcs8(bytes: &[u8]) -> Result<RSASigner> {
    //     Ok(Self::new(
    //         &ring::signature::RSA_PKCS1_SHA384,
    //         ring::signature::RsaKeyPair::from_pkcs8(bytes)?,
    //     ))
    // }
    //
    // pub fn with_rs512_pkcs8(bytes: &[u8]) -> Result<RSASigner> {
    //     Ok(Self::new(
    //         &ring::signature::RSA_PKCS1_SHA512,
    //         ring::signature::RsaKeyPair::from_pkcs8(bytes)?,
    //     ))
    // }
    //
    // pub fn with_ps256_pkcs8(bytes: &[u8]) -> Result<RSASigner> {
    //     Ok(Self::new(
    //         &ring::signature::RSA_PSS_SHA256,
    //         ring::signature::RsaKeyPair::from_pkcs8(bytes)?,
    //     ))
    // }
    //
    // pub fn with_ps384_pkcs8(bytes: &[u8]) -> Result<RSASigner> {
    //     Ok(Self::new(
    //         &ring::signature::RSA_PSS_SHA384,
    //         ring::signature::RsaKeyPair::from_pkcs8(bytes)?,
    //     ))
    // }
    //
    // pub fn with_ps512_pkcs8(bytes: &[u8]) -> Result<RSASigner> {
    //     Ok(Self::new(
    //         &ring::signature::RSA_PSS_SHA512,
    //         ring::signature::RsaKeyPair::from_pkcs8(bytes)?,
    //     ))
    // }

    #[inline]
    pub fn encode_and_sign_json_str(&self, header: &str, claims: &str) -> Result<String> {
        self.encode_and_sign_json_bytes(header.as_bytes(), claims.as_bytes())
    }

    #[inline]
    pub fn encode_and_sign_json_bytes(&self, header: &[u8], claims: &[u8]) -> Result<String> {
        let encoded_header = base64::encode_config(header, base64::URL_SAFE_NO_PAD);
        let encoded_claims = base64::encode_config(claims, base64::URL_SAFE_NO_PAD);
        let data_to_sign = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");

        let mut signature = vec![0; self.key_pair.public_modulus_len()];
        self.key_pair.sign(
            self.alg,
            self.secure_random,
            data_to_sign.as_bytes(),
            &mut signature,
        )?;
        let signature = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);

        Ok([data_to_sign, signature].join("."))
    }
}
