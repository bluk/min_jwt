//! Verify various types of signatures for a JWT.
//!
//! See the tests for how to verify a specific signing algorithm.

use ring::{hmac, signature::UnparsedPublicKey};

use crate::{
    error::{Error, Result},
    SignatureVerifiedJwt, UnverifiedJwt,
};

/// Verifies a JWT's signature is correct with an unparsed public key.
///
/// # Important
///
/// The public key may be unparsed until the `verify()` functions are called, so an invalid
/// signature error may be due to an invalid public key.
///
/// `ring` requires specific formats for the public key which may not be easy to convert
/// an existing public key from. See the `ring` documentation and project for more information
/// on how to convert the public key data into an acceptable format.
///
/// ```
/// # use min_jwt::Error;
/// #
/// # fn try_main() -> Result<(), Error> {
/// use min_jwt::{UnverifiedJwt, ring::{signer::EcdsaSigner, verifier::PublicKeyVerifier}};
/// use ring::{signature::EcdsaKeyPair, signature::KeyPair, signature::UnparsedPublicKey, rand::SystemRandom};
/// #
/// # let sys_rand = SystemRandom::new();
/// #
/// # let header = String::from("{\"alg\":\"ES256\",\"typ\":\"JWT\"}");
/// # let claims = String::from("{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true,\"iat\":1516239022}");
/// #
/// # // Normally the key's bytes are read from a file or another data store
/// # // and should not be randomly generated on every invocation
/// # let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(
/// #   &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
/// #   &sys_rand
/// # )?;
/// # let key_pair = EcdsaKeyPair::from_pkcs8(
/// #   &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
/// #   pkcs8_bytes.as_ref()
/// # )?;
/// #
/// # let public_key_bytes = key_pair.public_key().clone();
/// #
/// # let signer = EcdsaSigner::with_key_pair(key_pair, &sys_rand);
/// #
/// # let jwt = signer.encode_and_sign_json_str(&header, &claims)?;
///
/// let unverified_jwt = UnverifiedJwt::with_str(&jwt).unwrap();
///
/// let unparsed_public_key =
///     UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, &public_key_bytes);
///
/// let public_key_verifier = PublicKeyVerifier::with_public_key(unparsed_public_key);
///
/// let signature_verified_jwt = public_key_verifier.verify(&unverified_jwt)?;
///
/// #   Ok(())
/// # }
/// # fn main() {
/// #   try_main().unwrap();
/// # }
/// ```
pub struct PublicKeyVerifier<B: AsRef<[u8]>> {
    public_key: UnparsedPublicKey<B>,
}

impl<B> PublicKeyVerifier<B>
where
    B: AsRef<[u8]>,
{
    /// Instantiates a new verifier with the given public key.
    pub fn with_public_key(public_key: UnparsedPublicKey<B>) -> Self {
        PublicKeyVerifier { public_key }
    }

    /// Attempts to verify signed data with a base64 decoded signature.
    ///
    /// This function is available for debugging purposes.
    ///
    /// # Errors
    ///
    /// If the public key or signature is invalid, the function will return an error variant.
    pub fn verify_data_with_decoded_signature(
        &self,
        signed_data: &[u8],
        decoded_signature: &[u8],
    ) -> Result<()> {
        match self.public_key.verify(signed_data, decoded_signature) {
            Ok(()) => Ok(()),
            Err(_) => Err(Error::invalid_signature()),
        }
    }

    /// Attempts to verify a JWT's signature.
    ///
    /// # Errors
    ///
    /// If the public key or signature is invalid, the function will return an error variant.
    pub fn verify<'a>(
        &self,
        unverified_jwt: &'a UnverifiedJwt<'a>,
    ) -> Result<SignatureVerifiedJwt<'a>> {
        let signed_data = unverified_jwt.signed_data().as_bytes();
        let decoded_signature = unverified_jwt.decode_signature()?;

        self.verify_data_with_decoded_signature(signed_data, &decoded_signature)
            .map(|_| SignatureVerifiedJwt { unverified_jwt })
    }
}

/// Verifies a JWT's signature is correct for the signed data with a HMAC secret key.
///
/// ```
/// # use min_jwt::Error;
/// #
/// static ENCODED_HMAC_KEY_RFC7515_A1: &str =
///    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
///
/// fn get_hmac_key() -> Vec<u8> {
///   base64::decode_config(&ENCODED_HMAC_KEY_RFC7515_A1, base64::URL_SAFE_NO_PAD).unwrap()
/// }
///
/// # fn try_main() -> Result<(), Error> {
/// use min_jwt::{UnverifiedJwt, ring::verifier::HmacVerifier};
/// use ring::hmac;
///
/// let jwt = String::from("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.\
///                        eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzO\
///                        DAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb2\
///                        90Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p\
///                        1r_wW1gFWFOEjXk\
///                        ");
/// let unverified_jwt = UnverifiedJwt::with_str(&jwt)?;
///
/// let hmac_verifier =
///     HmacVerifier::with_key(hmac::Key::new(hmac::HMAC_SHA256, &get_hmac_key()));
///
/// let signature_verified_jwt = hmac_verifier.verify(&unverified_jwt)?;
///
/// let decoded_claims = signature_verified_jwt.decode_claims()?;
/// #   Ok(())
/// # }
/// # fn main() {
/// #   try_main().unwrap();
/// # }
/// ```
pub struct HmacVerifier {
    key: hmac::Key,
}

impl HmacVerifier {
    /// Instantiates a new verifier with the given HMAC key.
    pub fn with_key(key: hmac::Key) -> Self {
        HmacVerifier { key }
    }

    /// Attempts to verify signed data with a base64 decoded signature.
    ///
    /// This function is available for debugging purposes.
    ///
    /// # Errors
    ///
    /// If the signature is invalid, the function will return an error variant.
    pub fn verify_data_with_decoded_signature(
        &self,
        signed_data: &[u8],
        decoded_signature: &[u8],
    ) -> Result<()> {
        match hmac::verify(&self.key, signed_data, decoded_signature) {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::invalid_signature()),
        }
    }

    /// Attempts to verify a JWT's signature.
    ///
    /// # Errors
    ///
    /// If the signature is invalid, the function will return an error variant.
    pub fn verify<'a>(
        &self,
        unverified_jwt: &'a UnverifiedJwt<'a>,
    ) -> Result<SignatureVerifiedJwt<'a>> {
        let signed_data = unverified_jwt.signed_data().as_bytes();
        let decoded_signature = unverified_jwt.decode_signature()?;

        self.verify_data_with_decoded_signature(signed_data, &decoded_signature)
            .map(|_| SignatureVerifiedJwt { unverified_jwt })
    }
}
