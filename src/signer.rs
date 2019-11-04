use base64;
use ring::hmac;
use ring::rand::SecureRandom;
use ring::signature::{EcdsaKeyPair, RsaKeyPair};

use crate::error::Result;

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
    pub fn with_key_pair(key_pair: EcdsaKeyPair, secure_random: &'a T) -> EcdsaSigner<'a, T> {
        EcdsaSigner {
            key_pair,
            secure_random,
        }
    }

    // pub fn with_es256(private_key: &[u8]) -> Result<ECDSASigner> {
    //     let key_pair = EcdsaKeyPair::from_pkcs8(
    //         &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
    //         private_key,
    //     )?;
    //     Ok(ECDSASigner { key_pair })
    // }
    //
    // pub fn with_es384(private_key: &[u8]) -> Result<ECDSASigner> {
    //     let key_pair = EcdsaKeyPair::from_pkcs8(
    //         &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
    //         private_key,
    //     )?;
    //     Ok(ECDSASigner { key_pair })
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

        let signature = self
            .key_pair
            .sign(self.secure_random, data_to_sign.as_bytes())?;
        let signature = base64::encode_config(&signature, base64::URL_SAFE_NO_PAD);

        Ok([data_to_sign, signature].join("."))
    }
}

pub struct HmacSigner {
    key: hmac::Key,
}

impl HmacSigner {
    pub fn with_key(key: hmac::Key) -> Self {
        HmacSigner { key }
    }

    #[inline]
    pub fn encode_and_sign_json_str(&self, header: &str, claims: &str) -> Result<String> {
        self.encode_and_sign_json_bytes(header.as_bytes(), claims.as_bytes())
    }

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
        let signature = base64::encode_config::<[u8]>(&signature, base64::URL_SAFE_NO_PAD);

        Ok([data_to_sign, signature].join("."))
    }
}
