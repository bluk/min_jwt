use base64;
use ring::hmac;
use ring::rand::SecureRandom;
use ring::signature::{EcdsaKeyPair, RsaKeyPair};
use serde::Serialize;

use crate::error::Result;
use crate::header::Header;

pub struct ECDSASigner {
    key_pair: EcdsaKeyPair,
}

impl ECDSASigner {
    pub fn new(key_pair: EcdsaKeyPair) -> Self {
        ECDSASigner { key_pair }
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

    pub fn encode_and_sign<H, C>(
        &self,
        header: &H,
        claims: &C,
        secure_random: &dyn SecureRandom,
    ) -> Result<String>
    where
        H: ?Sized + Header,
        C: ?Sized + Serialize,
    {
        let encoded_header = to_encoded_part(header)?;
        let encoded_claims = to_encoded_part(claims)?;
        let data_to_sign = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");

        let signature = self.key_pair.sign(secure_random, data_to_sign.as_bytes())?;
        let signature = base64::encode_config(&signature, base64::URL_SAFE_NO_PAD);

        Ok([data_to_sign, signature].join("."))
    }
}

pub struct HMACSigner {
    key: hmac::Key,
}

impl HMACSigner {
    pub fn new(key: hmac::Key) -> Self {
        HMACSigner { key }
    }

    // pub fn with_hs256(key: &[u8]) -> Result<HMACSigner> {
    //     let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    //     Ok(HMACSigner { key })
    // }
    //
    // pub fn with_hs384(key: &[u8]) -> Result<HMACSigner> {
    //     let key = hmac::Key::new(hmac::HMAC_SHA384, key);
    //     Ok(HMACSigner { key })
    // }
    //
    // pub fn with_hs512(key: &[u8]) -> Result<HMACSigner> {
    //     let key = hmac::Key::new(hmac::HMAC_SHA512, key);
    //     Ok(HMACSigner { key })
    // }

    pub fn encode_and_sign<H, C>(&self, header: &H, claims: &C) -> Result<String>
    where
        H: ?Sized + Header,
        C: ?Sized + Serialize,
    {
        let encoded_header = to_encoded_part(header)?;
        let encoded_claims = to_encoded_part(claims)?;
        let data_to_sign = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");

        let signature = hmac::sign(&self.key, data_to_sign.as_bytes());
        let signature = base64::encode_config(&signature, base64::URL_SAFE_NO_PAD);

        Ok([data_to_sign, signature].join("."))
    }
}

pub struct RSASigner {
    alg: &'static dyn ring::signature::RsaEncoding,
    key_pair: RsaKeyPair,
}

impl RSASigner {
    pub fn new(alg: &'static dyn ring::signature::RsaEncoding, key_pair: RsaKeyPair) -> Self {
        RSASigner { alg, key_pair }
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

    pub fn encode_and_sign<H, C>(
        &self,
        header: &H,
        claims: &C,
        secure_random: &dyn SecureRandom,
    ) -> Result<String>
    where
        H: ?Sized + Header,
        C: ?Sized + Serialize,
    {
        let encoded_header = to_encoded_part(header)?;
        let encoded_claims = to_encoded_part(claims)?;
        let data_to_sign = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");

        let mut signature = vec![0; self.key_pair.public_modulus_len()];
        self.key_pair.sign(
            self.alg,
            secure_random,
            data_to_sign.as_bytes(),
            &mut signature,
        )?;
        let signature = base64::encode_config::<[u8]>(&signature, base64::URL_SAFE_NO_PAD);

        Ok([data_to_sign, signature].join("."))
    }
}

fn to_encoded_part<T: Serialize>(v: &T) -> Result<String>
where
    T: ?Sized + Serialize,
{
    let encoded = serde_json::to_string(v)?;
    Ok(base64::encode_config(
        encoded.as_bytes(),
        base64::URL_SAFE_NO_PAD,
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
