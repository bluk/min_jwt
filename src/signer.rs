use base64;
use ring::hmac;
use ring::rand::SecureRandom;
use ring::signature::{EcdsaKeyPair, RsaKeyPair};
use serde::Serialize;

use crate::error::Result;

pub struct EcdsaSigner {
    key_pair: EcdsaKeyPair,
}

impl EcdsaSigner {
    pub fn with_key_pair(key_pair: EcdsaKeyPair) -> Self {
        EcdsaSigner { key_pair }
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
    pub fn encode_and_sign<H, C>(
        &self,
        header: &H,
        claims: &C,
        secure_random: &dyn SecureRandom,
    ) -> Result<String>
    where
        H: ?Sized + Serialize,
        C: ?Sized + Serialize,
    {
        let encoded_header = serde_json::to_string(header)?;
        let encoded_claims = serde_json::to_string(claims)?;
        self.encode_and_sign_json_str(&encoded_header, &encoded_claims, secure_random)
    }

    #[inline]
    pub fn encode_and_sign_json_str(
        &self,
        header: &str,
        claims: &str,
        secure_random: &dyn SecureRandom,
    ) -> Result<String> {
        self.encode_and_sign_json_bytes(header.as_bytes(), claims.as_bytes(), secure_random)
    }

    #[inline]
    pub fn encode_and_sign_json_bytes(
        &self,
        header: &[u8],
        claims: &[u8],
        secure_random: &dyn SecureRandom,
    ) -> Result<String> {
        let encoded_header = base64::encode_config(header, base64::URL_SAFE_NO_PAD);
        let encoded_claims = base64::encode_config(claims, base64::URL_SAFE_NO_PAD);
        let data_to_sign = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");

        let signature = self.key_pair.sign(secure_random, data_to_sign.as_bytes())?;
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

    #[inline]
    pub fn encode_and_sign<H, C>(&self, header: &H, claims: &C) -> Result<String>
    where
        H: ?Sized + Serialize,
        C: ?Sized + Serialize,
    {
        let encoded_header = serde_json::to_string(header)?;
        let encoded_claims = serde_json::to_string(claims)?;
        self.encode_and_sign_json_str(&encoded_header, &encoded_claims)
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

pub struct RsaSigner {
    alg: &'static dyn ring::signature::RsaEncoding,
    key_pair: RsaKeyPair,
}

impl RsaSigner {
    pub fn new(alg: &'static dyn ring::signature::RsaEncoding, key_pair: RsaKeyPair) -> Self {
        RsaSigner { alg, key_pair }
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
    pub fn encode_and_sign<H, C>(
        &self,
        header: &H,
        claims: &C,
        secure_random: &dyn SecureRandom,
    ) -> Result<String>
    where
        H: ?Sized + Serialize,
        C: ?Sized + Serialize,
    {
        let encoded_header = serde_json::to_string(header)?;
        let encoded_claims = serde_json::to_string(claims)?;
        self.encode_and_sign_json_str(&encoded_header, &encoded_claims, secure_random)
    }

    #[inline]
    pub fn encode_and_sign_json_str(
        &self,
        header: &str,
        claims: &str,
        secure_random: &dyn SecureRandom,
    ) -> Result<String> {
        self.encode_and_sign_json_bytes(header.as_bytes(), claims.as_bytes(), secure_random)
    }

    #[inline]
    pub fn encode_and_sign_json_bytes(
        &self,
        header: &[u8],
        claims: &[u8],
        secure_random: &dyn SecureRandom,
    ) -> Result<String> {
        let encoded_header = base64::encode_config(header, base64::URL_SAFE_NO_PAD);
        let encoded_claims = base64::encode_config(claims, base64::URL_SAFE_NO_PAD);
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

#[cfg(test)]
mod tests {
    use ring::hmac;

    use super::HmacSigner;

    #[test]
    fn encode_and_sign_hs256_json_str() {
        let header_bytes = vec![
            123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32, 34, 97, 108, 103,
            34, 58, 34, 72, 83, 50, 53, 54, 34, 125,
        ];
        let header = String::from_utf8(header_bytes).unwrap();
        let claims_bytes = vec![
            123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120,
            112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116,
            112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95,
            114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125,
        ];
        let claims = String::from_utf8(claims_bytes).unwrap();

        let hmac_key = String::from("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");
        let hmac_key = base64::decode_config(&hmac_key, base64::URL_SAFE_NO_PAD).unwrap();

        let signer = HmacSigner::with_key(hmac::Key::new(hmac::HMAC_SHA256, &hmac_key));

        assert_eq!(
            signer.encode_and_sign_json_str(&header, &claims).unwrap(),
            String::from("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.")
                + &String::from("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzO")
                + &String::from("DAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb2")
                + &String::from("90Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p")
                + &String::from("1r_wW1gFWFOEjXk")
        );
    }

    #[test]
    fn encode_and_sign_hs256_json_bytes() {
        let header_bytes = vec![
            123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32, 34, 97, 108, 103,
            34, 58, 34, 72, 83, 50, 53, 54, 34, 125,
        ];
        let claims_bytes = vec![
            123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120,
            112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116,
            112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95,
            114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125,
        ];

        let hmac_key = String::from("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");
        let hmac_key = base64::decode_config(&hmac_key, base64::URL_SAFE_NO_PAD).unwrap();

        let signer = HmacSigner::with_key(hmac::Key::new(hmac::HMAC_SHA256, &hmac_key));

        assert_eq!(
            signer
                .encode_and_sign_json_bytes(&header_bytes, &claims_bytes)
                .unwrap(),
            String::from("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.")
                + &String::from("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzO")
                + &String::from("DAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb2")
                + &String::from("90Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p")
                + &String::from("1r_wW1gFWFOEjXk")
        );
    }
}
