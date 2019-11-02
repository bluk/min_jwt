use ring::hmac;
use std::result;

use crate::error::Error;

#[derive(Debug)]
pub struct SignatureVerifiedJWT<'a> {
    pub data: &'a str,
    pub decoded_signature: Vec<u8>,
}

#[derive(Debug)]
pub struct UnverifiedJWT<'a> {
    pub data: &'a str,
    pub signature: Option<Vec<u8>>,
}

pub struct HmacVerifier {
    key: hmac::Key,
}

impl HmacVerifier {
    pub fn with_key(key: hmac::Key) -> Self {
        HmacVerifier { key }
    }

    pub fn verify_signature<'a>(
        &self,
        jwt: &'a str,
    ) -> result::Result<SignatureVerifiedJWT<'a>, Error<'a>> {
        let parts: Vec<&str> = jwt.rsplitn(2, '.').collect();
        if parts.len() != 2 {
            return Err(Error::malformed_jwt());
        }

        let (signature, data) = (parts[0], parts[1]);
        let decoded_signature = base64::decode_config(&signature, base64::URL_SAFE_NO_PAD)?;

        match hmac::verify(&self.key, data.as_bytes(), &decoded_signature) {
            Ok(_) => Ok(SignatureVerifiedJWT {
                data,
                decoded_signature,
            }),
            Err(_) => Err(Error::invalid_signature(UnverifiedJWT {
                data,
                signature: Some(decoded_signature),
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use ring::hmac;

    use super::{HmacVerifier, SignatureVerifiedJWT};

    #[test]
    fn hs256_verify_valid_signature() {
        let encoded_signature = String::from("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        let jwt = String::from("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.")
            + &String::from("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzO")
            + &String::from("DAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb2")
            + &String::from("90Ijp0cnVlfQ.")
            + &encoded_signature;

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

        let signer = HmacVerifier::with_key(hmac::Key::new(hmac::HMAC_SHA256, &hmac_key));

        let SignatureVerifiedJWT {
            data,
            decoded_signature,
        } = signer.verify_signature(&jwt).unwrap();

        let encoded_header = base64::encode_config(&header, base64::URL_SAFE_NO_PAD);
        let encoded_claims = base64::encode_config(&claims, base64::URL_SAFE_NO_PAD);
        let data_to_sign = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");

        assert_eq!(data, &data_to_sign);

        assert_eq!(
            decoded_signature,
            base64::decode_config(&encoded_signature, base64::URL_SAFE_NO_PAD).unwrap()
        );
    }

    #[test]
    fn hs256_verify_invalid_signature() {
        let encoded_signature = String::from("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXg");

        let jwt = String::from("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.")
            + &String::from("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzO")
            + &String::from("DAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb2")
            + &String::from("90Ijp0cnVlfQ.")
            + &encoded_signature;

        let hmac_key = String::from("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");
        let hmac_key = base64::decode_config(&hmac_key, base64::URL_SAFE_NO_PAD).unwrap();

        let signer = HmacVerifier::with_key(hmac::Key::new(hmac::HMAC_SHA256, &hmac_key));

        signer.verify_signature(&jwt).unwrap_err();
    }
}
