use ring::hmac;
use ring::signature::UnparsedPublicKey;

use crate::error::Error;
use crate::{SignatureVerifiedJwt, UnverifiedJwt};

use crate::error::Result;

pub struct PublicKeyVerifier<B: AsRef<[u8]>> {
    public_key: UnparsedPublicKey<B>,
}

impl<B> PublicKeyVerifier<B>
where
    B: AsRef<[u8]>,
{
    pub fn with_public_key(public_key: UnparsedPublicKey<B>) -> Self {
        PublicKeyVerifier { public_key }
    }

    #[must_use]
    pub fn verify_data_with_decoded_signature(
        &self,
        signed_data: &[u8],
        decoded_signature: &[u8],
    ) -> Result<()> {
        match self.public_key.verify(signed_data, &decoded_signature) {
            Ok(()) => Ok(()),
            Err(_) => Err(Error::invalid_signature()),
        }
    }

    #[must_use]
    pub fn verify<'a>(
        &self,
        unverified_jwt: &'a UnverifiedJwt<'a>,
    ) -> Result<SignatureVerifiedJwt<'a>> {
        let signed_data = unverified_jwt.signed_data().as_bytes();
        let decoded_signature = unverified_jwt.decode_signature()?;

        self.verify_data_with_decoded_signature(&signed_data, &decoded_signature)
            .map(|_| SignatureVerifiedJwt { unverified_jwt })
    }
}

pub struct HmacVerifier {
    key: hmac::Key,
}

impl HmacVerifier {
    pub fn with_key(key: hmac::Key) -> Self {
        HmacVerifier { key }
    }

    #[must_use]
    pub fn verify_data_with_decoded_signature(
        &self,
        signed_data: &[u8],
        decoded_signature: &[u8],
    ) -> Result<()> {
        match hmac::verify(&self.key, signed_data, &decoded_signature) {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::invalid_signature()),
        }
    }

    #[must_use]
    pub fn verify<'a>(
        &self,
        unverified_jwt: &'a UnverifiedJwt<'a>,
    ) -> Result<SignatureVerifiedJwt<'a>> {
        let signed_data = unverified_jwt.signed_data().as_bytes();
        let decoded_signature = unverified_jwt.decode_signature()?;

        self.verify_data_with_decoded_signature(&signed_data, &decoded_signature)
            .map(|_| SignatureVerifiedJwt {
                unverified_jwt: &unverified_jwt,
            })
    }
}

#[cfg(test)]
mod tests {
    use ring::hmac;

    use super::HmacVerifier;
    use crate::UnverifiedJwt;

    #[test]
    fn hs256_verify_valid_signature() {
        let encoded_header = String::from("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");

        let encoded_claims = String::from(
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb2\
             90Ijp0cnVlfQ",
        );

        let encoded_signature = String::from("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        let jwt = format!(
            "{}.{}.{}",
            encoded_header, encoded_claims, encoded_signature
        );

        let header_bytes = vec![
            123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32, 34, 97, 108, 103,
            34, 58, 34, 72, 83, 50, 53, 54, 34, 125,
        ];
        assert_eq!(
            base64::encode_config(
                &String::from_utf8(header_bytes).unwrap(),
                base64::URL_SAFE_NO_PAD
            ),
            encoded_header
        );

        let claims_bytes = vec![
            123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120,
            112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116,
            112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95,
            114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125,
        ];
        assert_eq!(
            base64::encode_config(
                &String::from_utf8(claims_bytes).unwrap(),
                base64::URL_SAFE_NO_PAD
            ),
            encoded_claims
        );

        let hmac_key = String::from("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");
        let hmac_key = base64::decode_config(&hmac_key, base64::URL_SAFE_NO_PAD).unwrap();

        let hmac_verifier = HmacVerifier::with_key(hmac::Key::new(hmac::HMAC_SHA256, &hmac_key));

        let unverified_jwt = UnverifiedJwt::with_str(&jwt).unwrap();

        let signature_verified_jwt = hmac_verifier.verify(&unverified_jwt).unwrap();

        assert_eq!(
            String::from_utf8(signature_verified_jwt.decode_claims().unwrap()).unwrap(),
            "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
        );
    }

    #[test]
    fn hs256_verify_invalid_signature() {
        let encoded_header = String::from("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");

        let encoded_claims = String::from(
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb2\
             90Ijp0cnVlfQ",
        );

        let invalid_encoded_signature = String::from("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXg");

        let jwt = format!(
            "{}.{}.{}",
            encoded_header, encoded_claims, invalid_encoded_signature
        );

        let hmac_key = String::from("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");
        let hmac_key = base64::decode_config(&hmac_key, base64::URL_SAFE_NO_PAD).unwrap();

        let verifier = HmacVerifier::with_key(hmac::Key::new(hmac::HMAC_SHA256, &hmac_key));

        let unverified_jwt = UnverifiedJwt::with_str(&jwt).unwrap();

        assert!(verifier
            .verify(&unverified_jwt)
            .unwrap_err()
            .is_invalid_signature());
    }
}
