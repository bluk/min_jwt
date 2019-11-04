use ring::hmac;
use ring::signature::UnparsedPublicKey;

use crate::error::Error;
use crate::UnverifiedJwt;

use crate::error::Result;

#[derive(Debug)]
pub struct SignatureVerifiedJwt<'a> {
    unverified_jwt: UnverifiedJwt<'a>,
}

impl<'a> SignatureVerifiedJwt<'a> {
    pub fn decode_header(&self) -> Result<Vec<u8>> {
        self.unverified_jwt.decode_header()
    }

    pub fn decode_claims(&self) -> Result<Vec<u8>> {
        self.unverified_jwt.decode_claims()
    }

    pub fn decode_signature(&self) -> Result<Vec<u8>> {
        self.unverified_jwt.decode_signature()
    }

    pub fn encoded_header(&self) -> &'a str {
        self.unverified_jwt.encoded_header()
    }

    pub fn encoded_claims(&self) -> &'a str {
        self.unverified_jwt.claims
    }

    pub fn encoded_signature(&self) -> &'a str {
        self.unverified_jwt.encoded_signature()
    }

    pub fn signed_data(&self) -> &'a str {
        self.unverified_jwt.signed_data()
    }
}

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
    pub fn verify<'a>(&self, jwt: &'a str) -> Result<SignatureVerifiedJwt<'a>> {
        let unverified_jwt = UnverifiedJwt::with_str(jwt)?;
        self.verify_unverified_jwt(unverified_jwt)
    }

    #[must_use]
    pub fn verify_unverified_jwt<'a>(
        &self,
        unverified_jwt: UnverifiedJwt<'a>,
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
    pub fn verify<'a>(&self, jwt: &'a str) -> Result<SignatureVerifiedJwt<'a>> {
        let unverified_jwt = UnverifiedJwt::with_str(jwt)?;
        self.verify_unverified_jwt(unverified_jwt)
    }

    #[must_use]
    pub fn verify_unverified_jwt<'a>(
        &self,
        unverified_jwt: UnverifiedJwt<'a>,
    ) -> Result<SignatureVerifiedJwt<'a>> {
        let signed_data = unverified_jwt.signed_data().as_bytes();
        let decoded_signature = unverified_jwt.decode_signature()?;

        self.verify_data_with_decoded_signature(&signed_data, &decoded_signature)
            .map(|_| SignatureVerifiedJwt { unverified_jwt })
    }
}

#[cfg(test)]
mod tests {
    use ring::hmac;

    use super::HmacVerifier;

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

        let verifier = HmacVerifier::with_key(hmac::Key::new(hmac::HMAC_SHA256, &hmac_key));

        let signature_verified_jwt = verifier.verify(&jwt).unwrap();

        let encoded_header = base64::encode_config(&header, base64::URL_SAFE_NO_PAD);
        let encoded_claims = base64::encode_config(&claims, base64::URL_SAFE_NO_PAD);
        let data_to_sign = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");

        assert_eq!(signature_verified_jwt.signed_data(), &data_to_sign);

        assert_eq!(
            signature_verified_jwt.decode_signature().unwrap(),
            base64::decode_config(&encoded_signature, base64::URL_SAFE_NO_PAD).unwrap()
        );
    }

    #[test]
    fn hs256_verify_invalid_signature() {
        let encoded_signature = String::from("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXg");

        let jwt = String::from(
            "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.\
             eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzO\
             DAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb2\
             90Ijp0cnVlfQ.\
             ",
        ) + &encoded_signature;

        let hmac_key = String::from("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");
        let hmac_key = base64::decode_config(&hmac_key, base64::URL_SAFE_NO_PAD).unwrap();

        let signer = HmacVerifier::with_key(hmac::Key::new(hmac::HMAC_SHA256, &hmac_key));

        assert!(signer.verify(&jwt).unwrap_err().is_invalid_signature());
    }
}
