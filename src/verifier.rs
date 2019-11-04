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
