#[cfg(test)]
mod tests {
    use crate::{error::Result, sign::ring::EcdsaKeyPairSigner, BasicHeader};
    use ring::{rand::SystemRandom, signature::KeyPair, signature::UnparsedPublicKey};

    #[cfg(all(feature = "serde", feature = "serde_json"))]
    #[test]
    fn test_es256() -> Result<()> {
        const HEADER: &str = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
        let claims = crate::tests::jwt_claims_str();

        let sys_rand = SystemRandom::new();

        // Normally the key's bytes are read from a file or another data store
        // and should not be randomly generated on every invocation
        let pkcs8_bytes = ::ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &sys_rand,
        )?;
        let signing_key_pair = ::ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8_bytes.as_ref(),
        )?;
        let verifying_key = *signing_key_pair.public_key();
        let verifying_key =
            UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, verifying_key);
        let key_pair_with_rand = EcdsaKeyPairSigner::with_es256(signing_key_pair, sys_rand);

        let jwt = crate::encode_and_sign(
            HEADER.as_bytes(),
            crate::tests::jwt_claims_str().as_bytes(),
            key_pair_with_rand,
        )?;

        let verifier = crate::verify::ring::RsaKeyVerifier::with_rs256(&verifying_key);
        let signature_verified_jwt = crate::verify(&jwt, &verifier)?;

        let decoded_header = signature_verified_jwt.decode_header()?;
        let deserialized_header =
            serde_json::from_slice::<BasicHeader<'_>>(&decoded_header).unwrap();
        assert_eq!(
            deserialized_header,
            BasicHeader {
                alg: Some("ES256"),
                typ: Some("JWT"),
                kid: None,
            }
        );

        let decoded_claims = signature_verified_jwt.decode_claims()?;
        let deserialized_claims =
            serde_json::from_slice::<serde_json::Value>(&decoded_claims).unwrap();
        let expected_claims = serde_json::from_str::<serde_json::Value>(&claims).unwrap();
        assert_eq!(deserialized_claims, expected_claims);

        Ok(())
    }
}
