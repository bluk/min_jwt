#[cfg(test)]
mod tests {
    #[cfg(all(feature = "serde", feature = "serde_json"))]
    #[test]
    fn test_es256() -> crate::error::Result<()> {
        use crate::BasicHeader;

        const HEADER: &str = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
        let claims = crate::tests::jwt_claims_str();

        let signing_key = ::p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let jwt = crate::encode_and_sign(HEADER, &claims, &signing_key)?;

        let verifying_key = signing_key.verifying_key();
        let signature_verified_jwt = crate::verify(&jwt, verifying_key)?;

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
