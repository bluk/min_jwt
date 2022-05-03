mod common;

#[cfg(feature = "ring")]
use ring::signature::{self, UnparsedPublicKey};

#[cfg(all(feature = "ring", feature = "serde", feature = "serde_json"))]
#[test]
fn rs256_verify_valid_signature_jwt_io_example() {
    use min_jwt::verify::ring::RsaKeyVerifier;

    let encoded_header = String::from("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9");

    let encoded_claims = String::from(
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWU\
         sImlhdCI6MTUxNjIzOTAyMn0",
    );

    let encoded_signature = String::from(
        "POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZ\
         WF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-\
         W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguE\
         IcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecF\
         awIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWB\
         FfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA",
    );

    let jwt = format!(
        "{}.{}.{}",
        encoded_header, encoded_claims, encoded_signature
    );

    let public_key = include_bytes!("rs256_public_key_rsa.der");
    let public_key =
        UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, &public_key[..]);

    let verifier = RsaKeyVerifier::with_rs256(&public_key);
    let signature_verified_jwt = min_jwt::verify(&jwt, &verifier).unwrap();

    assert_eq!(encoded_header, signature_verified_jwt.encoded_header());
    assert_eq!(encoded_claims, signature_verified_jwt.encoded_claims());
    assert_eq!(
        encoded_signature,
        signature_verified_jwt.encoded_signature()
    );

    let decoded_header = signature_verified_jwt.decode_header().unwrap();
    let header: common::jwt_io::Header = serde_json::from_slice(&decoded_header).unwrap();

    assert_eq!("JWT", header.typ);
    assert_eq!("RS256", header.alg);

    let decoded_claims = signature_verified_jwt.decode_claims().unwrap();
    let claims: common::jwt_io::Claims = serde_json::from_slice(&decoded_claims).unwrap();

    assert_eq!("1234567890", claims.sub);
    assert_eq!("John Doe", claims.name);
    assert!(claims.admin);
    assert_eq!(1_516_239_022, claims.iat);
}

#[cfg(feature = "ring")]
#[test]
fn rs256_verify_invalid_signature() {
    use min_jwt::verify::ring::RsaKeyVerifier;

    let encoded_header = String::from("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9");

    let encoded_claims = String::from(
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWU\
         sImlhdCI6MTUxNjIzOTAyMn0",
    );

    let encoded_signature = String::from(
        "QOstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZ\
         WF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-\
         W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguE\
         IcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecF\
         awIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWB\
         FfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA",
    );

    let jwt = format!(
        "{}.{}.{}",
        encoded_header, encoded_claims, encoded_signature
    );

    let public_key = include_bytes!("rs256_public_key_rsa.der");
    let public_key =
        UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, &public_key[..]);

    let verifier = RsaKeyVerifier::with_rs256(&public_key);
    let error = min_jwt::verify(&jwt, &verifier).unwrap_err();
    assert!(error.is_invalid_signature());
}

#[cfg(all(
    feature = "rsa",
    feature = "serde",
    feature = "serde_json",
    feature = "sha2"
))]
#[test]
fn rs256_verify_valid_signature_jwt_io_example_with_rsa() {
    use rsa::{pkcs8::DecodePublicKey, RsaPublicKey};

    let encoded_header = String::from("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9");

    let encoded_claims = String::from(
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWU\
         sImlhdCI6MTUxNjIzOTAyMn0",
    );

    let encoded_signature = String::from(
        "POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZ\
         WF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-\
         W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguE\
         IcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecF\
         awIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWB\
         FfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA",
    );

    let jwt = format!(
        "{}.{}.{}",
        encoded_header, encoded_claims, encoded_signature
    );

    let public_key = include_str!("rs256_public_key_rsa.pem");
    let public_key = RsaPublicKey::from_public_key_pem(public_key).unwrap();
    let verifier = min_jwt::verify::rsa::PublicKeyVerifier::with_rs256(public_key);

    let signature_verified_jwt = min_jwt::verify(&jwt, &verifier).unwrap();

    assert_eq!(encoded_header, signature_verified_jwt.encoded_header());
    assert_eq!(encoded_claims, signature_verified_jwt.encoded_claims());
    assert_eq!(
        encoded_signature,
        signature_verified_jwt.encoded_signature()
    );

    let decoded_header = signature_verified_jwt.decode_header().unwrap();
    let header: common::jwt_io::Header = serde_json::from_slice(&decoded_header).unwrap();

    assert_eq!("JWT", header.typ);
    assert_eq!("RS256", header.alg);

    let decoded_claims = signature_verified_jwt.decode_claims().unwrap();
    let claims: common::jwt_io::Claims = serde_json::from_slice(&decoded_claims).unwrap();

    assert_eq!("1234567890", claims.sub);
    assert_eq!("John Doe", claims.name);
    assert!(claims.admin);
    assert_eq!(1_516_239_022, claims.iat);
}

#[cfg(all(
    feature = "rsa",
    feature = "serde",
    feature = "serde_json",
    feature = "sha2"
))]
#[test]
fn test_rs256_with_rsa() -> Result<(), min_jwt::error::Error> {
    use min_jwt::BasicHeader;

    const HEADER: &str = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    const CLAIMS: &str =
        "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true,\"iat\":1516239022}";

    let mut rng = ::rand::thread_rng();
    let bits = 2048;
    let signing_key = ::rsa::RsaPrivateKey::new(&mut rng, bits).unwrap();
    let verifying_key = signing_key.to_public_key();

    let signing_key = min_jwt::sign::rsa::PrivateKeySigner::with_rs256(&signing_key);

    let jwt = min_jwt::encode_and_sign(HEADER, CLAIMS, &signing_key)?;

    let verifying_key = min_jwt::verify::rsa::PublicKeyVerifier::with_rs256(&verifying_key);
    let signature_verified_jwt = min_jwt::verify(&jwt, &verifying_key)?;

    let decoded_header = signature_verified_jwt.decode_header()?;
    let deserialized_header = serde_json::from_slice::<BasicHeader>(&decoded_header).unwrap();

    assert_eq!(deserialized_header.alg, Some("RS256"));
    assert_eq!(deserialized_header.typ, Some("JWT"));
    assert_eq!(deserialized_header.kid, None);

    let decoded_claims = signature_verified_jwt.decode_claims()?;
    let deserialized_claims = serde_json::from_slice::<serde_json::Value>(&decoded_claims).unwrap();
    let expected_claims = serde_json::from_str::<serde_json::Value>(CLAIMS).unwrap();
    assert_eq!(deserialized_claims, expected_claims);

    Ok(())
}
