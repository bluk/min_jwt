extern crate min_jwt;
extern crate ring;

mod common;

use min_jwt::verifier::PublicKeyVerifier;
use min_jwt::UnverifiedJwt;
use ring::signature::{self, UnparsedPublicKey};

#[test]
fn rs256_verify_valid_signature_jwt_io_example() {
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

    let public_key_verifier = PublicKeyVerifier::with_public_key(public_key);

    let unverified_jwt = UnverifiedJwt::with_str(&jwt).unwrap();

    let signature_verified_jwt = public_key_verifier.verify(&unverified_jwt).unwrap();

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
    assert_eq!(1516239022, claims.iat);
}

#[test]
fn rs256_verify_invalid_signature() {
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

    let public_key_verifier = PublicKeyVerifier::with_public_key(public_key);

    let unverified_jwt = UnverifiedJwt::with_str(&jwt).unwrap();

    let error = public_key_verifier.verify(&unverified_jwt).unwrap_err();
    assert!(error.is_invalid_signature());
}
