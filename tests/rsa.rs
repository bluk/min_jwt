extern crate jwt_with_ring;
extern crate ring;

use jwt_with_ring::verifier::PublicKeyVerifier;
use ring::signature::{self, UnparsedPublicKey};
use std::io::Read;
use std::path::Path;

#[test]
fn test_rs256_verification() {
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

    let public_key_path = Path::new("./tests/public_key_rsa.der");
    let public_key = read_file(public_key_path).unwrap();
    let public_key = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, &public_key);

    let public_key_verifier = PublicKeyVerifier::with_public_key(public_key);

    let signature_verified_jwt = public_key_verifier.verify(&jwt).unwrap();

    assert_eq!(encoded_header, signature_verified_jwt.encoded_header());
    assert_eq!(encoded_claims, signature_verified_jwt.encoded_claims());
    assert_eq!(
        encoded_signature,
        signature_verified_jwt.encoded_signature()
    );
}

fn read_file(path: &std::path::Path) -> Result<Vec<u8>, std::io::Error> {
    let mut file = std::fs::File::open(path)?;
    let mut contents: Vec<u8> = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(contents)
}
