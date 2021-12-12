mod common;

#[cfg(feature = "ring")]
use min_jwt::{ring::verifier::HmacVerifier, signer::ring::HmacKey, UnverifiedJwt};
#[cfg(feature = "ring")]
use ring::hmac;

#[cfg(feature = "ring")]
static EXPECTED_JWT_JWT_IO_384: &str = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.\
                                        eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik\
                                        pvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6\
                                        MTUxNjIzOTAyMn0.bQTnz6AuMJvmXXQsVPrxeQ\
                                        NvzDkimo7VNXxHeSBfClLufmCVZRUuyTwJF311\
                                        JHuh\
                                        ";

#[cfg(feature = "ring")]
static EXPECTED_CLAIMS: &str =
    "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true,\"iat\":1516239022}";

#[cfg(feature = "ring")]
fn decoded_hmac_key() -> Vec<u8> {
    "your-384-bit-secret".as_bytes().into()
}

#[cfg(feature = "ring")]
#[test]
fn hs384_encode_and_sign_json_str_jwt_io_example() {
    // See https://jwt.io

    let header = String::from("{\"alg\":\"HS384\",\"typ\":\"JWT\"}");
    let claims = EXPECTED_CLAIMS;

    let signing_key = HmacKey::with_hs384(hmac::Key::new(hmac::HMAC_SHA384, &decoded_hmac_key()));

    assert_eq!(
        min_jwt::signer::encode_and_sign_json(&header, claims, &signing_key).unwrap(),
        EXPECTED_JWT_JWT_IO_384
    );
}

#[cfg(feature = "ring")]
#[test]
fn hs384_verify_valid_signature_jwt_io_example() {
    // See https://jwt.io

    let jwt = &EXPECTED_JWT_JWT_IO_384;

    let unverified_jwt = UnverifiedJwt::with_str(jwt).unwrap();

    let hmac_verifier =
        HmacVerifier::with_key(hmac::Key::new(hmac::HMAC_SHA384, &decoded_hmac_key()));

    let signature_verified_jwt = hmac_verifier.verify(&unverified_jwt).unwrap();

    assert_eq!(
        String::from_utf8(signature_verified_jwt.decode_claims().unwrap()).unwrap(),
        EXPECTED_CLAIMS,
    );
}

#[cfg(feature = "ring")]
#[test]
fn hs384_verify_invalid_signature() {
    let jwt_with_invalid_signature = String::from(
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.\
         eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik\
         pvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6\
         MTUxNjIzOTAyMn0.aQTnz6AuMJvmXXQsVPrxeQ\
         NvzDkimo7VNXxHeSBfClLufmCVZRUuyTwJF311\
         JHuh\
         ",
    );

    let unverified_jwt = UnverifiedJwt::with_str(&jwt_with_invalid_signature).unwrap();

    let hmac_verifier =
        HmacVerifier::with_key(hmac::Key::new(hmac::HMAC_SHA384, &decoded_hmac_key()));

    let error = hmac_verifier.verify(&unverified_jwt).unwrap_err();

    assert!(error.is_invalid_signature());
}
