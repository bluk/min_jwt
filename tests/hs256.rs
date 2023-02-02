mod common;

#[cfg(all(feature = "ring", feature = "alloc", not(feature = "std")))]
extern crate alloc;

#[cfg(all(feature = "ring", feature = "alloc", not(feature = "std")))]
use alloc::{string::String, vec::Vec};

#[cfg(all(feature = "ring", feature = "std"))]
use std::{string::String, vec::Vec};

#[cfg(feature = "ring")]
use ring::hmac;

#[cfg(feature = "ring")]
static EXPECTED_JWT_RFC7515_A1: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.\
                                        eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzO\
                                        DAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb2\
                                        90Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p\
                                        1r_wW1gFWFOEjXk\
                                        ";

#[cfg(feature = "ring")]
static ENCODED_HMAC_KEY_RFC7515_A1: &str =
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

#[cfg(feature = "ring")]
static EXPECTED_CLAIMS: &str =
    "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

#[cfg(feature = "ring")]
fn decoded_hmac_key() -> Vec<u8> {
    use base64ct::Encoding;
    ::base64ct::Base64UrlUnpadded::decode_vec(ENCODED_HMAC_KEY_RFC7515_A1).unwrap()
}

#[cfg(feature = "ring")]
#[test]
fn hs256_encode_and_sign_json_str_rfc7515_appendix_a_1_example() {
    use min_jwt::sign::ring::HmacKeySigner;

    // See https://tools.ietf.org/html/rfc7515#appendix-A.1

    let header = String::from("{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}");
    let claims = EXPECTED_CLAIMS;

    let key = hmac::Key::new(hmac::HMAC_SHA256, &decoded_hmac_key());
    let signer = HmacKeySigner::with_hs256(&key);

    assert_eq!(
        min_jwt::encode_and_sign(header, claims, signer).unwrap(),
        EXPECTED_JWT_RFC7515_A1
    );
}

#[cfg(feature = "ring")]
#[test]
fn hs256_encode_and_sign_json_bytes_rfc7515_appendix_a_1_example() {
    use min_jwt::sign::ring::HmacKeySigner;

    // See https://tools.ietf.org/html/rfc7515#appendix-A.1

    let header_bytes = [
        123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32, 34, 97, 108, 103, 34,
        58, 34, 72, 83, 50, 53, 54, 34, 125,
    ];
    let claims_bytes = [
        123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112,
        34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58,
        47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111,
        111, 116, 34, 58, 116, 114, 117, 101, 125,
    ];

    let signer = HmacKeySigner::with_hs256(hmac::Key::new(hmac::HMAC_SHA256, &decoded_hmac_key()));

    assert_eq!(
        min_jwt::encode_and_sign(header_bytes, claims_bytes, signer).unwrap(),
        EXPECTED_JWT_RFC7515_A1
    );
}

#[cfg(feature = "ring")]
#[test]
fn hs256_verify_valid_signature_rfc7515_appendix_a_1_example() {
    use min_jwt::verify::ring::HmacKeyVerifier;

    // See https://tools.ietf.org/html/rfc7515#appendix-A.1

    let jwt = EXPECTED_JWT_RFC7515_A1;
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &decoded_hmac_key());

    let verifier = HmacKeyVerifier::with_hs256(&hmac_key);
    let signature_verified_jwt = min_jwt::verify(jwt, &verifier).unwrap();

    assert_eq!(
        String::from_utf8(signature_verified_jwt.decode_claims().unwrap()).unwrap(),
        EXPECTED_CLAIMS,
    );
}

#[cfg(feature = "ring")]
#[test]
fn hs256_verify_invalid_signature() {
    use min_jwt::verify::ring::HmacKeyVerifier;

    let jwt_with_invalid_signature = String::from(
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.\
         eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzO\
         DAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb2\
         90Ijp0cnVlfQ.cBjftJeZ4CVP-mB92K27uhbUJU1p\
         1r_wW1gFWFOEjXk\
         ",
    );

    let verifier =
        HmacKeyVerifier::with_hs256(hmac::Key::new(hmac::HMAC_SHA256, &decoded_hmac_key()));

    let error = min_jwt::verify(&jwt_with_invalid_signature, &verifier).unwrap_err();

    assert!(error.is_invalid_signature());
}
