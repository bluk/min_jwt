extern crate jwt_with_ring;
extern crate ring;

mod common;

use jwt_with_ring::{signer::HmacSigner, verifier::HmacVerifier, UnverifiedJwt};
use ring::hmac;

static EXPECTED_JWT_RFC7515_A1: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.\
                                        eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzO\
                                        DAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb2\
                                        90Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p\
                                        1r_wW1gFWFOEjXk\
                                        ";

static ENCODED_HMAC_KEY_RFC7515_A1: &str =
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

static EXPECTED_CLAIMS: &str =
    "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

fn decoded_hmac_key() -> Vec<u8> {
    base64::decode_config(&ENCODED_HMAC_KEY_RFC7515_A1, base64::URL_SAFE_NO_PAD).unwrap()
}

#[test]
fn hs256_encode_and_sign_json_str_rfc7515_appendix_a_1_example() {
    // See https://tools.ietf.org/html/rfc7515#appendix-A.1

    let header = String::from("{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}");
    let claims = EXPECTED_CLAIMS;

    let signer = HmacSigner::with_key(hmac::Key::new(hmac::HMAC_SHA256, &decoded_hmac_key()));

    assert_eq!(
        signer.encode_and_sign_json_str(&header, &claims).unwrap(),
        EXPECTED_JWT_RFC7515_A1
    );
}

#[test]
fn hs256_encode_and_sign_json_bytes_rfc7515_appendix_a_1_example() {
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

    let signer = HmacSigner::with_key(hmac::Key::new(hmac::HMAC_SHA256, &decoded_hmac_key()));

    assert_eq!(
        signer
            .encode_and_sign_json_bytes(&header_bytes, &claims_bytes)
            .unwrap(),
        EXPECTED_JWT_RFC7515_A1
    );
}

#[test]
fn hs256_verify_valid_signature_rfc7515_appendix_a_1_example() {
    // See https://tools.ietf.org/html/rfc7515#appendix-A.1

    let jwt = &EXPECTED_JWT_RFC7515_A1;

    let unverified_jwt = UnverifiedJwt::with_str(&jwt).unwrap();

    let hmac_verifier =
        HmacVerifier::with_key(hmac::Key::new(hmac::HMAC_SHA256, &decoded_hmac_key()));

    let signature_verified_jwt = hmac_verifier.verify(&unverified_jwt).unwrap();

    assert_eq!(
        String::from_utf8(signature_verified_jwt.decode_claims().unwrap()).unwrap(),
        EXPECTED_CLAIMS,
    );
}

#[test]
fn hs256_verify_invalid_signature() {
    let jwt_with_invalid_signature = String::from(
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.\
         eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzO\
         DAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb2\
         90Ijp0cnVlfQ.cBjftJeZ4CVP-mB92K27uhbUJU1p\
         1r_wW1gFWFOEjXk\
         ",
    );

    let unverified_jwt = UnverifiedJwt::with_str(&jwt_with_invalid_signature).unwrap();

    let hmac_verifier =
        HmacVerifier::with_key(hmac::Key::new(hmac::HMAC_SHA256, &decoded_hmac_key()));

    let error = hmac_verifier.verify(&unverified_jwt).unwrap_err();

    assert!(error.is_invalid_signature());
}
