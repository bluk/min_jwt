extern crate min_jwt;
extern crate ring;

mod common;

use min_jwt::{signer::HmacSigner, verifier::HmacVerifier, UnverifiedJwt};
use ring::hmac;

static EXPECTED_JWT_JWT_IO_512: &str = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.\
                                        eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6I\
                                        kpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdC\
                                        I6MTUxNjIzOTAyMn0.VFb0qJ1LRg_4ujbZoRM\
                                        XnVkUgiuKq5KxWqNdbKq_G9Vvz-S1zZa9LPxt\
                                        HWKa64zDl2ofkT8F6jBt_K4riU-fPg\
                                        ";

static EXPECTED_CLAIMS: &str =
    "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true,\"iat\":1516239022}";

fn decoded_hmac_key() -> Vec<u8> {
    "your-512-bit-secret".as_bytes().into()
}

#[test]
fn hs512_encode_and_sign_json_str_jwt_io_example() {
    // See https://jwt.io

    let header = String::from("{\"alg\":\"HS512\",\"typ\":\"JWT\"}");
    let claims = EXPECTED_CLAIMS;

    let signer = HmacSigner::with_key(hmac::Key::new(hmac::HMAC_SHA512, &decoded_hmac_key()));

    assert_eq!(
        signer.encode_and_sign_json_str(&header, &claims).unwrap(),
        EXPECTED_JWT_JWT_IO_512
    );
}

#[test]
fn hs512_verify_valid_signature_jwt_io_example() {
    // See https://jwt.io

    let jwt = &EXPECTED_JWT_JWT_IO_512;

    let unverified_jwt = UnverifiedJwt::with_str(&jwt).unwrap();

    let hmac_verifier =
        HmacVerifier::with_key(hmac::Key::new(hmac::HMAC_SHA512, &decoded_hmac_key()));

    let signature_verified_jwt = hmac_verifier.verify(&unverified_jwt).unwrap();

    assert_eq!(
        String::from_utf8(signature_verified_jwt.decode_claims().unwrap()).unwrap(),
        EXPECTED_CLAIMS,
    );
}

#[test]
fn hs512_verify_invalid_signature() {
    let jwt_with_invalid_signature = String::from(
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.\
         eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6I\
         kpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdC\
         I6MTUxNjIzOTAyMn0.WFb0qJ1LRg_4ujbZoRM\
         XnVkUgiuKq5KxWqNdbKq_G9Vvz-S1zZa9LPxt\
         HWKa64zDl2ofkT8F6jBt_K4riU-fPg\
         ",
    );

    let unverified_jwt = UnverifiedJwt::with_str(&jwt_with_invalid_signature).unwrap();

    let hmac_verifier =
        HmacVerifier::with_key(hmac::Key::new(hmac::HMAC_SHA512, &decoded_hmac_key()));

    let error = hmac_verifier.verify(&unverified_jwt).unwrap_err();

    assert!(error.is_invalid_signature());
}
