extern crate min_jwt;
extern crate ring;

mod common;

use min_jwt::{signer::EcdsaSigner, verifier::PublicKeyVerifier, UnverifiedJwt};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, UnparsedPublicKey};

static EXPECTED_JWT_JWT_IO_256: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.\
                                        eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik\
                                        pvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6\
                                        MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7Df\
                                        yjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17\
                                        HWP_3cYHBw7AhHale5wky6-sVA\
                                        ";

static EXPECTED_CLAIMS: &str =
    "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true,\"iat\":1516239022}";

// See https://github.com/Keats/jsonwebtoken/pull/73#issuecomment-460322317
//
// openssl ecparam -name prime256v1 -genkey -noout -out private_key.pem
// openssl pkcs8 -in private_key.pem -topk8 -nocrypt -outform DER -out private_key.p8.der
//
// openssl ec -in private_key.pem -pubout -out public_key.pem
// openssl asn1parse -in public_key.pem -offset $((23 + 2)) -out public_key.p8.der.block
// dd bs=1 skip=1 if=public_key.p8.der.block of=public_key.p8.der

fn private_key_pair() -> EcdsaKeyPair {
    let private_key = include_bytes!("es256_private_key.p8.der");
    EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &private_key[..],
    )
    .unwrap()
}

#[test]
fn es256_encode_and_sign_json_str_jwt_io_example() {
    let sys_rand = SystemRandom::new();

    let header = String::from("{\"alg\":\"ES256\",\"typ\":\"JWT\"}");
    let claims = EXPECTED_CLAIMS;

    let signer = EcdsaSigner::with_key_pair(private_key_pair(), &sys_rand);

    let jwt = signer.encode_and_sign_json_str(&header, &claims).unwrap();

    let unverified_jwt = UnverifiedJwt::with_str(&jwt).unwrap();

    // Verify the signature generated

    let public_key = include_bytes!("es256_public_key.p8.der");
    let unparsed_public_key =
        UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, &public_key[..]);

    let public_key_verifier = PublicKeyVerifier::with_public_key(unparsed_public_key);

    let signature_verified_jwt = public_key_verifier.verify(&unverified_jwt).unwrap();

    assert_eq!(
        String::from_utf8(signature_verified_jwt.decode_claims().unwrap()).unwrap(),
        EXPECTED_CLAIMS,
    );
}

#[test]
fn es256_verify_valid_signature_jwt_io_example() {
    // See https://jwt.io
    let jwt = &EXPECTED_JWT_JWT_IO_256;

    let unverified_jwt = UnverifiedJwt::with_str(&jwt).unwrap();

    let public_key = include_bytes!("es256_jwt_io_public_key.p8.der");

    let unparsed_public_key =
        UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, &public_key[..]);
    let public_key_verifier = PublicKeyVerifier::with_public_key(unparsed_public_key);

    let signature_verified_jwt = public_key_verifier.verify(&unverified_jwt).unwrap();

    assert_eq!(
        String::from_utf8(signature_verified_jwt.decode_claims().unwrap()).unwrap(),
        EXPECTED_CLAIMS,
    );
}

#[test]
fn es256_verify_invalid_signature() {
    let jwt_with_invalid_signature = String::from(
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.\
         eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik\
         pvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6\
         MTUxNjIzOTAyMn0.syh-VfuzIxCyGYDlkBA7Df\
         yjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17\
         HWP_3cYHBw7AhHale5wky6-sVA\
         ",
    );

    let unverified_jwt = UnverifiedJwt::with_str(&jwt_with_invalid_signature).unwrap();

    let public_key = include_bytes!("es256_jwt_io_public_key.p8.der");

    let unparsed_public_key =
        UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, &public_key[..]);
    let public_key_verifier = PublicKeyVerifier::with_public_key(unparsed_public_key);

    let error = public_key_verifier.verify(&unverified_jwt).unwrap_err();

    assert!(error.is_invalid_signature());
}
