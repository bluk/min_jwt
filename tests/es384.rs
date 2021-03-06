extern crate min_jwt;
extern crate ring;

mod common;

use min_jwt::{signer::EcdsaSigner, verifier::PublicKeyVerifier, UnverifiedJwt};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, UnparsedPublicKey};

static EXPECTED_JWT_JWT_IO_384: &str = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6I\
                                        mlUcVhYSTB6YkFuSkNLRGFvYmZoa00xZi02ck1TcFRmeVp\
                                        NUnBfMnRLSTgifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibm\
                                        FtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6\
                                        MTUxNjIzOTAyMn0.cJOP_w-hBqnyTsBm3T6lOE5WpcHaAk\
                                        LuQGAs1QO-lg2eWs8yyGW8p9WagGjxgvx7h9X72H7pXmXq\
                                        ej3GdlVbFmhuzj45A9SXDOAHZ7bJXwM1VidcPi7ZcrsMSC\
                                        tP1hiN\
                                        ";

static EXPECTED_CLAIMS: &str =
    "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true,\"iat\":1516239022}";

// See https://github.com/Keats/jsonwebtoken/pull/73#issuecomment-460322317
//
// openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
// -pkeyopt ec_param_enc:named_curve -out private_key.pem
// openssl pkcs8 -in private_key.pem -topk8 -nocrypt -outform DER -out private_key.p8.der
//
// openssl ec -in private_key.pem -pubout -out public_key.pem
// openssl asn1parse -in public_key.pem -offset $((20 + 2)) -out public_key.p8.der.block
// dd bs=1 skip=1 if=public_key.p8.der.block of=public_key.p8.der

fn private_key_pair() -> EcdsaKeyPair {
    let private_key = include_bytes!("es384_private_key.p8.der");
    EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        &private_key[..],
    )
    .unwrap()
}

#[test]
fn es384_encode_and_sign_json_str_jwt_io_example() {
    let sys_rand = SystemRandom::new();

    let header = String::from("{\"alg\":\"ES384\",\"typ\":\"JWT\"}");
    let claims = EXPECTED_CLAIMS;

    let signer = EcdsaSigner::with_key_pair(private_key_pair(), &sys_rand);

    let jwt = signer.encode_and_sign_json_str(&header, &claims).unwrap();

    let unverified_jwt = UnverifiedJwt::with_str(&jwt).unwrap();

    // Verify the signature generated

    let public_key = include_bytes!("es384_public_key.p8.der");
    let unparsed_public_key =
        UnparsedPublicKey::new(&ring::signature::ECDSA_P384_SHA384_FIXED, &public_key[..]);

    let public_key_verifier = PublicKeyVerifier::with_public_key(unparsed_public_key);

    let signature_verified_jwt = public_key_verifier.verify(&unverified_jwt).unwrap();

    assert_eq!(
        String::from_utf8(signature_verified_jwt.decode_claims().unwrap()).unwrap(),
        EXPECTED_CLAIMS,
    );
}

#[test]
fn es384_verify_valid_signature_jwt_io_example() {
    // See https://jwt.io
    let jwt = &EXPECTED_JWT_JWT_IO_384;

    let unverified_jwt = UnverifiedJwt::with_str(&jwt).unwrap();

    let public_key = include_bytes!("es384_jwt_io_public_key.p8.der");

    let unparsed_public_key =
        UnparsedPublicKey::new(&ring::signature::ECDSA_P384_SHA384_FIXED, &public_key[..]);
    let public_key_verifier = PublicKeyVerifier::with_public_key(unparsed_public_key);

    let signature_verified_jwt = public_key_verifier.verify(&unverified_jwt).unwrap();

    assert_eq!(
        String::from_utf8(signature_verified_jwt.decode_claims().unwrap()).unwrap(),
        EXPECTED_CLAIMS,
    );
}

#[test]
fn es384_verify_invalid_signature() {
    let jwt_with_invalid_signature = String::from(
        "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6I\
         mlUcVhYSTB6YkFuSkNLRGFvYmZoa00xZi02ck1TcFRmeVp\
         NUnBfMnRLSTgifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibm\
         FtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6\
         MTUxNjIzOTAyMn0.dJOP_w-hBqnyTsBm3T6lOE5WpcHaAk\
         LuQGAs1QO-lg2eWs8yyGW8p9WagGjxgvx7h9X72H7pXmXq\
         ej3GdlVbFmhuzj45A9SXDOAHZ7bJXwM1VidcPi7ZcrsMSC\
         tP1hiN\
         ",
    );

    let unverified_jwt = UnverifiedJwt::with_str(&jwt_with_invalid_signature).unwrap();

    let public_key = include_bytes!("es384_jwt_io_public_key.p8.der");

    let unparsed_public_key =
        UnparsedPublicKey::new(&ring::signature::ECDSA_P384_SHA384_FIXED, &public_key[..]);
    let public_key_verifier = PublicKeyVerifier::with_public_key(unparsed_public_key);

    let error = public_key_verifier.verify(&unverified_jwt).unwrap_err();

    assert!(error.is_invalid_signature());
}
