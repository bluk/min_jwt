# Minimal JSON Web Token

A minimal JSON Web Token library.

JSON Web Tokens are a method for representing claims between two parties.

They are used in authentication flows with a third party provider (e.g.
Sign in with...) amongst other scenarios.

This crate provides functionality to sign and verify the signatures of
JWTs.

## Documentation

* [Latest API Docs][docs_rs_min_jwt]

## Cryptography Features/Dependencies

This crate depends on other crates for all cryptographic operations.
Find a supported crypto crate below which supports the algorithms required.

| Dependent Crate(s)       | Algorithm(s) Supported | Feature(s)
| ------------------       | ---------------------- | ----------
| [p256][p256]             | ES256                  | p256
| [ring][ring]             | ES256, HS256, RS256    | ring
| [rsa][rsa], [sha2][sha2], [signature][signature] | RS256                  | rsa, sha2, signature

For instance, if you need `ES256` support, you may choose to use the `p256`
crate and/or the `ring` crate.  Suppose you chose the `p256` crate. In your
crate, depend on this crate and the relevant dependent crate in your
`Cargo.toml`:

```toml
[dependencies]
min_jwt = { version = "0.8.0", features = [ "p256", "serde", "serde_json"] }
p256 = { version = "0.13.0", features = [ "ecdsa", "jwk", "pem"] }
```

Be sure to enable the relevant features as well.

When choosing a cryptography implementation, you may want to consider
compatibility with your environment, the ability to import the signing and
verifying keys in the given formats, and the security properties of the
code (e.g. an audited implementation, resistence to timing attacks, etc.).

## Usage

The [encode_and_sign] and [verify][fn@verify] functions are the primary functions for this crate.

To use the functions, construct the cryptography crate's key. The
cryptography crate may provide methods to import a key in PKCS8 PEM, PKCS8
DER, JSON Web Key (JWK), and other formats.

Then, use the key as either a [sign::Signer] or [verify::Verifier]
parameter. The key may need to be wrapped in a provided type.
See the [sign] or [verify][mod@verify] modules for more documentation and examples.

## Examples

### Sign using ES256 with `p256` crate

```rust
# #[cfg(feature = "p256")]
# {
let header = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
let claims = "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\",\"iat\":1516239022}";
let jwk = r#"
{
    "kty": "EC",
    "crv": "P-256",
    "x": "erEk-zqoG1oYBLD3ohuz0tzIlU7XzFG1098HcCOu0Ck",
    "y": "lQLKfGS2F6mA97bOvo9AlfyNsn88Mf6Iwa5vmf6UkJw",
    "d": "8UmkmK0KO64KCDRZb4RCAHRZ0AfRWBn3Pv6hTv1VR9k"
}
"#;

let secret_key = ::p256::SecretKey::from_jwk_str(jwk).unwrap();
let signing_key = ::p256::ecdsa::SigningKey::from(secret_key);

let jwt = min_jwt::encode_and_sign(header.as_bytes(), claims.as_bytes(), &signing_key)?;
# assert_eq!(
# "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZ\
# SI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.t2IAtoWoX5iMaIXJmOELc_LY-B8Y\
# xlsgkCsEKso_qvYgg0DR6_Q1pZO6SVeOTLFhgDFku9l_cIoL1A6js5rhjw",
# jwt);
# }
# Ok::<(), min_jwt::Error>(())
```

### Verify using RS256 with `rsa`, `sha2`, and `signature` crates

```rust
# #[cfg(all(feature = "rsa", feature = "sha2", feature = "signature"))]
# {
# let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
# eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
# BV5tgihZQo_CCSJuwSmespFnUPVcE1tZ52td6wYfB6j-YuKanRuHD4hJZPO-fN2GYe492aU4FDF\
# VqVqC3cZcv5sZgkZolPgAhXVlQymw___vmvcodWv7xLjZBr4INpzb4FPUkaNhAd1LvF28CXHx0a\
# NvoyyOo4i_AR1ZYBk6CbsCrVj7XxdsVmP3VBpXLSFKcit0FrWBs_sP0-g2qQDIKZ5w9HNiv4H3f\
# U5NZ_TNKRKIQkwMJ1hvI_JbacIZ9uk2oYZ6LwV_NMeh0EqIwRg1EsH6TcdXhzLRozVa1fbej9hd2\
# -AOGxZTba3LQtBAEKbyEATd7N5mqtEsRvcTHzXJmw";
use ::rsa::pkcs8::DecodePublicKey;

let public_key =
"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyfEiSb2ElqylyAfWkbV0
JmKwzaYH2JtWi05dELrGpSI+OM2mNmFnpxZVUUx77GWASD+u/EbDpB7TxoL8wW6r
SFuduTIb63uhqeilkj6VhpPXVLpZg6m8korAXPGaN5BBMTyBAbpWk9e72z5gOGaF
GI4xOv0v3N0MX2h9uXJvhPTpOdKn6jXEflUFF89OWGEh/3JnyZbX5p8+F8BAuseb
8gfpqT2Ct6KT5GrNiA7dPwjN7XFvVnvyYgR7+QXTVNRMrcrEUoJbR4DG+QVeyIRh
0JGqXtm901cviPBRbicIMn2f8qfs15XMSeHWrgel21Cv1wQh3I4xy+soZuZZ2i/p
zwIDAQAB
-----END PUBLIC KEY-----";

let public_key = ::rsa::RsaPublicKey::from_public_key_pem(public_key).unwrap();
let verifying_key = ::rsa::pkcs1v15::VerifyingKey::new_with_prefix(public_key);

let result = min_jwt::verify(jwt, &verifying_key)?;

let header = result.decode_header();
let claims = result.decode_claims();
# }
# Ok::<(), min_jwt::Error>(())
```

## License

Licensed under either of [Apache License, Version 2.0][LICENSE_APACHE] or [MIT
License][LICENSE_MIT] at your option.

### Contributions

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[docs_rs_min_jwt]: https://docs.rs/min_jwt
[LICENSE_APACHE]: LICENSE-APACHE
[LICENSE_MIT]: LICENSE-MIT
[p256]: https://github.com/RustCrypto/elliptic-curves
[ring]: https://github.com/briansmith/ring
[rsa]: https://github.com/RustCrypto/RSA
[rust_crypto]: https://github.com/RustCrypto
[sha2]: https://github.com/RustCrypto/hashes
[signature]: https://github.com/RustCrypto/traits/tree/master/signature