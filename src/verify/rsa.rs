//! `rsa` crate Verifier implementation.
//!
//! # Supported Algorithms
//!
//! | Algorithm | Type | Wrapper Type |
//! | --------- | ---- | ------------ |
//! | rs256     | [`::rsa::RsaPublicKey`] | [`PublicKeyVerifier`] |
//!
//! Note that you will also need the `sha2` feature enabled.
//!
//! # Examples
//!
//! ## PKCS8
//!
//! The `pem` feature on the `rsa` dependency must be enabled.
//!
//! ```
//! # #[cfg(all(feature = "rsa", feature = "sha2", feature = "signature"))]
//! # fn try_main() -> Result<(), min_jwt::error::Error> {
//! # let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.BV5tgihZQo_CCSJuwSmespFnUPVcE1tZ52td6wYfB6j-YuKanRuHD4hJZPO-fN2GYe492aU4FDFVqVqC3cZcv5sZgkZolPgAhXVlQymw___vmvcodWv7xLjZBr4INpzb4FPUkaNhAd1LvF28CXHx0aNvoyyOo4i_AR1ZYBk6CbsCrVj7XxdsVmP3VBpXLSFKcit0FrWBs_sP0-g2qQDIKZ5w9HNiv4H3fU5NZ_TNKRKIQkwMJ1hvI_JbacIZ9uk2oYZ6LwV_NMeh0EqIwRg1EsH6TcdXhzLRozVa1fbej9hd2-AOGxZTba3LQtBAEKbyEATd7N5mqtEsRvcTHzXJmw";
//! use ::rsa::pkcs8::DecodePublicKey;
//!
//! let public_key =
//! "-----BEGIN PUBLIC KEY-----
//! MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyfEiSb2ElqylyAfWkbV0
//! JmKwzaYH2JtWi05dELrGpSI+OM2mNmFnpxZVUUx77GWASD+u/EbDpB7TxoL8wW6r
//! SFuduTIb63uhqeilkj6VhpPXVLpZg6m8korAXPGaN5BBMTyBAbpWk9e72z5gOGaF
//! GI4xOv0v3N0MX2h9uXJvhPTpOdKn6jXEflUFF89OWGEh/3JnyZbX5p8+F8BAuseb
//! 8gfpqT2Ct6KT5GrNiA7dPwjN7XFvVnvyYgR7+QXTVNRMrcrEUoJbR4DG+QVeyIRh
//! 0JGqXtm901cviPBRbicIMn2f8qfs15XMSeHWrgel21Cv1wQh3I4xy+soZuZZ2i/p
//! zwIDAQAB
//! -----END PUBLIC KEY-----";
//!
//! let public_key = ::rsa::RsaPublicKey::from_public_key_pem(public_key).unwrap();
//!
//! let verifier = ::rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new_with_prefix(public_key);
//! let result = min_jwt::verify(jwt, &verifier)?;
//!
//! let header = result.decode_header();
//! let claims = result.decode_claims();
//! # Ok::<(), min_jwt::Error>(())
//! # }
//! # fn main() {
//! #   #[cfg(all(feature = "rsa", feature = "sha2"))]
//! #   try_main().unwrap();
//! # }
//! ```

use crate::error::{Error, Result};

#[cfg(all(feature = "sha2", feature = "signature"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "sha2", feature = "signature"))))]
impl super::Verifier for ::rsa::pkcs1v15::VerifyingKey<sha2::Sha256> {
    fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
    where
        M: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        let signature = ::rsa::pkcs1v15::Signature::try_from(signature.as_ref())
            .map_err(|_| Error::invalid_signature())?;
        ::signature::Verifier::verify(self, message.as_ref(), &signature)
            .map_err(|_| Error::invalid_signature())
    }
}
