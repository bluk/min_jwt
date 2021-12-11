//! Sign JWTs using various signature algorithms.
//!
//! See the tests for how to use a specific signing algorithm.

use crate::error::Result;

pub trait Signature: AsRef<[u8]> {}

impl Signature for Vec<u8> {}

pub trait SigningKey {
    const ALG: &'static str;

    type Signature: Signature;

    fn sign(&self, bytes: &[u8]) -> Result<Self::Signature>;
}

#[derive(Debug)]
pub struct Signer<T>
where
    T: SigningKey,
{
    key: T,
}

impl<T> Signer<T>
where
    T: SigningKey,
{
    #[cfg(feature = "serde_json")]
    #[inline]
    pub fn encode_and_sign<H, C>(&self, header: H, claims: C) -> Result<String>
    where
        H: crate::Header + serde::Serialize,
        C: crate::Claims + serde::Serialize,
    {
        let header = serde_json::to_vec(&header).unwrap();
        let claims = serde_json::to_vec(&claims).unwrap();
        self.encode_and_sign_json(header, claims)
    }

    #[inline]
    pub fn encode_and_sign_json<H, C>(&self, header: H, claims: C) -> Result<String>
    where
        H: AsRef<[u8]>,
        C: AsRef<[u8]>,
    {
        let encoded_header = base64::encode_config(header, base64::URL_SAFE_NO_PAD);
        let encoded_claims = base64::encode_config(claims, base64::URL_SAFE_NO_PAD);
        let data_to_sign = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");

        let signature = self.key.sign(data_to_sign.as_bytes())?;
        let signature = signature.as_ref();
        let signature = base64::encode_config(&signature, base64::URL_SAFE_NO_PAD);

        Ok([data_to_sign, signature].join("."))
    }
}

#[cfg(feature = "p256")]
mod p256 {
    use crate::error::Result;

    impl super::Signature for p256::ecdsa::Signature {}

    impl super::SigningKey for p256::ecdsa::SigningKey {
        const ALG: &'static str = "ES256";

        type Signature = p256::ecdsa::Signature;

        fn sign(&self, bytes: &[u8]) -> Result<Self::Signature> {
            Ok(p256::ecdsa::signature::Signer::sign(self, bytes))
        }
    }

    impl From<p256::ecdsa::SigningKey> for super::Signer<p256::ecdsa::SigningKey> {
        fn from(key: p256::ecdsa::SigningKey) -> Self {
            Self { key }
        }
    }

    impl<'a> super::SigningKey for &'a p256::ecdsa::SigningKey {
        const ALG: &'static str = "ES256";

        type Signature = p256::ecdsa::Signature;

        fn sign(&self, bytes: &[u8]) -> Result<Self::Signature> {
            Ok(p256::ecdsa::signature::Signer::sign(*self, bytes))
        }
    }

    impl<'a> From<&'a p256::ecdsa::SigningKey> for super::Signer<&'a p256::ecdsa::SigningKey> {
        fn from(key: &'a p256::ecdsa::SigningKey) -> Self {
            Self { key }
        }
    }

    #[cfg(test)]
    mod test {
        use crate::signer::*;

        const CLAIMS: &str =
            "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true,\"iat\":1516239022}";

        #[test]
        fn test_rust_crypto_p256() {
            const HEADER: &str = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";

            let rng = rand::thread_rng();
            let signer = Signer::from(::p256::ecdsa::SigningKey::random(rng));

            let signers = vec![
                Signer::from(::p256::ecdsa::SigningKey::random(rand::thread_rng())),
                Signer::from(::p256::ecdsa::SigningKey::random(rand::thread_rng())),
                Signer::from(::p256::ecdsa::SigningKey::random(rand::thread_rng())),
            ];

            // assert_eq!("", signer.encode_and_sign_json(HEADER, CLAIMS).unwrap());
        }
    }
}

#[cfg(feature = "ring")]
pub mod ring {
    use crate::{
        algorithm::{Algorithm, Es256, Es384, Hs256, Hs384, Hs512, Rs256},
        error::{Error, Result},
    };
    use ring::rand::SecureRandom;

    impl super::Signature for ::ring::signature::Signature {}
    impl super::Signature for ::ring::hmac::Tag {}

    #[derive(Debug)]
    pub struct EcdsaKeyPair<R, A>
    where
        R: SecureRandom,
        A: Algorithm,
    {
        key_pair: ::ring::signature::EcdsaKeyPair,
        secure_random: R,
        alg: std::marker::PhantomData<A>,
    }

    macro_rules! ecdsa_impl {
        ($alg:ty, $alg_str:expr) => {
            impl<R> super::SigningKey for EcdsaKeyPair<R, $alg>
            where
                R: SecureRandom,
            {
                const ALG: &'static str = $alg_str;

                type Signature = ring::signature::Signature;

                fn sign(&self, bytes: &[u8]) -> Result<Self::Signature> {
                    self.key_pair
                        .sign(&self.secure_random, bytes)
                        .map_err(|_| todo!())
                }
            }

            impl<R> From<EcdsaKeyPair<R, $alg>> for super::Signer<EcdsaKeyPair<R, $alg>>
            where
                R: SecureRandom,
            {
                fn from(key: EcdsaKeyPair<R, $alg>) -> Self {
                    Self { key }
                }
            }

            impl<R> super::SigningKey for &EcdsaKeyPair<R, $alg>
            where
                R: SecureRandom,
            {
                const ALG: &'static str = $alg_str;

                type Signature = ring::signature::Signature;

                fn sign(&self, bytes: &[u8]) -> Result<Self::Signature> {
                    self.key_pair
                        .sign(&self.secure_random, bytes)
                        .map_err(|_| todo!())
                }
            }

            impl<'a, R> From<&'a EcdsaKeyPair<R, $alg>> for super::Signer<&'a EcdsaKeyPair<R, $alg>>
            where
                R: SecureRandom,
            {
                fn from(key: &'a EcdsaKeyPair<R, $alg>) -> Self {
                    Self { key }
                }
            }
        };
    }

    ecdsa_impl!(Es256, "ES256");
    ecdsa_impl!(Es384, "ES384");

    impl<R> EcdsaKeyPair<R, Es256>
    where
        R: SecureRandom,
    {
        /// Signs header and claims parts with an ECDSA key.
        ///
        /// ```
        /// # use min_jwt::Error;
        /// #
        /// # fn try_main() -> Result<(), Error> {
        /// use min_jwt::signer::{ring::EcdsaKeyPair, Signer};
        /// use ring::{rand::SystemRandom};
        ///
        /// let sys_rand = SystemRandom::new();
        ///
        /// let header = String::from("{\"alg\":\"ES256\",\"typ\":\"JWT\"}");
        /// let claims = String::from("{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true,\"iat\":1516239022}");
        ///
        /// // Normally the key's bytes are read from a file or another data store
        /// // and should not be randomly generated on every invocation
        /// let pkcs8_bytes = ::ring::signature::EcdsaKeyPair::generate_pkcs8(
        ///   &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        ///   &sys_rand
        /// )?;
        /// let key_pair = ::ring::signature::EcdsaKeyPair::from_pkcs8(
        ///   &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        ///   pkcs8_bytes.as_ref()
        /// )?;
        ///
        /// let signing_key = EcdsaKeyPair::with_es256(key_pair, sys_rand);
        /// let signer = Signer::from(signing_key);
        ///
        /// /* the header and claims could be serialized by Serde */
        /// /* in the end, the serialized JSON should be referenced as either &str or &[u8] */
        ///
        /// let jwt = signer.encode_and_sign_json(&header, &claims)?;
        ///
        /// #   Ok(())
        /// # }
        /// # fn main() {
        /// #   try_main().unwrap();
        /// # }
        /// ```
        pub fn with_es256(
            key_pair: ::ring::signature::EcdsaKeyPair,
            secure_random: R,
        ) -> EcdsaKeyPair<R, Es256> {
            Self {
                key_pair,
                secure_random,
                alg: std::marker::PhantomData::<Es256>::default(),
            }
        }
    }

    impl<R> EcdsaKeyPair<R, Es384>
    where
        R: SecureRandom,
    {
        pub fn with_es384(
            key_pair: ::ring::signature::EcdsaKeyPair,
            secure_random: R,
        ) -> EcdsaKeyPair<R, Es384> {
            Self {
                key_pair,
                secure_random,
                alg: std::marker::PhantomData::<Es384>::default(),
            }
        }
    }

    #[derive(Debug)]
    pub struct HmacKey<A>
    where
        A: Algorithm,
    {
        key: ::ring::hmac::Key,
        alg: std::marker::PhantomData<A>,
    }

    macro_rules! hmac_impl {
        ($alg:ty, $alg_str:expr) => {
            impl super::SigningKey for HmacKey<$alg> {
                const ALG: &'static str = $alg_str;

                type Signature = ::ring::hmac::Tag;

                fn sign(&self, bytes: &[u8]) -> Result<Self::Signature> {
                    Ok(::ring::hmac::sign(&self.key, bytes))
                }
            }

            impl From<HmacKey<$alg>> for super::Signer<HmacKey<$alg>> {
                fn from(key: HmacKey<$alg>) -> Self {
                    Self { key }
                }
            }

            impl super::SigningKey for &HmacKey<$alg> {
                const ALG: &'static str = $alg_str;

                type Signature = ::ring::hmac::Tag;

                fn sign(&self, bytes: &[u8]) -> Result<Self::Signature> {
                    Ok(::ring::hmac::sign(&self.key, bytes))
                }
            }

            impl<'a> From<&'a HmacKey<$alg>> for super::Signer<&'a HmacKey<$alg>> {
                fn from(key: &'a HmacKey<$alg>) -> Self {
                    Self { key }
                }
            }
        };
    }

    hmac_impl!(Hs256, "HS256");
    hmac_impl!(Hs384, "HS384");
    hmac_impl!(Hs512, "HS512");

    impl HmacKey<Hs256> {
        /// Signs header and claims parts with a HMAC secret key.
        ///
        /// ```
        /// # use min_jwt::Error;
        /// #
        /// # fn try_main() -> Result<(), Error> {
        /// use min_jwt::signer::{ring::HmacKey, Signer};
        /// use ring::hmac::{Key, self};
        ///
        /// let header = String::from("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        /// let claims = String::from("{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true,\"iat\":1516239022}");
        ///
        /// let hmac_key = String::from("your-secret-key");
        /// let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &hmac_key.as_bytes());
        /// let hmac_key = HmacKey::with_hs256(hmac_key);
        /// let signer = Signer::from(hmac_key);
        ///
        /// /* the header and claims could be serialized by Serde */
        /// /* in the end, the serialized JSON should be referenced as either &str or &[u8] */
        ///
        /// let jwt = signer.encode_and_sign_json(&header, &claims)?;
        ///
        /// #   Ok(())
        /// # }
        /// # fn main() {
        /// #   try_main().unwrap();
        /// # }
        /// ```
        pub fn with_hs256(key: ::ring::hmac::Key) -> HmacKey<Hs256> {
            Self {
                key,
                alg: std::marker::PhantomData::<Hs256>::default(),
            }
        }
    }

    impl HmacKey<Hs384> {
        pub fn with_hs384(key: ::ring::hmac::Key) -> HmacKey<Hs384> {
            Self {
                key,
                alg: std::marker::PhantomData::<Hs384>::default(),
            }
        }
    }

    impl HmacKey<Hs512> {
        pub fn with_hs512(key: ::ring::hmac::Key) -> HmacKey<Hs512> {
            Self {
                key,
                alg: std::marker::PhantomData::<Hs512>::default(),
            }
        }
    }

    #[derive(Debug)]
    pub struct RsaKeyPair<R, A>
    where
        R: SecureRandom,
        A: Algorithm,
    {
        key_pair: ::ring::signature::RsaKeyPair,
        secure_random: R,
        alg: std::marker::PhantomData<A>,
    }

    macro_rules! rsa_impl {
        ($alg:ty, $alg_str:expr, $ring_alg:expr) => {
            impl<R> super::SigningKey for RsaKeyPair<R, $alg>
            where
                R: SecureRandom,
            {
                const ALG: &'static str = $alg_str;

                type Signature = Vec<u8>;

                fn sign(&self, bytes: &[u8]) -> Result<Self::Signature> {
                    let mut signature = vec![0; self.key_pair.public_modulus_len()];
                    self.key_pair
                        .sign(&$ring_alg, &self.secure_random, bytes, &mut signature)
                        .map_err(|_| Error::invalid_signature())?;
                    Ok(signature)
                }
            }

            impl<R> From<RsaKeyPair<R, $alg>> for super::Signer<RsaKeyPair<R, $alg>>
            where
                R: SecureRandom,
            {
                fn from(key: RsaKeyPair<R, $alg>) -> Self {
                    Self { key }
                }
            }

            impl<R> super::SigningKey for &RsaKeyPair<R, $alg>
            where
                R: SecureRandom,
            {
                const ALG: &'static str = $alg_str;

                type Signature = Vec<u8>;

                fn sign(&self, bytes: &[u8]) -> Result<Self::Signature> {
                    let mut signature = vec![0; self.key_pair.public_modulus_len()];
                    self.key_pair
                        .sign(&$ring_alg, &self.secure_random, bytes, &mut signature)
                        .map_err(|_| Error::invalid_signature())?;
                    Ok(signature)
                }
            }

            impl<'a, R> From<&'a RsaKeyPair<R, $alg>> for super::Signer<&'a RsaKeyPair<R, $alg>>
            where
                R: SecureRandom,
            {
                fn from(key: &'a RsaKeyPair<R, $alg>) -> Self {
                    Self { key }
                }
            }
        };
    }

    rsa_impl!(Rs256, "RS256", ring::signature::RSA_PKCS1_SHA256);

    impl<R> RsaKeyPair<R, Rs256>
    where
        R: SecureRandom,
    {
        /// Signs header and claims parts with an RSA key.
        pub fn with_rs256(
            key_pair: ::ring::signature::RsaKeyPair,
            secure_random: R,
        ) -> RsaKeyPair<R, Rs256> {
            Self {
                key_pair,
                secure_random,
                alg: std::marker::PhantomData::<Rs256>::default(),
            }
        }
    }

    #[cfg(test)]
    mod test {
        use super::{super::*, EcdsaKeyPair};

        const HEADER: &str = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
        const CLAIMS: &str =
            "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true,\"iat\":1516239022}";

        #[test]
        fn test_ring_ecdsa_key_pair() {
            let secure_random = ::ring::rand::SystemRandom::new();
            let key_pair = ::ring::signature::EcdsaKeyPair::from_pkcs8(
                &::ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                ::ring::signature::EcdsaKeyPair::generate_pkcs8(
                    &::ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    &secure_random,
                )
                .unwrap()
                .as_ref(),
            )
            .unwrap();

            let key_pair_with_rand = EcdsaKeyPair::with_es256(key_pair, secure_random);
            let signer = Signer::from(&key_pair_with_rand);
            // assert_eq!("", signer.encode_and_sign_json(HEADER, CLAIMS).unwrap());
        }
    }
}
