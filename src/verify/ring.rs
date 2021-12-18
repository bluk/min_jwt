use crate::{
    algorithm::{Algorithm, Es256, Hs256, Rs256},
    error::{Error, Result},
};
use core::marker::PhantomData;

mod private {
    pub trait Private {}

    impl<T> Private for &T where T: Private {}
}

impl<B> private::Private for ::ring::signature::UnparsedPublicKey<B> where B: AsRef<[u8]> {}

macro_rules! key_verifier {
    ($verifier_name:ident, $key_name:ident) => {
        pub trait $key_name: private::Private {
            fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
            where
                M: AsRef<[u8]>,
                S: AsRef<[u8]>;
        }

        impl<T> $key_name for &T
        where
            T: $key_name,
        {
            fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
            where
                M: AsRef<[u8]>,
                S: AsRef<[u8]>,
            {
                T::verify(self, message, signature)
            }
        }

        impl<B> $key_name for ::ring::signature::UnparsedPublicKey<B>
        where
            B: AsRef<[u8]>,
        {
            fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
            where
                M: AsRef<[u8]>,
                S: AsRef<[u8]>,
            {
                ::ring::signature::UnparsedPublicKey::verify(
                    self,
                    message.as_ref(),
                    signature.as_ref(),
                )
                .map_err(|_| Error::invalid_signature())
            }
        }

        pub struct $verifier_name<K, A>
        where
            K: $key_name,
            A: Algorithm,
        {
            key: K,
            algorithm: PhantomData<A>,
        }

        impl<K, A> $verifier_name<K, A>
        where
            K: $key_name,
            A: Algorithm,
        {
            pub fn into_inner(self) -> K {
                self.key
            }
        }

        impl<K, A> super::Verifier for $verifier_name<K, A>
        where
            K: $key_name,
            A: Algorithm,
        {
            fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
            where
                M: AsRef<[u8]>,
                S: AsRef<[u8]>,
            {
                self.key.verify(message, signature)
            }
        }

        impl<K, A> super::private::Private for $verifier_name<K, A>
        where
            K: $key_name,
            A: Algorithm,
        {
        }
    };
}

key_verifier!(EcdsaKeyVerifier, EcdsaKey);

impl<K> EcdsaKeyVerifier<K, Es256>
where
    K: EcdsaKey,
{
    pub fn with_es256(key: K) -> EcdsaKeyVerifier<K, Es256> {
        Self {
            key,
            algorithm: PhantomData::default(),
        }
    }
}

key_verifier!(RsaKeyVerifier, RsaKey);

impl<K> RsaKeyVerifier<K, Rs256>
where
    K: RsaKey,
{
    pub fn with_rs256(key: K) -> RsaKeyVerifier<K, Rs256> {
        Self {
            key,
            algorithm: PhantomData::default(),
        }
    }
}

pub trait HmacKey: private::Private {
    fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
    where
        M: AsRef<[u8]>,
        S: AsRef<[u8]>;
}

impl<T> HmacKey for &T
where
    T: HmacKey,
{
    fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
    where
        M: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        T::verify(self, message, signature)
    }
}

impl HmacKey for ::ring::hmac::Key {
    fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
    where
        M: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        ::ring::hmac::verify(self, message.as_ref(), signature.as_ref())
            .map_err(|_| Error::invalid_signature())
    }
}
impl private::Private for ::ring::hmac::Key {}

pub struct HmacKeyVerifier<K, A>
where
    K: HmacKey,
    A: Algorithm,
{
    key: K,
    algorithm: PhantomData<A>,
}

impl<K, A> HmacKeyVerifier<K, A>
where
    K: HmacKey,
    A: Algorithm,
{
    pub fn into_inner(self) -> K {
        self.key
    }
}

impl<K, A> super::Verifier for HmacKeyVerifier<K, A>
where
    K: HmacKey,
    A: Algorithm,
{
    fn verify<M, S>(&self, message: M, signature: S) -> Result<()>
    where
        M: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        self.key.verify(message, signature)
    }
}

impl<K, A> super::private::Private for HmacKeyVerifier<K, A>
where
    K: HmacKey,
    A: Algorithm,
{
}

impl<K> HmacKeyVerifier<K, Hs256>
where
    K: HmacKey,
{
    pub fn with_hs256(key: K) -> HmacKeyVerifier<K, Hs256> {
        Self {
            key,
            algorithm: PhantomData::default(),
        }
    }
}
