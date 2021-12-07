pub mod jwk;
pub mod pkcs8;

use jwk::{Jwk, JwkSet};

use crate::{Header, UnverifiedJwt};

#[derive(Debug)]
pub struct Keys<T> {
    keys: T,
}

impl Keys<JwkSet> {
    pub fn with_keys(keys: JwkSet) -> Self {
        Self { keys }
    }

    pub fn len(&self) -> usize {
        self.keys.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.keys.is_empty()
    }

    pub fn signing_keys(&self) -> impl Iterator<Item = &Jwk> {
        self.keys.signing_keys()
    }

    #[cfg(feature = "serde_json")]
    pub fn find_signing_key(&self, jwt: UnverifiedJwt) -> Option<&Jwk> {
        let header = jwt.decode_header().ok()?;
        let header = serde_json::from_slice::<Header>(&header).ok()?;
        let alg = header.alg();
        let kid = header.kid();

        self.keys
            .signing_keys()
            .find(|&jwk| jwk.alg.as_deref() == Some(alg) && jwk.kid.as_deref() == Some(kid))
    }
}
