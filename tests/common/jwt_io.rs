#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg(feature = "ring")]
pub struct Header {
    pub typ: String,
    pub alg: String,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg(feature = "ring")]
pub struct Claims {
    pub sub: String,
    pub name: String,
    pub admin: bool,
    pub iat: u64,
}
