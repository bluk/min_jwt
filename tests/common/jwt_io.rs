#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Header {
    pub typ: String,
    pub alg: String,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Claims {
    pub sub: String,
    pub name: String,
    pub admin: bool,
    pub iat: u64,
}
