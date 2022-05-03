#[cfg(all(feature = "ring", feature = "alloc", not(feature = "std")))]
extern crate alloc;

#[cfg(all(feature = "ring", feature = "alloc", not(feature = "std")))]
use alloc::string::String;

#[cfg(all(feature = "ring", feature = "std"))]
use std::string::String;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg(feature = "ring")]
pub struct Header {
    pub typ: String,
    pub alg: String,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg(feature = "ring")]
pub struct Claims {
    pub sub: String,
    pub name: String,
    pub admin: bool,
    pub iat: u64,
}
