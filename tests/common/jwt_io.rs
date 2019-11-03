use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Header {
    pub typ: String,
    pub alg: String,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub name: String,
    pub admin: bool,
    pub iat: u64,
}
