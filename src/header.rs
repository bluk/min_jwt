// use serde::Serialize;
//
// /// [JSON Web Token Header][jwt_header_spec].
// /// [jwt_header_spec]: https://tools.ietf.org/html/rfc7515#section-4.1
// #[derive(Debug, Serialize)]
// pub struct CompleteHeader {
//     /// Type
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub typ: Option<String>,
//     // /// Algorithm
//     // #[serde(skip_serializing_if = "Option::is_none")]
//     // pub alg: Option<String>,
//     /// JSON Web Token Key URL
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub jku: Option<String>,
//     /// JSON Web Token Key
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub jwk: Option<String>,
//
//     /// Key ID
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub kid: Option<String>,
//
//     /// X.509 URL
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub x5u: Option<String>,
//     /// X.509 Certificate Chain
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub x5c: Option<String>,
//     /// X.509 Certificate SHA-1 Thumbprint
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub x5t: Option<String>,
//     /// X.509 Certificate SHA-256 Thumbprint
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub x5t256: Option<String>,
//
//     /// Content Type
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub cty: Option<String>,
//
//     /// Critical
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub ctr: Option<Vec<String>>,
// }
//
// impl CompleteHeader {
//     pub fn new() -> Self {
//         CompleteHeader {
//             typ: None,
//             // alg: None,
//             jku: None,
//             jwk: None,
//             kid: None,
//             x5u: None,
//             x5c: None,
//             x5t: None,
//             x5t256: None,
//             cty: None,
//             ctr: None,
//         }
//     }
// }
