extern crate base64;
extern crate ring;
extern crate serde;
extern crate serde_derive;
extern crate serde_json;

pub mod header;
pub mod signer;
pub mod verifier;

pub use error::Error;

mod error;

use error::Result;

#[derive(Debug)]
pub struct UnverifiedJwt<'a> {
    jwt: &'a str,
    header: &'a str,
    claims: &'a str,
    signed_data: &'a str,
    signature: &'a str,
}

#[derive(Debug)]
struct SplitJwt<'a> {
    header: &'a str,
    claims: &'a str,
    signed_data: &'a str,
    signature: &'a str,
}

impl<'a> UnverifiedJwt<'a> {
    pub fn with_str<'b>(jwt: &'b str) -> Result<UnverifiedJwt<'b>> {
        let split_jwt = Self::split(jwt)?;
        Ok(UnverifiedJwt {
            jwt,
            header: split_jwt.header,
            claims: split_jwt.claims,
            signed_data: split_jwt.signed_data,
            signature: split_jwt.signature,
        })
    }

    pub fn decode_header(&self) -> Result<Vec<u8>> {
        Ok(base64::decode_config(
            &self.header,
            base64::URL_SAFE_NO_PAD,
        )?)
    }

    // Should a SignatureVerifiedJwt be required before looking at the claims?
    fn decode_claims(&self) -> Result<Vec<u8>> {
        Ok(base64::decode_config(
            &self.claims,
            base64::URL_SAFE_NO_PAD,
        )?)
    }

    pub fn decode_signature(&self) -> Result<Vec<u8>> {
        Ok(base64::decode_config(
            &self.signature,
            base64::URL_SAFE_NO_PAD,
        )?)
    }

    pub fn encoded_header(&self) -> &'a str {
        &self.header
    }

    pub fn encoded_signature(&self) -> &'a str {
        &self.signature
    }

    pub fn encoded_signed_data(&self) -> &'a str {
        &self.signed_data
    }

    fn split<'b>(jwt: &'b str) -> Result<SplitJwt<'b>> {
        let mut parts = jwt.rsplitn(2, '.');
        let (signature, signed_data) = match (parts.next(), parts.next()) {
            (Some(signature), Some(signed_data)) => (signature, signed_data),
            _ => return Err(Error::malformed_jwt()),
        };

        let mut parts = signed_data.rsplitn(3, '.');
        let (claims, header) = match (parts.next(), parts.next(), parts.next()) {
            (Some(claims), Some(header), None) => (claims, header),
            _ => return Err(Error::malformed_jwt()),
        };

        Ok(SplitJwt {
            header,
            claims,
            signed_data,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{SplitJwt, UnverifiedJwt};

    #[test]
    fn test_unverified_jwt_split_normal() {
        let jwt = String::from("abc.defg.vwxyz");
        let SplitJwt {
            header,
            claims,
            signed_data,
            signature,
        } = UnverifiedJwt::split(&jwt).unwrap();

        assert_eq!("abc", header);
        assert_eq!("defg", claims);
        assert_eq!("abc.defg", signed_data);
        assert_eq!("vwxyz", signature);
    }

    #[test]
    fn test_unverified_jwt_normal_parts() {
        let jwt = String::from("abc.defg.vwxyz");
        let unverified_jwt = UnverifiedJwt::with_str(&jwt).unwrap();

        assert_eq!("abc", unverified_jwt.encoded_header());
        assert_eq!("abc.defg", unverified_jwt.encoded_signed_data());
        assert_eq!("vwxyz", unverified_jwt.encoded_signature());
    }

    #[test]
    fn test_unverified_jwt_split_no_data() {
        let jwt = String::from("..");
        let SplitJwt {
            header,
            claims,
            signed_data,
            signature,
        } = UnverifiedJwt::split(&jwt).unwrap();

        assert_eq!("", header);
        assert_eq!("", claims);
        assert_eq!(".", signed_data);
        assert_eq!("", signature);
    }

    #[test]
    fn test_unverified_jwt_no_data_parts() {
        let jwt = String::from("..");
        let unverified_jwt = UnverifiedJwt::with_str(&jwt).unwrap();

        assert_eq!("", unverified_jwt.encoded_header());
        assert_eq!(".", unverified_jwt.encoded_signed_data());
        assert_eq!("", unverified_jwt.encoded_signature());
    }

    #[test]
    fn test_unverified_jwt_split_too_many() {
        let jwt = String::from("abc.defg.lmnop.vwxyz");
        let error = UnverifiedJwt::split(&jwt).unwrap_err();
        assert!(error.is_malformed_jwt())
    }

    #[test]
    fn test_unverified_jwt_too_many_parts() {
        let jwt = String::from("abc.defg.lmnop.vwxyz");
        let error = UnverifiedJwt::with_str(&jwt).unwrap_err();
        assert!(error.is_malformed_jwt())
    }

    #[test]
    fn test_unverified_jwt_split_too_few() {
        let jwt = String::from("abc.defg");
        let error = UnverifiedJwt::split(&jwt).unwrap_err();
        assert!(error.is_malformed_jwt())
    }

    #[test]
    fn test_unverified_jwt_too_few_parts() {
        let jwt = String::from("abc.defg");
        let error = UnverifiedJwt::with_str(&jwt).unwrap_err();
        assert!(error.is_malformed_jwt())
    }
}
