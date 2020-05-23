extern crate base64;
extern crate crypto_mac;
extern crate digest;
#[cfg(doctest)]
#[macro_use]
extern crate doc_comment;
extern crate hmac;
#[cfg(feature = "openssl")]
extern crate openssl;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate sha2;

#[cfg(doctest)]
doctest!("../README.md");

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::borrow::Cow;

pub use crate::algorithm::{AlgorithmType, SigningAlgorithm, VerifyingAlgorithm};
pub use crate::claims::Claims;
pub use crate::claims::RegisteredClaims;
pub use crate::error::Error;
pub use crate::header::{Header, JoseHeader};
pub use crate::signature::{Unsigned, Unverified, Verified};
pub use crate::token::legacy::Component;
pub use crate::token::signed::SignWithKey;
pub use crate::token::verified::VerifyWithKey;

pub mod algorithm;
pub mod claims;
pub mod error;
pub mod header;
pub mod legacy;
pub mod signature;
pub mod token;

const SEPARATOR: &'static str = ".";

pub struct Token<H, C, S> {
    header: H,
    claims: C,
    signature: S,
}

impl<H, C, S> Token<H, C, S> {
    pub fn header(&self) -> &H {
        &self.header
    }

    pub fn claims(&self) -> &C {
        &self.claims
    }

    pub fn remove_signature(self) -> Token<H, C, Unsigned> {
        Token {
            header: self.header,
            claims: self.claims,
            signature: Unsigned,
        }
    }
}

impl<H, C, S> Into<(H, C)> for Token<H, C, S> {
    fn into(self) -> (H, C) {
        (self.header, self.claims)
    }
}

pub trait ToBase64 {
    fn to_base64(&self) -> Result<Cow<str>, Error>;
}

impl<T: Serialize> ToBase64 for T {
    fn to_base64(&self) -> Result<Cow<str>, Error> {
        let json_bytes = serde_json::to_vec(&self)?;
        let encoded_json_bytes = base64::encode_config(&json_bytes, base64::URL_SAFE_NO_PAD);
        Ok(Cow::Owned(encoded_json_bytes))
    }
}

pub trait FromBase64: Sized {
    fn from_base64<Input: ?Sized + AsRef<[u8]>>(raw: &Input) -> Result<Self, Error>;
}

impl<T: DeserializeOwned + Sized> FromBase64 for T {
    fn from_base64<Input: ?Sized + AsRef<[u8]>>(raw: &Input) -> Result<Self, Error> {
        let json_bytes = base64::decode_config(raw, base64::URL_SAFE_NO_PAD)?;
        Ok(serde_json::from_slice(&json_bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithm::AlgorithmType::Hs256;
    use crate::header::Header;
    use crate::token::signed::SignWithKey;
    use crate::token::verified::VerifyWithKey;
    use crate::Claims;
    use crate::Token;
    use hmac::Hmac;
    use hmac::Mac;
    use sha2::Sha256;

    #[test]
    pub fn raw_data() {
        let raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let token: Token<Header, Claims, _> = Token::parse_unverified(raw).unwrap();

        assert_eq!(token.header.algorithm, Hs256);

        let verifier: Hmac<Sha256> = Hmac::new_varkey(b"secret").unwrap();
        assert!(token.verify_with_key(&verifier).is_ok());
    }

    #[test]
    pub fn roundtrip() {
        let token: Token<Header, Claims, _> = Default::default();
        let key: Hmac<Sha256> = Hmac::new_varkey(b"secret").unwrap();
        let signed_token = token.sign_with_key(&key).unwrap();
        let signed_token_str = signed_token.as_str();

        let recreated_token: Token<Header, Claims, _> =
            Token::parse_unverified(signed_token_str).unwrap();

        assert_eq!(signed_token.header(), recreated_token.header());
        assert_eq!(signed_token.claims(), recreated_token.claims());
        assert!(recreated_token.verify_with_key(&key).is_ok());
    }
}
