extern crate base64;
extern crate crypto_mac;
extern crate digest;
extern crate hmac;
#[cfg(feature = "openssl")]
extern crate openssl;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate sha2;

use serde::de::DeserializeOwned;
use serde::Serialize;

pub use crate::algorithm::{AlgorithmType, SigningAlgorithm, VerifyingAlgorithm};
pub use crate::claims::Claims;
pub use crate::claims::RegisteredClaims;
pub use crate::error::Error;
pub use crate::header::Header;
pub use crate::signature::{Unverified, Verified};

pub mod algorithm;
pub mod claims;
pub mod error;
pub mod header;
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
}

impl<H, C, S> Into<(H, C)> for Token<H, C, S> {
    fn into(self) -> (H, C) {
        (self.header, self.claims)
    }
}

pub trait Component: Sized {
    fn from_base64<Input: ?Sized + AsRef<[u8]>>(raw: &Input) -> Result<Self, Error>;
    fn to_base64(&self) -> Result<String, Error>;
}

impl<T> Component for T
where
    T: Serialize + DeserializeOwned + Sized,
{
    /// Parse from a string.
    fn from_base64<Input: ?Sized + AsRef<[u8]>>(raw: &Input) -> Result<T, Error> {
        let json_bytes = base64::decode_config(raw, base64::URL_SAFE_NO_PAD)?;
        Ok(serde_json::from_slice(&json_bytes)?)
    }

    /// Encode to a string.
    fn to_base64(&self) -> Result<String, Error> {
        let json_bytes = serde_json::to_vec(&self)?;
        let encoded_json_bytes = base64::encode_config(&json_bytes, base64::URL_SAFE_NO_PAD);
        Ok(encoded_json_bytes)
    }
}

pub fn parse_unverified<H, C>(token_str: &str) -> Result<Token<H, C, Unverified>, Error>
where
    H: Component,
    C: Component,
{
    let [header_str, claims_str, signature_str] = split_components(token_str)?;
    let header = Component::from_base64(header_str)?;
    let claims = Component::from_base64(claims_str)?;
    let signature = Unverified {
        header_str,
        claims_str,
        signature_str,
    };

    Ok(Token {
        header,
        claims,
        signature,
    })
}

pub fn parse_and_verify_with_key<H, C>(
    token_str: &str,
    key: &dyn VerifyingAlgorithm,
) -> Result<Token<H, C, Verified>, Error>
where
    H: Component,
    C: Component,
{
    let unverifed = parse_unverified(token_str)?;
    unverifed.verify_with_key(key)
}

fn split_components(token: &str) -> Result<[&str; 3], Error> {
    let mut components = token.split(SEPARATOR);
    let header = components.next().ok_or(Error::Format)?;
    let claims = components.next().ok_or(Error::Format)?;
    let signature = components.next().ok_or(Error::Format)?;

    Ok([header, claims, signature])
}

#[cfg(test)]
mod tests {
    use crate::algorithm::AlgorithmType::Hs256;
    use crate::header::Header;
    use crate::parse_unverified;
    use crate::Claims;
    use crate::Token;
    use hmac::Hmac;
    use hmac::Mac;
    use sha2::Sha256;

    #[test]
    pub fn raw_data() {
        let raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let token: Token<Header, Claims, _> = parse_unverified(raw).unwrap();

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

        let recreated_token: Token<Header, Claims, _> = parse_unverified(signed_token_str).unwrap();

        assert_eq!(signed_token.header(), recreated_token.header());
        assert_eq!(signed_token.claims(), recreated_token.claims());
        assert!(recreated_token.verify_with_key(&key).is_ok());
    }
}
