extern crate base64;
extern crate crypto_mac;
extern crate digest;
extern crate hmac;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate sha2;

use serde::Serialize;
use serde::de::DeserializeOwned;

use digest::generic_array::ArrayLength;
use digest::*;

pub use crate::error::Error;
pub use crate::header::Header;
pub use crate::claims::Claims;
pub use crate::claims::Registered;

pub mod error;
pub mod header;
pub mod claims;
mod crypt;

#[derive(Debug, Default)]
pub struct Token<H, C>
where
    H: Component,
    C: Component,
{
    raw: Option<String>,
    pub header: H,
    pub claims: C,
}

const SEPARATOR: char = '.';

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

impl<H, C> Token<H, C>
where
    H: Component,
    C: Component,
{
    pub fn new(header: H, claims: C) -> Token<H, C> {
        Token {
            raw: None,
            header: header,
            claims: claims,
        }
    }

    /// Parse a token from a string.
    pub fn parse(raw: &str) -> Result<Token<H, C>, Error> {
        let components: Vec<_> = raw.split(SEPARATOR).collect();
        let (header, claims) = match &*components {
            [header, claims, _signature] => (
                Component::from_base64(header)?,
                Component::from_base64(claims)?,
            ),
            _ => return Err(Error::Format),
        };

        Ok(Token {
            raw: Some(raw.into()),
            header,
            claims,
        })
    }

    /// Verify a from_base64d token with a key and a given hashing algorithm.
    /// Make sure to check the token's algorithm before applying.
    pub fn verify<D>(&self, key: &[u8], digest: D) -> bool
    where
        D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
        D::BlockSize: ArrayLength<u8>,
        D::OutputSize: ArrayLength<u8>,
    {
        let raw = match self.raw {
            Some(ref s) => s,
            None => return false,
        };

        let components: Vec<_> = raw.rsplitn(2, SEPARATOR).collect();
        let (signature, payload) = match &*components {
            [s, p] => (s, p),
            _ => return false,
        };

        crypt::verify(signature, payload, key, digest)
    }

    /// Generate the signed token from a key and a given hashing algorithm.
    pub fn signed<D>(&self, key: &[u8], digest: D) -> Result<String, Error>
    where
        D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
        D::BlockSize: ArrayLength<u8>,
        D::OutputSize: ArrayLength<u8>,
    {
        let header = self.header.to_base64()?;
        let claims = self.claims.to_base64()?;
        let data = format!("{}.{}", header, claims);

        let sig = crypt::sign(&*data, key, digest);
        Ok(format!("{}.{}", data, sig))
    }
}

impl<H, C> PartialEq for Token<H, C>
where
    H: Component + PartialEq,
    C: Component + PartialEq,
{
    fn eq(&self, other: &Token<H, C>) -> bool {
        self.header == other.header && self.claims == other.claims
    }
}

#[cfg(test)]
mod tests {
    use crate::crypt::{sign, verify};
    use crate::Claims;
    use crate::Token;
    use digest::Digest;
    use crate::header::Algorithm::HS256;
    use crate::header::Header;
    use sha2::Sha256;

    #[test]
    pub fn sign_data() {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let real_sig = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let data = format!("{}.{}", header, claims);

        let sig = sign(&*data, "secret".as_bytes(), Sha256::new());

        assert_eq!(sig, real_sig);
    }

    #[test]
    pub fn verify_data() {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let target = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let data = format!("{}.{}", header, claims);

        assert!(verify(target, &*data, "secret".as_bytes(), Sha256::new()));
    }

    #[test]
    pub fn raw_data() {
        let raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let token = Token::<Header, Claims>::parse(raw).unwrap();

        {
            assert_eq!(token.header.alg, HS256);
        }
        assert!(token.verify("secret".as_bytes(), Sha256::new()));
    }

    #[test]
    pub fn roundtrip() {
        let token: Token<Header, Claims> = Default::default();
        let key = "secret".as_bytes();
        let raw = token.signed(key, Sha256::new()).unwrap();
        let same = Token::parse(&*raw).unwrap();

        assert_eq!(token, same);
        assert!(same.verify(key, Sha256::new()));
    }
}
