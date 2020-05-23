use crate::algorithm::{self, SigningAlgorithm, VerifyingAlgorithm};
use crate::error::Error;
use crate::{split_components, FromBase64, ToBase64, SEPARATOR};
use digest::generic_array::ArrayLength;
use digest::*;
use hmac::{Hmac, Mac};

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
    pub fn verify<D>(&self, key: &[u8], _digest: D) -> bool
    where
        D: Input
            + BlockInput
            + FixedOutput
            + Reset
            + Default
            + Clone
            + algorithm::rust_crypto::TypeLevelAlgorithmType,
        D::BlockSize: ArrayLength<u8>,
        D::OutputSize: ArrayLength<u8>,
    {
        self.raw
            .as_ref()
            .ok_or(Error::Format)
            .and_then(|token| split_components(&*token))
            .and_then(|[header, claims, signature]| {
                // This will panic for bad key sizes. Returning an error
                // would probably be better, but for now, I want to keep the
                // API as stable as possible
                let hmac = Hmac::<D>::new_varkey(key).unwrap();
                VerifyingAlgorithm::verify(&hmac, &header, &claims, &signature)
            })
            .unwrap_or(false)
    }

    /// Generate the signed token from a key and a given hashing algorithm.
    pub fn signed<D>(&self, key: &[u8], _digest: D) -> Result<String, Error>
    where
        D: Input
            + BlockInput
            + FixedOutput
            + Reset
            + Default
            + Clone
            + algorithm::rust_crypto::TypeLevelAlgorithmType,
        D::BlockSize: ArrayLength<u8>,
        D::OutputSize: ArrayLength<u8>,
    {
        let data = [self.header.to_base64()?, self.claims.to_base64()?].join(SEPARATOR);

        // This will panic for bad key sizes. Returning an error
        // would probably be better, but for now, I want to keep the
        // API as stable as possible
        let hmac = Hmac::<D>::new_varkey(key).unwrap();
        let mut components = data.split(SEPARATOR);
        let header = components.next().unwrap();
        let claims = components.next().unwrap();
        let signature = SigningAlgorithm::sign(&hmac, header, claims).unwrap();

        let signed_token = [data, signature].join(SEPARATOR);

        Ok(signed_token)
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

pub trait Component: Sized {
    fn from_base64<Input: ?Sized + AsRef<[u8]>>(raw: &Input) -> Result<Self, Error>;
    fn to_base64(&self) -> Result<String, Error>;
}

impl<T: ToBase64 + FromBase64> Component for T {
    /// Parse from a string.
    fn from_base64<Input: ?Sized + AsRef<[u8]>>(raw: &Input) -> Result<T, Error> {
        FromBase64::from_base64(raw)
    }

    /// Encode to a string.
    fn to_base64(&self) -> Result<String, Error> {
        ToBase64::to_base64(self).map(Into::<String>::into)
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithm::AlgorithmType::Hs256;
    use crate::claims::Claims;
    use crate::header::Header;
    use crate::token::legacy::Token;
    use digest::Digest;
    use sha2::Sha256;

    #[test]
    pub fn raw_data() {
        let raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let token = Token::<Header, Claims>::parse(raw).unwrap();

        {
            assert_eq!(token.header.algorithm, Hs256);
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
