use crate::algorithm::VerifyingAlgorithm;
use crate::error::Error;
use crate::header::{Header, JoseHeader};
use crate::signature::{Unverified, Verified};
use crate::{FromBase64, Token, SEPARATOR};

pub trait VerifyWithKey<T> {
    fn verify_with_key(self, key: &dyn VerifyingAlgorithm) -> Result<T, Error>;
}

impl<'a, H: JoseHeader, C> VerifyWithKey<Token<H, C, Verified>> for Token<H, C, Unverified<'a>> {
    fn verify_with_key(self, key: &dyn VerifyingAlgorithm) -> Result<Token<H, C, Verified>, Error> {
        let header = self.header() as &dyn JoseHeader;
        let header_algorithm = header.algorithm_type();
        let key_algorithm = key.algorithm_type();
        if header_algorithm != key_algorithm {
            return Err(Error::AlgorithmMismatch(header_algorithm, key_algorithm));
        }

        let Unverified {
            header_str,
            claims_str,
            signature_str,
        } = self.signature;

        key.verify(header_str, claims_str, signature_str)?;

        Ok(Token {
            header: self.header,
            claims: self.claims,
            signature: Verified,
        })
    }
}

impl<'a, H, C> VerifyWithKey<Token<H, C, Verified>> for &'a str
where
    H: FromBase64 + JoseHeader,
    C: FromBase64,
{
    fn verify_with_key(self, key: &dyn VerifyingAlgorithm) -> Result<Token<H, C, Verified>, Error> {
        let unverified = Token::parse_unverified(self)?;
        unverified.verify_with_key(key)
    }
}

impl<'a, C: FromBase64> VerifyWithKey<C> for &'a str {
    fn verify_with_key(self, key: &dyn VerifyingAlgorithm) -> Result<C, Error> {
        let token: Token<Header, C, _> = VerifyWithKey::verify_with_key(self, key)?;
        Ok(token.claims)
    }
}

impl<'a, H: FromBase64, C: FromBase64> Token<H, C, Unverified<'a>> {
    pub fn parse_unverified(token_str: &str) -> Result<Token<H, C, Unverified>, Error> {
        let [header_str, claims_str, signature_str] = split_components(token_str)?;
        let header = H::from_base64(header_str)?;
        let claims = C::from_base64(claims_str)?;
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
}

pub(crate) fn split_components(token: &str) -> Result<[&str; 3], Error> {
    let mut components = token.split(SEPARATOR);
    let header = components.next().ok_or(Error::Format)?;
    let claims = components.next().ok_or(Error::Format)?;
    let signature = components.next().ok_or(Error::Format)?;

    Ok([header, claims, signature])
}
