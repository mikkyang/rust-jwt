use crate::algorithm::VerifyingAlgorithm;
use crate::error::Error;
use crate::signature::{Unverified, Verified};
use crate::{split_components, FromBase64, Token};

pub trait VerifyWithKey<T> {
    fn verify_with_key(self, key: &dyn VerifyingAlgorithm) -> Result<T, Error>;
}

impl<'a, H, C> VerifyWithKey<Token<H, C, Verified>> for Token<H, C, Unverified<'a>> {
    fn verify_with_key(self, key: &dyn VerifyingAlgorithm) -> Result<Token<H, C, Verified>, Error> {
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

impl<'a, H: FromBase64, C: FromBase64> VerifyWithKey<Token<H, C, Verified>> for &'a str {
    fn verify_with_key(self, key: &dyn VerifyingAlgorithm) -> Result<Token<H, C, Verified>, Error> {
        let unverified = Token::parse_unverified(self)?;
        unverified.verify_with_key(key)
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
