use crate::algorithm::VerifyingAlgorithm;
use crate::error::Error;
use crate::signature::{Unverified, Verified};
use crate::{split_components, Component, Token};
use std::convert::TryFrom;

impl<'a, H, C> Token<H, C, Unverified<'a>>
where
    H: Component,
    C: Component,
{
    pub fn verify_with_key(
        self,
        key: &dyn VerifyingAlgorithm,
    ) -> Result<Token<H, C, Verified>, Error> {
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

impl<'a, H, C> TryFrom<&'a str> for Token<H, C, Unverified<'a>>
where
    H: Component,
    C: Component,
{
    type Error = Error;

    fn try_from(token_str: &'a str) -> Result<Self, Self::Error> {
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
}
