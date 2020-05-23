use crate::algorithm::VerifyingAlgorithm;
use crate::error::Error;
use crate::signature::{Unverified, Verified};
use crate::{Component, Token};

impl<'a, H, C> Token<H, C, Unverified<'a>>
where
    H: Component,
    C: Component,
{
    pub fn verify_with_algorithm(
        self,
        algorithm: &dyn VerifyingAlgorithm,
    ) -> Result<Token<H, C, Verified>, Error> {
        let Unverified {
            header_str,
            claims_str,
            signature_str,
        } = self.signature;

        algorithm.verify(header_str, claims_str, signature_str)?;

        Ok(Token {
            header: self.header,
            claims: self.claims,
            signature: Verified,
        })
    }
}
