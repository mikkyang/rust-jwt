use crate::algorithm::VerifyingAlgorithm;
use crate::error::Error;
use crate::signature::{Unverified, Verified};
use crate::{Component, Token};

/// An unverified token. It does not take ownership of the original token.
pub type UnverifiedToken<'a, H, C> = Token<H, C, Unverified<'a>>;

/// A token that has been verified.
pub type VerifiedToken<H, C> = Token<H, C, Verified>;

impl<'a, H, C> UnverifiedToken<'a, H, C>
where
    H: Component,
    C: Component,
{
    pub fn verify_with_algorithm(
        self,
        algorithm: &dyn VerifyingAlgorithm,
    ) -> Result<VerifiedToken<H, C>, Error> {
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
