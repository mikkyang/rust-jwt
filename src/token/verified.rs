use crate::algorithm::VerifyingAlgorithm;
use crate::error::Error;
use crate::signature::{Unverified, Verified};
use crate::Token;

pub trait VerifyWithKey {
    type Output;

    fn verify_with_key(self, key: &dyn VerifyingAlgorithm) -> Result<Self::Output, Error>;
}

impl<'a, H, C> VerifyWithKey for Token<H, C, Unverified<'a>> {
    type Output = Token<H, C, Verified>;

    fn verify_with_key(self, key: &dyn VerifyingAlgorithm) -> Result<Self::Output, Error> {
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
