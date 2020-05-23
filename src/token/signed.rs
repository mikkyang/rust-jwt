use crate::algorithm::SigningAlgorithm;
use crate::error::Error;
use crate::signature::{Signed, Unsigned};
use crate::{Component, Token, SEPARATOR};

/// A completely unsigned token. Will have mutable header and claims fields.
pub type UnsignedToken<H, C> = Token<H, C, Unsigned>;

/// A signed token. In order to modify the header or claims, the signature must
/// be removed.
pub type SignedToken<H, C> = Token<H, C, Signed>;

impl<H, C> Default for UnsignedToken<H, C>
where
    H: Default + Component,
    C: Default + Component,
{
    fn default() -> Self {
        Token::new(H::default(), C::default())
    }
}

impl<'a, H, C> UnsignedToken<H, C>
where
    H: Component,
    C: Component,
{
    pub fn new(header: H, claims: C) -> Self {
        Token {
            header,
            claims,
            signature: Unsigned,
        }
    }

    pub fn header_mut(&mut self) -> &mut H {
        &mut self.header
    }

    pub fn claims_mut(&mut self) -> &mut C {
        &mut self.claims
    }

    pub fn sign_with_algorithm(
        self,
        algorithm: &dyn SigningAlgorithm,
    ) -> Result<SignedToken<H, C>, Error> {
        let header = self.header.to_base64()?;
        let claims = self.claims.to_base64()?;
        let signature = algorithm.sign(&header, &claims)?;

        let token_string = [header, claims, signature].join(SEPARATOR);

        Ok(Token {
            header: self.header,
            claims: self.claims,
            signature: Signed { token_string },
        })
    }
}

impl<'a, H, C> SignedToken<H, C>
where
    H: Component,
    C: Component,
{
    pub fn as_str(&self) -> &str {
        &self.signature.token_string
    }
}

impl<H, C> Into<String> for SignedToken<H, C> {
    fn into(self) -> String {
        self.signature.token_string
    }
}
