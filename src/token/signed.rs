use crate::algorithm::SigningAlgorithm;
use crate::error::Error;
use crate::signature::{Signed, Unsigned};
use crate::{Component, Token, SEPARATOR};

impl<H, C> Default for Token<H, C, Unsigned>
where
    H: Default + Component,
    C: Default + Component,
{
    fn default() -> Self {
        Token::new(H::default(), C::default())
    }
}

impl<'a, H, C> Token<H, C, Unsigned>
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
    ) -> Result<Token<H, C, Signed>, Error> {
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

impl<'a, H, C> Token<H, C, Signed>
where
    H: Component,
    C: Component,
{
    pub fn as_str(&self) -> &str {
        &self.signature.token_string
    }

    pub fn remove_signature(self) -> Token<H, C, Unsigned> {
        Token {
            header: self.header,
            claims: self.claims,
            signature: Unsigned,
        }
    }
}

impl<H, C> Into<String> for Token<H, C, Signed> {
    fn into(self) -> String {
        self.signature.token_string
    }
}
