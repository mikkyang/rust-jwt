use crate::algorithm::SigningAlgorithm;
use crate::error::Error;
use crate::header::Header;
use crate::signature::{Signed, Unsigned};
use crate::{ToBase64, Token, SEPARATOR};

pub trait SignWithKey {
    type Output;

    fn sign_with_key(self, key: &dyn SigningAlgorithm) -> Result<Self::Output, Error>;
}

impl<H, C> Token<H, C, Unsigned> {
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
}

impl<H, C> Default for Token<H, C, Unsigned>
where
    H: Default,
    C: Default,
{
    fn default() -> Self {
        Token::new(H::default(), C::default())
    }
}

impl<H, C> SignWithKey for Token<H, C, Unsigned>
where
    H: ToBase64,
    C: ToBase64,
{
    type Output = Token<H, C, Signed>;

    fn sign_with_key(self, key: &dyn SigningAlgorithm) -> Result<Self::Output, Error> {
        let header = self.header.to_base64()?;
        let claims = self.claims.to_base64()?;
        let signature = key.sign(&header, &claims)?;

        let token_string = [&*header, &*claims, &signature].join(SEPARATOR);

        Ok(Token {
            header: self.header,
            claims: self.claims,
            signature: Signed { token_string },
        })
    }
}

impl<'a, H, C> Token<H, C, Signed> {
    pub fn as_str(&self) -> &str {
        &self.signature.token_string
    }
}

impl<H, C> Into<String> for Token<H, C, Signed> {
    fn into(self) -> String {
        self.signature.token_string
    }
}
