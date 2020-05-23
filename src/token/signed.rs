use crate::algorithm::SigningAlgorithm;
use crate::error::Error;
use crate::header::{Header, JoseHeader};
use crate::token::{Signed, Unsigned};
use crate::{ToBase64, Token, SEPARATOR};

pub trait SignWithKey<T> {
    fn sign_with_key(self, key: &dyn SigningAlgorithm) -> Result<T, Error>;
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

impl<C: ToBase64> SignWithKey<String> for C {
    fn sign_with_key(self, key: &dyn SigningAlgorithm) -> Result<String, Error> {
        let header = Header {
            algorithm: key.algorithm_type(),
            ..Default::default()
        };

        let token = Token::new(header, self).sign_with_key(key)?;
        Ok(token.signature.token_string)
    }
}

impl<H, C> SignWithKey<Token<H, C, Signed>> for Token<H, C, Unsigned>
where
    H: ToBase64 + JoseHeader,
    C: ToBase64,
{
    fn sign_with_key(self, key: &dyn SigningAlgorithm) -> Result<Token<H, C, Signed>, Error> {
        let header_algorithm = self.header.algorithm_type();
        let key_algorithm = key.algorithm_type();
        if header_algorithm != key_algorithm {
            return Err(Error::AlgorithmMismatch(header_algorithm, key_algorithm));
        }

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

#[cfg(test)]
mod tests {
    use crate::token::signed::SignWithKey;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    #[derive(Serialize)]
    struct Claims<'a> {
        name: &'a str,
    }

    #[test]
    pub fn sign_claims() {
        let claims = Claims { name: "John Doe" };
        let key: Hmac<Sha256> = Hmac::new_varkey(b"secret").unwrap();

        let signed_token = claims.sign_with_key(&key).unwrap();

        assert_eq!(signed_token, "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.LlTGHPZRXbci-y349jXXN0byQniQQqwKGybzQCFIgY0");
    }
}
