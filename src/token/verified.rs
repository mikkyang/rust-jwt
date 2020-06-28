use crate::algorithm::store::Store;
use crate::algorithm::VerifyingAlgorithm;
use crate::error::Error;
use crate::header::{Header, JoseHeader};
use crate::token::{Unverified, Verified};
use crate::{FromBase64, Token, SEPARATOR};

/// Allow objects to be verified with a key.
pub trait VerifyWithKey<T> {
    fn verify_with_key(self, key: &impl VerifyingAlgorithm) -> Result<T, Error>;
}

/// Allow objects to be verified with a store.
pub trait VerifyWithStore<T> {
    fn verify_with_store<S, A>(self, store: &S) -> Result<T, Error>
    where
        S: Store<Algorithm = A>,
        A: VerifyingAlgorithm;
}

impl<'a, H: JoseHeader, C> VerifyWithKey<Token<H, C, Verified>> for Token<H, C, Unverified<'a>> {
    fn verify_with_key(
        self,
        key: &impl VerifyingAlgorithm,
    ) -> Result<Token<H, C, Verified>, Error> {
        let header = self.header();
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

impl<'a, H: JoseHeader, C> VerifyWithStore<Token<H, C, Verified>> for Token<H, C, Unverified<'a>> {
    fn verify_with_store<S, A>(self, store: &S) -> Result<Token<H, C, Verified>, Error>
    where
        S: Store<Algorithm = A>,
        A: VerifyingAlgorithm,
    {
        let header = self.header();
        let key_id = header.key_id().ok_or(Error::NoKeyId)?;
        let key = store
            .get(key_id)
            .ok_or_else(|| Error::NoKeyWithKeyId(key_id.to_owned()))?;

        self.verify_with_key(key)
    }
}

impl<'a, H, C> VerifyWithKey<Token<H, C, Verified>> for &'a str
where
    H: FromBase64 + JoseHeader,
    C: FromBase64,
{
    fn verify_with_key(
        self,
        key: &impl VerifyingAlgorithm,
    ) -> Result<Token<H, C, Verified>, Error> {
        let unverified = Token::parse_unverified(self)?;
        unverified.verify_with_key(key)
    }
}

impl<'a, H, C> VerifyWithStore<Token<H, C, Verified>> for &'a str
where
    H: FromBase64 + JoseHeader,
    C: FromBase64,
{
    fn verify_with_store<S, A>(self, store: &S) -> Result<Token<H, C, Verified>, Error>
    where
        S: Store<Algorithm = A>,
        A: VerifyingAlgorithm,
    {
        let unverified: Token<H, C, _> = Token::parse_unverified(self)?;
        unverified.verify_with_store(store)
    }
}

impl<'a, C: FromBase64> VerifyWithKey<C> for &'a str {
    fn verify_with_key(self, key: &impl VerifyingAlgorithm) -> Result<C, Error> {
        let token: Token<Header, C, _> = self.verify_with_key(key)?;
        Ok(token.claims)
    }
}

impl<'a, C: FromBase64> VerifyWithStore<C> for &'a str {
    fn verify_with_store<S, A>(self, store: &S) -> Result<C, Error>
    where
        S: Store<Algorithm = A>,
        A: VerifyingAlgorithm,
    {
        let token: Token<Header, C, _> = self.verify_with_store(store)?;
        Ok(token.claims)
    }
}

impl<'a, H: FromBase64, C: FromBase64> Token<H, C, Unverified<'a>> {
    /// Not recommended. Parse the header and claims without checking the validity of the signature.
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

#[cfg(test)]
mod tests {
    use crate::algorithm::VerifyingAlgorithm;
    use crate::error::Error;
    use crate::token::verified::VerifyWithStore;
    use hmac::{Hmac, NewMac};
    use sha2::{Sha256, Sha512};
    use std::collections::BTreeMap;

    #[derive(Deserialize)]
    struct Claims {
        name: String,
    }

    #[test]
    pub fn verify_claims_with_store() -> Result<(), Error> {
        let mut key_store = BTreeMap::new();
        let key1: Hmac<Sha256> = Hmac::new_varkey(b"first")?;
        let key2: Hmac<Sha512> = Hmac::new_varkey(b"second")?;
        key_store.insert("first_key", Box::new(key1) as Box<dyn VerifyingAlgorithm>);
        key_store.insert("second_key", Box::new(key2) as Box<dyn VerifyingAlgorithm>);

        let claims: Claims =
        "eyJhbGciOiJIUzUxMiIsImtpZCI6InNlY29uZF9rZXkifQ.eyJuYW1lIjoiSmFuZSBEb2UifQ.t2ON5s8DDb2hefBIWAe0jaEcp-T7b2Wevmj0kKJ8BFxKNQURHpdh4IA-wbmBmqtiCnqTGoRdqK45hhW0AOtz0A"
            .verify_with_store(&key_store)?;

        assert_eq!(claims.name, "Jane Doe");
        Ok(())
    }
}
