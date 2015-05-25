extern crate crypto;
extern crate rustc_serialize;

use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::{
    Mac,
    MacResult,
};
use rustc_serialize::base64::{
    self,
    CharacterSet,
    FromBase64,
    Newline,
    ToBase64,
};
pub use error::Error;
pub use header::Header;
pub use claims::Claims;
pub use claims::Registered;

pub mod error;
pub mod header;
pub mod claims;

#[derive(Debug, Default)]
pub struct Token {
    raw: Option<String>,
    header: Header,
    claims: Claims,
}

impl Token {
    pub fn new(header: Header, claims: Claims) -> Token {
        Token {
            header: header,
            claims: claims,
            ..Default::default()
        }
    }

    /// Parse a token from a string.
    pub fn parse(raw: &str) -> Result<Token, Error> {
        let pieces: Vec<_> = raw.split('.').collect();

        Ok(Token {
            raw: Some(raw.into()),
            header: try!(Header::parse(pieces[0])),
            claims: try!(Claims::parse(pieces[1])),
        })
    }

    /// Verify a parsed token with a key and a given hashing algorithm.
    /// Make sure to check the token's algorithm before applying.
    pub fn verify<D: Digest>(&self, key: &[u8], digest: D) -> bool {
        let raw = match self.raw {
            Some(ref s) => s,
            None => return false,
        };

        let pieces: Vec<_> = raw.rsplitn(2, '.').collect();
        let sig = pieces[0];
        let data = pieces[1];

        verify(sig, data, key, digest)
    }

    /// Generate the signed token from a key and a given hashing algorithm.
    pub fn signed<D: Digest>(&self, key: &[u8], digest: D) -> Result<String, Error> {
        let header = try!(self.header.encode());
        let claims = try!(self.claims.encode());
        let data = format!("{}.{}", header, claims);

        let sig = sign(&*data, key, digest);
        Ok(format!("{}.{}", data, sig))
    }
}

impl PartialEq for Token {
    fn eq(&self, other: &Token) -> bool {
        self.header == other.header &&
        self.claims == other.claims
    }
}

const BASE_CONFIG: base64::Config = base64::Config {
    char_set: CharacterSet::Standard,
    newline: Newline::LF,
    pad: false,
    line_length: None,
};

fn sign<D: Digest>(data: &str, key: &[u8], digest: D) -> String {
    let mut hmac = Hmac::new(digest, key);
    hmac.input(data.as_bytes());

    let mac = hmac.result();
    let code = mac.code();
    (*code).to_base64(BASE_CONFIG)
}

fn verify<D: Digest>(target: &str, data: &str, key: &[u8], digest: D) -> bool {
    let target_bytes = match target.from_base64() {
        Ok(x) => x,
        Err(_) => return false,
    };
    let target_mac = MacResult::new_from_owned(target_bytes);

    let mut hmac = Hmac::new(digest, key);
    hmac.input(data.as_bytes());

    hmac.result() == target_mac
}

#[cfg(test)]
mod tests {
    use sign;
    use verify;
    use Token;
    use header::Algorithm::HS256;
    use crypto::sha2::Sha256;

    #[test]
    pub fn sign_data() {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let real_sig = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let data = format!("{}.{}", header, claims);

        let sig = sign(&*data, "secret".as_bytes(), Sha256::new());

        assert_eq!(sig, real_sig);
    }

    #[test]
    pub fn verify_data() {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let target = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let data = format!("{}.{}", header, claims);

        assert!(verify(target, &*data, "secret".as_bytes(), Sha256::new()));
    }

    #[test]
    pub fn raw_data() {
        let raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let token = Token::parse(raw).unwrap();

        {
            assert_eq!(token.header.alg, Some(HS256));
        }
        assert!(token.verify("secret".as_bytes(), Sha256::new()));
    }

    #[test]
    pub fn roundtrip() {
        let token: Token = Default::default();
        let key = "secret".as_bytes();
        let raw = token.signed(key, Sha256::new()).unwrap();
        let same = Token::parse(&*raw).unwrap();

        assert_eq!(token, same);
        assert!(same.verify(key, Sha256::new()));
    }
}
