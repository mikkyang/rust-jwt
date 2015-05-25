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
use error::Error;
use header::Header;
use claims::Claims;

pub mod error;
pub mod header;
pub mod claims;

pub struct Token {
    raw: Option<String>,
    header: Header,
    claims: Claims,
}

impl Token {
    pub fn parse(raw: &str) -> Result<Token, Error> {
        let pieces: Vec<_> = raw.split('.').collect();

        Ok(Token {
            raw: Some(raw.into()),
            header: try!(Header::parse(pieces[0])),
            claims: try!(Claims::parse(pieces[1])),
        })
    }

    pub fn verify<D: Digest>(&self, key: &str, digest: D) -> bool {
        let raw = match self.raw {
            Some(ref s) => s,
            None => return false,
        };

        let pieces: Vec<_> = raw.rsplitn(2, '.').collect();
        let sig = pieces[0];
        let data = pieces[1];

        verify(sig, data, key, digest)
    }
}

const BASE_CONFIG: base64::Config = base64::Config {
    char_set: CharacterSet::Standard,
    newline: Newline::LF,
    pad: false,
    line_length: None,
};

fn sign<D: Digest>(data: &str, key: &str, digest: D) -> String {
    let mut hmac = Hmac::new(digest, key.as_bytes());
    hmac.input(data.as_bytes());

    let mac = hmac.result();
    let code = mac.code();
    (*code).to_base64(BASE_CONFIG)
}

fn verify<D: Digest>(target: &str, data: &str, key: &str, digest: D) -> bool {
    let target_bytes = match target.from_base64() {
        Ok(x) => x,
        Err(_) => return false,
    };
    let target_mac = MacResult::new_from_owned(target_bytes);

    let mut hmac = Hmac::new(digest, key.as_bytes());
    hmac.input(data.as_bytes());

    hmac.result() == target_mac
}

#[cfg(test)]
mod tests {
    use sign;
    use verify;
    use Token;
    use crypto::sha2::Sha256;

    #[test]
    pub fn sign_data() {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let real_sig = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let data = format!("{}.{}", header, claims);

        let sig = sign(&*data, "secret", Sha256::new());

        assert_eq!(sig, real_sig);
    }

    #[test]
    pub fn verify_data() {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let target = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let data = format!("{}.{}", header, claims);

        assert!(verify(target, &*data, "secret", Sha256::new()));
    }

    #[test]
    pub fn raw_data() {
        let raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let token = Token::parse(raw).unwrap();

        {
            assert_eq!(token.header.alg, Some("HS256".into()));
        }
        assert!(token.verify("secret", Sha256::new()));
    }
}
