extern crate crypto;
extern crate rustc_serialize;

use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use rustc_serialize::base64::{
    self,
    CharacterSet,
    Newline,
    ToBase64,
};
use header::Header;
use claims::Claims;

pub mod error;
pub mod header;
pub mod claims;

pub struct Token {
    header: Header,
    claims: Claims,
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

#[cfg(test)]
mod tests {
    use sign;
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
}
