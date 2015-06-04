extern crate crypto;
extern crate jwt;
extern crate rustc_serialize;

use std::default::Default;
use crypto::sha2::Sha256;
use jwt::{
    Header,
    Token,
};

#[derive(Default, RustcDecodable, RustcEncodable)]
struct Custom {
    sub: String,
    rhino: bool,
}

fn new_token(user_id: &str, password: &str) -> Option<String> {
    // Dummy auth
    if password != "password" {
        return None
    }

    let header: Header = Default::default();
    let claims = Custom {
        sub: user_id.into(),
        rhino: true,
        ..Default::default()
    };
    let token = Token::new(header, claims);

    token.signed(b"secret_key", Sha256::new()).ok()
}

fn login(token: &str) -> Option<String> {
    let token = Token::<Header, Custom>::parse(token).unwrap();

    if token.verify(b"secret_key", Sha256::new()) {
        Some(token.claims.sub)
    } else {
        None
    }
}

fn main() {
    let token = new_token("Michael Yang", "password").unwrap();

    let logged_in_user = login(&*token).unwrap();

    assert_eq!(logged_in_user, "Michael Yang");
}
