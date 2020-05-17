extern crate jwt;
extern crate sha2;

use jwt::{Header, RegisteredClaims, Token};
use sha2::Digest;
use sha2::Sha256;
use std::default::Default;

fn new_token(user_id: &str, password: &str) -> Option<String> {
    // Dummy auth
    if password != "password" {
        return None;
    }

    let header: Header = Default::default();
    let claims = RegisteredClaims {
        issuer: Some("mikkyang.com".into()),
        subject: Some(user_id.into()),
        ..Default::default()
    };
    let token = Token::new(header, claims);

    token.signed(b"secret_key", Sha256::new()).ok()
}

fn login(token: &str) -> Option<String> {
    let token = Token::<Header, RegisteredClaims>::parse(token).unwrap();

    if token.verify(b"secret_key", Sha256::new()) {
        token.claims.subject
    } else {
        None
    }
}

fn main() {
    let token = new_token("Michael Yang", "password").unwrap();

    let logged_in_user = login(&*token).unwrap();

    assert_eq!(logged_in_user, "Michael Yang");
}
