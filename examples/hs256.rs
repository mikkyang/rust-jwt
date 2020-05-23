extern crate hmac;
extern crate jwt;
extern crate sha2;

use hmac::{Hmac, Mac};
use jwt::{parse_and_verify_with_key, Header, RegisteredClaims, SignWithKey, Token};
use sha2::Sha256;
use std::default::Default;

fn new_token(user_id: &str, password: &str) -> Result<String, &'static str> {
    // Dummy auth
    if password != "password" {
        return Err("Wrong password");
    }

    let header: Header = Default::default();
    let claims = RegisteredClaims {
        issuer: Some("mikkyang.com".into()),
        subject: Some(user_id.into()),
        ..Default::default()
    };
    let unsigned_token = Token::new(header, claims);

    let key: Hmac<Sha256> = Hmac::new_varkey(b"secret_key").map_err(|_e| "Invalid key")?;

    let signed_token = unsigned_token
        .sign_with_key(&key)
        .map_err(|_e| "Sign failed")?;

    Ok(signed_token.into())
}

fn login(token: &str) -> Result<String, &'static str> {
    let key: Hmac<Sha256> = Hmac::new_varkey(b"secret_key").map_err(|_e| "Invalid key")?;
    let token: Token<Header, RegisteredClaims, _> =
        parse_and_verify_with_key(token, &key).map_err(|_e| "Parse failed")?;

    let (_, claims) = token.into();
    claims.subject.ok_or("Missing subject")
}

fn main() {
    let token = new_token("Michael Yang", "password").unwrap();

    let logged_in_user = login(&*token).unwrap();

    assert_eq!(logged_in_user, "Michael Yang");
}
