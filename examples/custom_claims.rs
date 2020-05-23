extern crate hmac;
extern crate jwt;
#[macro_use]
extern crate serde_derive;
extern crate sha2;

use hmac::{Hmac, Mac};
use jwt::{parse_and_verify_with_key, Header, SignWithKey, Token};
use sha2::Sha256;
use std::default::Default;

#[derive(Default, Deserialize, Serialize)]
struct Custom {
    sub: String,
    rhino: bool,
}

fn new_token(user_id: &str, password: &str) -> Result<String, &'static str> {
    // Dummy auth
    if password != "password" {
        return Err("Wrong password");
    }

    let header: Header = Default::default();
    let claims = Custom {
        sub: user_id.into(),
        rhino: true,
        ..Default::default()
    };
    let unsigned_token = Token::new(header, claims);

    let key: Hmac<Sha256> = Hmac::new_varkey(b"secret_key").map_err(|_e| "Invalid key")?;

    let signed_token = unsigned_token
        .sign_with_key(&key)
        .map_err(|_e| "Sign error")?;
    Ok(signed_token.into())
}

fn login(token: &str) -> Result<String, &'static str> {
    let key: Hmac<Sha256> = Hmac::new_varkey(b"secret_key").map_err(|_e| "Invalid key")?;

    let token: Token<Header, Custom, _> =
        parse_and_verify_with_key(token, &key).map_err(|_e| "Verification failed")?;

    let (_, claims) = token.into();
    Ok(claims.sub)
}

fn main() {
    let token = new_token("Michael Yang", "password").unwrap();

    let logged_in_user = login(&*token).unwrap();

    assert_eq!(logged_in_user, "Michael Yang");
}
