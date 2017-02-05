extern crate crypto;
extern crate jwt;

use std::default::Default;
use std::fs::File;
use std::io::{Error, Read};
use jwt::{
    Algorithm,
    DefaultHeader,
    Registered,
    Token,
};

fn load_key(keypath: &str) -> Result<String, Error> {
    let mut key_file = try!(File::open(keypath));
    let mut key = String::new();
    try!(key_file.read_to_string(&mut key));
    Ok(key)
}

fn new_token(user_id: &str, password: &str) -> Option<String> {
    // Dummy auth
    if password != "password" {
        return None
    }

    let header: DefaultHeader = DefaultHeader {
        alg: Algorithm::RS256,
        ..Default::default()
    };
    let claims = Registered {
        iss: Some("mikkyang.com".into()),
        sub: Some(user_id.into()),
        ..Default::default()
    };
    let token = Token::new(header, claims);

    token.signed(load_key("./privateKey.pem").unwrap().as_bytes()).ok()
}

fn login(token: &str) -> Option<String> {
    let token = Token::<DefaultHeader, Registered>::parse(token).unwrap();

    if token.verify(load_key("./publicKey.pub").unwrap().as_bytes()) {
        token.claims.sub
    } else {
        None
    }
}

fn main() {
    let token = new_token("Michael Yang", "password").unwrap();

    let logged_in_user = login(&*token).unwrap();

    assert_eq!(logged_in_user, "Michael Yang");
}
