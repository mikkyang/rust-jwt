extern crate crypto;
extern crate jwt;

use std::default::Default;
use jwt::{
    Header,
    Registered,
    Token,
};
use std::fs::File;
use std::io::Read;

fn new_token(user_id: &str) -> Option<String> {

	/* TODO: Run these commands:
			 $ mkdir -p examples/keys
			 $ openssl genrsa -out examples/keys/key.rsa 2048
			 $ openssl rsa -in examples/keys/key.rsa -pubout > examples/keys/key.rsa.pub
	*/
	match File::open("keys/key.rsa") {
		Ok(mut f) => {
			let mut s = String::new();
			f.read_to_string(&mut s).unwrap();
			let header = Header{
				typ: Some(jwt::header::HeaderType::JWT),
				kid: None,
				alg: jwt::header::Algorithm::RS256,
			};
		    let claims = Registered {
		        iss: Some("mikkyang.com".into()),
		        sub: Some(user_id.into()),
		        ..Default::default()
		    };
		    let token = Token::new(header, claims);
		    Some(token.sign_rsa(s.as_bytes()).unwrap())
		},
		Err(e) => {
			println!("Error: {}", e);
			None
		}
	}
}

fn main() {
    let token = new_token("Michael Yang").unwrap();
	println!("Token: {}", token);
}
