# JWT

A JSON Web Token library.

[Documentation](http://mikkyang.github.io/rust-jwt/doc/jwt/index.html)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
jwt = "0.1.0"
```

and this to your crate root:
```rust
extern crate jwt;
```

## Example

```rust
extern crate crypto;
extern crate jwt;

use std::default::Default;
use crypto::sha2::Sha256;
use jwt::{
    Claims,
    Registered,
    Token,
}

fn new_token(user_id: &str, password: &str) -> Option<String> {
    // Dummy auth
    if password != "password" {
        return None
    }

    let header = Default::default();
    let claims = Registered {
        iss: Some("mikkyang.com".into()),
        sub: Some(user_id.into()),
        ..Default::default()
    };
    let token = Token::new(header, Claims::new(claims));

    token.signed(b"secret_key", Sha256::new()).ok()
}

fn login(token: &str) -> Option<String> {
    let token = Token::parse(token).unwrap();

    if token.verify(b"secret_key", Sha256::new()) {
        token.claims.reg.sub
    } else {
        None
    }
}

fn main() {
    let token = new_token("Michael Yang", "password").unwrap();

    let logged_in_user = login(&*token).unwrap();

    assert_eq!(logged_in_user, "Michael Yang");
}
```
