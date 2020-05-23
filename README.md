# JWT [![Build Status]][travis] [![Latest Version]][crates.io]

[Build Status]: https://api.travis-ci.org/mikkyang/rust-jwt.svg?branch=master
[travis]: https://travis-ci.org/mikkyang/rust-jwt
[Latest Version]: https://img.shields.io/crates/v/jwt.svg
[crates.io]: https://crates.io/crates/jwt

A JSON Web Token library.

[Documentation](http://mikkyang.github.io/rust-jwt/doc/jwt/index.html)

## Usage

### Only Claims

If you don't care about that header as long as the header is verified, signing
and verification can be done with just a few traits.

#### Signing

Claims can be any `serde::Serialize` type, usually derived with
`serde_derive`.

```rust
extern crate hmac;
extern crate jwt;
extern crate sha2;

use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use sha2::Sha256;
use std::collections::BTreeMap;

let key: Hmac<Sha256> = Hmac::new_varkey(b"some-secret").unwrap();
let mut claims = BTreeMap::new();
claims.insert("sub", "someone");

let token_str = claims.sign_with_key(&key).unwrap();

assert_eq!(token_str, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzb21lb25lIn0.5wwE1sBrs-vftww_BGIuTVDeHtc1Jsjo-fiHhDwR8m0");
```

#### Verification

Claims can be any `serde::de::DeserializeOwned` type, usually derived with
`serde_derive`.

```rust
extern crate hmac;
extern crate jwt;
extern crate sha2;

use hmac::{Hmac, Mac};
use jwt::VerifyWithKey;
use sha2::Sha256;
use std::collections::BTreeMap;

let key: Hmac<Sha256> = Hmac::new_varkey(b"some-secret").unwrap();
let token_str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzb21lb25lIn0.5wwE1sBrs-vftww_BGIuTVDeHtc1Jsjo-fiHhDwR8m0";

let claims: BTreeMap<String, String> = VerifyWithKey::verify_with_key(token_str, &key).unwrap();

assert_eq!(claims["sub"], "someone");
```

### Header and Claims

If you need to customize the header, you can use the `Token` struct. For
convenience, a `Header` struct is provided for all of the commonly defined
fields, but any type that implements `JoseHeader` can be used.

#### Signing

Both header and claims have to implement `serde::Serialize`.

```rust
extern crate hmac;
extern crate jwt;
extern crate sha2;

use hmac::{Hmac, Mac};
use jwt::{AlgorithmType, Header, SignWithKey, Token};
use sha2::Sha384;
use std::collections::BTreeMap;

let key: Hmac<Sha384> = Hmac::new_varkey(b"some-secret").unwrap();
let header = Header {
    algorithm: AlgorithmType::Hs384,
    ..Default::default()
};
let mut claims = BTreeMap::new();
claims.insert("sub", "someone");

let token = Token::new(header, claims).sign_with_key(&key).unwrap();

assert_eq!(token.as_str(), "eyJhbGciOiJIUzM4NCJ9.eyJzdWIiOiJzb21lb25lIn0.WM_WnPUkHK6zm6Wz7zk1kmIxz990Te7nlDjQ3vzcye29szZ-Sj47rLNSTJNzpQd_");
```
