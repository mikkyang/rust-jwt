//! Note, for legacy support (not recommended), import from
//! [`jwt::legacy`](legacy/index.html) instead of directly from `jwt`.
//! Everything should work as before, with some small improvements.
//! ### Only Claims
//! If you don't care about that header as long as the header is verified, signing
//! and verification can be done with just a few traits.
//! #### Signing
//! Claims can be any `serde::Serialize` type, usually derived with
//! `serde_derive`.
//! ```rust
//! extern crate hmac;
//! extern crate sha2;
//!
//! use hmac::{Hmac, Mac};
//! use jwt::SignWithKey;
//! use sha2::Sha256;
//! use std::collections::BTreeMap;
//!
//! let key: Hmac<Sha256> = Hmac::new_varkey(b"some-secret").unwrap();
//! let mut claims = BTreeMap::new();
//! claims.insert("sub", "someone");
//! let token_str = claims.sign_with_key(&key).unwrap();
//! assert_eq!(token_str, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzb21lb25lIn0.5wwE1sBrs-vftww_BGIuTVDeHtc1Jsjo-fiHhDwR8m0");
//! ```
//! #### Verification
//! Claims can be any `serde::de::DeserializeOwned` type, usually derived with
//! `serde_derive`.
//! ```rust
//! extern crate hmac;
//! extern crate sha2;
//!
//! use hmac::{Hmac, Mac};
//! use jwt::VerifyWithKey;
//! use sha2::Sha256;
//! use std::collections::BTreeMap;
//!
//! let key: Hmac<Sha256> = Hmac::new_varkey(b"some-secret").unwrap();
//! let token_str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzb21lb25lIn0.5wwE1sBrs-vftww_BGIuTVDeHtc1Jsjo-fiHhDwR8m0";
//! let claims: BTreeMap<String, String> = VerifyWithKey::verify_with_key(token_str, &key).unwrap();
//! assert_eq!(claims["sub"], "someone");
//! ```
//! ### Header and Claims
//! If you need to customize the header, you can use the `Token` struct. For
//! convenience, a `Header` struct is provided for all of the commonly defined
//! fields, but any type that implements `JoseHeader` can be used.
//! #### Signing
//! Both header and claims have to implement `serde::Serialize`.
//! ```rust
//! extern crate hmac;
//! extern crate sha2;
//!
//! use hmac::{Hmac, Mac};
//! use jwt::{AlgorithmType, Header, SignWithKey, Token};
//! use sha2::Sha384;
//! use std::collections::BTreeMap;
//!
//! let key: Hmac<Sha384> = Hmac::new_varkey(b"some-secret").unwrap();
//! let header = Header {
//!     algorithm: AlgorithmType::Hs384,
//!     ..Default::default()
//! };
//! let mut claims = BTreeMap::new();
//! claims.insert("sub", "someone");
//! let token = Token::new(header, claims).sign_with_key(&key).unwrap();
//! assert_eq!(token.as_str(), "eyJhbGciOiJIUzM4NCJ9.eyJzdWIiOiJzb21lb25lIn0.WM_WnPUkHK6zm6Wz7zk1kmIxz990Te7nlDjQ3vzcye29szZ-Sj47rLNSTJNzpQd_");
//! ```
//! #### Verification
//! Both header and claims have to implement `serde::de::DeserializeOwned`.
//! ```rust
//! extern crate hmac;
//! extern crate sha2;
//!
//! use hmac::{Hmac, Mac};
//! use jwt::{AlgorithmType, Header, Token, VerifyWithKey};
//! use sha2::Sha384;
//! use std::collections::BTreeMap;
//!
//! let key: Hmac<Sha384> = Hmac::new_varkey(b"some-secret").unwrap();
//! let token_str = "eyJhbGciOiJIUzM4NCJ9.eyJzdWIiOiJzb21lb25lIn0.WM_WnPUkHK6zm6Wz7zk1kmIxz990Te7nlDjQ3vzcye29szZ-Sj47rLNSTJNzpQd_";
//! let token: Token<Header, BTreeMap<String, String>, _> = VerifyWithKey::verify_with_key(token_str, &key).unwrap();
//! let header = token.header();
//! let claims = token.claims();
//! assert_eq!(header.algorithm, AlgorithmType::Hs384);
//! assert_eq!(claims["sub"], "someone");
//! ```


extern crate base64;
extern crate crypto_mac;
extern crate digest;
#[cfg(doctest)]
#[macro_use]
extern crate doc_comment;
extern crate hmac;
#[cfg(feature = "openssl")]
extern crate openssl;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate sha2;

#[cfg(doctest)]
doctest!("../README.md");

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::borrow::Cow;

#[cfg(feature = "openssl")]
pub use crate::algorithm::openssl::PKeyWithDigest;
pub use crate::algorithm::{AlgorithmType, SigningAlgorithm, VerifyingAlgorithm};
pub use crate::claims::Claims;
pub use crate::claims::RegisteredClaims;
pub use crate::error::Error;
pub use crate::header::{Header, JoseHeader};
pub use crate::token::{Unsigned, Unverified, Verified};
pub use crate::token::signed::SignWithKey;
pub use crate::token::verified::VerifyWithKey;

pub mod algorithm;
pub mod claims;
pub mod error;
pub mod header;
#[allow(deprecated)]
pub mod legacy;
pub mod token;

const SEPARATOR: &'static str = ".";

/// Representation of a structured JWT. Methods vary based on the signature
/// type `S`.
pub struct Token<H, C, S> {
    header: H,
    claims: C,
    signature: S,
}

impl<H, C, S> Token<H, C, S> {
    pub fn header(&self) -> &H {
        &self.header
    }

    pub fn claims(&self) -> &C {
        &self.claims
    }

    pub fn remove_signature(self) -> Token<H, C, Unsigned> {
        Token {
            header: self.header,
            claims: self.claims,
            signature: Unsigned,
        }
    }
}

impl<H, C, S> Into<(H, C)> for Token<H, C, S> {
    fn into(self) -> (H, C) {
        (self.header, self.claims)
    }
}

/// A trait used to convert objects in base64 encoding. The return type can
/// be either owned if the header is dynamic, or it can be borrowed if the
/// header is a static, pre-computed value. It is implemented automatically
/// for every type that implements
/// [Serialize](../../serde/trait.Serialize.html). as a base64 encoding of
/// the object's JSON representation.
pub trait ToBase64 {
    fn to_base64(&self) -> Result<Cow<str>, Error>;
}

impl<T: Serialize> ToBase64 for T {
    fn to_base64(&self) -> Result<Cow<str>, Error> {
        let json_bytes = serde_json::to_vec(&self)?;
        let encoded_json_bytes = base64::encode_config(&json_bytes, base64::URL_SAFE_NO_PAD);
        Ok(Cow::Owned(encoded_json_bytes))
    }
}


/// A trait used to parse objects from base64 encoding. The return type can
/// be either owned if the header is dynamic, or it can be borrowed if the
/// header is a static, pre-computed value. It is implemented automatically
/// for every type that implements
/// [DeserializeOwned](../../serde/de/trait.DeserializeOwned.html) for
/// the base64 encoded JSON representation.
pub trait FromBase64: Sized {
    fn from_base64<Input: ?Sized + AsRef<[u8]>>(raw: &Input) -> Result<Self, Error>;
}

impl<T: DeserializeOwned + Sized> FromBase64 for T {
    fn from_base64<Input: ?Sized + AsRef<[u8]>>(raw: &Input) -> Result<Self, Error> {
        let json_bytes = base64::decode_config(raw, base64::URL_SAFE_NO_PAD)?;
        Ok(serde_json::from_slice(&json_bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithm::AlgorithmType::Hs256;
    use crate::header::Header;
    use crate::token::signed::SignWithKey;
    use crate::token::verified::VerifyWithKey;
    use crate::Claims;
    use crate::Token;
    use hmac::Hmac;
    use hmac::Mac;
    use sha2::Sha256;

    #[test]
    pub fn raw_data() {
        let raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        let token: Token<Header, Claims, _> = Token::parse_unverified(raw).unwrap();

        assert_eq!(token.header.algorithm, Hs256);

        let verifier: Hmac<Sha256> = Hmac::new_varkey(b"secret").unwrap();
        assert!(token.verify_with_key(&verifier).is_ok());
    }

    #[test]
    pub fn roundtrip() {
        let token: Token<Header, Claims, _> = Default::default();
        let key: Hmac<Sha256> = Hmac::new_varkey(b"secret").unwrap();
        let signed_token = token.sign_with_key(&key).unwrap();
        let signed_token_str = signed_token.as_str();

        let recreated_token: Token<Header, Claims, _> =
            Token::parse_unverified(signed_token_str).unwrap();

        assert_eq!(signed_token.header(), recreated_token.header());
        assert_eq!(signed_token.claims(), recreated_token.claims());
        assert!(recreated_token.verify_with_key(&key).is_ok());
    }
}
