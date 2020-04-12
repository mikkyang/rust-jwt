# JWT [![Build Status]][travis] [![Latest Version]][crates.io]

[Build Status]: https://api.travis-ci.org/mikkyang/rust-jwt.svg?branch=master
[travis]: https://travis-ci.org/mikkyang/rust-jwt
[Latest Version]: https://img.shields.io/crates/v/jwt.svg
[crates.io]: https://crates.io/crates/jwt

A JSON Web Token library.

[Documentation](http://mikkyang.github.io/rust-jwt/doc/jwt/index.html)

## Usage

The library provides a `Token` type that wraps a header and claims. The header
and claims can be any types that implement the `Component` trait, which is
automatically implemented for types that implement the `Sized`, `Encodable`,
and `Decodable` traits. See the examples.
