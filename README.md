# JWT

[![crates.io](http://meritbadge.herokuapp.com/jwt)](https://crates.io/crates/jwt)

A JSON Web Token library.

[Documentation](http://mikkyang.github.io/rust-jwt/doc/jwt/index.html)

## Usage

The library provides a `Token` type that wraps a header and claims. The header
and claims can be any types that implement the `Component` trait, which is
automatically implemented for types that implement the `Sized`, `Encodable`,
and `Decodable` traits. See the examples.
