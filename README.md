# JWT

[![crates.io](http://meritbadge.herokuapp.com/jwt)](https://crates.io/crates/jwt)

A JSON Web Token library.

[Documentation](http://mikkyang.github.io/rust-jwt/doc/jwt/index.html)

## Usage

The library provides a `Token` type that wraps a header and claims. The claims can be any type that implements the `Component` trait, which is automatically implemented for types that implement the `Sized`, `Encodable`,
and `Decodable` traits. Header can be any type that implements `Component` and `Header`. `Header` ensures that the required algorithm is available for signing and verification. `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, and `RS512` are supported. See the examples.
