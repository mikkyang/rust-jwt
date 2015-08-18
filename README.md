# JWT

A JSON Web Token library.

[Documentation](http://mikkyang.github.io/rust-jwt/doc/jwt/index.html)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
jwt = "0.3.0"
```

and this to your crate root:
```rust
extern crate jwt;
```

## Usage

The library provides a `Token` type that wraps a header and claims. The header
and claims can be any types that implement the `Component` trait, which is
automatically implemented for types that implement the `Sized`, `Encodable`,
and `Decodable` traits. See the examples.
