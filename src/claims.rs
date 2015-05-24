use std::collections::BTreeMap;
use rustc_serialize::json::Json;

pub struct Claims {
    reg: Registered,
    private: BTreeMap<String, Json>,
}

#[derive(RustcDecodable, RustcEncodable)]
pub struct Registered {
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<String>,
    exp: Option<u64>,
    nbf: Option<u64>,
    iat: Option<u64>,
    jti: Option<String>,
}
