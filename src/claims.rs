use std::collections::BTreeMap;
use rustc_serialize::Decodable;
use rustc_serialize::base64::FromBase64;
use rustc_serialize::json::{Decoder, Json};
use error::Error;

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

impl Claims {
    pub fn parse(raw: &str) -> Result<Claims, Error> {
        let data = try!(raw.from_base64());
        let s = try!(String::from_utf8(data));
        let tree = match try!(Json::from_str(&*s)) {
            Json::Object(x) => x,
            _ => return Err(Error::Format),
        };

        const FIELDS: [&'static str; 7] = [
            "iss", "sub", "aud",
            "exp", "nbf", "iat",
            "jti",
        ];

        let (reg, pri): (BTreeMap<_, _>, BTreeMap<_, _>) = tree.into_iter()
            .partition(|&(ref key, _)| {
                FIELDS.iter().any(|f| f == key)
            });

        let mut decoder = Decoder::new(Json::Object(reg));
        let reg_claims: Registered = try!(Decodable::decode(&mut decoder));

        Ok(Claims{
            reg: reg_claims,
            private: pri,
        })
    }
}

#[cfg(test)]
mod tests {
    use claims::Claims;

    #[test]
    fn parse() {
        let enc = "ew0KICAiaXNzIjogIm1pa2t5YW5nLmNvbSIsDQogICJleHAiOiAxMzAyMzE5MTAwLA0KICAibmFtZSI6ICJNaWNoYWVsIFlhbmciLA0KICAiYWRtaW4iOiB0cnVlDQp9";
        let claims = Claims::parse(enc).unwrap();

        assert_eq!(claims.reg.iss.unwrap(), "mikkyang.com");
        assert_eq!(claims.reg.exp.unwrap(), 1302319100);
    }
}
