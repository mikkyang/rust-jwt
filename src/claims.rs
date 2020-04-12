use std::collections::BTreeMap;
use base64;
use serde_json;
use serde_json::Value as Json;

use Component;
use error::Error;

#[derive(Debug, Default, PartialEq)]
pub struct Claims {
    pub reg: Registered,
    pub private: BTreeMap<String, Json>,
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Registered {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub exp: Option<u64>,
    pub nbf: Option<u64>,
    pub iat: Option<u64>,
    pub jti: Option<String>,
}

/// JWT Claims. Registered claims are directly accessible via the `Registered`
/// struct embedded, while private fields are a map that contains `Json`
/// values.
impl Claims {
    pub fn new(reg: Registered) -> Claims {
        Claims {
            reg: reg,
            private: BTreeMap::new(),
        }
    }
}

impl Component for Claims {
    fn from_base64(raw: &str) -> Result<Claims, Error> {
        let data = base64::decode_config(raw, base64::URL_SAFE_NO_PAD)?;
        let s = String::from_utf8(data)?;
        let tree = match serde_json::from_str(&*s)? {
            Json::Object(x) => x,
            _ => return Err(Error::Format),
        };

        const FIELDS: [&'static str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

        let (_, pri): (BTreeMap<_, _>, BTreeMap<_, _>) = tree.into_iter()
            .partition(|&(ref key, _)| FIELDS.iter().any(|f| f == key));

        let reg_claims: Registered = serde_json::from_str(&*s)?;

        Ok(Claims {
            reg: reg_claims,
            private: pri,
        })
    }

    fn to_base64(&self) -> Result<String, Error> {
        let mut json_claims = match serde_json::to_value(&self.reg)? {
            Json::Object(x) => x,
            _ => return Err(Error::Format),
        };

        json_claims.extend(self.private.clone());

        let s = serde_json::to_string(&json_claims)?;
        let enc = base64::encode_config(&*s, base64::URL_SAFE_NO_PAD);
        Ok(enc)
    }
}

#[cfg(test)]
mod tests {
    use std::default::Default;
    use claims::{Claims, Registered};
    use Component;
    use serde_json::Value;

    // {"iss":"mikkyang.com","exp":1302319100,"custom_claim":true}
    const ENCODED_PAYLOAD: &'static str = "eyJpc3MiOiJtaWtreWFuZy5jb20iLCJleHAiOjEzMDIzMTkxMDAsImN1c3RvbV9jbGFpbSI6dHJ1ZX0K";

    #[test]
    fn registered_claims() {
        let claims = Claims::from_base64(ENCODED_PAYLOAD).unwrap();

        assert_eq!(claims.reg.iss.unwrap(), "mikkyang.com");
        assert_eq!(claims.reg.exp.unwrap(), 1302319100);
    }

    #[test]
    fn private_claims() {
        let claims = Claims::from_base64(ENCODED_PAYLOAD).unwrap();

        assert_eq!(claims.private["custom_claim"], Value::Bool(true));
    }

    #[test]
    fn roundtrip() {
        let mut claims: Claims = Default::default();
        claims.reg.iss = Some("mikkyang.com".into());
        claims.reg.exp = Some(1302319100);
        let enc = claims.to_base64().unwrap();
        assert_eq!(claims, Claims::from_base64(&*enc).unwrap());
    }
}
