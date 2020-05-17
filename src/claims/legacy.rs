use serde_json::Value as Json;
use std::collections::BTreeMap;

#[deprecated(note = "Please use ClaimsV2 instead")]
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    #[serde(flatten)]
    pub reg: Registered,
    #[serde(flatten)]
    pub private: BTreeMap<String, Json>,
}

#[deprecated(note = "Please use RegisteredClaims instead")]
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

#[cfg(test)]
mod tests {
    use crate::claims::legacy::Claims;
    use crate::Component;
    use serde_json::Value;
    use std::default::Default;

    // {"iss":"mikkyang.com","exp":1302319100,"custom_claim":true}
    const ENCODED_PAYLOAD: &'static str =
        "eyJpc3MiOiJtaWtreWFuZy5jb20iLCJleHAiOjEzMDIzMTkxMDAsImN1c3RvbV9jbGFpbSI6dHJ1ZX0K";

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
