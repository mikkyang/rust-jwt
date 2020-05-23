use serde_json;
use std::collections::BTreeMap;

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    #[serde(flatten)]
    pub registered: RegisteredClaims,
    #[serde(flatten)]
    pub private: BTreeMap<String, serde_json::Value>,
}

impl Claims {
    pub fn new(registered: RegisteredClaims) -> Self {
        Claims {
            registered,
            private: BTreeMap::new(),
        }
    }
}

pub type SecondsSinceEpoch = u64;

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RegisteredClaims {
    #[serde(rename = "iss", skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    #[serde(rename = "sub", skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    #[serde(rename = "aud", skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,

    #[serde(rename = "exp", skip_serializing_if = "Option::is_none")]
    pub expiration: Option<SecondsSinceEpoch>,

    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<SecondsSinceEpoch>,

    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<SecondsSinceEpoch>,

    #[serde(rename = "jti", skip_serializing_if = "Option::is_none")]
    pub json_web_token_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::claims::Claims;
    use crate::{FromBase64, ToBase64};
    use serde_json::Value;
    use std::default::Default;

    // {"iss":"mikkyang.com","exp":1302319100,"custom_claim":true}
    const ENCODED_PAYLOAD: &'static str =
        "eyJpc3MiOiJtaWtreWFuZy5jb20iLCJleHAiOjEzMDIzMTkxMDAsImN1c3RvbV9jbGFpbSI6dHJ1ZX0K";

    #[test]
    fn registered_claims() {
        let claims = Claims::from_base64(ENCODED_PAYLOAD).unwrap();

        assert_eq!(claims.registered.issuer.unwrap(), "mikkyang.com");
        assert_eq!(claims.registered.expiration.unwrap(), 1302319100);
    }

    #[test]
    fn private_claims() {
        let claims = Claims::from_base64(ENCODED_PAYLOAD).unwrap();

        assert_eq!(claims.private["custom_claim"], Value::Bool(true));
    }

    #[test]
    fn roundtrip() {
        let mut claims: Claims = Default::default();
        claims.registered.issuer = Some("mikkyang.com".into());
        claims.registered.expiration = Some(1302319100);
        let enc = claims.to_base64().unwrap();
        assert_eq!(claims, Claims::from_base64(&*enc).unwrap());
    }
}
