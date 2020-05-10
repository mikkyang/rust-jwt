use std::collections::BTreeMap;
use serde_json;

pub mod legacy;

pub use self::legacy::*;

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ClaimsV2 {
    #[serde(flatten)]
    pub registered: RegisteredClaims,
    #[serde(flatten)]
    pub private: BTreeMap<String, serde_json::Value>,
}

pub type Time = u64;

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RegisteredClaims {
    #[serde(rename="iss", skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    #[serde(rename="sub", skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    
    #[serde(rename="aud", skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,

    #[serde(rename="exp", skip_serializing_if = "Option::is_none")]
    pub expiration: Option<Time>,

    #[serde(rename="nbf", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<Time>,

    #[serde(rename="nbf", skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<Time>,

    #[serde(rename="jti", skip_serializing_if = "Option::is_none")]
    pub json_web_token_id: Option<String>,
}
