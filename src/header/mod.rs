use crate::algorithm::AlgorithmType;

#[allow(deprecated)]
pub mod legacy;

#[derive(Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct Header {
    #[serde(rename = "alg")]
    pub algorithm: AlgorithmType,

    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    pub type_: Option<HeaderType>,

    #[serde(rename = "cty", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<HeaderContentType>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HeaderType {
    #[serde(rename = "JWT")]
    JsonWebToken,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum HeaderContentType {
    #[serde(rename = "JWT")]
    JsonWebToken,
}

#[cfg(test)]
mod tests {
    use crate::algorithm::AlgorithmType;
    use crate::header::{Header, HeaderType};
    use crate::Component;

    #[test]
    fn from_base64() {
        let enc = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let header = Header::from_base64(enc).unwrap();

        assert_eq!(header.type_.unwrap(), HeaderType::JsonWebToken);
        assert_eq!(header.algorithm, AlgorithmType::Hs256);

        let enc = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFLU0YzZyJ9";
        let header = Header::from_base64(enc).unwrap();

        assert_eq!(header.key_id.unwrap(), "1KSF3g".to_string());
        assert_eq!(header.algorithm, AlgorithmType::Rs256);
    }

    #[test]
    fn roundtrip() {
        let header: Header = Default::default();
        let enc = Component::to_base64(&header).unwrap();
        assert_eq!(header, Header::from_base64(&*enc).unwrap());
    }
}
