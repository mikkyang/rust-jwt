use crate::algorithm::AlgorithmType;

pub trait JoseHeader {
    fn algorithm_type(&self) -> AlgorithmType;

    fn key_id(&self) -> Option<&str> {
        None
    }

    fn type_(&self) -> Option<HeaderType> {
        None
    }

    fn content_type(&self) -> Option<HeaderContentType> {
        None
    }
}

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

impl JoseHeader for Header {
    fn algorithm_type(&self) -> AlgorithmType {
        self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        self.key_id.as_ref().map(|s| &**s)
    }

    fn type_(&self) -> Option<HeaderType> {
        self.type_
    }

    fn content_type(&self) -> Option<HeaderContentType> {
        self.content_type
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HeaderType {
    #[serde(rename = "JWT")]
    JsonWebToken,
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum HeaderContentType {
    #[serde(rename = "JWT")]
    JsonWebToken,
}

#[cfg(test)]
mod tests {
    use crate::algorithm::AlgorithmType;
    use crate::header::{Header, HeaderType};
    use crate::{FromBase64, ToBase64};

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
        let enc = header.to_base64().unwrap();
        assert_eq!(header, Header::from_base64(&*enc).unwrap());
    }
}
