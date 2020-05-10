use crate::algorithm::AlgorithmType;

pub mod legacy;

pub use self::legacy::*;

#[derive(Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct HeaderV2 {
    #[serde(rename="alg")]
    pub algorithm: AlgorithmType,

    #[serde(rename="kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    #[serde(rename="typ", skip_serializing_if = "Option::is_none")]
    pub type_: Option<HeaderTypeV2>,

    #[serde(rename="cty", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<HeaderContentType>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all="UPPERCASE")]
pub enum HeaderTypeV2 {
    #[serde(rename="JWT")]
    JsonWebToken,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum HeaderContentType {
    #[serde(rename="JWT")]
    JsonWebToken,
}


#[cfg(test)]
mod tests {
    use crate::Component;
    use crate::algorithm::AlgorithmType;
    use crate::header::{HeaderV2, HeaderTypeV2};

    #[test]
    fn from_base64() {
        let enc = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let header = HeaderV2::from_base64(enc).unwrap();

        assert_eq!(header.type_.unwrap(), HeaderTypeV2::JsonWebToken);
        assert_eq!(header.algorithm, AlgorithmType::Hs256);

        let enc = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFLU0YzZyJ9";
        let header = HeaderV2::from_base64(enc).unwrap();

        assert_eq!(header.key_id.unwrap(), "1KSF3g".to_string());
        assert_eq!(header.algorithm, AlgorithmType::Rs256);
    }

    #[test]
    fn roundtrip() {
        let header: HeaderV2 = Default::default();
        let enc = Component::to_base64(&header).unwrap();
        assert_eq!(header, HeaderV2::from_base64(&*enc).unwrap());
    }
}
