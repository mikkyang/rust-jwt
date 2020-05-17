use std::default::Default;

#[deprecated(note = "Please use HeaderV2 instead")]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Header {
    pub typ: Option<HeaderType>,
    pub kid: Option<String>,
    pub alg: Algorithm,
}

#[deprecated(note = "Please use header::HeaderType instead")]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum HeaderType {
    JWT,
}

#[deprecated(note = "Please use algorithm::AlgorithmType instead")]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Algorithm {
    HS256,
    RS256,
}

impl Default for Header {
    fn default() -> Header {
        Header {
            typ: Some(HeaderType::JWT),
            kid: None,
            alg: Algorithm::HS256,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::header::legacy::{Algorithm, Header, HeaderType};
    use crate::Component;

    #[test]
    fn from_base64() {
        let enc = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let header = Header::from_base64(enc).unwrap();

        assert_eq!(header.typ.unwrap(), HeaderType::JWT);
        assert_eq!(header.alg, Algorithm::HS256);

        let enc = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFLU0YzZyJ9";
        let header = Header::from_base64(enc).unwrap();

        assert_eq!(header.kid.unwrap(), "1KSF3g".to_string());
        assert_eq!(header.alg, Algorithm::RS256);
    }

    #[test]
    fn roundtrip() {
        let header: Header = Default::default();
        let enc = Component::to_base64(&header).unwrap();
        assert_eq!(header, Header::from_base64(&*enc).unwrap());
    }
}
