use std::default::Default;

#[derive(Debug, PartialEq, RustcDecodable, RustcEncodable)]
pub struct Header {
    pub typ: Option<HeaderType>,
    pub kid: Option<String>,
    pub alg: Algorithm,
}


#[derive(Debug, PartialEq, RustcDecodable, RustcEncodable)]
pub enum HeaderType {
    JWT,
}

#[derive(Debug, PartialEq, RustcDecodable, RustcEncodable)]
pub enum Algorithm {
    HS256, RS256,
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
    use Component;
    use header::{
        Algorithm,
        Header,
        HeaderType,
    };

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
