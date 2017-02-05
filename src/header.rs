use std::default::Default;
use Header;

#[derive(Debug, PartialEq, RustcDecodable, RustcEncodable)]
pub struct DefaultHeader {
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
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512
}

impl Default for DefaultHeader {
    fn default() -> DefaultHeader {
        DefaultHeader {
            typ: Some(HeaderType::JWT),
            kid: None,
            alg: Algorithm::HS256,
        }
    }
}

impl Header for DefaultHeader {
    fn alg(&self) -> &Algorithm {
        &(self.alg)
    }
}

#[cfg(test)]
mod tests {
    use Component;
    use header::{
        Algorithm,
        DefaultHeader,
        HeaderType,
    };

    #[test]
    fn from_base64() {
        let enc = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let header = DefaultHeader::from_base64(enc).unwrap();

        assert_eq!(header.typ.unwrap(), HeaderType::JWT);
        assert_eq!(header.alg, Algorithm::HS256);


        let enc = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFLU0YzZyJ9";
        let header = DefaultHeader::from_base64(enc).unwrap();

        assert_eq!(header.kid.unwrap(), "1KSF3g".to_string());
        assert_eq!(header.alg, Algorithm::RS256);
    }

    #[test]
    fn roundtrip() {
        let header: DefaultHeader = Default::default();
        let enc = Component::to_base64(&header).unwrap();
        assert_eq!(header, DefaultHeader::from_base64(&*enc).unwrap());
    }
}
