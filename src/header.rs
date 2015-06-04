use std::default::Default;
use error::Error;

#[derive(Debug, PartialEq, RustcDecodable, RustcEncodable)]
pub struct Header {
    pub typ: HeaderType,
    pub alg: Option<Algorithm>,
}


#[derive(Debug, PartialEq, RustcDecodable, RustcEncodable)]
pub enum HeaderType {
    JWT,
}

#[derive(Debug, PartialEq, RustcDecodable, RustcEncodable)]
pub enum Algorithm {
    HS256,
}

impl Default for Header {
    fn default() -> Header {
        Header {
            typ: HeaderType::JWT,
            alg: Some(Algorithm::HS256),
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
    fn parse() {
        let enc = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let header = Header::parse(enc).unwrap();

        assert_eq!(header.typ, HeaderType::JWT);
        assert_eq!(header.alg.unwrap(), Algorithm::HS256);
    }

    #[test]
    fn roundtrip() {
        let header: Header = Default::default();
        let enc = Component::encode(&header).unwrap();
        assert_eq!(header, Header::parse(&*enc).unwrap());
    }
}
