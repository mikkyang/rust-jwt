use std::default::Default;
use rustc_serialize::json;
use rustc_serialize::base64::{
    FromBase64,
    ToBase64,
};
use error::Error;
use BASE_CONFIG;

#[derive(Debug, PartialEq, RustcDecodable, RustcEncodable)]
pub struct Header {
    pub typ: HeaderType,
    pub alg: Option<String>,
}

impl Header {
    pub fn parse(raw: &str) -> Result<Header, Error> {
        let data = try!(raw.from_base64());
        let s = try!(String::from_utf8(data));
        let header = try!(json::decode(&*s));

        Ok(header)
    }

    pub fn encode(&self) -> Result<String, Error> {
        let s = try!(json::encode(&self));
        let enc = (&*s).as_bytes().to_base64(BASE_CONFIG);
        Ok(enc)
    }
}

#[derive(Debug, PartialEq, RustcDecodable, RustcEncodable)]
pub enum HeaderType {
    JWT,
}

impl Default for Header {
    fn default() -> Header {
        Header {
            typ: HeaderType::JWT,
            alg: Some("HS256".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use header::{
        Header,
        HeaderType,
    };

    #[test]
    fn parse() {
        let enc = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let header = Header::parse(enc).unwrap();

        assert_eq!(header.typ, HeaderType::JWT);
        assert_eq!(header.alg.unwrap(), "HS256");
    }

    #[test]
    fn roundtrip() {
        let header: Header = Default::default();
        let enc = header.encode().unwrap();
        assert_eq!(header, Header::parse(&*enc).unwrap());
    }
}
