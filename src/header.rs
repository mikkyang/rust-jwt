use error::Error;

#[derive(RustcDecodable, RustcEncodable)]
pub struct Header {
    pub typ: String,
    pub alg: Option<String>,
}

impl Header {
    pub fn parse(raw: &str) -> Result<Header, Error> {
        let header = Header {
            typ: "".into(),
            alg: None,
        };
        Ok(header)
    }
}
