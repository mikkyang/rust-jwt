use std::string::FromUtf8Error;
use rustc_serialize::base64::FromBase64Error;
use rustc_serialize::json;

#[derive(Debug)]
pub enum Error {
    Format,
    Base64,
    Decode,
    Json,
    Utf8,
}

macro_rules! error_wrap {
    ($f: ty, $e: expr) => {
    impl From<$f> for Error {
        fn from(_: $f) -> Error { $e }
    }
}
}

error_wrap!(FromBase64Error, Error::Base64);
error_wrap!(json::DecoderError, Error::Decode);
error_wrap!(json::ErrorCode, Error::Json);
error_wrap!(FromUtf8Error, Error::Utf8);
