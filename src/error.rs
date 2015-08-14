use std::string::FromUtf8Error;
use rustc_serialize::base64::FromBase64Error;
use rustc_serialize::json;

#[derive(Debug)]
pub enum Error {
    Format,
    Base64(FromBase64Error),
    Decode(json::DecoderError),
    Encode(json::EncoderError),
    Json(json::ErrorCode),
    Parse(json::ParserError),
    Utf8(FromUtf8Error),
}

macro_rules! error_wrap {
    ($f: ty, $e: expr) => {
        impl From<$f> for Error {
            fn from(f: $f) -> Error { $e(f) }
        }
    }
}

error_wrap!(FromBase64Error, Error::Base64);
error_wrap!(json::DecoderError, Error::Decode);
error_wrap!(json::EncoderError, Error::Encode);
error_wrap!(json::ErrorCode, Error::Json);
error_wrap!(json::ParserError, Error::Parse);
error_wrap!(FromUtf8Error, Error::Utf8);
