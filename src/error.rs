use std::string::FromUtf8Error;
use base64::DecodeError;
use serde_json::Error as JsonError;

#[derive(Debug)]
pub enum Error {
    Format,
    Base64(DecodeError),
    Json(JsonError),
    Utf8(FromUtf8Error),
}

macro_rules! error_wrap {
    ($f: ty, $e: expr) => {
        impl From<$f> for Error {
            fn from(f: $f) -> Error { $e(f) }
        }
    }
}

error_wrap!(DecodeError, Error::Base64);
error_wrap!(JsonError, Error::Json);
error_wrap!(FromUtf8Error, Error::Utf8);
