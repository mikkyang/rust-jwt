use std::string::FromUtf8Error;
use base64::DecodeError;
use serde_json::Error as JsonError;

use std::error::Error as StdError;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    Format,
    Base64(DecodeError),
    Json(JsonError),
    Utf8(FromUtf8Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Error::Format => write!(f, "Format"),
            Error::Base64(ref x) => write!(f, "{}", x),
            Error::Json(ref x) => write!(f, "{}", x),
            Error::Utf8(ref x) => write!(f, "{}", x),
        }
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Format => "invalid formatting",
            Error::Base64(ref x) => x.description(),
            Error::Json(ref x) => x.description(),
            Error::Utf8(ref x) => x.description(),
        }
    }
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
