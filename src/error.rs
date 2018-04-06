use self::Error::*;
use crate::algorithm::AlgorithmType;
use base64::DecodeError;
use crypto_mac::{InvalidKeyLength, MacError};
use serde_json::Error as JsonError;
use std::fmt;
use std::string::FromUtf8Error;

#[derive(Debug)]
pub enum Error {
    AlgorithmMismatch(AlgorithmType, AlgorithmType),
    NoKeyId,
    NoKeyWithKeyId(String),
    NoHeaderComponent,
    NoClaimsComponent,
    NoSignatureComponent,
    TooManyComponents,
    Format,
    Base64(DecodeError),
    Json(JsonError),
    Utf8(FromUtf8Error),
    RustCryptoMac(MacError),
    RustCryptoMacKeyLength(InvalidKeyLength),
    #[cfg(feature = "openssl")]
    OpenSsl(openssl::error::ErrorStack),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            AlgorithmMismatch(a, b) => {
                write!(f, "Expected algorithm type {:?} but found {:?}", a, b)
            }
            NoKeyId => write!(f, "No key id found"),
            NoKeyWithKeyId(ref kid) => write!(f, "Key with key id {} not found", kid),
            NoHeaderComponent => write!(f, "No header component found in token string"),
            NoClaimsComponent => write!(f, "No claims component found in token string"),
            NoSignatureComponent => write!(f, "No signature component found in token string"),
            TooManyComponents => write!(f, "Too many components found in token string"),
            Format => write!(f, "Format"),
            Base64(ref x) => write!(f, "{}", x),
            Json(ref x) => write!(f, "{}", x),
            Utf8(ref x) => write!(f, "{}", x),
            RustCryptoMac(ref x) => write!(f, "{}", x),
            RustCryptoMacKeyLength(ref x) => write!(f, "{}", x),
            #[cfg(feature = "openssl")]
            OpenSsl(ref x) => write!(f, "{}", x),
        }
    }
}

impl std::error::Error for Error {}

macro_rules! error_wrap {
    ($f:ty, $e:expr) => {
        impl From<$f> for Error {
            fn from(f: $f) -> Error {
                $e(f)
            }
        }
    };
}

error_wrap!(DecodeError, Base64);
error_wrap!(JsonError, Json);
error_wrap!(FromUtf8Error, Utf8);
error_wrap!(MacError, RustCryptoMac);
error_wrap!(InvalidKeyLength, RustCryptoMacKeyLength);
#[cfg(feature = "openssl")]
error_wrap!(openssl::error::ErrorStack, Error::OpenSsl);
