use crate::algorithm::AlgorithmType;
use base64::DecodeError;
use crypto_mac::MacError;
use serde_json::Error as JsonError;
use std::fmt;
use std::string::FromUtf8Error;

#[derive(Debug)]
pub enum Error {
    AlgorithmMismatch(AlgorithmType, AlgorithmType),
    NoKeyId,
    NoKeyWithKeyId(String),
    Format,
    Base64(DecodeError),
    Json(JsonError),
    Utf8(FromUtf8Error),
    RustCryptoMac(MacError),
    #[cfg(feature = "openssl")]
    OpenSsl(openssl::error::ErrorStack),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Error::AlgorithmMismatch(a, b) => {
                write!(f, "Expected algorithm type {:?} but found {:?}", a, b)
            }
            Error::NoKeyId => write!(f, "No key id found"),
            Error::NoKeyWithKeyId(ref kid) => write!(f, "Key with key id {} not found", kid),
            Error::Format => write!(f, "Format"),
            Error::Base64(ref x) => write!(f, "{}", x),
            Error::Json(ref x) => write!(f, "{}", x),
            Error::Utf8(ref x) => write!(f, "{}", x),
            Error::RustCryptoMac(ref x) => write!(f, "{}", x),
            #[cfg(feature = "openssl")]
            Error::OpenSsl(ref x) => write!(f, "{}", x),
        }
    }
}

macro_rules! error_wrap {
    ($f: ty, $e: expr) => {
        impl From<$f> for Error {
            fn from(f: $f) -> Error {
                $e(f)
            }
        }
    };
}

error_wrap!(DecodeError, Error::Base64);
error_wrap!(JsonError, Error::Json);
error_wrap!(FromUtf8Error, Error::Utf8);
error_wrap!(MacError, Error::RustCryptoMac);
#[cfg(feature = "openssl")]
error_wrap!(openssl::error::ErrorStack, Error::OpenSsl);

#[cfg(test)]
pub(crate) mod tests {
    #[derive(Debug)]
    pub enum TestError {
        LibError(super::Error),
        KeyError(crypto_mac::InvalidKeyLength),
    }

    impl<T> From<T> for TestError
    where
        T: Into<super::Error>,
    {
        fn from(error: T) -> Self {
            TestError::LibError(error.into())
        }
    }

    impl From<crypto_mac::InvalidKeyLength> for TestError {
        fn from(error: crypto_mac::InvalidKeyLength) -> Self {
            TestError::KeyError(error)
        }
    }

    pub type TestResult = Result<(), TestError>;
}
