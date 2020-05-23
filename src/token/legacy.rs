use crate::error::Error;
use crate::{FromBase64, ToBase64};
use serde::de::DeserializeOwned;
use serde::Serialize;

pub trait Component: Sized {
    fn from_base64<Input: ?Sized + AsRef<[u8]>>(raw: &Input) -> Result<Self, Error>;
    fn to_base64(&self) -> Result<String, Error>;
}

impl<T: ToBase64 + FromBase64> Component for T
where
    T: Serialize + DeserializeOwned + Sized,
{
    /// Parse from a string.
    fn from_base64<Input: ?Sized + AsRef<[u8]>>(raw: &Input) -> Result<T, Error> {
        FromBase64::from_base64(raw)
    }

    /// Encode to a string.
    fn to_base64(&self) -> Result<String, Error> {
        ToBase64::to_base64(self).map(Into::<String>::into)
    }
}
