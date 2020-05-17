use crate::error::Error;

#[cfg(feature = "openssl")]
pub mod openssl;
pub mod rust_crypto;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AlgorithmType {
    Hs256,
    Hs384,
    Hs512,
    Rs256,
    Rs384,
    Rs512,
    Es256,
    Es384,
    Es512,
    Ps256,
    Ps384,
    Ps512,
    #[serde(rename = "none")]
    None,
}

impl Default for AlgorithmType {
    fn default() -> Self {
        AlgorithmType::Hs256
    }
}

pub trait SigningAlgorithm {
    fn algorithm_type(&self) -> AlgorithmType;

    fn sign(&self, header: &str, claims: &str) -> Result<String, Error>;
}
pub trait VerifyingAlgorithm {
    fn algorithm_type(&self) -> AlgorithmType;

    fn verify_bytes(&self, header: &str, claims: &str, signature: &[u8]) -> Result<bool, Error>;

    fn verify(&self, header: &str, claims: &str, signature: &str) -> Result<bool, Error> {
        let signature_bytes = base64::decode_config(signature, base64::URL_SAFE_NO_PAD)?;
        self.verify_bytes(header, claims, &*signature_bytes)
    }
}
