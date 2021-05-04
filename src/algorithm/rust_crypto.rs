//! RustCrypto implementations of signing and verifying algorithms.
//! According to that organization, only hmac is safely implemented at the
//! moment.

use crypto_mac::Mac;
use digest::generic_array::ArrayLength;
use digest::{BlockInput, FixedOutput, Reset, Update};
use hmac::Hmac;

use crate::algorithm::{AlgorithmType, SigningAlgorithm, VerifyingAlgorithm};
use crate::error::Error;
use crate::SEPARATOR;
/// A trait used to make the implementation of `SigningAlgorithm` and
/// `VerifyingAlgorithm` easier.
/// RustCrypto crates tend to have algorithm types defined at the type level,
/// so they cannot accept a self argument.
pub trait TypeLevelAlgorithmType {
    fn algorithm_type() -> AlgorithmType;
}

macro_rules! type_level_algorithm_type {
    ($rust_crypto_type: ty, $algorithm_type: expr) => {
        impl TypeLevelAlgorithmType for $rust_crypto_type {
            fn algorithm_type() -> AlgorithmType {
                $algorithm_type
            }
        }
    };
}

type_level_algorithm_type!(sha2::Sha256, AlgorithmType::Hs256);
type_level_algorithm_type!(sha2::Sha384, AlgorithmType::Hs384);
type_level_algorithm_type!(sha2::Sha512, AlgorithmType::Hs512);

impl<D> SigningAlgorithm for Hmac<D>
where
    D: Update + BlockInput + FixedOutput + Reset + Default + Clone + TypeLevelAlgorithmType,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    fn algorithm_type(&self) -> AlgorithmType {
        D::algorithm_type()
    }

    fn sign(&self, header: &str, claims: &str) -> Result<String, Error> {
        let hmac = get_hmac_with_data(&self, header, claims);
        let mac_result = hmac.finalize();
        let code = mac_result.into_bytes();
        Ok(base64::encode_config(&code, base64::URL_SAFE_NO_PAD))
    }
}

impl<D> VerifyingAlgorithm for Hmac<D>
where
    D: Update + BlockInput + FixedOutput + Reset + Default + Clone + TypeLevelAlgorithmType,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    fn algorithm_type(&self) -> AlgorithmType {
        D::algorithm_type()
    }

    fn verify_bytes(&self, header: &str, claims: &str, signature: &[u8]) -> Result<bool, Error> {
        let hmac = get_hmac_with_data(self, header, claims);
        hmac.verify(&signature)?;
        Ok(true)
    }
}

fn get_hmac_with_data<D>(hmac: &Hmac<D>, header: &str, claims: &str) -> Hmac<D>
where
    D: Update + BlockInput + FixedOutput + Reset + Default + Clone + TypeLevelAlgorithmType,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    let mut hmac = hmac.clone();
    hmac.reset();
    hmac.update(header.as_bytes());
    hmac.update(SEPARATOR.as_bytes());
    hmac.update(claims.as_bytes());
    hmac
}

#[cfg(test)]
mod tests {
    use crate::algorithm::{SigningAlgorithm, VerifyingAlgorithm};
    use crate::error::Error;
    use crypto_mac::NewMac;
    use hmac::Hmac;
    use sha2::Sha256;

    #[test]
    pub fn sign() -> Result<(), Error> {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let expected_signature = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

        let signer: Hmac<Sha256> = Hmac::new_from_slice(b"secret")?;
        let computed_signature = SigningAlgorithm::sign(&signer, &header, &claims)?;

        assert_eq!(computed_signature, expected_signature);
        Ok(())
    }

    #[test]
    pub fn verify() -> Result<(), Error> {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let signature = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

        let verifier: Hmac<Sha256> = Hmac::new_from_slice(b"secret")?;
        assert!(VerifyingAlgorithm::verify(
            &verifier, &header, &claims, &signature
        )?);
        Ok(())
    }
}
