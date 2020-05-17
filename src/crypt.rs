use crate::algorithm::rust_crypto::TypeLevelAlgorithmType;
use crate::algorithm::{SigningAlgorithm, VerifyingAlgorithm};
use crate::SEPARATOR;
use crypto_mac::Mac;
use digest::generic_array::ArrayLength;
use digest::*;
use hmac::Hmac;

#[deprecated(
    note = "Please use Hmac type with the SigningAlgorithm trait directly. See the source of this function for an example."
)]
pub fn sign<D>(data: &str, key: &[u8], _digest: D) -> String
where
    D: Input + BlockInput + FixedOutput + Reset + Default + Clone + TypeLevelAlgorithmType,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    // This will panic for bad key sizes. Returning an error
    // would probably be better, but for now, I want to keep the
    // API as stable as possible
    let hmac = Hmac::<D>::new_varkey(key).unwrap();
    let mut components = data.split(SEPARATOR);
    let header = components.next().unwrap();
    let claims = components.next().unwrap();
    SigningAlgorithm::sign(&hmac, header, claims).unwrap()
}

#[deprecated(
    note = "Please use Hmac type with the VerifyingAlgorithm trait directly. See the source of this function for an example."
)]
pub fn verify<D>(signature: &str, data: &str, key: &[u8], _digest: D) -> bool
where
    D: Input + BlockInput + FixedOutput + Reset + Default + Clone + TypeLevelAlgorithmType,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    // This will panic for bad key sizes. Returning an error
    // would probably be better, but for now, I want to keep the
    // API as stable as possible
    let hmac = Hmac::<D>::new_varkey(key).unwrap();

    let mut components = data.split(SEPARATOR);
    let header = components.next().unwrap();
    let claims = components.next().unwrap();

    VerifyingAlgorithm::verify(&hmac, &header, &claims, &signature).unwrap_or(false)
}
