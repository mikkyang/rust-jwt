//! RustCrypto implementations of signing and verifying algorithms.
//! According to that organization, only hmac is safely implemented at the
//! moment.

use digest::{
    block_buffer::Eager,
    consts::U256,
    core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore},
    generic_array::typenum::{IsLess, Le, NonZero},
    HashMarker, Digest,
};
use hmac::{Hmac, Mac};
use std::marker::PhantomData;
use crate::algorithm::{AlgorithmType, SigningAlgorithm, VerifyingAlgorithm};
use crate::error::Error;
use crate::SEPARATOR;
use signature::{DigestSigner, DigestVerifier, SignatureEncoding};

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
        D: CoreProxy + TypeLevelAlgorithmType,
        D::Core: HashMarker
        + BufferKindUser<BufferKind=Eager>
        + FixedOutputCore
        + digest::Reset
        + Default
        + Clone,
        <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn algorithm_type(&self) -> AlgorithmType {
        D::algorithm_type()
    }

    fn sign(&self, header: &str, claims: &str) -> Result<String, Error> {
        let hmac = get_hmac_with_data(self, header, claims);
        let mac_result = hmac.finalize();
        let code = mac_result.into_bytes();
        Ok(base64::encode_config(&code, base64::URL_SAFE_NO_PAD))
    }
}


pub struct AsymmetricAuthentication<HashAlgo, SignatureScheme, S> (SignatureScheme, PhantomData<HashAlgo>, PhantomData<S>);

impl<HashAlgo, SignatureScheme, S> AsymmetricAuthentication<HashAlgo, SignatureScheme, S> {
    pub fn new(scheme: SignatureScheme) -> Self {
        AsymmetricAuthentication(scheme, PhantomData, PhantomData)
    }
}

pub struct AsymmetricAuthenticationBuilder<H>(PhantomData<H>);

impl<H> AsymmetricAuthenticationBuilder<H> {
    pub fn build<G, S>(scheme: G) -> AsymmetricAuthentication::<H, G, S> {
        AsymmetricAuthentication::new(scheme)
    }
}

macro_rules! type_level_Asymmetric_algorithm_type {
    ($hash_type: ty, $signature_scheme: ty, $output: ty, $algorithm_type: expr) => {
        impl TypeLevelAlgorithmType for AsymmetricAuthentication<$hash_type, $signature_scheme, $output> {
            fn algorithm_type() -> AlgorithmType {
                $algorithm_type
            }
        }
    };
}

type_level_Asymmetric_algorithm_type!(sha2::Sha256, p256::ecdsa::SigningKey, p256::ecdsa::Signature, AlgorithmType::Es256);
type_level_Asymmetric_algorithm_type!(sha2::Sha256, p256::ecdsa::VerifyingKey, p256::ecdsa::Signature, AlgorithmType::Es256);

type_level_Asymmetric_algorithm_type!(sha2::Sha384, p384::ecdsa::SigningKey, p384::ecdsa::Signature, AlgorithmType::Es384);
type_level_Asymmetric_algorithm_type!(sha2::Sha384, p384::ecdsa::VerifyingKey, p384::ecdsa::Signature, AlgorithmType::Es384);

// TODO: Es512 once p521 is implemented

type_level_Asymmetric_algorithm_type!(sha2::Sha256, rsa::pkcs1v15::SigningKey<sha2::Sha256>, rsa::pkcs1v15::Signature, AlgorithmType::Rs256);
type_level_Asymmetric_algorithm_type!(sha2::Sha256, rsa::pkcs1v15::VerifyingKey<sha2::Sha256>, rsa::pkcs1v15::Signature, AlgorithmType::Rs256);

type_level_Asymmetric_algorithm_type!(sha2::Sha384, rsa::pkcs1v15::SigningKey<sha2::Sha384>, rsa::pkcs1v15::Signature, AlgorithmType::Rs384);
type_level_Asymmetric_algorithm_type!(sha2::Sha384, rsa::pkcs1v15::VerifyingKey<sha2::Sha384>, rsa::pkcs1v15::Signature, AlgorithmType::Rs384);

type_level_Asymmetric_algorithm_type!(sha2::Sha512, rsa::pkcs1v15::SigningKey<sha2::Sha512>, rsa::pkcs1v15::Signature, AlgorithmType::Rs512);
type_level_Asymmetric_algorithm_type!(sha2::Sha512, rsa::pkcs1v15::VerifyingKey<sha2::Sha512>, rsa::pkcs1v15::Signature, AlgorithmType::Rs512);

// TODO: Ps256, Ps384, Ps512


impl<HashAlgo, SignatureScheme, S> SigningAlgorithm for AsymmetricAuthentication<HashAlgo, SignatureScheme, S>
    where
        Self: TypeLevelAlgorithmType,
        SignatureScheme: DigestSigner<HashAlgo, S>,
        HashAlgo: Digest,
        S: SignatureEncoding + std::fmt::Debug
{
    fn algorithm_type(&self) -> AlgorithmType {
        <Self as TypeLevelAlgorithmType>::algorithm_type()
    }

    fn sign(&self, header: &str, claims: &str) -> Result<String, Error> {
        let mut hash = HashAlgo::new();
        hash.update(header.as_bytes());
        hash.update(SEPARATOR.as_bytes());
        hash.update(claims.as_bytes());

        let signature = self.0.sign_digest(hash);
        let code = signature.to_bytes();
        Ok(base64::encode_config(code, base64::URL_SAFE_NO_PAD))
    }
}


impl<HashAlgo, SignatureScheme, S> VerifyingAlgorithm for AsymmetricAuthentication<HashAlgo, SignatureScheme, S>
    where
        Self: TypeLevelAlgorithmType,
        SignatureScheme: DigestVerifier<HashAlgo, S>,
        HashAlgo: Digest,
        S: SignatureEncoding
{
    fn algorithm_type(&self) -> AlgorithmType {
        <Self as TypeLevelAlgorithmType>::algorithm_type()
    }

    fn verify_bytes(&self, header: &str, claims: &str, signature: &[u8]) -> Result<bool, Error> {
        let mut hash = HashAlgo::new();
        hash.update(header.as_bytes());
        hash.update(SEPARATOR.as_bytes());
        hash.update(claims.as_bytes());

        let sig = S::try_from(signature).map_err(|_| Error::InvalidSignature)?;

        self.0.verify_digest(hash, &sig).map_err(|_| Error::InvalidSignature)?;
        Ok(true)
    }
}


impl<D> VerifyingAlgorithm for Hmac<D>
    where
        D: CoreProxy + TypeLevelAlgorithmType,
        D::Core: HashMarker
        + BufferKindUser<BufferKind=Eager>
        + FixedOutputCore
        + digest::Reset
        + Default
        + Clone,
        <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn algorithm_type(&self) -> AlgorithmType {
        D::algorithm_type()
    }

    fn verify_bytes(&self, header: &str, claims: &str, signature: &[u8]) -> Result<bool, Error> {
        let hmac = get_hmac_with_data(self, header, claims);
        hmac.verify_slice(signature)?;
        Ok(true)
    }
}

fn get_hmac_with_data<D>(hmac: &Hmac<D>, header: &str, claims: &str) -> Hmac<D>
    where
        D: CoreProxy,
        D::Core: HashMarker
        + BufferKindUser<BufferKind=Eager>
        + FixedOutputCore
        + digest::Reset
        + Default
        + Clone,
        <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
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
    use crate::algorithm::rust_crypto::{AsymmetricAuthenticationBuilder};
    use crate::error::Error;
    use hmac::{Hmac, Mac};
    use p256::ecdsa::{SigningKey};
    use p256::pkcs8::{DecodePrivateKey};
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use sha2::Sha256;
    use rsa::{RsaPrivateKey};
    use signature::Keypair;


    #[test]
    pub fn sign() -> Result<(), Error> {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let expected_signature = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

        let signer: Hmac<Sha256> = Hmac::new_from_slice(b"secret")?;
        let computed_signature = SigningAlgorithm::sign(&signer, header, claims)?;

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
            &verifier, header, claims, signature,
        )?);
        Ok(())
    }

    #[test]
    pub fn sign_asymmetric_ec() -> Result<(), Error> {
        let private_key = include_str!("../../test/es256-private-2.pem");
        let signing_key = SigningKey::from_pkcs8_pem(private_key).unwrap();

        let signer = AsymmetricAuthenticationBuilder::<Sha256>::build(signing_key);

        let header = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
        let expected_signature = "dnpKzqJ1nYJc0BNCCwF0knVd5RQEX9abZrDETQrXfO_mZ9k8FMSMGb4Y8EF2OgAPw3HGCQ-gOn7TM6QPjXBvtA";

        let computed_signature = SigningAlgorithm::sign(&signer, header, claims)?;

        assert_eq!(computed_signature, expected_signature);

        Ok(())
    }

    #[test]
    pub fn verify_asymmetric_ec() -> Result<(), Error> {
        let private_key = include_str!("../../test/es256-private-2.pem");
        let signing_key = SigningKey::from_pkcs8_pem(private_key).unwrap();
        let verifying_key = *signing_key.verifying_key();


        let verifer = AsymmetricAuthenticationBuilder::<Sha256>::build(verifying_key);

        let header = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
        let signature = "dnpKzqJ1nYJc0BNCCwF0knVd5RQEX9abZrDETQrXfO_mZ9k8FMSMGb4Y8EF2OgAPw3HGCQ-gOn7TM6QPjXBvtA";

        assert!(VerifyingAlgorithm::verify(&verifer, header, claims, signature)?);


        Ok(())
    }

    #[test]
    pub fn sign_asymmetric_rsa_pkcs1v15() -> Result<(), Error> {
        let private_key = include_str!("../../test/rs256-private-3.pem");
        let private_key = RsaPrivateKey::from_pkcs1_pem(private_key).unwrap();
        let signing_key = rsa::pkcs1v15::SigningKey::new(private_key);


        let signer = AsymmetricAuthenticationBuilder::<Sha256>::build(signing_key);

        let header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
        let expected_signature = "PI6Ji_Nh9-j8Q_BvtE3yJLvVOUugUuDMB3wau7gFN6ZMxg8M2_jlJhK8MnbPT-6_VgZBI63Lm_2KsCGSHvqiEPVK9io5yJdgSjpHvuzQnsbZyTvtKJrsZCeI_whuUPCKOlqoDLxzmYAegqYb_fmpkJ8odfhNdO3CGQIh0lL1hWKF27TBB095o5NfYm52OE2LjmTPltixGgoiLBsmrOCHiXscjAZrppG0cOB5q9BbZhYIQIbTykL9bTXqwe-QEaJefKp6lpp36M0pPsPTqMf00wNQZSl7_iFUf_4IPAiGQrUHgNqGzbBLJz_i651AfXlpL7u85vbjFUyIDqASN5csYw";

        let computed_signature = SigningAlgorithm::sign(&signer, header, claims)?;

        assert_eq!(computed_signature, expected_signature);

        Ok(())
    }

    #[test]
    pub fn verify_asymmetric_rsa_pkcs1v15() -> Result<(), Error> {
        let private_key = include_str!("../../test/rs256-private-3.pem");
        let private_key = RsaPrivateKey::from_pkcs1_pem(private_key).unwrap();
        let signing_key = rsa::pkcs1v15::SigningKey::new(private_key);
        let verifying_key = signing_key.verifying_key();

        let verifer = AsymmetricAuthenticationBuilder::<Sha256>::build(verifying_key);

        let header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
        let signature = "PI6Ji_Nh9-j8Q_BvtE3yJLvVOUugUuDMB3wau7gFN6ZMxg8M2_jlJhK8MnbPT-6_VgZBI63Lm_2KsCGSHvqiEPVK9io5yJdgSjpHvuzQnsbZyTvtKJrsZCeI_whuUPCKOlqoDLxzmYAegqYb_fmpkJ8odfhNdO3CGQIh0lL1hWKF27TBB095o5NfYm52OE2LjmTPltixGgoiLBsmrOCHiXscjAZrppG0cOB5q9BbZhYIQIbTykL9bTXqwe-QEaJefKp6lpp36M0pPsPTqMf00wNQZSl7_iFUf_4IPAiGQrUHgNqGzbBLJz_i651AfXlpL7u85vbjFUyIDqASN5csYw";

        assert!(VerifyingAlgorithm::verify(&verifer, header, claims, signature)?);

        Ok(())
    }
}
