use crate::algorithm::{AlgorithmType, SigningAlgorithm, VerifyingAlgorithm};
use crate::error::Error;
use crate::SEPARATOR;

use base64::Engine;
use crypto_common::generic_array::ArrayLength;
use digest::{Digest, FixedOutput};
use ecdsa::elliptic_curve::ops::Invert;
use ecdsa::elliptic_curve::subtle::CtOption;
use ecdsa::elliptic_curve::{CurveArithmetic, FieldBytesSize, Scalar};
use ecdsa::hazmat::SignPrimitive;
use ecdsa::{PrimeCurve, SignatureSize};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
use p256::NistP256;
use rsa::pkcs1::DecodeRsaPrivateKey;
use signature::{DigestSigner, DigestVerifier, SignatureEncoding};

#[derive(Clone, Debug)]
pub enum PublicKey<D: SupportedAsymmetricDigest> {
    RSA(rsa::pkcs1v15::VerifyingKey<D>),
    EC(p256::ecdsa::VerifyingKey),
}

impl<D: SupportedAsymmetricDigest> PublicKey<D> {
    pub fn from_pem_bytes(encoded: &[u8]) -> Result<Self, Error> {
        Self::from_pem(std::str::from_utf8(encoded).map_err(|_| Error::InvalidKey)?)
    }

    pub fn from_pem(encoded: &str) -> Result<Self, Error> {
        if let Ok(ec) = encoded.parse::<p256::PublicKey>() {
            Ok(PublicKey::EC(ecdsa::VerifyingKey::from(ec)))
        } else if let Ok(rsa) = rsa::RsaPublicKey::from_public_key_pem(encoded) {
            Ok(PublicKey::RSA(rsa::pkcs1v15::VerifyingKey::new(rsa)))
        } else {
            Err(Error::InvalidKey)
        }
    }
}

impl<D: SupportedAsymmetricDigest> DigestVerifier<D, rsa::pkcs1v15::Signature> for PublicKey<D> {
    fn verify_digest(
        &self,
        digest: D,
        signature: &rsa::pkcs1v15::Signature,
    ) -> Result<(), signature::Error> {
        match self {
            PublicKey::RSA(key) => key.verify_digest(digest, signature),
            PublicKey::EC(_) => Err(signature::Error::new()),
        }
    }
}

impl<D: SupportedAsymmetricDigest> DigestVerifier<D, p256::ecdsa::Signature> for PublicKey<D>
where
    D: FixedOutput<OutputSize = FieldBytesSize<NistP256>>,
{
    fn verify_digest(
        &self,
        digest: D,
        signature: &p256::ecdsa::Signature,
    ) -> Result<(), signature::Error> {
        match self {
            PublicKey::RSA(_) => Err(signature::Error::new()),
            PublicKey::EC(key) => key.verify_digest(digest, signature),
        }
    }
}

#[derive(Clone, Debug)]
pub enum PrivateKey<D: SupportedAsymmetricDigest> {
    RSA(Box<rsa::pkcs1v15::SigningKey<D>>),
    EC(p256::ecdsa::SigningKey),
}

impl<D: SupportedAsymmetricDigest> PrivateKey<D> {
    pub fn from_pem_bytes(encoded: &[u8]) -> Result<Self, Error> {
        Self::from_pem(std::str::from_utf8(encoded).map_err(|_| Error::InvalidKey)?)
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        if let Ok(ec) = pem.parse::<p256::SecretKey>() {
            Ok(PrivateKey::EC(ecdsa::SigningKey::from(ec)))
        } else if let Ok(rsa) = rsa::RsaPrivateKey::from_pkcs8_pem(pem) {
            Ok(PrivateKey::RSA(Box::new(rsa::pkcs1v15::SigningKey::new(
                rsa,
            ))))
        } else if let Ok(rsa) = rsa::RsaPrivateKey::from_pkcs1_pem(pem) {
            Ok(PrivateKey::RSA(Box::new(rsa::pkcs1v15::SigningKey::new(
                rsa,
            ))))
        } else {
            Err(Error::InvalidKey)
        }
    }
}

impl<D: SupportedAsymmetricDigest> DigestSigner<D, rsa::pkcs1v15::Signature> for PrivateKey<D> {
    fn try_sign_digest(&self, digest: D) -> Result<rsa::pkcs1v15::Signature, signature::Error> {
        match self {
            PrivateKey::RSA(key) => key.try_sign_digest(digest),
            PrivateKey::EC(_) => Err(signature::Error::new()),
        }
    }
}

impl<D: SupportedAsymmetricDigest> DigestSigner<D, p256::ecdsa::Signature> for PrivateKey<D>
where
    D: FixedOutput<OutputSize = FieldBytesSize<NistP256>>,
{
    fn try_sign_digest(&self, digest: D) -> Result<p256::ecdsa::Signature, signature::Error> {
        match self {
            PrivateKey::RSA(_) => Err(signature::Error::new()),
            PrivateKey::EC(key) => key.try_sign_digest(digest),
        }
    }
}

pub struct AsymmetricKeyWithDigest<
    D: SupportedAsymmetricDigest,
    S: SignatureEncoding,
    K: SupportedAsymmetricKey,
> {
    key: K,
    _marker: std::marker::PhantomData<(S, D)>,
}

impl<D: SupportedAsymmetricDigest, S: SignatureEncoding, K: SupportedAsymmetricKey>
    AsymmetricKeyWithDigest<D, S, K>
{
    pub fn new(key: K) -> Self {
        Self {
            key,
            _marker: std::marker::PhantomData,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestType {
    SHA256,
    SHA384,
    SHA512,
}

pub trait SupportedAsymmetricDigest: Digest + digest::const_oid::AssociatedOid {
    fn digest_type() -> DigestType;
}

impl SupportedAsymmetricDigest for sha2::Sha256 {
    fn digest_type() -> DigestType {
        DigestType::SHA256
    }
}

impl SupportedAsymmetricDigest for sha2::Sha384 {
    fn digest_type() -> DigestType {
        DigestType::SHA384
    }
}

impl SupportedAsymmetricDigest for sha2::Sha512 {
    fn digest_type() -> DigestType {
        DigestType::SHA512
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PKeyType {
    EC,
    RSA,
}

pub trait SupportedAsymmetricKey {
    fn key_type(&self) -> PKeyType;
}

impl<C> SupportedAsymmetricKey for ecdsa::SigningKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn key_type(&self) -> PKeyType {
        PKeyType::EC
    }
}

impl<C> SupportedAsymmetricKey for ecdsa::VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic,
{
    fn key_type(&self) -> PKeyType {
        PKeyType::EC
    }
}

impl<D: SupportedAsymmetricDigest> SupportedAsymmetricKey for rsa::pkcs1v15::SigningKey<D> {
    fn key_type(&self) -> PKeyType {
        PKeyType::RSA
    }
}

impl<D: SupportedAsymmetricDigest> SupportedAsymmetricKey for rsa::pkcs1v15::VerifyingKey<D> {
    fn key_type(&self) -> PKeyType {
        PKeyType::RSA
    }
}

impl<D: SupportedAsymmetricDigest> SupportedAsymmetricKey for PublicKey<D> {
    fn key_type(&self) -> PKeyType {
        match self {
            PublicKey::RSA(_) => PKeyType::RSA,
            PublicKey::EC(_) => PKeyType::EC,
        }
    }
}

impl<D: SupportedAsymmetricDigest> SupportedAsymmetricKey for PrivateKey<D> {
    fn key_type(&self) -> PKeyType {
        match self {
            PrivateKey::RSA(_) => PKeyType::RSA,
            PrivateKey::EC(_) => PKeyType::EC,
        }
    }
}

impl<D: SupportedAsymmetricDigest, S: SignatureEncoding, K: SupportedAsymmetricKey>
    AsymmetricKeyWithDigest<D, S, K>
{
    fn algorithm_type(&self) -> AlgorithmType {
        match (self.key.key_type(), D::digest_type()) {
            (PKeyType::RSA, DigestType::SHA256) => AlgorithmType::Rs256,
            (PKeyType::RSA, DigestType::SHA384) => AlgorithmType::Rs384,
            (PKeyType::RSA, DigestType::SHA512) => AlgorithmType::Rs512,
            (PKeyType::EC, DigestType::SHA256) => AlgorithmType::Es256,
            (PKeyType::EC, DigestType::SHA384) => AlgorithmType::Es384,
            (PKeyType::EC, DigestType::SHA512) => AlgorithmType::Es512,
        }
    }
}

impl<
        D: SupportedAsymmetricDigest,
        S: SignatureEncoding,
        K: DigestSigner<D, S> + SupportedAsymmetricKey,
    > SigningAlgorithm for AsymmetricKeyWithDigest<D, S, K>
{
    fn algorithm_type(&self) -> AlgorithmType {
        AsymmetricKeyWithDigest::algorithm_type(self)
    }

    fn sign(&self, header: &str, claims: &str) -> Result<String, Error> {
        let mut digest = D::new();

        digest.update(header.as_bytes());
        digest.update(SEPARATOR.as_bytes());
        digest.update(claims.as_bytes());

        let signature = self.key.try_sign_digest(digest)?;

        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }
}

impl<
        D: SupportedAsymmetricDigest,
        S: SignatureEncoding,
        K: DigestVerifier<D, S> + SupportedAsymmetricKey,
    > VerifyingAlgorithm for AsymmetricKeyWithDigest<D, S, K>
{
    fn algorithm_type(&self) -> AlgorithmType {
        AsymmetricKeyWithDigest::algorithm_type(self)
    }

    fn verify_bytes(&self, header: &str, claims: &str, signature: &[u8]) -> Result<bool, Error> {
        let mut digest = D::new();

        digest.update(header.as_bytes());
        digest.update(SEPARATOR.as_bytes());
        digest.update(claims.as_bytes());

        let signature = S::try_from(signature).map_err(|_| Error::InvalidSignature)?;

        Ok(self.key.verify_digest(digest, &signature).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::algorithm::AlgorithmType::*;
    use crate::algorithm::{SigningAlgorithm, VerifyingAlgorithm};
    use crate::error::Error;
    use crate::header::PrecomputedAlgorithmOnlyHeader as AlgOnly;
    use crate::ToBase64;

    // {"sub":"1234567890","name":"John Doe","admin":true}
    const CLAIMS: &str = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";

    const RS256_SIGNATURE: &str =
    "cQsAHF2jHvPGFP5zTD8BgoJrnzEx6JNQCpupebWLFnOc2r_punDDTylI6Ia4JZNkvy2dQP-7W-DEbFQ3oaarHsDndqUgwf9iYlDQxz4Rr2nEZX1FX0-FMEgFPeQpdwveCgjtTYUbVy37ijUySN_rW-xZTrsh_Ug-ica8t-zHRIw";

    const PREGENERATED_ES256_SIGNATURE: &str =
        "6SgeIURSNz_qFcxsKQOWZmi_ALiBctj_ZINvce4AOa-OQn9QI6lh8P78FTZx5LQtOleF3XeBlGIAdYms_VPecA";

    #[test]
    fn rs256_sign() -> Result<(), Error> {
        let key = PrivateKey::from_pem_bytes(include_bytes!("../../../test/rs256-private.pem"))?;
        let algorithm =
            AsymmetricKeyWithDigest::<sha2::Sha256, rsa::pkcs1v15::Signature, _>::new(key);
        let result = algorithm.sign(&AlgOnly(Rs256).to_base64()?, CLAIMS)?;
        assert_eq!(result, RS256_SIGNATURE);
        Ok(())
    }

    #[test]
    fn rs256_verify() -> Result<(), Error> {
        let key = PublicKey::from_pem_bytes(include_bytes!("../../../test/rs256-public.pem"))?;
        let verifier =
            AsymmetricKeyWithDigest::<sha2::Sha256, rsa::pkcs1v15::Signature, _>::new(key);
        assert!(
            verifier.verify(&AlgOnly(Rs256).to_base64()?, CLAIMS, RS256_SIGNATURE)?,
            "signature should be valid"
        );
        Ok(())
    }

    #[test]
    fn es256_sign() -> Result<(), Error> {
        let key = PrivateKey::from_pem_bytes(include_bytes!("../../../test/es256-private.pem"))?;
        let signer = AsymmetricKeyWithDigest::<sha2::Sha256, p256::ecdsa::Signature, _>::new(key);
        let signature = signer.sign(&AlgOnly(Es256).to_base64()?, CLAIMS)?;

        let key = PublicKey::from_pem_bytes(include_bytes!("../../../test/es256-public.pem"))?;
        let verifier = AsymmetricKeyWithDigest::<sha2::Sha256, p256::ecdsa::Signature, _>::new(key);
        assert!(
            verifier.verify(&AlgOnly(Es256).to_base64()?, CLAIMS, &signature)?,
            "signature should be valid"
        );
        Ok(())
    }

    #[test]
    fn es256_verify() -> Result<(), Error> {
        let key = PublicKey::from_pem_bytes(include_bytes!("../../../test/es256-public.pem"))?;
        let verifier = AsymmetricKeyWithDigest::<sha2::Sha256, p256::ecdsa::Signature, _>::new(key);
        assert!(
            verifier.verify(
                &AlgOnly(Es256).to_base64()?,
                CLAIMS,
                PREGENERATED_ES256_SIGNATURE
            )?,
            "signature should be valid"
        );

        Ok(())
    }

    #[test]
    fn genric_public_key_parse() -> Result<(), Error> {
        let pem = include_bytes!("../../../test/rs256-public.pem");
        super::PublicKey::<sha2::Sha256>::from_pem(
            std::str::from_utf8(pem).expect("invalid utf8 rsa key"),
        )
        .expect("invalid rsa key");

        let pem = include_bytes!("../../../test/es256-public.pem");
        super::PublicKey::<sha2::Sha256>::from_pem(
            std::str::from_utf8(pem).expect("invalid utf8 ec key"),
        )
        .expect("invalid ec key");

        Ok(())
    }

    #[test]
    fn genric_private_key_parse() -> Result<(), Error> {
        let pem = include_bytes!("../../../test/rs256-private.pem");
        super::PrivateKey::<sha2::Sha256>::from_pem(
            std::str::from_utf8(pem).expect("invalid utf8 rsa key"),
        )
        .expect("invalid rsa key");

        let pem = include_bytes!("../../../test/es256-private.pem");
        super::PrivateKey::<sha2::Sha256>::from_pem(
            std::str::from_utf8(pem).expect("invalid utf8 ec key"),
        )
        .expect("invalid ec key");

        Ok(())
    }
}
