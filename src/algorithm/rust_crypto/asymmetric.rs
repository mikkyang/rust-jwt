use crate::algorithm::{AlgorithmType, SigningAlgorithm, VerifyingAlgorithm};
use crate::error::Error;
use crate::SEPARATOR;

use base64::Engine;
use digest::Digest;
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use signature::{DigestSigner, DigestVerifier, SignatureEncoding};

#[derive(Clone, Debug)]
pub enum VerifyingKey {
    RS256(Box<rsa::pkcs1v15::VerifyingKey<sha2::Sha256>>),
    RS384(Box<rsa::pkcs1v15::VerifyingKey<sha2::Sha384>>),
    RS512(Box<rsa::pkcs1v15::VerifyingKey<sha2::Sha512>>),
    EC256(Box<p256::ecdsa::VerifyingKey>),
}

impl VerifyingKey {
    pub fn from_ec256(key: p256::PublicKey) -> Self {
        Self::EC256(p256::ecdsa::VerifyingKey::from(key).into())
    }

    pub fn from_rsa256(key: RsaPublicKey) -> Self {
        Self::RS256(rsa::pkcs1v15::VerifyingKey::new(key).into())
    }

    pub fn from_rsa384(key: RsaPublicKey) -> Self {
        Self::RS384(rsa::pkcs1v15::VerifyingKey::new(key).into())
    }

    pub fn from_rsa512(key: RsaPublicKey) -> Self {
        Self::RS512(rsa::pkcs1v15::VerifyingKey::new(key).into())
    }
}

#[derive(Clone, Debug)]
pub enum SigningKey {
    RS256(Box<rsa::pkcs1v15::SigningKey<sha2::Sha256>>),
    RS384(Box<rsa::pkcs1v15::SigningKey<sha2::Sha384>>),
    RS512(Box<rsa::pkcs1v15::SigningKey<sha2::Sha512>>),
    EC256(Box<p256::ecdsa::SigningKey>),
}

impl SigningKey {
    pub fn from_ec256(key: p256::SecretKey) -> Self {
        Self::EC256(p256::ecdsa::SigningKey::from(key).into())
    }

    pub fn from_rsa256(key: RsaPrivateKey) -> Self {
        Self::RS256(rsa::pkcs1v15::SigningKey::new(key).into())
    }

    pub fn from_rsa384(key: RsaPrivateKey) -> Self {
        Self::RS384(rsa::pkcs1v15::SigningKey::new(key).into())
    }

    pub fn from_rsa512(key: RsaPrivateKey) -> Self {
        Self::RS512(rsa::pkcs1v15::SigningKey::new(key).into())
    }
}

pub use ::{digest, ecdsa, p256, rsa, signature};

#[derive(Clone, Debug)]
pub enum PublicKey {
    RSA(Box<RsaPublicKey>),
    EC256(Box<p256::PublicKey>),
}

impl PublicKey {
    pub fn from_pem_bytes(encoded: &[u8]) -> Result<Self, Error> {
        Self::from_pem(std::str::from_utf8(encoded).map_err(|_| Error::InvalidKey)?)
    }

    pub fn from_pem(encoded: &str) -> Result<Self, Error> {
        if let Ok(ec) = encoded.parse::<p256::PublicKey>() {
            Ok(PublicKey::EC256(ec.into()))
        } else if let Ok(rsa) = rsa::RsaPublicKey::from_public_key_pem(encoded) {
            Ok(PublicKey::RSA(rsa.into()))
        } else {
            Err(Error::InvalidKey)
        }
    }

    pub fn into_rsa(self) -> Result<RsaPublicKey, Self> {
        match self {
            PublicKey::RSA(rsa) => Ok(*rsa),
            _ => Err(self),
        }
    }

    pub fn into_ec256(self) -> Result<p256::PublicKey, Self> {
        match self {
            PublicKey::EC256(ec) => Ok(*ec),
            _ => Err(self),
        }
    }
}

#[derive(Clone, Debug)]
pub enum PrivateKey {
    RSA(Box<RsaPrivateKey>),
    EC256(Box<p256::SecretKey>),
}

impl PrivateKey {
    pub fn from_pem_bytes(encoded: &[u8]) -> Result<Self, Error> {
        Self::from_pem(std::str::from_utf8(encoded).map_err(|_| Error::InvalidKey)?)
    }

    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        if let Ok(ec) = pem.parse::<p256::SecretKey>() {
            Ok(PrivateKey::EC256(ec.into()))
        } else if let Ok(rsa) = rsa::RsaPrivateKey::from_pkcs8_pem(pem) {
            Ok(PrivateKey::RSA(rsa.into()))
        } else if let Ok(rsa) = rsa::RsaPrivateKey::from_pkcs1_pem(pem) {
            Ok(PrivateKey::RSA(rsa.into()))
        } else {
            Err(Error::InvalidKey)
        }
    }

    pub fn into_rsa(self) -> Result<RsaPrivateKey, Self> {
        match self {
            PrivateKey::RSA(rsa) => Ok(*rsa),
            _ => Err(self),
        }
    }

    pub fn into_ec256(self) -> Result<p256::SecretKey, Self> {
        match self {
            PrivateKey::EC256(ec) => Ok(*ec),
            _ => Err(self),
        }
    }
}

pub struct AsymmetricKeyWithDigest<K> {
    key: K,
}

impl<K> AsymmetricKeyWithDigest<K> {
    pub fn new(key: K) -> Self {
        Self { key }
    }
}

impl SigningAlgorithm for AsymmetricKeyWithDigest<SigningKey> {
    fn algorithm_type(&self) -> AlgorithmType {
        match self.key {
            SigningKey::RS256(_) => AlgorithmType::Rs256,
            SigningKey::RS384(_) => AlgorithmType::Rs384,
            SigningKey::RS512(_) => AlgorithmType::Rs512,
            SigningKey::EC256(_) => AlgorithmType::Es256,
        }
    }

    fn sign(&self, header: &str, claims: &str) -> Result<String, Error> {
        macro_rules! short_hand {
            ($key:ident, $hash:ty, $sig:ty) => {
                let mut digest = <$hash>::new();

                digest.update(header.as_bytes());
                digest.update(SEPARATOR.as_bytes());
                digest.update(claims.as_bytes());

                let signed: $sig = $key.try_sign_digest(digest)?;

                return Ok(
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signed.to_bytes())
                );
            };
        }

        match &self.key {
            SigningKey::RS256(key) => {
                short_hand!(key, sha2::Sha256, rsa::pkcs1v15::Signature);
            }
            SigningKey::RS384(key) => {
                short_hand!(key, sha2::Sha384, rsa::pkcs1v15::Signature);
            }
            SigningKey::RS512(key) => {
                short_hand!(key, sha2::Sha512, rsa::pkcs1v15::Signature);
            }
            SigningKey::EC256(key) => {
                short_hand!(key, sha2::Sha256, p256::ecdsa::Signature);
            }
        }
    }
}

impl VerifyingAlgorithm for AsymmetricKeyWithDigest<VerifyingKey> {
    fn algorithm_type(&self) -> AlgorithmType {
        match self.key {
            VerifyingKey::RS256(_) => AlgorithmType::Rs256,
            VerifyingKey::RS384(_) => AlgorithmType::Rs384,
            VerifyingKey::RS512(_) => AlgorithmType::Rs512,
            VerifyingKey::EC256(_) => AlgorithmType::Es256,
        }
    }

    fn verify_bytes(&self, header: &str, claims: &str, signature: &[u8]) -> Result<bool, Error> {
        macro_rules! short_hand {
            ($key:ident, $hash:ty, $sig:ty) => {
                let mut digest = <$hash>::new();

                digest.update(header.as_bytes());
                digest.update(SEPARATOR.as_bytes());
                digest.update(claims.as_bytes());

                let signature = <$sig>::try_from(signature).map_err(|_| Error::InvalidSignature)?;

                return Ok($key.verify_digest(digest, &signature).is_ok());
            };
        }

        match &self.key {
            VerifyingKey::RS256(key) => {
                short_hand!(key, sha2::Sha256, rsa::pkcs1v15::Signature);
            }
            VerifyingKey::RS384(key) => {
                short_hand!(key, sha2::Sha384, rsa::pkcs1v15::Signature);
            }
            VerifyingKey::RS512(key) => {
                short_hand!(key, sha2::Sha512, rsa::pkcs1v15::Signature);
            }
            VerifyingKey::EC256(key) => {
                short_hand!(key, sha2::Sha256, p256::ecdsa::Signature);
            }
        }
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
        let signer = AsymmetricKeyWithDigest::new(SigningKey::from_rsa256(key.into_rsa().unwrap()));
        let result = signer.sign(&AlgOnly(Rs256).to_base64()?, CLAIMS)?;
        assert_eq!(result, RS256_SIGNATURE);
        Ok(())
    }

    #[test]
    fn rs256_verify() -> Result<(), Error> {
        let key = PublicKey::from_pem_bytes(include_bytes!("../../../test/rs256-public.pem"))?;
        let verifier =
            AsymmetricKeyWithDigest::new(VerifyingKey::from_rsa256(key.into_rsa().unwrap()));
        assert!(
            verifier.verify(&AlgOnly(Rs256).to_base64()?, CLAIMS, RS256_SIGNATURE)?,
            "signature should be valid"
        );
        Ok(())
    }

    #[test]
    fn es256_sign() -> Result<(), Error> {
        let key = PrivateKey::from_pem_bytes(include_bytes!("../../../test/es256-private.pem"))?;
        let signer =
            AsymmetricKeyWithDigest::new(SigningKey::from_ec256(key.into_ec256().unwrap()));
        let signature = signer.sign(&AlgOnly(Es256).to_base64()?, CLAIMS)?;

        let key = PublicKey::from_pem_bytes(include_bytes!("../../../test/es256-public.pem"))?;
        let verifier =
            AsymmetricKeyWithDigest::new(VerifyingKey::from_ec256(key.into_ec256().unwrap()));
        assert!(
            verifier.verify(&AlgOnly(Es256).to_base64()?, CLAIMS, &signature)?,
            "signature should be valid"
        );
        Ok(())
    }

    #[test]
    fn es256_verify() -> Result<(), Error> {
        let key = PublicKey::from_pem_bytes(include_bytes!("../../../test/es256-public.pem"))?;
        let verifier =
            AsymmetricKeyWithDigest::new(VerifyingKey::from_ec256(key.into_ec256().unwrap()));
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
        match PublicKey::from_pem_bytes(include_bytes!("../../../test/rs256-public.pem")) {
            Ok(PublicKey::RSA(_)) => {}
            _ => panic!("invalid rsa key"),
        }

        match PublicKey::from_pem_bytes(include_bytes!("../../../test/es256-public.pem")) {
            Ok(PublicKey::EC256(_)) => {}
            _ => panic!("invalid ec key"),
        }

        Ok(())
    }

    #[test]
    fn genric_private_key_parse() -> Result<(), Error> {
        match PrivateKey::from_pem_bytes(include_bytes!("../../../test/rs256-private.pem")) {
            Ok(PrivateKey::RSA(_)) => {}
            _ => panic!("invalid rsa key"),
        }

        match PrivateKey::from_pem_bytes(include_bytes!("../../../test/es256-private.pem")) {
            Ok(PrivateKey::EC256(_)) => {}
            _ => panic!("invalid ec key"),
        }

        Ok(())
    }
}
