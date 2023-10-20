use crate::algorithm::{AlgorithmType, SigningAlgorithm, VerifyingAlgorithm};
use crate::error::Error;

use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier};

impl SigningAlgorithm for SigningKey {
    fn algorithm_type(&self) -> AlgorithmType {
        AlgorithmType::EdDSA
    }

    fn sign(&self, header: &str, claims: &str) -> Result<String, Error> {
        Ok(base64::encode_config(Signer::sign(self, super::make_body(header, claims).as_slice()).to_bytes(), base64::URL_SAFE_NO_PAD))
    }
}

impl VerifyingAlgorithm for VerifyingKey {
    fn algorithm_type(&self) -> AlgorithmType {
        AlgorithmType::EdDSA
    }

    fn verify_bytes(&self, header: &str, claims: &str, signature: &[u8]) -> Result<bool, Error> {
        let signature = ed25519_dalek::Signature::from_slice(signature).map_err(|_| Error::InvalidSignature)?;
        Ok(Verifier::verify(self, super::make_body(header, claims).as_slice(), &signature).is_ok())
    }
}

#[cfg(test)]
mod test {
    use crate::{header::PrecomputedAlgorithmOnlyHeader as AlgOnly, ToBase64, Error};
    use super::{SigningAlgorithm,VerifyingAlgorithm};

    use ed25519_dalek::pkcs8::{DecodePrivateKey,DecodePublicKey};

    // {"sub":"1234567890","name":"John Doe","admin":true}
    const CLAIMS: &'static str =
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";

    #[test]
    fn roundtrip() -> Result<(), Error> {

        let private_key_pem = include_str!("../../test/eddsa-private.pem");
        let private_key = ed25519_dalek::SigningKey::from_pkcs8_pem(private_key_pem).expect("couldn't load private key");

        let signature = private_key.sign(&AlgOnly(super::AlgorithmType::EdDSA).to_base64()?, CLAIMS)?;

        let public_key_pem = include_str!("../../test/eddsa-public.pem");
        let public_key = ed25519_dalek::VerifyingKey::from_public_key_pem(public_key_pem).expect("couldn't load public key");

        let verification_result = public_key.verify(&AlgOnly(super::AlgorithmType::EdDSA).to_base64()?, CLAIMS, &*signature)?;
        assert!(verification_result);

        Ok(())
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn cross_verify_openssl() -> Result<(), Error> {
        let private_key_pem = include_str!("../../test/eddsa-private.pem");
        let dalek_private_key = ed25519_dalek::SigningKey::from_pkcs8_pem(private_key_pem).expect("couldn't load private key");
        let openssl_private_key = crate::algorithm::openssl::PKeyWithDigest {
            digest: openssl::hash::MessageDigest::null(),
            key: openssl::pkey::PKey::private_key_from_pem(private_key_pem.as_bytes())?,
        };

        let public_key_pem = include_str!("../../test/eddsa-public.pem");

        let dalek_public_key = ed25519_dalek::VerifyingKey::from_public_key_pem(public_key_pem).expect("couldn't load public key");
        let openssl_public_key = crate::algorithm::openssl::PKeyWithDigest {
            digest: openssl::hash::MessageDigest::null(),
            key: openssl::pkey::PKey::public_key_from_pem(public_key_pem.as_bytes())?,
        };

        let dalek_signature = dalek_private_key.sign(&AlgOnly(super::AlgorithmType::EdDSA).to_base64()?, CLAIMS)?;
        let openssl_signature = openssl_private_key.sign(&AlgOnly(super::AlgorithmType::EdDSA).to_base64()?, CLAIMS)?;

        assert!(dalek_public_key.verify(&AlgOnly(super::AlgorithmType::EdDSA).to_base64()?, CLAIMS, &*dalek_signature)?);
        assert!(openssl_public_key.verify(&AlgOnly(super::AlgorithmType::EdDSA).to_base64()?, CLAIMS, &*dalek_signature)?);
        assert!(dalek_public_key.verify(&AlgOnly(super::AlgorithmType::EdDSA).to_base64()?, CLAIMS, &*openssl_signature)?);
        assert!(openssl_public_key.verify(&AlgOnly(super::AlgorithmType::EdDSA).to_base64()?, CLAIMS, &*openssl_signature)?);
        Ok(())
    }
}
