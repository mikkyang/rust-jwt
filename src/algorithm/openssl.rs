//! OpenSSL support through the openssl crate.
//! Note that private keys can only be used for signing and that public keys
//! can only be used for verification.
//! ## Examples
//! ```
//! extern crate jwt;
//! extern crate openssl;
//!
//! use jwt::PKeyWithDigest;
//! use openssl::hash::MessageDigest;
//! use openssl::pkey::PKey;
//! let pem = include_bytes!("../../test/rs256-public.pem");
//! let rs256_public_key = PKeyWithDigest {
//!     digest: MessageDigest::sha256(),
//!     key: PKey::public_key_from_pem(pem).unwrap(),
//! };
//!
//! ```

use crate::algorithm::{AlgorithmType, SigningAlgorithm, VerifyingAlgorithm};
use crate::error::Error;
use crate::SEPARATOR;
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::sign::{Signer, Verifier};

/// A wrapper class around [PKey](../../../openssl/pkey/struct.PKey.html) that
/// associates the key with a
/// [MessageDigest](../../../openssl/hash/struct.MessageDigest.html).
pub struct PKeyWithDigest<T> {
    pub digest: MessageDigest,
    pub key: PKey<T>,
}

impl<T> PKeyWithDigest<T> {
    fn algorithm_type(&self) -> AlgorithmType {
        match (self.key.id(), self.digest.type_()) {
            (Id::RSA, Nid::SHA256) => AlgorithmType::Rs256,
            (Id::EC, Nid::SHA256) => AlgorithmType::Es256,
            _ => panic!("Invalid algorithm type"),
        }
    }
}

impl SigningAlgorithm for PKeyWithDigest<Private> {
    fn algorithm_type(&self) -> AlgorithmType {
        PKeyWithDigest::algorithm_type(self)
    }

    fn sign(&self, header: &str, claims: &str) -> Result<String, Error> {
        let mut signer = Signer::new(self.digest.clone(), &self.key)?;
        signer.update(header.as_bytes())?;
        signer.update(SEPARATOR.as_bytes())?;
        signer.update(claims.as_bytes())?;
        let signer_signature = signer.sign_to_vec()?;

        let signature = if self.key.id() == Id::EC {
            der_to_jose(&signer_signature)?
        } else {
            signer_signature
        };

        Ok(base64::encode_config(&signature, base64::URL_SAFE_NO_PAD))
    }
}

impl VerifyingAlgorithm for PKeyWithDigest<Public> {
    fn algorithm_type(&self) -> AlgorithmType {
        PKeyWithDigest::algorithm_type(self)
    }

    fn verify_bytes(&self, header: &str, claims: &str, signature: &[u8]) -> Result<bool, Error> {
        let mut verifier = Verifier::new(self.digest.clone(), &self.key)?;
        verifier.update(header.as_bytes())?;
        verifier.update(SEPARATOR.as_bytes())?;
        verifier.update(claims.as_bytes())?;

        let verified = if self.key.id() == Id::EC {
            let der = jose_to_der(signature)?;
            verifier.verify(&der)?
        } else {
            verifier.verify(signature)?
        };

        Ok(verified)
    }
}

/// OpenSSL by default signs ECDSA in DER, but JOSE expects them in a concatenated (R, S) format
fn der_to_jose(der: &[u8]) -> Result<Vec<u8>, Error> {
    let signature = EcdsaSig::from_der(&der)?;
    let r = signature.r().to_vec();
    let s = signature.s().to_vec();
    Ok([r, s].concat())
}

/// OpenSSL by default verifies ECDSA in DER, but JOSE parses out a concatenated (R, S) format
fn jose_to_der(jose: &[u8]) -> Result<Vec<u8>, Error> {
    let (r, s) = jose.split_at(jose.len() / 2);
    let ecdsa_signature =
        EcdsaSig::from_private_components(BigNum::from_slice(r)?, BigNum::from_slice(s)?)?;
    Ok(ecdsa_signature.to_der()?)
}

#[cfg(test)]
mod tests {
    use crate::algorithm::openssl::PKeyWithDigest;
    use crate::algorithm::{SigningAlgorithm, VerifyingAlgorithm};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;

    // {"alg":"RS256","typ":"JWT"}
    const RS256_HEADER: &'static str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
    // {"alg":"ES256","typ":"JWT"}
    const ES256_HEADER: &'static str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9";
    // {"sub":"1234567890","name":"John Doe","admin":true}
    const CLAIMS: &'static str =
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";

    const RS256_SIGNATURE: &'static str =
    "EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHGuERTqYZyuhtF39y\
    xJPAjUESwxk2J5k_4zM3O-vtd1Ghyo4IbqKKSy6J9mTniYJPenn5-HIirE";

    #[test]
    fn rs256_sign() {
        let pem = include_bytes!("../../test/rs256-private.pem");

        let algorithm = PKeyWithDigest {
            digest: MessageDigest::sha256(),
            key: PKey::private_key_from_pem(pem).unwrap(),
        };

        let result = algorithm.sign(RS256_HEADER, CLAIMS).unwrap();
        assert_eq!(result, RS256_SIGNATURE);
    }

    #[test]
    fn rs256_verify() {
        let pem = include_bytes!("../../test/rs256-public.pem");

        let algorithm = PKeyWithDigest {
            digest: MessageDigest::sha256(),
            key: PKey::public_key_from_pem(pem).unwrap(),
        };

        assert!(algorithm
            .verify(RS256_HEADER, CLAIMS, RS256_SIGNATURE)
            .unwrap_or(false));
    }

    #[test]
    fn es256() {
        let private_pem = include_bytes!("../../test/es256-private.pem");
        let private_key = PKeyWithDigest {
            digest: MessageDigest::sha256(),
            key: PKey::private_key_from_pem(private_pem).unwrap(),
        };

        let signature = private_key.sign(ES256_HEADER, CLAIMS).unwrap();

        let public_pem = include_bytes!("../../test/es256-public.pem");

        let public_key = PKeyWithDigest {
            digest: MessageDigest::sha256(),
            key: PKey::public_key_from_pem(public_pem).unwrap(),
        };

        assert!(public_key
            .verify(ES256_HEADER, CLAIMS, &*signature)
            .unwrap_or(false));
    }
}
