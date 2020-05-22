use crate::algorithm::{AlgorithmType, SigningAlgorithm, VerifyingAlgorithm};
use crate::error::Error;
use crate::SEPARATOR;
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::sign::{Signer, Verifier};

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
            let der_signature = signer_signature;

            let signature = EcdsaSig::from_der(&der_signature)?;
            let r = signature.r().to_vec();
            let s = signature.s().to_vec();
            [r, s].concat()
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
            let (r, s) = signature.split_at(signature.len() / 2);
            let ecdsa_signature =
                EcdsaSig::from_private_components(BigNum::from_slice(r)?, BigNum::from_slice(s)?)?;
            let der_signature = ecdsa_signature.to_der()?;
            verifier.verify(&der_signature)?
        } else {
            verifier.verify(signature)?
        };

        Ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithm::openssl::PKeyWithDigest;
    use crate::algorithm::{SigningAlgorithm, VerifyingAlgorithm};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;

    #[test]
    fn rs256_sign() {
        let pem = include_bytes!("../../test/private_rsa.pem");

        let algorithm = PKeyWithDigest {
            digest: MessageDigest::sha256(),
            key: PKey::private_key_from_pem(pem).unwrap(),
        };

        let result = algorithm
            .sign(
                "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
                "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9",
            )
            .unwrap();
        assert_eq!(result, "EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHGuERTqYZyuhtF39yxJPAjUESwxk2J5k_4zM3O-vtd1Ghyo4IbqKKSy6J9mTniYJPenn5-HIirE");
    }

    #[test]
    fn rs256_verify() {
        let pem = include_bytes!("../../test/public_rsa.pem");

        let algorithm = PKeyWithDigest {
            digest: MessageDigest::sha256(),
            key: PKey::public_key_from_pem(pem).unwrap(),
        };

        assert!(algorithm.verify(
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9",
            "EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHGuERTqYZyuhtF39yxJPAjUESwxk2J5k_4zM3O-vtd1Ghyo4IbqKKSy6J9mTniYJPenn5-HIirE",
        ).unwrap_or(false));
    }

    #[test]
    fn es256() {
        let header = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9";
        let claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";

        let private_pem = include_bytes!("../../test/es256-private.pem");
        let private_key = PKeyWithDigest {
            digest: MessageDigest::sha256(),
            key: PKey::private_key_from_pem(private_pem).unwrap(),
        };

        let signature = private_key.sign(header, claims).unwrap();

        let public_pem = include_bytes!("../../test/es256-public.pem");

        let public_key = PKeyWithDigest {
            digest: MessageDigest::sha256(),
            key: PKey::public_key_from_pem(public_pem).unwrap(),
        };

        assert!(public_key
            .verify(header, claims, &*signature)
            .unwrap_or(false));
    }
}
