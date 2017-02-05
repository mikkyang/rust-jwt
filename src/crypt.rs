use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::{
    Mac,
    MacResult,
};
use openssl::sign::{Signer, Verifier};
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use openssl::rsa::Rsa;
use rustc_serialize::base64::{
    FromBase64,
    ToBase64,
};
use BASE_CONFIG;

pub fn sign<D: Digest>(data: &str, key: &[u8], digest: D) -> String {
    let mut hmac = Hmac::new(digest, key);
    hmac.input(data.as_bytes());

    let mac = hmac.result();
    let code = mac.code();
    (*code).to_base64(BASE_CONFIG)
}

pub fn sign_rsa(data: &str, key: &[u8], digest: MessageDigest) -> String {
    let private_key = Rsa::private_key_from_pem(key).unwrap();
    let pkey = PKey::from_rsa(private_key).unwrap();

    let mut signer = Signer::new(digest, &pkey).unwrap();
    signer.update(data.as_bytes()).unwrap();
    let sig = signer.finish().unwrap();
    sig.to_base64(BASE_CONFIG)
}

pub fn verify<D: Digest>(target: &str, data: &str, key: &[u8], digest: D) -> bool {
    let target_bytes = match target.from_base64() {
        Ok(x) => x,
        Err(_) => return false,
    };
    let target_mac = MacResult::new_from_owned(target_bytes);

    let mut hmac = Hmac::new(digest, key);
    hmac.input(data.as_bytes());

    hmac.result() == target_mac
}

pub fn verify_rsa(signature: &str, data: &str, key: &[u8], digest: MessageDigest) -> bool {
    let signature_bytes = match signature.from_base64() {
        Ok(x) => x,
        Err(_) => return false,
    };
    let public_key = Rsa::public_key_from_pem(key).unwrap();
    let pkey = PKey::from_rsa(public_key).unwrap();
    let mut verifier = Verifier::new(digest, &pkey).unwrap();
    verifier.update(data.as_bytes()).unwrap();
    verifier.finish(&signature_bytes).unwrap()
}
