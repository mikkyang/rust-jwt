extern crate openssl;

use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::{
    Mac,
    MacResult,
};
use rustc_serialize::base64::{
    FromBase64,
    ToBase64,
};
use self::openssl::crypto::rsa;
use self::openssl::crypto::hash;
use BASE_CONFIG;

pub fn sign<D: Digest>(data: &str, key: &[u8], digest: D) -> String {
    let mut hmac = Hmac::new(digest, key);
    hmac.input(data.as_bytes());

    let mac = hmac.result();
    let code = mac.code();
    (*code).to_base64(BASE_CONFIG)
}

pub fn sign_rsa(data: &str, key: &[u8]) -> String {
	let private_key = rsa::RSA::private_key_from_pem(key).unwrap();
	(private_key.sign(hash::Type::SHA256, data.as_bytes()).unwrap()).to_base64(BASE_CONFIG)
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
