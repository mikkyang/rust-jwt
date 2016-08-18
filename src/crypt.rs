extern crate openssl;

use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::{
    Mac,
    MacResult,
};
use crypto::sha2::Sha256;
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
	let mut hasher = Sha256::new();
	hasher.input_str(data);
	let data_bytes = hasher.output_bytes();
	let mut data = vec![0u8; data_bytes];
	let mut data = &mut data[..];
	hasher.result(&mut data);
	(private_key.sign(hash::Type::SHA256, data).unwrap()).to_base64(BASE_CONFIG)
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
