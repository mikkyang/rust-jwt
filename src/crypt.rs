use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};
use base64;


pub fn sign<D: Digest>(data: &str, key: &[u8], digest: D) -> String {
    let mut hmac = Hmac::new(digest, key);
    hmac.input(data.as_bytes());

    let mac = hmac.result();
    let code = mac.code();
    base64::encode_config(code, base64::URL_SAFE_NO_PAD)
}

pub fn verify<D: Digest>(target: &str, data: &str, key: &[u8], digest: D) -> bool {
    let target_bytes = match base64::decode_config(target, base64::URL_SAFE_NO_PAD) {
        Ok(x) => x,
        Err(_) => return false,
    };
    let target_mac = MacResult::new_from_owned(target_bytes);

    let mut hmac = Hmac::new(digest, key);
    hmac.input(data.as_bytes());

    hmac.result() == target_mac
}
