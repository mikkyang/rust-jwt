use base64;
use crypto_mac::Mac;
use digest::generic_array::ArrayLength;
use digest::*;
use hmac::Hmac;

pub fn sign<D>(data: &str, key: &[u8], _digest: D) -> String
where
    D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    // This will panic for bad key sizes. Returning an error
    // would probably be better, but for now, I want to keep the
    // API as stable as possible
    let mut hmac = Hmac::<D>::new_varkey(key).unwrap();
    hmac.input(data.as_bytes());

    let mac = hmac.result();
    let code = mac.code();
    base64::encode_config(&code, base64::URL_SAFE_NO_PAD)
}

pub fn verify<D>(target: &str, data: &str, key: &[u8], _digest: D) -> bool
where
    D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    let target_bytes = match base64::decode_config(target, base64::URL_SAFE_NO_PAD) {
        Ok(x) => x,
        Err(_) => return false,
    };

    // This will panic for bad key sizes. Returning an error
    // would probably be better, but for now, I want to keep the
    // API as stable as possible
    let mut hmac = Hmac::<D>::new_varkey(key).unwrap();
    hmac.input(data.as_bytes());
    hmac.verify(&target_bytes).is_ok()
}
