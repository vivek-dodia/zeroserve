use async_ebpf::program::HelperScope;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

const SHA256_LEN: usize = 32;
const HMAC_SHA256_LEN: usize = 32;

pub fn h_getrandom(
    scope: &HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if out_len == 0 {
        return Ok(0);
    }
    let mut out = scope.user_memory_mut(out_ptr, out_len)?;
    rand::thread_rng().fill_bytes(&mut out[..]);
    Ok(out_len)
}

pub fn h_sha256(
    scope: &HelperScope,
    data_ptr: u64,
    data_len: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    if (out_len as usize) != SHA256_LEN {
        return Err(());
    }
    let data = scope.user_memory(data_ptr, data_len)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let digest = hasher.finalize();
    let mut out = scope.user_memory_mut(out_ptr, SHA256_LEN as u64)?;
    out.copy_from_slice(&digest);
    Ok(SHA256_LEN as u64)
}

pub fn h_hmac_sha256(
    scope: &HelperScope,
    key_ptr: u64,
    key_len: u64,
    msg_ptr: u64,
    msg_len: u64,
    out_ptr: u64,
) -> Result<u64, ()> {
    type HmacSha256 = Hmac<Sha256>;
    let key = scope.user_memory(key_ptr, key_len)?;
    let msg = scope.user_memory(msg_ptr, msg_len)?;
    let mut mac = HmacSha256::new_from_slice(&key).map_err(|_| ())?;
    mac.update(&msg);
    let digest = mac.finalize().into_bytes();
    let mut out = scope.user_memory_mut(out_ptr, HMAC_SHA256_LEN as u64)?;
    out[..digest.len()].copy_from_slice(&digest);
    Ok(digest.len() as u64)
}
