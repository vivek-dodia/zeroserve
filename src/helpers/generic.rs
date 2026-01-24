use std::time::{SystemTime, UNIX_EPOCH};

use async_ebpf::program::HelperScope;
use base64ct::{Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::{
    logging::async_log,
    script::{ScriptResponse, deref_and_write_cstr, read_utf8, with_ectx},
};

const SHA256_LEN: usize = 32;
const HMAC_SHA256_LEN: usize = 32;
const BASE64_ENCODING_STANDARD: u64 = 0;
const BASE64_ENCODING_STANDARD_NO_PAD: u64 = 1;
const BASE64_ENCODING_URL: u64 = 2;
const BASE64_ENCODING_URL_NO_PAD: u64 = 3;
pub fn h_log(
    scope: &async_ebpf::program::HelperScope,
    msg_ptr: u64,
    msg_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let mut msg = scope.user_memory(msg_ptr, msg_len)?;
    let newline_index = msg.iter().enumerate().find(|x| *x.1 == b'\n').map(|x| x.0);
    with_ectx(scope, |ctx| {
        let buf = &mut ctx.log_buffer;
        if newline_index.is_none() && buf.len() < 512 {
            buf.extend_from_slice(msg);
            return Ok(());
        }
        if let Some(i) = newline_index {
            buf.extend_from_slice(&msg[..i]);
            msg = &msg[i + 1..];
        }
        for b in &mut *buf {
            if !b.is_ascii() || (b.is_ascii_control() && *b != b'\t') {
                *b = b'?';
            }
        }
        let output = format!(
            "[user_log] {}: {}: {}\n",
            ctx.request.request_id,
            ctx.script_name,
            std::str::from_utf8(&buf).unwrap_or("(invalid)")
        );
        buf.clear();
        buf.extend_from_slice(msg);
        scope.post_task(async move {
            async_log(output.into_bytes()).await;
            |_: &HelperScope| Ok(0)
        });
        Ok(())
    })?;
    Ok(0)
}

pub fn h_now_ms(
    _: &async_ebpf::program::HelperScope,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Ok(now.as_millis() as u64)
}

pub fn h_env_get(
    scope: &async_ebpf::program::HelperScope,
    name_ptr: u64,
    name_len: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let name = read_utf8(scope, name_ptr, name_len)?;
    let value = std::env::var(name.trim()).unwrap_or_default();
    deref_and_write_cstr(scope, out_ptr, out_len, &value)
}

pub fn h_getrandom(
    scope: &async_ebpf::program::HelperScope,
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
    scope: &async_ebpf::program::HelperScope,
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
    scope: &async_ebpf::program::HelperScope,
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

pub fn h_base64_encode(
    scope: &async_ebpf::program::HelperScope,
    data_ptr: u64,
    data_len: u64,
    out_ptr: u64,
    out_len: u64,
    encoding: u64,
) -> Result<u64, ()> {
    let data = scope.user_memory(data_ptr, data_len)?;
    let required_len = base64_encoded_len(encoding, &data)?;
    if data_len != 0 && required_len == 0 {
        return Err(());
    }
    if out_len == 0 {
        return Ok(required_len as u64);
    }
    if required_len as u64 > out_len {
        return Err(());
    }
    let mut out = scope.user_memory_mut(out_ptr, out_len)?;
    base64_encode_into(encoding, &data, &mut out[..required_len])?;
    Ok(required_len as u64)
}

pub fn h_base64_decode_in_place(
    scope: &async_ebpf::program::HelperScope,
    buf_ptr: u64,
    buf_len: u64,
    encoding: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if buf_len == 0 {
        return Ok(0);
    }
    let mut buf = scope.user_memory_mut(buf_ptr, buf_len)?;
    match base64_decode_in_place(encoding, &mut buf) {
        Ok(x) => Ok(x),
        Err(_) => Ok(-1i64 as u64),
    }
}

pub fn h_memcpy(
    scope: &async_ebpf::program::HelperScope,
    dst_ptr: u64,
    src_ptr: u64,
    n: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if n == 0 {
        return Ok(dst_ptr);
    }
    let src = scope.user_memory(src_ptr, n)?;
    let mut dst = scope.user_memory_mut(dst_ptr, n)?;
    dst.copy_from_slice(&src);
    Ok(dst_ptr)
}

pub fn h_memcmp(
    scope: &async_ebpf::program::HelperScope,
    a_ptr: u64,
    b_ptr: u64,
    n: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if n == 0 {
        return Ok(0);
    }
    let a = scope.user_memory(a_ptr, n)?;
    let b = scope.user_memory(b_ptr, n)?;
    for (left, right) in a.iter().zip(b.iter()) {
        if left != right {
            let diff = i64::from(*left) - i64::from(*right);
            return Ok(diff as u64);
        }
    }
    Ok(0)
}

pub fn h_memset(
    scope: &async_ebpf::program::HelperScope,
    dst_ptr: u64,
    c: u64,
    n: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if n == 0 {
        return Ok(dst_ptr);
    }
    let mut dst = scope.user_memory_mut(dst_ptr, n)?;
    dst.fill(c as u8);
    Ok(dst_ptr)
}

pub fn h_object_free(
    scope: &async_ebpf::program::HelperScope,
    idx: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        if ctx.external_objects.remove(idx) {
            Ok(0)
        } else {
            ctx.error = format!("invalid object index {}", idx);
            Err(())
        }
    })
}

fn base64_encoded_len(encoding: u64, data: &[u8]) -> Result<usize, ()> {
    match encoding {
        BASE64_ENCODING_STANDARD => Ok(Base64::encoded_len(data)),
        BASE64_ENCODING_STANDARD_NO_PAD => Ok(Base64Unpadded::encoded_len(data)),
        BASE64_ENCODING_URL => Ok(Base64Url::encoded_len(data)),
        BASE64_ENCODING_URL_NO_PAD => Ok(Base64UrlUnpadded::encoded_len(data)),
        _ => Err(()),
    }
}

fn base64_encode_into(encoding: u64, data: &[u8], out: &mut [u8]) -> Result<(), ()> {
    match encoding {
        BASE64_ENCODING_STANDARD => Base64::encode(data, out).map(|_| ()).map_err(|_| ()),
        BASE64_ENCODING_STANDARD_NO_PAD => Base64Unpadded::encode(data, out)
            .map(|_| ())
            .map_err(|_| ()),
        BASE64_ENCODING_URL => Base64Url::encode(data, out).map(|_| ()).map_err(|_| ()),
        BASE64_ENCODING_URL_NO_PAD => Base64UrlUnpadded::encode(data, out)
            .map(|_| ())
            .map_err(|_| ()),
        _ => Err(()),
    }
}

fn base64_decode_in_place(encoding: u64, buf: &mut [u8]) -> Result<u64, ()> {
    match encoding {
        BASE64_ENCODING_STANDARD => Base64::decode_in_place(buf)
            .map(|decoded| decoded.len() as u64)
            .map_err(|_| ()),
        BASE64_ENCODING_STANDARD_NO_PAD => Base64Unpadded::decode_in_place(buf)
            .map(|decoded| decoded.len() as u64)
            .map_err(|_| ()),
        BASE64_ENCODING_URL => Base64Url::decode_in_place(buf)
            .map(|decoded| decoded.len() as u64)
            .map_err(|_| ()),
        BASE64_ENCODING_URL_NO_PAD => Base64UrlUnpadded::decode_in_place(buf)
            .map(|decoded| decoded.len() as u64)
            .map_err(|_| ()),
        _ => Err(()),
    }
}

pub fn h_req_method(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        deref_and_write_cstr(scope, out_ptr, out_len, &ctx.request.method)
    })
}

pub fn h_req_path(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        deref_and_write_cstr(scope, out_ptr, out_len, &ctx.request.path)
    })
}

pub fn h_req_uri(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        deref_and_write_cstr(scope, out_ptr, out_len, &ctx.request.uri)
    })
}

pub fn h_req_set_uri(
    scope: &async_ebpf::program::HelperScope,
    uri_ptr: u64,
    uri_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let uri = read_utf8(scope, uri_ptr, uri_len)?;
    with_ectx(scope, |ctx| {
        ctx.request.set_uri(uri)?;
        Ok(0)
    })
}

pub fn h_req_query(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        deref_and_write_cstr(scope, out_ptr, out_len, &ctx.request.query)
    })
}

pub fn h_req_scheme(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        deref_and_write_cstr(scope, out_ptr, out_len, &ctx.request.scheme)
    })
}

pub fn h_req_peer(
    scope: &async_ebpf::program::HelperScope,
    out_ptr: u64,
    out_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        deref_and_write_cstr(scope, out_ptr, out_len, &ctx.request.peer)
    })
}

pub fn h_req_header(
    scope: &async_ebpf::program::HelperScope,
    name_ptr: u64,
    name_len: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let name = read_utf8(scope, name_ptr, name_len)?;
    with_ectx(scope, |ctx| {
        let value = ctx.request.header(name.trim()).unwrap_or("");
        deref_and_write_cstr(scope, out_ptr, out_len, value)
    })
}

pub fn h_req_set_header(
    scope: &async_ebpf::program::HelperScope,
    name_ptr: u64,
    name_len: u64,
    value_ptr: u64,
    value_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let name = read_utf8(scope, name_ptr, name_len)?;
    let value = if value_len == 0 {
        None
    } else {
        Some(read_utf8(scope, value_ptr, value_len)?)
    };
    with_ectx(scope, |ctx| {
        ctx.request.set_header(name, value)?;
        Ok(0)
    })
}

pub fn h_req_query_param(
    scope: &async_ebpf::program::HelperScope,
    name_ptr: u64,
    name_len: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let name = read_utf8(scope, name_ptr, name_len)?;
    with_ectx(scope, |ctx| {
        let value = ctx.request.query_param(name.trim()).unwrap_or("");
        deref_and_write_cstr(scope, out_ptr, out_len, value)
    })
}

pub fn h_meta_get(
    scope: &async_ebpf::program::HelperScope,
    key_ptr: u64,
    key_len: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = read_utf8(scope, key_ptr, key_len)?;
    with_ectx(scope, |ctx| {
        let value = ctx
            .metadata
            .get(key.trim())
            .map(String::as_str)
            .unwrap_or("");
        deref_and_write_cstr(scope, out_ptr, out_len, value)
    })
}

pub fn h_meta_set(
    scope: &async_ebpf::program::HelperScope,
    key_ptr: u64,
    key_len: u64,
    val_ptr: u64,
    val_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let key = read_utf8(scope, key_ptr, key_len)?;
    let key = key.trim().to_string();
    if key.is_empty() {
        return Err(());
    }
    let value = read_utf8(scope, val_ptr, val_len)?.to_string();
    with_ectx(scope, |ctx| {
        ctx.metadata.insert(key, value);
        Ok(0)
    })
}

pub fn h_respond(
    scope: &async_ebpf::program::HelperScope,
    status: u64,
    body_ptr: u64,
    body_len: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let status = u16::try_from(status).map_err(|_| ())?;
    let body = if body_len == 0 {
        Vec::new()
    } else {
        scope.user_memory(body_ptr, body_len)?.to_vec()
    };
    with_ectx(scope, |ctx| {
        ctx.response = Some(ScriptResponse { status, body });
        Ok(0)
    })
}

pub fn h_reverse_proxy(
    scope: &async_ebpf::program::HelperScope,
    url_ptr: u64,
    url_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let url = read_utf8(scope, url_ptr, url_len)?;
    let url = url.trim();
    if url.is_empty() {
        return Err(());
    }
    with_ectx(scope, |ctx| {
        if ctx.response.is_some() || ctx.reverse_proxy.is_some() {
            return Err(());
        }
        ctx.reverse_proxy = Some(url.to_string());
        Ok(0)
    })
}
