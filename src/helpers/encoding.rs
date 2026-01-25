use async_ebpf::program::HelperScope;
use base64ct::{Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding};

const BASE64_ENCODING_STANDARD: u64 = 0;
const BASE64_ENCODING_STANDARD_NO_PAD: u64 = 1;
const BASE64_ENCODING_URL: u64 = 2;
const BASE64_ENCODING_URL_NO_PAD: u64 = 3;

pub fn h_base64_encode(
    scope: &HelperScope,
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
    scope: &HelperScope,
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

const HEX_LOWERCASE: u64 = 0;
const HEX_UPPERCASE: u64 = 1;

const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";
const HEX_CHARS_UPPER: &[u8; 16] = b"0123456789ABCDEF";

pub fn h_hex_encode(
    scope: &HelperScope,
    data_ptr: u64,
    data_len: u64,
    out_ptr: u64,
    out_len: u64,
    case: u64,
) -> Result<u64, ()> {
    let data = scope.user_memory(data_ptr, data_len)?;
    let required_len = data.len() * 2;
    if out_len == 0 {
        return Ok(required_len as u64);
    }
    if (out_len as usize) < required_len {
        return Err(());
    }
    let hex_chars = match case {
        HEX_LOWERCASE => HEX_CHARS_LOWER,
        HEX_UPPERCASE => HEX_CHARS_UPPER,
        _ => return Err(()),
    };
    let mut out = scope.user_memory_mut(out_ptr, out_len)?;
    for (i, &byte) in data.iter().enumerate() {
        out[i * 2] = hex_chars[(byte >> 4) as usize];
        out[i * 2 + 1] = hex_chars[(byte & 0x0f) as usize];
    }
    Ok(required_len as u64)
}

pub fn h_hex_decode_in_place(
    scope: &HelperScope,
    buf_ptr: u64,
    buf_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    if buf_len == 0 {
        return Ok(0);
    }
    if buf_len % 2 != 0 {
        return Ok(-1i64 as u64);
    }
    let mut buf = scope.user_memory_mut(buf_ptr, buf_len)?;
    match hex_decode_in_place(&mut buf) {
        Ok(len) => Ok(len),
        Err(_) => Ok(-1i64 as u64),
    }
}

fn hex_char_to_nibble(c: u8) -> Result<u8, ()> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(()),
    }
}

fn hex_decode_in_place(buf: &mut [u8]) -> Result<u64, ()> {
    let out_len = buf.len() / 2;
    for i in 0..out_len {
        let high = hex_char_to_nibble(buf[i * 2])?;
        let low = hex_char_to_nibble(buf[i * 2 + 1])?;
        buf[i] = (high << 4) | low;
    }
    Ok(out_len as u64)
}
