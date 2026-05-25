use std::time::{SystemTime, UNIX_EPOCH};

use async_ebpf::program::HelperScope;

use crate::{
    logging::async_log,
    script::{ScriptResponse, deref_and_write_cstr, read_utf8, with_ectx},
};

pub fn h_log(
    scope: &HelperScope,
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

pub fn h_now_ms(_: &HelperScope, _: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, ()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Ok(now.as_millis() as u64)
}

pub fn h_env_get(
    scope: &HelperScope,
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

pub fn h_memcpy(
    scope: &HelperScope,
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
    scope: &HelperScope,
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
    scope: &HelperScope,
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
    scope: &HelperScope,
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

pub fn h_req_method(
    scope: &HelperScope,
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
    scope: &HelperScope,
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
    scope: &HelperScope,
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
    scope: &HelperScope,
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
    scope: &HelperScope,
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
    scope: &HelperScope,
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
    scope: &HelperScope,
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
    scope: &HelperScope,
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
    scope: &HelperScope,
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
    scope: &HelperScope,
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
    scope: &HelperScope,
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
    scope: &HelperScope,
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
    scope: &HelperScope,
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
        ctx.response = Some(ScriptResponse {
            status,
            body,
            headers: Vec::new(),
        });
        Ok(0)
    })
}

pub fn h_reverse_proxy(
    scope: &HelperScope,
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
