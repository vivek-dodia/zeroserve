use async_ebpf::program::HelperScope;

use crate::script::{deref_and_write_cstr, read_utf8, with_ectx};

pub fn h_res_status(
    scope: &HelperScope,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let Some(response_context) = &ctx.response_context else {
            return Err(());
        };
        Ok(response_context.borrow().status as u64)
    })
}

pub fn h_res_set_status(
    scope: &HelperScope,
    status: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    let status = u16::try_from(status).map_err(|_| ())?;
    if !(100..=999).contains(&status) {
        return Err(());
    }
    with_ectx(scope, |ctx| {
        let Some(response_context) = &ctx.response_context else {
            return Err(());
        };
        response_context.borrow_mut().status = status;
        Ok(0)
    })
}

pub fn h_res_header(
    scope: &HelperScope,
    name_ptr: u64,
    name_len: u64,
    out_ptr: u64,
    out_len: u64,
    _: u64,
) -> Result<u64, ()> {
    let name = read_utf8(scope, name_ptr, name_len)?;
    let name = name.trim();
    if name.is_empty() {
        return Err(());
    }
    with_ectx(scope, |ctx| {
        let Some(response_context) = &ctx.response_context else {
            return Err(());
        };
        let headers = &response_context.borrow().headers;
        let value = headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        deref_and_write_cstr(scope, out_ptr, out_len, value)
    })
}

pub fn h_res_continue_request(
    scope: &HelperScope,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    with_ectx(scope, |ctx| {
        let Some(response_context) = &ctx.response_context else {
            return Err(());
        };
        response_context.borrow_mut().continue_request = true;
        Ok(0)
    })
}
