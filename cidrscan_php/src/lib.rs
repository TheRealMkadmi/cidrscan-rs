#![cfg_attr(windows, feature(abi_vectorcall))]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::collections::HashMap;

use ext_php_rs::exception::PhpException;
use ext_php_rs::prelude::*;

use cidrscan_core as core;
use core::constants::TAG_MAX_LEN;
use core::{
    cidr_available_capacity, cidr_clear, cidr_close, cidr_flush, cidr_force_destroy, cidr_insert,
    cidr_lookup, cidr_lookup_full, cidr_open, cidr_resize, cidr_strerror,
    PatriciaHandle, PatriciaMatchT,
};
use cidrscan_core::errors::ErrorCode;
use ext_php_rs::types::Zval;

// ───────────────────────── helpers ──────────────────────────────────── //

/// Convert an `ErrorCode` into a `PhpException` using `cidr_strerror`.
fn err(code: ErrorCode) -> PhpException {
    let msg = unsafe { CStr::from_ptr(cidr_strerror(code)) }
        .to_string_lossy()
        .into_owned();
    PhpException::default(msg)
}

/// Convert a Rust `&str` to a *nul‑terminated* `CString`.
#[inline]
fn to_cstr(s: &str) -> Result<CString, PhpException> {
    CString::new(s).map_err(|_| PhpException::default("String contains NUL byte".into()))
}

// ───────────────────────── lifetime ──────────────────────────────────── //

/// Open (or create) a shared‑memory arena and return the opaque handle.
#[php_function]
pub fn cidr_open_php(name: String, capacity: usize) -> PhpResult<isize> {
    let cname = to_cstr(&name)?;
    let mut handle: PatriciaHandle = ptr::null_mut();
    let rc = cidr_open(cname.as_ptr(), capacity, &mut handle);
    if rc == ErrorCode::Success {
        Ok(handle as isize)
    } else {
        Err(err(rc))
    }
}

/// Close a previously obtained handle (idempotent).
#[php_function]
pub fn cidr_close_php(handle: isize) {
    if handle != 0 {
        cidr_close(handle as PatriciaHandle);
    }
}

// ───────────────────────── CRUD ──────────────────────────────────────── //

#[php_function]
pub fn cidr_insert_php(handle: isize, cidr: String, ttl: u64, tag: Option<String>) -> PhpResult<()> {
    let h = handle as PatriciaHandle;
    let cidr_c = to_cstr(&cidr)?;
    let (_tag_c, tag_ptr): (Option<CString>, *const c_char) = match tag {
        Some(t) => {
            let tag_cstring = to_cstr(&t)?;
            let ptr = tag_cstring.as_ptr();
            (Some(tag_cstring), ptr)
        },
        None => (None, ptr::null()),
    };
    let rc = cidr_insert(h, cidr_c.as_ptr(), ttl, tag_ptr);
    if rc == ErrorCode::Success { Ok(()) } else { Err(err(rc)) }
}

#[php_function]
pub fn cidr_delete_php(handle: isize, cidr: String) -> PhpResult<()> {
    let h = handle as PatriciaHandle;
    let cidr_c = to_cstr(&cidr)?;
    let rc = core::cidr_delete(h, cidr_c.as_ptr());
    if rc == ErrorCode::Success { Ok(()) } else { Err(err(rc)) }
}

#[php_function]
pub fn cidr_lookup_php(handle: isize, addr: String) -> PhpResult<bool> {
    let h = handle as PatriciaHandle;
    let addr_c = to_cstr(&addr)?;
    let mut found: bool = false;
    let rc = cidr_lookup(h, addr_c.as_ptr(), &mut found);
    if rc == ErrorCode::Success {
        Ok(found)
    } else {
        Err(err(rc))
    }
}

#[php_function]
pub fn cidr_lookup_full_php(handle: isize, addr: String) -> PhpResult<HashMap<String, Zval>> {
    let h = handle as PatriciaHandle;
    let addr_c = to_cstr(&addr)?;
    let mut m = PatriciaMatchT {
        key_high: 0,
        key_low: 0,
        plen: 0,
        tag: [0; TAG_MAX_LEN],
    };
    let rc = cidr_lookup_full(h, addr_c.as_ptr(), &mut m);
    if rc != ErrorCode::Success {
        return Err(err(rc));
    }
    // Build associative array for PHP.
    let mut out: HashMap<String, Zval> = HashMap::with_capacity(4);

    let mut zv = Zval::new();
    zv.set_long(m.key_high as i64);
    out.insert("key_high".into(), zv);

    let mut zv = Zval::new();
    zv.set_long(m.key_low as i64);
    out.insert("key_low".into(), zv);

    let mut zv = Zval::new();
    zv.set_long(m.plen as i64);
    out.insert("plen".into(), zv);

    let tag_cstr = unsafe { CStr::from_ptr(m.tag.as_ptr()) };
    let tag_str: String = tag_cstr.to_string_lossy().into_owned();
    let mut zv = Zval::new();
    zv.set_string(&tag_str, false).expect("failed to set string zval");
    out.insert("tag".into(), zv);

    Ok(out)
}

// ───────────────────── capacity & maintenance ───────────────────────── //

#[php_function]
pub fn cidr_available_capacity_php(handle: isize) -> PhpResult<u64> {
    let h = handle as PatriciaHandle;
    let mut cap: u64 = 0;
    let rc = cidr_available_capacity(h, &mut cap);
    if rc == ErrorCode::Success { Ok(cap) } else { Err(err(rc)) }
}

#[php_function]
pub fn cidr_flush_php(handle: isize) -> PhpResult<()> {
    let rc = cidr_flush(handle as PatriciaHandle);
    if rc == ErrorCode::Success { Ok(()) } else { Err(err(rc)) }
}

#[php_function]
pub fn cidr_clear_php(handle: isize) -> PhpResult<()> {
    let rc = cidr_clear(handle as PatriciaHandle);
    if rc == ErrorCode::Success { Ok(()) } else { Err(err(rc)) }
}

#[php_function]
pub fn cidr_resize_php(handle: isize, new_capacity: usize) -> PhpResult<()> {
    let rc = cidr_resize(handle as PatriciaHandle, new_capacity);
    if rc == ErrorCode::Success { Ok(()) } else { Err(err(rc)) }
}

// ───────────────────── misc helpers ─────────────────────────────────── //

#[php_function]
pub fn cidr_strerror_php(code: i32) -> String {
    let code_enum: ErrorCode = unsafe { std::mem::transmute(code) };
    unsafe { CStr::from_ptr(cidr_strerror(code_enum)).to_string_lossy().into_owned() }
}

#[php_function]
pub fn cidr_force_destroy_php(name: String) -> PhpResult<()> {
    let cname = to_cstr(&name)?;
    let rc = cidr_force_destroy(cname.as_ptr());
    if rc == ErrorCode::Success { Ok(()) } else { Err(err(rc)) }
}

// ───────────────────── module registration ──────────────────────────── //

#[php_module]
pub fn module(module: ModuleBuilder) -> ModuleBuilder {
    module
}
