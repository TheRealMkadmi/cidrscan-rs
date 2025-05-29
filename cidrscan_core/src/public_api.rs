use crate::{
    constants::TAG_MAX_LEN,
    errors::{map_error, ErrorCode},
    helpers::v4_key,
    PatriciaTree,
};
use ipnet::IpNet;
use std::{
    ffi::CStr,
    os::raw::c_char,
};

/// Opaque handle – **always** treated as owned by the caller.
pub type PatriciaHandle = *mut PatriciaTree;

/// Full-match record returned by `cidr_lookup_full`.
#[repr(C)]
pub struct PatriciaMatchT {
    pub key_high: u64,
    pub key_low:  u64,
    pub plen:     u8,
    pub tag:      [c_char; TAG_MAX_LEN],
}

// ─────────────────────────── helpers ─────────────────────────────────── //

#[inline]
fn cstr<'a>(p: *const c_char) -> Result<&'a str, ErrorCode> {
    if p.is_null() {
        return Err(ErrorCode::Utf8Error);
    }
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|_| ErrorCode::Utf8Error)
}

#[inline]
fn write_tag(dst: &mut [c_char; TAG_MAX_LEN], s: &str) {
    dst.iter_mut().for_each(|b| *b = 0);
    let n = s.len().min(TAG_MAX_LEN);
    dst[..n].copy_from_slice(
        &s.as_bytes()[..n]
            .iter()
            .map(|b| *b as c_char)
            .collect::<Vec<_>>(),
    );
}

#[inline]
fn ip_to_u128(s: &str) -> Result<(u128, u8), ErrorCode> {
    // Accept "addr/prefix" OR plain address
    if let Ok(net) = s.parse::<IpNet>() {
        let key = match net.network() {
            std::net::IpAddr::V4(v4) => v4_key(u32::from_be_bytes(v4.octets())) as u128,
            std::net::IpAddr::V6(v6) => u128::from(v6),
        };
        Ok((key, net.prefix_len() as u8))
    } else if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => Ok((v4_key(u32::from_be_bytes(v4.octets())) as u128, 32)),
            std::net::IpAddr::V6(v6) => Ok((u128::from(v6), 128)),
        }
    } else {
        Err(ErrorCode::InvalidPrefix)
    }
}

// ─── small helper to turn Result<T,ErrorCode> into early-return ──────────
macro_rules! try_c { ($expr:expr) => { match $expr {
    Ok(v)  => v,
    Err(e) => return e,
}}}

// ───────────────────────── lifetime ──────────────────────────────────── //

/// Open (or create) a shared-memory arena.  
/// Returns `Success` **and** stores the handle in `*out`
/// -- or an error code otherwise.
#[no_mangle]
pub extern "C" fn cidr_open(
    name_utf8: *const c_char,
    capacity: usize,
    out: *mut PatriciaHandle,
) -> ErrorCode {
    if out.is_null() {
        return ErrorCode::InvalidHandle;
    }
    match cstr(name_utf8).and_then(|n| PatriciaTree::open(n, capacity).map_err(|_| ErrorCode::ShmemOpenFailed)) {
        Ok(tree) => unsafe {
            *out = Box::into_raw(Box::new(tree));
            ErrorCode::Success
        },
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cidr_close(h: PatriciaHandle) {
    if !h.is_null() {
        unsafe { drop(Box::from_raw(h)) };
    }
}

// ───────────────────────── CRUD ──────────────────────────────────────── //

#[no_mangle]
pub extern "C" fn cidr_insert(
    h: PatriciaHandle,
    cidr_utf8: *const c_char,
    ttl: u64,
    tag_utf8: *const c_char,       // may be NULL
) -> ErrorCode {
    let tree    = match unsafe { h.as_ref() } { Some(t) => t, None => return ErrorCode::InvalidHandle };
    let cidr_s  = try_c!(cstr(cidr_utf8));
    let tag_opt = if tag_utf8.is_null() { None } else { Some(try_c!(cstr(tag_utf8))) };

    let net: IpNet = match cidr_s.parse() {
        Ok(n) => n,
        Err(_) => return ErrorCode::InvalidPrefix,
    };
    let key = match net.network() {
        std::net::IpAddr::V4(ip) => v4_key(u32::from_be_bytes(ip.octets())),
        std::net::IpAddr::V6(ip) => u128::from(ip),
    };

    match tree.insert(key, net.prefix_len() as u8, ttl, tag_opt) {
        Ok(_) => ErrorCode::Success,
        Err(e) => map_error(&e),
    }
}

#[no_mangle]
pub extern "C" fn cidr_delete(h: PatriciaHandle, cidr_utf8: *const c_char) -> ErrorCode {
    let tree   = match unsafe { h.as_ref() } { Some(t) => t, None => return ErrorCode::InvalidHandle };
    let cidr_s = try_c!(cstr(cidr_utf8));
    let net: IpNet = match cidr_s.parse() {
        Ok(n) => n,
        Err(_) => return ErrorCode::InvalidPrefix,
    };
    let key = match net.network() {
        std::net::IpAddr::V4(ip) => v4_key(u32::from_be_bytes(ip.octets())),
        std::net::IpAddr::V6(ip) => u128::from(ip),
    };
    match tree.delete(key, net.prefix_len() as u8) {
        Ok(_) => ErrorCode::Success,
        Err(e) => map_error(&e),
    }
}

#[no_mangle]
pub extern "C" fn cidr_lookup(
    h: PatriciaHandle,
    addr_utf8: *const c_char,
    out_found: *mut bool,
) -> ErrorCode {
    if out_found.is_null() { return ErrorCode::InvalidHandle; }
    let tree   = match unsafe { h.as_ref() } { Some(t) => t, None => return ErrorCode::InvalidHandle };
    let addr_s = try_c!(cstr(addr_utf8));
    let (key, _) = try_c!(ip_to_u128(addr_s));
    unsafe { *out_found = tree.lookup(key).is_some(); }
    ErrorCode::Success
}

#[no_mangle]
pub extern "C" fn cidr_lookup_full(
    h: PatriciaHandle,
    addr_utf8: *const c_char,
    out: *mut PatriciaMatchT,
) -> ErrorCode {
    if out.is_null() {
        return ErrorCode::InvalidHandle;
    }
    let tree   = match unsafe { h.as_ref() } { Some(t) => t, None => return ErrorCode::InvalidHandle };
    let addr_s = try_c!(cstr(addr_utf8));
    let (key, _) = try_c!(ip_to_u128(addr_s));

    match tree.lookup(key) {
        Some(m) => unsafe {
            (*out).key_high = (m.cidr_key >> 64) as u64;
            (*out).key_low  =  m.cidr_key as u64;
            (*out).plen     =  m.plen;
            write_tag(&mut (*out).tag, m.tag);
            ErrorCode::Success
        },
        None => ErrorCode::NotFound,
    }
}

// ───────────────────── capacity & maintenance ────────────────────────── //

#[no_mangle]
pub extern "C" fn cidr_available_capacity(
    h: PatriciaHandle,
    out: *mut u64,
) -> ErrorCode {
    if out.is_null() {
        return ErrorCode::InvalidHandle;
    }
    unsafe { h.as_ref() }
        .map(|t| { unsafe { *out = t.available_capacity() as u64 };  ErrorCode::Success })
        .unwrap_or(ErrorCode::InvalidHandle)
}

// flush retired nodes & expired slots
#[no_mangle]
pub extern "C" fn cidr_flush(h: PatriciaHandle) -> ErrorCode {
    match unsafe { h.as_ref() } {
        Some(tree) => {
            tree.flush();
            ErrorCode::Success
        }
        None => ErrorCode::InvalidHandle,
    }
}

#[no_mangle]
pub extern "C" fn cidr_clear(h: PatriciaHandle) -> ErrorCode {
    match unsafe { h.as_ref() } {
        Some(t) => match t.clear() {
            Ok(_) => ErrorCode::Success,
            Err(e) => map_error(&e),
        },
        None => ErrorCode::InvalidHandle,
    }
}

#[no_mangle]
pub extern "C" fn cidr_resize(h: PatriciaHandle, new_cap: usize) -> ErrorCode {
    // exclusive – caller must guarantee no concurrent use
    if h.is_null() { return ErrorCode::InvalidHandle; }
    let tree = unsafe { &mut *h };
        match tree.resize(new_cap) {
            Ok(_) => ErrorCode::Success,
            Err(e) => map_error(&e),
        }
    }

#[no_mangle]
pub extern "C" fn cidr_force_destroy(name_utf8: *const c_char) -> ErrorCode {
    let name = try_c!(cstr(name_utf8));
    let hash = crate::helpers::fnv1a_64(name);
    #[cfg(unix)]
    {
        let os_id = crate::platform::unix::make_os_id(crate::constants::PREFIX, hash);
        crate::platform::unix::platform_drop(&os_id);
    }
    #[cfg(windows)]
    {
        let os_id = crate::platform::windows::make_os_id(crate::constants::PREFIX, hash);
        crate::platform::windows::platform_drop(&os_id);
    }
    ErrorCode::Success
}

// ───────────────────── convenience ─────────────────────────────────── //

#[no_mangle]
pub extern "C" fn cidr_strerror(code: ErrorCode) -> *const c_char {
    code.as_str().as_ptr() as *const c_char
}
