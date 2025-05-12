use crate::{
    constants::TAG_MAX_LEN,
    errors::{map_error, ErrorCode},
    helpers::v4_key,
    PatriciaTree,
};
use ipnet::IpNet;
use once_cell::sync::Lazy;
use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
    ptr,
};

pub type PatriciaHandle = *mut PatriciaTree;

/// C-ABI view of a successful lookup.
#[repr(C)]
pub struct PatriciaMatchT {
    pub key_high: u64,
    pub key_low: u64,
    pub plen: u8,
    pub tag: [c_char; TAG_MAX_LEN],
}

// ---------------------------------------------------------------------------
//  Helper utilities
// ---------------------------------------------------------------------------

fn cstr_to_str<'a>(ptr: *const c_char) -> Result<&'a str, ErrorCode> {
    if ptr.is_null() {
        return Err(ErrorCode::Utf8Error);
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| ErrorCode::Utf8Error)
}

fn write_tag_buf(dst: &mut [c_char; TAG_MAX_LEN], tag: &str) {
    for b in dst.iter_mut() {
        *b = 0;
    }
    let bytes = tag.as_bytes();
    let len = bytes.len().min(TAG_MAX_LEN);
    for i in 0..len {
        dst[i] = bytes[i] as c_char;
    }
}

// ---------------------------------------------------------------------------
//  Lifetime
// ---------------------------------------------------------------------------

/// Open or create a shared-memory arena and return an opaque handle.
///
/// * `name_utf8` – logical name (process-wide); will be hashed to an OS-specific
///                 identifier, so any UTF-8 string is fine.
/// * `capacity`  – maximum number of prefixes (nodes).
///
/// Returns **NULL** on error – consult `cidr_last_error()`.
#[no_mangle]
pub extern "C" fn cidr_open(name_utf8: *const c_char, capacity: usize) -> PatriciaHandle {
    match cstr_to_str(name_utf8)
        .and_then(|s| PatriciaTree::open(s, capacity).map_err(|_| ErrorCode::ShmemOpenFailed))
    {
        Ok(tree) => {
            set_last_error(ErrorCode::Success);
            Box::into_raw(Box::new(tree))
        }
        Err(code) => {
            set_last_error(code);
            ptr::null_mut()
        }
    }
}

/// Close the handle (idempotent).  NULL is ignored.
#[no_mangle]
pub extern "C" fn cidr_close(h: PatriciaHandle) {
    if !h.is_null() {
        // SAFETY – we created it with Box::into_raw
        unsafe { drop(Box::from_raw(h)) };
    }
}

// ---------------------------------------------------------------------------
//  CRUD
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn cidr_insert(
    h: PatriciaHandle,
    cidr_utf8: *const c_char,
    ttl: u64,
    tag_utf8: *const c_char, // may be NULL
) -> ErrorCode {
    let tree = match unsafe { h.as_ref() } {
        Some(t) => t,
        None => return ErrorCode::InvalidHandle,
    };
    let cidr_str = match cstr_to_str(cidr_utf8) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let net: IpNet = match cidr_str.parse() {
        Ok(n) => n,
        Err(_) => return ErrorCode::InvalidPrefix,
    };
    
    let tag = if tag_utf8.is_null() {
        None
    } else {
        match cstr_to_str(tag_utf8) {
            Ok(s) => Some(s),
            Err(code) => return code,
        }
    };
    
    // Convert IpAddr to u128 based on type
    let key = match net.network() {
        std::net::IpAddr::V4(ipv4) => v4_key(u32::from_be_bytes(ipv4.octets())),
        std::net::IpAddr::V6(ipv6) => {
            let mut val = 0u128;
            for (i, octet) in ipv6.octets().iter().enumerate() {
                val |= (*octet as u128) << (120 - (i * 8));
            }
            val
        }
    };
    
    match tree.insert(key, net.prefix_len() as u8, ttl, tag) {
        Ok(_) => ErrorCode::Success,
        Err(e) => map_error(&e),
    }
}

#[no_mangle]
pub extern "C" fn cidr_delete(h: PatriciaHandle, cidr_utf8: *const c_char) -> ErrorCode {
    let tree = match unsafe { h.as_ref() } {
        Some(t) => t,
        None => return ErrorCode::InvalidHandle,
    };
    let cidr_str = match cstr_to_str(cidr_utf8) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let net: IpNet = match cidr_str.parse() {
        Ok(n) => n,
        Err(_) => return ErrorCode::InvalidPrefix,
    };
    
    // Convert IpAddr to u128 based on type
    let key = match net.network() {
        std::net::IpAddr::V4(ipv4) => v4_key(u32::from_be_bytes(ipv4.octets())),
        std::net::IpAddr::V6(ipv6) => {
            let mut val = 0u128;
            for (i, octet) in ipv6.octets().iter().enumerate() {
                val |= (*octet as u128) << (120 - (i * 8));
            }
            val
        }
    };
    
    match tree.delete(key, net.prefix_len() as u8) {
        Ok(_) => ErrorCode::Success,
        Err(e) => map_error(&e),
    }
}

#[no_mangle]
pub extern "C" fn cidr_lookup(h: PatriciaHandle, addr_utf8: *const c_char) -> bool {
    let tree = match unsafe { h.as_ref() } {
        Some(t) => t,
        None => {
            set_last_error(ErrorCode::InvalidHandle);
            return false;
        }
    };
    let addr_str = match cstr_to_str(addr_utf8) {
        Ok(s) => s,
        Err(code) => {
            set_last_error(code);
            return false;
        }
    };
    
    // Parse the address string into either IpNet or IpAddr
    let ip_addr = if let Ok(n) = addr_str.parse::<IpNet>() {
        n.network()
    } else if let Ok(ip) = addr_str.parse() {
        ip
    } else {
        set_last_error(ErrorCode::InvalidPrefix);
        return false;
    };
    
    // Convert IpAddr to u128 based on type
    let key = match ip_addr {
        std::net::IpAddr::V4(ipv4) => v4_key(u32::from_be_bytes(ipv4.octets())),
        std::net::IpAddr::V6(ipv6) => {
            let mut val = 0u128;
            for (i, octet) in ipv6.octets().iter().enumerate() {
                val |= (*octet as u128) << (120 - (i * 8));
            }
            val
        }
    };
    
    set_last_error(ErrorCode::Success);
    tree.lookup(key).is_some()
}

#[no_mangle]
pub extern "C" fn cidr_lookup_full(
    h: PatriciaHandle,
    addr_utf8: *const c_char,
    out: *mut PatriciaMatchT,
) -> ErrorCode {
    let tree = match unsafe { h.as_ref() } {
        Some(t) => t,
        None => return ErrorCode::InvalidHandle,
    };
    
    let addr_str = match cstr_to_str(addr_utf8) {
        Ok(s) => s,
        Err(code) => return code,
    };
    
    // Parse the address string into either IpNet or IpAddr
    let ip_addr = if let Ok(n) = addr_str.parse::<IpNet>() {
        n.network()
    } else if let Ok(ip) = addr_str.parse() {
        ip
    } else {
        return ErrorCode::InvalidPrefix;
    };
    
    // Convert IpAddr to u128 based on type
    let key = match ip_addr {
        std::net::IpAddr::V4(ipv4) => v4_key(u32::from_be_bytes(ipv4.octets())),
        std::net::IpAddr::V6(ipv6) => {
            let mut val = 0u128;
            for (i, octet) in ipv6.octets().iter().enumerate() {
                val |= (*octet as u128) << (120 - (i * 8));
            }
            val
        }
    };
    
    match tree.lookup(key) {
        Some(m) => unsafe {
            if out.is_null() {
                return ErrorCode::InvalidHandle;
            }
            (*out).key_high = (m.cidr_key >> 64) as u64;
            (*out).key_low = m.cidr_key as u64;
            (*out).plen = m.plen;
            write_tag_buf(&mut (*out).tag, m.tag);
            ErrorCode::Success
        },
        None => ErrorCode::NotFound,
    }
}

// ---------------------------------------------------------------------------
//  Capacity & maintenance
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn cidr_available_capacity(h: PatriciaHandle) -> u64 {
    unsafe { h.as_ref() }
        .map(|t| t.available_capacity() as u64)
        .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn cidr_flush(h: PatriciaHandle) -> ErrorCode {
    unsafe { h.as_ref() }
        .map(|t| {
            t.flush();
            ErrorCode::Success
        })
        .unwrap_or(ErrorCode::InvalidHandle)
}

#[no_mangle]
pub extern "C" fn cidr_clear(h: PatriciaHandle) -> ErrorCode {
    unsafe { h.as_ref() }
        .map(|t| {
            t.clear();
            ErrorCode::Success
        })
        .unwrap_or(ErrorCode::InvalidHandle)
}

#[no_mangle]
pub extern "C" fn cidr_resize(h: PatriciaHandle, new_capacity: usize) -> ErrorCode {
    // Safety: we have exclusive ownership only if the caller guarantees no other
    // threads use the handle.  That must be documented on the C side.
    let tree = match unsafe { h.as_mut() } {
        Some(t) => t,
        None => return ErrorCode::InvalidHandle,
    };
    match tree.resize(new_capacity) {
        Ok(_) => ErrorCode::Success,
        Err(e) => map_error(&e),
    }
}

// ---------------------------------------------------------------------------
//  Error helpers (unchanged signatures)
// ---------------------------------------------------------------------------

thread_local! {
    static LAST_ERROR: std::cell::Cell<ErrorCode> = std::cell::Cell::new(ErrorCode::Success);
}

pub(crate) fn set_last_error(code: ErrorCode) {
    LAST_ERROR.with(|c| c.set(code));
}

#[no_mangle]
pub extern "C" fn cidr_last_error() -> ErrorCode {
    LAST_ERROR.with(|c| c.get())
}

#[no_mangle]
pub extern "C" fn cidr_strerror(code: ErrorCode) -> *const c_char {
    static TABLE: Lazy<Vec<CString>> = Lazy::new(|| {
        use ErrorCode::*;
        [Success, CapacityExceeded, ZeroCapacity, InvalidPrefix, BranchHasChildren,
         InvalidHandle, Utf8Error, LockInitFailed, ShmemOpenFailed, ResizeFailed,
         FlushFailed, TagTooLong, NotFound, Unknown]
            .iter()
            .map(|c| CString::new(c.as_str()).unwrap())
            .collect()
    });
    TABLE[code as usize].as_ptr()
}
