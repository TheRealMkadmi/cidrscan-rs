#![cfg_attr(windows, feature(abi_vectorcall))]

use ext_php_rs::prelude::*;
use ext_php_rs::exception::PhpException;
use cidrscan_core::types::PatriciaTree;
use cidrscan_core::errors::{map_error, ErrorCode as CoreErrorCode};
use ipnet::IpNet;
use std::ffi::CStr;
use std::ptr;
use std::collections::HashMap;

// Convert a CoreErrorCode into a PhpException
fn errcode_to_exception(code: CoreErrorCode) -> PhpException {
    // Safety: cidr_strerror returns a valid C‐string pointer
    let msg = unsafe {
        CStr::from_ptr(cidrscan_core::public_api::cidr_strerror(code as i32))
            .to_string_lossy()
            .into_owned()
    };
    PhpException::default(msg)
}

/// Open or create the tree; return the opaque handle as an `isize`.
#[php_function]
pub fn cidr_open(name: String, capacity: usize) -> PhpResult<isize> {
    let tree = PatriciaTree::open(&name, capacity)
        .map_err(|_| errcode_to_exception(CoreErrorCode::ShmemOpenFailed))?;
    // Leak it into a raw pointer
    let raw = Box::into_raw(Box::new(tree));
    Ok(raw as isize)
}

/// Close the tree (idempotent).
#[php_function]
pub fn cidr_close(handle: isize) {
    if handle != 0 {
        // SAFETY: we trust that handle was originally from Box::into_raw
        unsafe { drop(Box::from_raw(handle as *mut PatriciaTree)) };
    }
}

/// Insert a CIDR entry.
#[php_function]
pub fn cidr_insert(
    handle: isize,
    cidr: String,
    ttl: u64,
    tag: Option<String>,
) -> PhpResult<()> {
    let tree = (handle as *mut PatriciaTree)
        .as_ref()
        .ok_or_else(|| PhpException::default("Invalid handle".into()))?;
    let net: IpNet = cidr.parse()
        .map_err(|_| PhpException::default("Invalid prefix".into()))?;
    let key = match net.network() {
        std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()) as u128,
        std::net::IpAddr::V6(v6) => v6.octets().iter().fold(0u128, |acc, &b| (acc << 8) | b as u128),
    };
    let plen = net.prefix_len() as u8;

    tree.insert(key, plen, ttl, tag.as_deref())
        .map_err(|e| errcode_to_exception(map_error(&e)))?;
    Ok(())
}

/// Delete a CIDR entry.
#[php_function]
pub fn cidr_delete(handle: isize, cidr: String) -> PhpResult<()> {
    let tree = (handle as *mut PatriciaTree)
        .as_mut()
        .ok_or_else(|| PhpException::default("Invalid handle".into()))?;
    let net: IpNet = cidr.parse()
        .map_err(|_| PhpException::default("Invalid prefix".into()))?;
    let key = match net.network() {
        std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()) as u128,
        std::net::IpAddr::V6(v6) => v6.octets().iter().fold(0u128, |acc, &b| (acc << 8) | b as u128),
    };
    let plen = net.prefix_len() as u8;

    tree.delete(key, plen)
        .map_err(|e| errcode_to_exception(map_error(&e)))?;
    Ok(())
}

/// Lookup an address, returning true if found.
#[php_function]
pub fn cidr_lookup(handle: isize, addr: String) -> PhpResult<bool> {
    let tree = (handle as *mut PatriciaTree)
        .as_ref()
        .ok_or_else(|| PhpException::default("Invalid handle".into()))?;
    let ip_addr = addr.parse()
        .map_err(|_| PhpException::default("Invalid prefix".into()))?;
    let key = match ip_addr {
        std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()) as u128,
        std::net::IpAddr::V6(v6) => v6.octets().iter().fold(0u128, |acc, &b| (acc << 8) | b as u128),
    };
    Ok(tree.lookup(key).is_some())
}

/// Full lookup info as an associative array.
#[php_function]
pub fn cidr_lookup_full(
    handle: isize,
    addr: String,
) -> PhpResult<HashMap<String, ext_php_rs::types::Zval>> {
    let tree = (handle as *mut PatriciaTree)
        .as_ref()
        .ok_or_else(|| PhpException::default("Invalid handle".into()))?;
    let ip_addr = addr.parse()
        .map_err(|_| PhpException::default("Invalid prefix".into()))?;
    let key = match ip_addr {
        std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()) as u128,
        std::net::IpAddr::V6(v6) => v6.octets().iter().fold(0u128, |acc, &b| (acc << 8) | b as u128),
    };

    if let Some(m) = tree.lookup(key) {
        let mut out = HashMap::new();
        out.insert("key_high".into(), ext_php_rs::types::Zval::from((m.cidr_key >> 64) as u128 as usize as i32));
        out.insert("key_low".into(),  ext_php_rs::types::Zval::from(m.cidr_key as usize as i32));
        out.insert("plen".into(),     ext_php_rs::types::Zval::from(m.plen as i32));
        out.insert("tag".into(),      ext_php_rs::types::Zval::from(m.tag.clone()));
        Ok(out)
    } else {
        Err(PhpException::default("Not found".into()))
    }
}

/// Available capacity.
#[php_function]
pub fn cidr_available_capacity(handle: isize) -> PhpResult<u64> {
    let tree = (handle as *mut PatriciaTree)
        .as_ref()
        .ok_or_else(|| PhpException::default("Invalid handle".into()))?;
    Ok(tree.available_capacity() as u64)
}

/// Flush the tree.
#[php_function]
pub fn cidr_flush(handle: isize) -> PhpResult<()> {
    let tree = (handle as *mut PatriciaTree)
        .as_mut()
        .ok_or_else(|| PhpException::default("Invalid handle".into()))?;
    tree.flush();
    Ok(())
}

/// Clear the tree.
#[php_function]
pub fn cidr_clear(handle: isize) -> PhpResult<()> {
    let tree = (handle as *mut PatriciaTree)
        .as_mut()
        .ok_or_else(|| PhpException::default("Invalid handle".into()))?;
    tree.clear();
    Ok(())
}

/// Resize the tree.
#[php_function]
pub fn cidr_resize(handle: isize, new_capacity: usize) -> PhpResult<()> {
    let tree = (handle as *mut PatriciaTree)
        .as_mut()
        .ok_or_else(|| PhpException::default("Invalid handle".into()))?;
    tree.resize(new_capacity)
        .map_err(|e| errcode_to_exception(map_error(&e)))?;
    Ok(())
}

/// Last error and strerror for low‐level debugging.
#[php_function]
pub fn cidr_last_error() -> i32 {
    cidrscan_core::public_api::cidr_last_error() as i32
}
#[php_function]
pub fn cidr_strerror(code: i32) -> String {
    unsafe {
        CStr::from_ptr(cidrscan_core::public_api::cidr_strerror(code))
            .to_string_lossy()
            .into_owned()
    }
}

/// Boilerplate module registration.
#[php_module]
pub fn module(m: ModuleBuilder) -> ModuleBuilder {
    m
}
