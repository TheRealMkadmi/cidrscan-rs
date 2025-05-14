#![cfg_attr(windows, feature(abi_vectorcall))]

use ext_php_rs::prelude::*;
use std::ffi::{CStr, CString};
use std::ptr;
use cidrscan_core::public_api::*;
use cidrscan_core::types::PatriciaTree;

type PatriciaHandle = *mut PatriciaTree;


#[php_function(name = "cidr_open")]
pub fn rs_cidr_open(name_utf8: String, capacity: u64) -> i64 {
    let cname = CString::new(name_utf8).expect("UTF-8 error");
    cidr_open(cname.as_ptr(), capacity as usize) as i64
}

#[php_function(name = "cidr_close")]
pub fn rs_cidr_close(handle: i64) {
    cidr_close(handle as PatriciaHandle);
}

#[php_function(name = "cidr_insert")]
pub fn rs_cidr_insert(
    handle: i64,
    cidr_utf8: String,
    ttl: u64,
    tag_utf8: Option<String>,
) -> i32 {
    let ccidr = CString::new(cidr_utf8).expect("UTF-8 error");
    let tag_ptr = tag_utf8
        .as_ref()
        .map(|s| CString::new(s.as_str()).unwrap())
        .map_or(ptr::null(), |c| c.as_ptr());

    cidr_insert(
        handle as PatriciaHandle,
        ccidr.as_ptr(),
        ttl,
        tag_ptr,
    ) as i32
}

#[php_function(name = "cidr_delete")]
pub fn rs_cidr_delete(handle: i64, cidr_utf8: String) -> i32 {
    let ccidr = CString::new(cidr_utf8).expect("UTF-8 error");
    cidr_delete(handle as PatriciaHandle, ccidr.as_ptr()) as i32
}

#[php_function(name = "cidr_lookup")]
pub fn rs_cidr_lookup(handle: i64, addr_utf8: String) -> bool {
    let caddr = CString::new(addr_utf8).expect("UTF-8 error");
    cidr_lookup(handle as PatriciaHandle, caddr.as_ptr())
}

#[php_function(name = "cidr_lookup_full")]
pub fn rs_cidr_lookup_full(handle: i64, addr_utf8: String, out_ptr: i64) -> i32 {
    let caddr = CString::new(addr_utf8).expect("UTF-8 error");
    cidr_lookup_full(
        handle as PatriciaHandle,
        caddr.as_ptr(),
        out_ptr as *mut PatriciaMatchT,
    ) as i32
}

#[php_function(name = "cidr_available_capacity")]
pub fn rs_cidr_available_capacity(handle: i64) -> u64 {
    cidr_available_capacity(handle as PatriciaHandle)
}

#[php_function(name = "cidr_flush")]
pub fn rs_cidr_flush(handle: i64) -> i32 {
    cidr_flush(handle as PatriciaHandle) as i32
}

#[php_function(name = "cidr_clear")]
pub fn rs_cidr_clear(handle: i64) -> i32 {
    cidr_clear(handle as PatriciaHandle) as i32
}

#[php_function(name = "cidr_resize")]
pub fn rs_cidr_resize(handle: i64, new_capacity: u64) -> i32 {
    cidr_resize(handle as PatriciaHandle, new_capacity as usize) as i32
}

#[php_function(name = "cidr_last_error")]
pub fn rs_cidr_last_error() -> i32 {
    cidr_last_error() as i32
}

#[php_function(name = "cidr_strerror")]
pub fn rs_cidr_strerror(code: i32) -> String {
    unsafe {
        let cstr = cidr_strerror(std::mem::transmute(code));
        CStr::from_ptr(cstr).to_string_lossy().into_owned() 
    }
}

/// ─── module entry point ───────────────────────────────────────────────────
#[php_module]
pub fn get_module(module: ModuleBuilder) -> ModuleBuilder {
    module
}
