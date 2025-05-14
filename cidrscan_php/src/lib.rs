#![cfg_attr(windows, feature(abi_vectorcall))]

use ext_php_rs::prelude::*;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

/// ─── raw FFI ──────────────────────────────────────────────────────────────
type PatriciaHandle = *mut core::ffi::c_void;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum ErrorCode {
    Success = 0,
    CapacityExceeded,
    ZeroCapacity,
    InvalidPrefix,
    BranchHasChildren,
    InvalidHandle,
    Utf8Error,
    LockInitFailed,
    ShmemOpenFailed,
    ResizeFailed,
    FlushFailed,
    TagTooLong,
    NotFound,
    Unknown,
}

pub const TAG_MAX_LEN: usize = 64;

#[repr(C)]
pub struct PatriciaMatchT {
    pub key_high: u64,
    pub key_low: u64,
    pub plen: u8,
    pub tag: [c_char; TAG_MAX_LEN],
}

#[link(name = "cidrscan_core", kind = "static")]
extern "C" {
    fn cidr_open(name_utf8: *const c_char, capacity: usize) -> PatriciaHandle;
    fn cidr_close(h: PatriciaHandle);

    fn cidr_insert(
        h: PatriciaHandle,
        cidr_utf8: *const c_char,
        ttl: u64,
        tag_utf8: *const c_char,
    ) -> ErrorCode;

    fn cidr_delete(h: PatriciaHandle, cidr_utf8: *const c_char) -> ErrorCode;
    fn cidr_lookup(h: PatriciaHandle, addr_utf8: *const c_char) -> bool;

    fn cidr_lookup_full(
        h: PatriciaHandle,
        addr_utf8: *const c_char,
        out: *mut PatriciaMatchT,
    ) -> ErrorCode;

    fn cidr_available_capacity(h: PatriciaHandle) -> u64;
    fn cidr_flush(h: PatriciaHandle) -> ErrorCode;
    fn cidr_clear(h: PatriciaHandle) -> ErrorCode;
    fn cidr_resize(h: PatriciaHandle, new_capacity: usize) -> ErrorCode;

    fn cidr_last_error() -> ErrorCode;
    fn cidr_strerror(code: ErrorCode) -> *const c_char;
}

#[php_function(name = "cidr_open")]
pub fn rs_cidr_open(name_utf8: String, capacity: u64) -> i64 {
    let cname = CString::new(name_utf8).expect("UTF-8 error");
    unsafe { cidr_open(cname.as_ptr(), capacity as usize) as i64 }
}

#[php_function(name = "cidr_close")]
pub fn rs_cidr_close(handle: i64) {
    unsafe { cidr_close(handle as PatriciaHandle) };
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

    unsafe {
        cidr_insert(
            handle as PatriciaHandle,
            ccidr.as_ptr(),
            ttl,
            tag_ptr,
        ) as i32
    }
}

#[php_function(name = "cidr_delete")]
pub fn rs_cidr_delete(handle: i64, cidr_utf8: String) -> i32 {
    let ccidr = CString::new(cidr_utf8).expect("UTF-8 error");
    unsafe { cidr_delete(handle as PatriciaHandle, ccidr.as_ptr()) as i32 }
}

#[php_function(name = "cidr_lookup")]
pub fn rs_cidr_lookup(handle: i64, addr_utf8: String) -> bool {
    let caddr = CString::new(addr_utf8).expect("UTF-8 error");
    unsafe { cidr_lookup(handle as PatriciaHandle, caddr.as_ptr()) }
}

#[php_function(name = "cidr_lookup_full")]
pub fn rs_cidr_lookup_full(handle: i64, addr_utf8: String, out_ptr: i64) -> i32 {
    let caddr = CString::new(addr_utf8).expect("UTF-8 error");
    unsafe {
        cidr_lookup_full(
            handle as PatriciaHandle,
            caddr.as_ptr(),
            out_ptr as *mut PatriciaMatchT,
        ) as i32
    }
}

#[php_function(name = "cidr_available_capacity")]
pub fn rs_cidr_available_capacity(handle: i64) -> u64 {
    unsafe { cidr_available_capacity(handle as PatriciaHandle) }
}

#[php_function(name = "cidr_flush")]
pub fn rs_cidr_flush(handle: i64) -> i32 {
    unsafe { cidr_flush(handle as PatriciaHandle) as i32 }
}

#[php_function(name = "cidr_clear")]
pub fn rs_cidr_clear(handle: i64) -> i32 {
    unsafe { cidr_clear(handle as PatriciaHandle) as i32 }
}

#[php_function(name = "cidr_resize")]
pub fn rs_cidr_resize(handle: i64, new_capacity: u64) -> i32 {
    unsafe { cidr_resize(handle as PatriciaHandle, new_capacity as usize) as i32 }
}

#[php_function(name = "cidr_last_error")]
pub fn rs_cidr_last_error() -> i32 {
    unsafe { cidr_last_error() as i32 }
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
