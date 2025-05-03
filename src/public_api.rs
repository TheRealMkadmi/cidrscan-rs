use crate::PatriciaTree;
use crate::errors::{ErrorCode, set_last_error, map_error};
use std::sync::Arc;
use once_cell::sync::Lazy;
use dashmap::DashMap;

static REGISTRY: Lazy<DashMap<i32, Arc<PatriciaTree>>> = Lazy::new(|| DashMap::new());
static NEXT_HANDLE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(1);

#[no_mangle]
pub extern "C" fn patricia_open(name: *const u8, name_len: usize, capacity: usize, out_handle: *mut i32) -> ErrorCode {
    let slice = unsafe { std::slice::from_raw_parts(name, name_len) };
    let s = std::str::from_utf8(slice).unwrap_or("");
    match PatriciaTree::open(s, capacity) {
        Ok(tree) => {
            let handle = NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            REGISTRY.insert(handle, Arc::new(tree));
            unsafe { *out_handle = handle; }
            set_last_error(ErrorCode::Success);
            ErrorCode::Success
        }
        Err(e) => {
            let code = ErrorCode::Unknown;
            set_last_error(code);
            code
        }
    }
}

#[no_mangle]
pub extern "C" fn patricia_close(handle: i32) -> ErrorCode {
    if REGISTRY.remove(&handle).is_some() {
        set_last_error(ErrorCode::Success);
        ErrorCode::Success
    } else {
        set_last_error(ErrorCode::Unknown);
        ErrorCode::Unknown
    }
}

#[no_mangle]
pub extern "C" fn patricia_insert(
    handle: i32,
    key_high: u64,
    key_low: u64,
    prefix_len: u8,
    ttl: u64,
) -> ErrorCode {
    if let Some(tree) = REGISTRY.get(&handle) {
        let key = ((key_high as u128) << 64) | (key_low as u128);
        match tree.insert(key, prefix_len, ttl) {
            Ok(_) => {
                set_last_error(ErrorCode::Success);
                ErrorCode::Success
            }
            Err(e) => {
                let code = map_error(&e);
                set_last_error(code);
                code
            }
        }
    } else {
        set_last_error(ErrorCode::Unknown);
        ErrorCode::Unknown
    }
}

#[no_mangle]
pub extern "C" fn patricia_lookup(
    handle: i32,
    key_high: u64,
    key_low: u64,
) -> bool {
    if let Some(tree) = REGISTRY.get(&handle) {
        let key = ((key_high as u128) << 64) | (key_low as u128);
        let found = tree.lookup(key);
        set_last_error(ErrorCode::Success);
        found
    } else {
        set_last_error(ErrorCode::Unknown);
        false
    }
}

#[no_mangle]
pub extern "C" fn patricia_delete(
    handle: i32,
    key_high: u64,
    key_low: u64,
    prefix_len: u8,
) -> ErrorCode {
    if let Some(tree) = REGISTRY.get(&handle) {
        let key = ((key_high as u128) << 64) | (key_low as u128);
        match tree.delete(key, prefix_len) {
            Ok(_) => {
                set_last_error(ErrorCode::Success);
                ErrorCode::Success
            }
            Err(e) => {
                let code = map_error(&e);
                set_last_error(code);
                code
            }
        }
    } else {
        set_last_error(ErrorCode::Unknown);
        ErrorCode::Unknown
    }
}

#[no_mangle]
pub extern "C" fn patricia_bulk_insert(
    handle: i32,
    items: *const (u64, u64, u8, u64),
    count: usize,
) -> ErrorCode {
    if let Some(tree) = REGISTRY.get(&handle) {
        let slice = unsafe { std::slice::from_raw_parts(items, count) };
        let mut vec = Vec::with_capacity(count);
        for &(high, low, len, ttl) in slice {
            vec.push(((high as u128) << 64 | low as u128, len, ttl));
        }
        match tree.bulk_insert(&vec) {
            Ok(_) => {
                set_last_error(ErrorCode::Success);
                ErrorCode::Success
            }
            Err(e) => {
                let code = map_error(&e);
                set_last_error(code);
                code
            }
        }
    } else {
        set_last_error(ErrorCode::Unknown);
        ErrorCode::Unknown
    }
}
