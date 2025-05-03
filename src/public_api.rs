use crate::PatriciaTree;
use crate::errors::{ErrorCode, set_last_error, map_error};
use std::sync::Arc;
use once_cell::sync::Lazy;
use dashmap::DashMap;

static REGISTRY: Lazy<DashMap<i32, Arc<PatriciaTree>>> = Lazy::new(|| DashMap::new());
static NEXT_HANDLE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(1);

fn get_tree(handle: i32) -> Result<Arc<PatriciaTree>, ErrorCode> {
    REGISTRY.get(&handle)
        .map(|entry| Arc::clone(&*entry))
        .ok_or(ErrorCode::InvalidHandle)
}

#[no_mangle]
pub extern "C" fn patricia_open(name: *const u8, name_len: usize, capacity: usize, out_handle: *mut i32) -> ErrorCode {
    let slice = unsafe { std::slice::from_raw_parts(name, name_len) };
    let s = match std::str::from_utf8(slice) {
        Ok(val) => val,
        Err(_) => {
            set_last_error(ErrorCode::Utf8Error);
            return ErrorCode::Utf8Error;
        }
    };
    match PatriciaTree::open(s, capacity) {
        Ok(tree) => {
            let handle = NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            REGISTRY.insert(handle, Arc::new(tree));
            unsafe { *out_handle = handle; }
            set_last_error(ErrorCode::Success);
            ErrorCode::Success
        }
        Err(_e) => {
            // e is a ShmemError, not a types::Error
            set_last_error(ErrorCode::Unknown);
            ErrorCode::Unknown
        }
    }
}

#[no_mangle]
pub extern "C" fn patricia_close(handle: i32) -> ErrorCode {
    // For backward compatibility, patricia_close is an alias for destroy.
    patricia_destroy(handle)
}

#[no_mangle]
pub extern "C" fn patricia_insert(
    handle: i32,
    key_high: u64,
    key_low: u64,
    prefix_len: u8,
    ttl: u64,
) -> ErrorCode {
    let tree = match get_tree(handle) {
        Ok(tree) => tree,
        Err(code) => {
            set_last_error(code);
            return code;
        }
    };
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
}

#[no_mangle]
pub extern "C" fn patricia_lookup(
    handle: i32,
    key_high: u64,
    key_low: u64,
) -> bool {
    let tree = match get_tree(handle) {
        Ok(tree) => tree,
        Err(code) => {
            set_last_error(code);
            return false;
        }
    };
    let key = ((key_high as u128) << 64) | (key_low as u128);
    let found = tree.lookup(key);
    set_last_error(ErrorCode::Success);
    found
}

#[no_mangle]
pub extern "C" fn patricia_delete(
    handle: i32,
    key_high: u64,
    key_low: u64,
    prefix_len: u8,
) -> ErrorCode {
    let tree = match get_tree(handle) {
        Ok(tree) => tree,
        Err(code) => {
            set_last_error(code);
            return code;
        }
    };
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
}

#[no_mangle]
pub extern "C" fn patricia_bulk_insert(
    handle: i32,
    items: *const (u64, u64, u8, u64),
    count: usize,
) -> ErrorCode {
    let tree = match get_tree(handle) {
        Ok(tree) => tree,
        Err(code) => {
            set_last_error(code);
            return code;
        }
    };
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
}

// Destroys the Patricia tree for the given handle, removing it from the registry and triggering cleanup.
// Returns ErrorCode::InvalidHandle if the handle is not found.
#[no_mangle]
pub extern "C" fn patricia_destroy(handle: i32) -> ErrorCode {
    // Remove from registry and drop Arc, then explicitly destroy the shared memory segment.
    if let Some((_, tree_arc)) = REGISTRY.remove(&handle) {
        // Only destroy if this is the last Arc (strong_count == 1)
        if Arc::strong_count(&tree_arc) == 1 {
            // Safety: we have the only Arc, so we can get a mutable reference
            let mut_tree = Arc::try_unwrap(tree_arc).ok().unwrap();
            // Explicitly drop the mapping and unlink the segment
            mut_tree.destroy();
        }
        set_last_error(ErrorCode::Success);
        ErrorCode::Success
    } else {
        set_last_error(ErrorCode::InvalidHandle);
        ErrorCode::InvalidHandle
    }
}
