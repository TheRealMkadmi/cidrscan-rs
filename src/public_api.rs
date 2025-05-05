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
            set_last_error(ErrorCode::ShmemOpenFailed);
            ErrorCode::ShmemOpenFailed
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

/// Bulk insert multiple prefixes into the Patricia tree.
///
/// # Safety
/// - `items` must point to an array of (u64, u64, u8, u64) tuples of length `count`.
/// - Each tuple is (key_high, key_low, prefix_len, ttl).
///
/// Returns `ErrorCode::Success` on success, or an error code on failure.
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
        return ErrorCode::Success
    } else {
        set_last_error(ErrorCode::InvalidHandle);
        return ErrorCode::InvalidHandle
    }
#[no_mangle]
pub extern "C" fn patricia_available_capacity(handle: i32) -> u64 {
    match get_tree(handle) {
        Ok(tree) => tree.available_capacity() as u64,
        Err(_) => 0,
    }
}
}

/// Insert an IPv4 prefix into the Patricia tree.
/// 
/// # Safety
/// - The handle must be valid.
/// - `addr` is a 32-bit IPv4 address in host byte order.
/// - `prefix_len` is the prefix length (0-32).
/// - `ttl` is the time-to-live in seconds.
/// 
/// Returns `ErrorCode::Success` on success, or an error code on failure.
#[no_mangle]
pub extern "C" fn patricia_insert_v4(
    handle: i32,
    addr: u32,
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
    match tree.insert_v4(addr, prefix_len, ttl) {
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

/// Lookup an IPv4 address in the Patricia tree.
/// 
/// # Safety
/// - The handle must be valid.
/// - `addr` is a 32-bit IPv4 address in host byte order.
/// 
/// Returns `true` if found, `false` otherwise.
#[no_mangle]
pub extern "C" fn patricia_lookup_v4(
    handle: i32,
    addr: u32,
) -> bool {
    let tree = match get_tree(handle) {
        Ok(tree) => tree,
        Err(code) => {
            set_last_error(code);
            return false;
        }
    };
    let found = tree.lookup_v4(addr);
    set_last_error(ErrorCode::Success);
    found
}

/// Delete an IPv4 prefix from the Patricia tree.
/// 
/// # Safety
/// - The handle must be valid.
/// - `addr` is a 32-bit IPv4 address in host byte order.
/// - `prefix_len` is the prefix length (0-32).
/// 
/// Returns `ErrorCode::Success` on success, or an error code on failure.
#[no_mangle]
pub extern "C" fn patricia_delete_v4(
    handle: i32,
    addr: u32,
    prefix_len: u8,
) -> ErrorCode {
    let tree = match get_tree(handle) {
        Ok(tree) => tree,
        Err(code) => {
            set_last_error(code);
            return code;
        }
    };
    match tree.delete_v4(addr, prefix_len) {
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

/// Flushes pending epoch callbacks for the Patricia tree.
/// 
/// # Safety
/// - The handle must be valid.
/// 
/// Returns `ErrorCode::Success` on success, or an error code on failure.
#[no_mangle]
pub extern "C" fn patricia_flush(handle: i32) -> ErrorCode {
    let tree = match get_tree(handle) {
        Ok(tree) => tree,
        Err(code) => {
            set_last_error(code);
            return code;
        }
    };
    tree.flush();
    set_last_error(ErrorCode::Success);
    ErrorCode::Success
}

/// Clears all prefixes from the Patricia tree.
/// 
/// # Safety
/// - The handle must be valid.
/// 
/// Returns `ErrorCode::Success` on success, or an error code on failure.
#[no_mangle]
pub extern "C" fn patricia_clear(handle: i32) -> ErrorCode {
    let tree = match get_tree(handle) {
        Ok(tree) => tree,
        Err(code) => {
            set_last_error(code);
            return code;
        }
    };
    tree.clear();
    set_last_error(ErrorCode::Success);
    ErrorCode::Success
}

/// Resizes the Patricia tree arena to a new capacity.
/// 
/// # Safety
/// - The handle must be valid.
/// - `new_capacity` must be greater than the current capacity.
/// 
/// Returns `ErrorCode::Success` on success, or an error code on failure.
/// Resizes the Patricia tree arena to a new capacity.
///
/// # Safety
/// - The handle must be valid.
/// - `new_capacity` must be greater than the current capacity.
///
/// Returns `ErrorCode::Success` on success, `ErrorCode::InvalidHandle` if handle is invalid,
/// `ErrorCode::ResizeFailed` if the tree is in use by multiple handles, or other mapped errors on failure.
#[no_mangle]
pub extern "C" fn patricia_resize(handle: i32, new_capacity: usize) -> ErrorCode {
    // Remove the existing PatriciaTree from the registry to obtain ownership.
    if let Some((_, tree_arc)) = REGISTRY.remove(&handle) {
        // Must be the only strong reference.
        if Arc::strong_count(&tree_arc) != 1 {
            // Reinsert the original Arc back into the registry.
            REGISTRY.insert(handle, tree_arc);
            set_last_error(ErrorCode::ResizeFailed);
            return ErrorCode::ResizeFailed;
        }
        // Unwrap the Arc to get owned PatriciaTree.
        let mut tree = match Arc::try_unwrap(tree_arc) {
            Ok(t) => t,
            Err(original_arc) => {
                // Unexpected, reinsert and error.
                REGISTRY.insert(handle, original_arc);
                set_last_error(ErrorCode::ResizeFailed);
                return ErrorCode::ResizeFailed;
            }
        };
        // Perform resize.
        match tree.resize(new_capacity) {
            Ok(_) => {
                // Reinsert resized tree.
                REGISTRY.insert(handle, Arc::new(tree));
                set_last_error(ErrorCode::Success);
                ErrorCode::Success
            }
            Err(e) => {
                // On error, reinsert original tree.
                // original tree is mutated or not? We mutated tree in place which may have failed,
                // but leave original mapping intact.
                REGISTRY.insert(handle, Arc::new(tree));
                let code = map_error(&e);
                set_last_error(code);
                code
            }
        }
    } else {
        set_last_error(ErrorCode::InvalidHandle);
        ErrorCode::InvalidHandle
    }
}
