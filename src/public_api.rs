use crate::PatriciaTree;

/// Create or open a shared‑memory tree (C API)
#[no_mangle]
pub extern "C" fn patricia_open(name: *const u8, name_len: usize, capacity: usize) -> i32 {
    let slice = unsafe { std::slice::from_raw_parts(name, name_len) };
    let s = std::str::from_utf8(slice).unwrap_or("");
    match PatriciaTree::open(s, capacity) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Insert a key with TTL (C API)
#[no_mangle]
pub extern "C" fn patricia_insert(
    tree: *mut PatriciaTree,
    key_high: u64,
    key_low: u64,
    prefix_len: u8,
    ttl: u64,
) {
    let t = unsafe { &*tree };
    let key = ((key_high as u128) << 64) | (key_low as u128);
    t.insert(key, prefix_len, ttl);
}

/// Lookup a key (C API)
#[no_mangle]
pub extern "C" fn patricia_lookup(
    tree: *mut PatriciaTree,
    key_high: u64,
    key_low: u64,
) -> bool {
    let t = unsafe { &*tree };
    let key = ((key_high as u128) << 64) | (key_low as u128);
    t.lookup(key)
}

/// Delete a key (C API)
#[no_mangle]
pub extern "C" fn patricia_delete(
    tree: *mut PatriciaTree,
    key_high: u64,
    key_low: u64,
) {
    let t = unsafe { &*tree };
    let key = ((key_high as u128) << 64) | (key_low as u128);
    t.delete(key);
}

/// Bulk insert multiple entries (C API)
#[no_mangle]
pub extern "C" fn patricia_bulk_insert(
    tree: *mut PatriciaTree,
    items: *const (u64, u64, u8, u64),
    count: usize,
) {
    let t = unsafe { &*tree };
    let slice = unsafe { std::slice::from_raw_parts(items, count) };
    let mut vec = Vec::with_capacity(count);
    for &(high, low, len, ttl) in slice {
        vec.push(((high as u128) << 64 | low as u128, len, ttl));
    }
    t.bulk_insert(&vec);
}
