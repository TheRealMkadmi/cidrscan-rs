use crate::PatriciaTree;
use std::collections::HashMap;
use std::sync::Arc;
use once_cell::sync::Lazy;
use std::sync::Mutex;

static REGISTRY: Lazy<Mutex<HashMap<i32, Arc<PatriciaTree>>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static NEXT_HANDLE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(1);

#[no_mangle]
pub extern "C" fn patricia_open(name: *const u8, name_len: usize, capacity: usize) -> i32 {
    let slice = unsafe { std::slice::from_raw_parts(name, name_len) };
    let s = std::str::from_utf8(slice).unwrap_or("");
    match PatriciaTree::open(s, capacity) {
        Ok(tree) => {
            let handle = NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            REGISTRY.lock().expect("lock registry").insert(handle, Arc::new(tree));
            handle
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn patricia_close(handle: i32) {
    REGISTRY.lock().expect("lock registry").remove(&handle);
}

#[no_mangle]
pub extern "C" fn patricia_insert(
    handle: i32,
    key_high: u64,
    key_low: u64,
    prefix_len: u8,
    ttl: u64,
) {
    if let Some(tree) = REGISTRY.lock().expect("lock registry").get(&handle) {
        let key = ((key_high as u128) << 64) | (key_low as u128);
        tree.insert(key, prefix_len, ttl);
    }
}

#[no_mangle]
pub extern "C" fn patricia_lookup(
    handle: i32,
    key_high: u64,
    key_low: u64,
) -> bool {
    if let Some(tree) = REGISTRY.lock().expect("lock registry").get(&handle) {
        let key = ((key_high as u128) << 64) | (key_low as u128);
        return tree.lookup(key);
    }
    false
}

#[no_mangle]
pub extern "C" fn patricia_delete(
    handle: i32,
    key_high: u64,
    key_low: u64,
    prefix_len: u8,
) {
    if let Some(tree) = REGISTRY.lock().expect("lock registry").get(&handle) {
        let key = ((key_high as u128) << 64) | (key_low as u128);
        tree.delete(key, prefix_len);
    }
}

#[no_mangle]
pub extern "C" fn patricia_bulk_insert(
    handle: i32,
    items: *const (u64, u64, u8, u64),
    count: usize,
) {
    if let Some(tree) = REGISTRY.lock().expect("lock registry").get(&handle) {
        let slice = unsafe { std::slice::from_raw_parts(items, count) };
        let mut vec = Vec::with_capacity(count);
        for &(high, low, len, ttl) in slice {
            vec.push(((high as u128) << 64 | low as u128, len, ttl));
        }
        tree.bulk_insert(&vec);
    }
}
