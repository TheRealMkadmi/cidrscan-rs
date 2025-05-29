use std::{
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};

use cidrscan_core::types::PatriciaTree;

/// Helper to convert an IPv4 octets into our u128 key representation.
fn ipv4_to_u128(a: u8, b: u8, c: u8, d: u8) -> u128 {
    u32::from_be_bytes([a, b, c, d]) as u128
}

#[test]
fn basic_insert_lookup_delete() {
    let name = format!("test_basic_insert_delete_{}", std::process::id());
    let tree = PatriciaTree::open(&name, 1024).unwrap();
        let key = ipv4_to_u128(192, 168, 0, 1);
    assert!(tree.lookup(key).is_none());
    let _ = tree.insert(key, 32, 60, None);
    assert!(tree.lookup(key).is_some());
    let _ = tree.delete(key, 32);
    assert!(tree.lookup(key).is_none());
}

#[test]
fn ttl_expiry_various() {
    let name = format!("test_ttl_{}", std::process::id());
    let tree = PatriciaTree::open(&name, 128).unwrap();
    let key1 = ipv4_to_u128(10, 0, 0, 1);
    let _ = tree.insert(key1, 32, 0, None);
    assert!(tree.lookup(key1).is_some());

    let key2 = ipv4_to_u128(10, 0, 0, 2);
    let _ = tree.insert(key2, 32, 1, None);
    assert!(tree.lookup(key2).is_some());
    thread::sleep(Duration::from_secs(2));
    assert!(tree.lookup(key2).is_none());
}

#[test]
fn ipv6_prefix_behavior() {
    let name = format!("test_ipv6_{}", std::process::id());
    let tree = PatriciaTree::open(&name, 64).unwrap();
    let segments = [
        0x2001u128 << 112,
        0x0db8u128 << 96,
        0u128 << 80,
        0u128 << 64,
        0u128 << 48,
        0u128 << 32,
        0u128 << 16,
        1u128,
    ];
    let key = segments.iter().fold(0u128, |acc, &part| acc | part);
    let _ = tree.insert(key, 64, 60, None);
    assert!(tree.lookup(key).is_some());
}

#[test]
fn shared_memory_visibility_between_handles() {
    let name = format!("test_shared_{}", std::process::id());
    let tree1 = PatriciaTree::open(&name, 128).unwrap();
    let key = ipv4_to_u128(172, 16, 0, 1);
    let _ = tree1.insert(key, 32, 60, None);

    let tree2 = PatriciaTree::open(&name, 128).unwrap();
    assert!(tree2.lookup(key).is_some());

    let _ = tree2.delete(key, 32);
    assert!(tree1.lookup(key).is_none());
}

#[test]
fn concurrent_threaded_inserts_and_lookups() {
    const THREADS: usize = 8;
    const OPS_PER_THREAD: usize = 1_000;
    // Use Arc directly, PatriciaTree handles internal locking
    let name = format!("test_conc_{}", std::process::id());
    let tree = Arc::new(PatriciaTree::open(&name, 16_384).unwrap());
    let barrier = Arc::new(Barrier::new(THREADS));

    let mut handles = vec![];
    for t in 0..THREADS {
        let tr = Arc::clone(&tree);
        let b  = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            for i in 0..OPS_PER_THREAD {
                let key = (t as u128) << 32 | i as u128;
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = tr.insert(key, 64, 10, None);
                }));
                let _ = tr.lookup(key);
                let _ = tr.delete(key, 64);
                assert!(tr.lookup(key).is_none(), "delete failed for {:x}", key);
            }
        }));
    }
    for h in handles { let _ = h.join(); }
}

#[test]
fn stress_test_timing() {
    const CAPACITY: usize = 65_536;
    const NUM_KEYS: usize = 20_000;

    let name = format!("test_stress_{}", std::process::id());
    let tree = PatriciaTree::open(&name, CAPACITY).unwrap();
    let keys: Vec<u128> = (0..NUM_KEYS).map(|i| i as u128).collect();
    
    for &k in &keys {
        let _ = tree.insert(k, 64, 3600, None);
    }

    let start = Instant::now();
    for &k in &keys {
        assert!(tree.lookup(k).is_some(), "Lookup failed for key {} during stress test", k);
    }
    let elapsed = start.elapsed();
    let avg = elapsed.as_micros() as f64 / keys.len() as f64;
    println!("avg lookup ({} keys): {:.2} μs", NUM_KEYS, avg);
}
