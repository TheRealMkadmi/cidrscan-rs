use cidrscan::PatriciaTree;
use rand;

#[test]
fn basic_ops() {
    let name = format!("test_shm_{}", std::process::id());
    let tree = PatriciaTree::open(&name, 1024).unwrap();
    let ip = 0xC0A80001; // 192.168.0.1
    let _ = tree.insert(ip, 32, 60);
    assert!(tree.lookup(ip));
    _ = tree.delete(ip);
    assert!(!tree.lookup(ip));
}

#[test]
fn ttl_expiry() {
    let name = format!("test_shm_ttl_{}", std::process::id());
    let tree = PatriciaTree::open(&name, 1024).unwrap();
    let ip = 0x01020304;
    tree.insert(ip, 32, 1);
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert!(!tree.lookup(ip));
}
#[test]
fn split_creates_balanced_branches() {
    // Two keys with a 31-bit common prefix, differing at bit 31 (MSB is bit 0)
    let key1 = 0b10000000_00000000_00000000_00000000u32 as u128; // 128.0.0.0
    let key2 = 0b00000000_00000000_00000000_00000000u32 as u128; // 0.0.0.0

    let name = format!("test_shm_split_{}", std::process::id());
    let tree = PatriciaTree::open(&name, 1024).unwrap();
    let _ = tree.insert(key1, 32, 60);
    _ = tree.insert(key2, 32, 60);

    // Both keys should be found
    assert!(tree.lookup(key1));
    assert!(tree.lookup(key2));

    // Deleting one should not affect the other
    _ = tree.delete(key1);
    assert!(!tree.lookup(key1));
    assert!(tree.lookup(key2));

    _ = tree.delete(key2);
    assert!(!tree.lookup(key2));
}
proptest! {
    #[test]
    fn property_insert_delete_lookup(
        keys in proptest::collection::vec(any::<u128>(), 10..100),
        prefix_lens in proptest::collection::vec(1u8..=128, 10..100)
    ) {
        use cidrscan::PatriciaTree;
        let n = keys.len().min(prefix_lens.len());
        let shm_name = format!("test_shm_prop_{}", rand::random::<u64>());
        let tree = PatriciaTree::open(&shm_name, n * 2).unwrap();

        let mut pairs: Vec<(u128, u8)> = keys.into_iter().zip(prefix_lens.into_iter()).take(n).collect();
        for (k, p) in &pairs {
            tree.insert(*k, *p, 60).expect("insert should not fail");
        }

        // Delete half
        let to_delete: Vec<_> = pairs.iter().take(n/2).cloned().collect();
        let to_keep: Vec<_> = pairs.iter().skip(n/2).cloned().collect();

        for (k, _p) in &to_delete {
            let _ = tree.delete(*k);
        }

        // Deleted keys should not be found
        for (k, _) in &to_delete {
            assert!(!tree.lookup(*k), "Deleted key was found");
        }
        // Remaining keys should be found
        for (k, _) in &to_keep {
            assert!(tree.lookup(*k), "Kept key was not found");
        }
    }
}

#[test]
fn stress_concurrent_inserts_and_lookups() {
    use cidrscan::PatriciaTree;
    let threads = num_cpus::get();
    let ops_per_thread = 100_000;
    let shm_name = format!("test_shm_stress_{}", rand::random::<u64>());
    let tree = Arc::new(PatriciaTree::open(&shm_name, threads * ops_per_thread * 2).unwrap());

    let mut handles = vec![];
    for t in 0..threads {
        let tree = Arc::clone(&tree);
        handles.push(thread::spawn(move || {
            let base = (t as u128) << 32;
            for i in 0..ops_per_thread {
                let key = base | (i as u128);
                tree.insert(key, 128, 60).expect("insert should not fail");
                assert!(tree.lookup(key));
                if i % 2 == 0 {
                    let _ = tree.delete(key);
                }
            }
        }));
    }
    for h in handles {
        h.join().expect("thread failed");
    }
}

use proptest::prelude::*;
use num_cpus;
use std::sync::Arc;
use std::thread;
