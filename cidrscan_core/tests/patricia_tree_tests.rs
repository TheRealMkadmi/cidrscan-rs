use num_cpus;
use proptest::collection::{hash_set, vec as pvec};
use proptest::prelude::*;
use rand;
use std::sync::Arc;
use std::thread;
use cidrscan_core::helpers::{v4_key, v4_plen};
use cidrscan_core::types::PatriciaTree;

#[test]
fn basic_ops() {
    let name = format!("test_shm_{}", std::process::id());
    let tree = PatriciaTree::open(&name, 1024).unwrap();
    let ip = 0xC0A80001;
    let key = v4_key(ip);
    let plen = v4_plen(32);
    let _ = tree.insert(key, plen, 60, None);
    assert!(tree.lookup(key).is_some());
    _ = tree.delete(key, plen);
    assert!(tree.lookup(key).is_none());
}

#[test]
fn ttl_expiry() {
    let name = format!("test_shm_ttl_{}", std::process::id());
    let tree = PatriciaTree::open(&name, 1024).unwrap();
    let ip = 0x01020304;
    let key = v4_key(ip);
    let plen = v4_plen(32);

    let _ = tree.insert(key, plen, 0, None);
    assert!(tree.lookup(key).is_some());

    let _ = tree.insert(key, plen, 1, None);
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert!(tree.lookup(key).is_none());
}
#[test]
fn split_creates_balanced_branches() {
    let key1 = v4_key(0b10000000_00000000_00000000_00000000u32);
    let key2 = v4_key(0b00000000_00000000_00000000_00000000u32);
    let plen = v4_plen(32);

    let name = format!("test_shm_split_{}", std::process::id());
    let tree = PatriciaTree::open(&name, 1024).unwrap();
    let _ = tree.insert(key1, plen, 6, None);
    _ = tree.insert(key2, plen, 60, None);

    assert!(tree.lookup(key1).is_some());
    assert!(tree.lookup(key2).is_some());

    _ = tree.delete(key1, plen);
    assert!(tree.lookup(key1).is_none());
    assert!(tree.lookup(key2).is_some());

    _ = tree.delete(key2, plen);
    assert!(tree.lookup(key2).is_none());
}


proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn property_insert_delete_lookup(
        keys in hash_set(0u128..1000, 3..8),
        prefix_lens in pvec(8u8..32, 3..32)
    ) {

        // Trim prefix_lens to have at most one length per key
        let n = keys.len();
        let lens = &prefix_lens[..n.min(prefix_lens.len())];

        // Pair each unique key with one prefix_len
        let pairs: Vec<_> = keys.into_iter().zip(lens.iter().copied()).collect();

        // Open tree with extra capacity
        let shm_name = format!("test_shm_prop_{}", rand::random::<u64>());
        let tree = PatriciaTree::open(&shm_name, pairs.len() * 2).unwrap();

        // Insert all as IPv4 prefixes
        for &(k, p) in &pairs {
            tree.insert_v4(k as u32, p, 60).unwrap();
        }

        // Split vector deterministically
        let mid = pairs.len() / 2;
        let (to_delete, to_keep) = pairs.split_at(mid);

        // Delete first half
        for &(k, p) in to_delete {
            tree.delete_v4(k as u32, p).unwrap();
        }

        // Deleted keys must be absent
        for &(k, _) in to_delete {
            assert!(tree.lookup_v4(k as u32).is_none(), "Deleted key still present: {k:#x}");
        }
        // Kept keys must be present
        for &(k, _) in to_keep {
            assert!(tree.lookup_v4(k as u32).is_some(), "Kept key missing: {k:#x}");
        }
    }
}

#[test]
fn stress_concurrent_inserts_and_lookups() {
    let threads = num_cpus::get();
    let ops_per_thread = 10_000;
    let shm_name = format!("test_shm_stress_{}", rand::random::<u64>());
    let tree = Arc::new(PatriciaTree::open(&shm_name, threads * ops_per_thread * 2).unwrap());

    let mut handles = vec![];
    for t in 0..threads {
        let tree = Arc::clone(&tree);
        handles.push(thread::spawn(move || {
            let base = (t as u128) << 32;
            for i in 0..ops_per_thread {
                let key = base | (i as u128);
                tree.insert(key, 128, 60, None).expect("insert should not fail");
                assert!(tree.lookup(key).is_some());
                if i % 2 == 0 {
                    let _ = tree.delete(key, 128);
                }
            }
        }));
    }
    for h in handles {
        h.join().expect("thread failed");
    }
}

#[test]
fn test_internal_node_terminal_flag_and_delete() {
    let tree = PatriciaTree::open("test_internal_node", 16).unwrap();

    tree.insert(v4_key(0x01020304), v4_plen(32), 60,None).unwrap();
    tree.insert(v4_key(0x01020300), v4_plen(24), 60,None).unwrap();

    assert!(tree.lookup(v4_key(0x01020304)).is_some());
    assert!(tree.lookup(v4_key(0x01020300)).is_some());

    tree.delete(v4_key(0x01020300), v4_plen(24)).unwrap();

    assert!(tree.lookup(v4_key(0x01020300)).is_none());
    assert!(tree.lookup(v4_key(0x01020304)).is_some());
}
 
#[test]
fn v4_lookup_returns_tag() {
    let name = format!("test_shm_tag_{}", std::process::id());
    let t = PatriciaTree::open(&name, 128).unwrap();
    t.insert(v4_key(0x08080808), v4_plen(24), 3600, Some("Google-DNS")).unwrap();
    let m = t.lookup(v4_key(0x08080808)).unwrap();
    assert_eq!(m.plen, v4_plen(24));
    assert_eq!(m.tag, "Google-DNS");
}
