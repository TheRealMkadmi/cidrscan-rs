use cidrscan::PatriciaTree;

#[test]
fn basic_ops() {
    let tree = PatriciaTree::open("test_shm", 1024).unwrap();
    let ip = 0xC0A80001; // 192.168.0.1
    let _ = tree.insert(ip, 32, 60);
    assert!(tree.lookup(ip));
    _ = tree.delete(ip);
    assert!(!tree.lookup(ip));
}

#[test]
fn ttl_expiry() {
    let tree = PatriciaTree::open("test_shm_ttl", 1024).unwrap();
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

    let tree = PatriciaTree::open("test_shm_split", 1024).unwrap();
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
