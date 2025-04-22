use cidrscan::PatriciaTree;

#[test]
fn basic_ops() {
    let tree = PatriciaTree::open("test_shm", 1024).unwrap();
    let ip = 0xC0A80001; // 192.168.0.1
    tree.insert(ip, 32, 60);
    assert!(tree.lookup(ip));
    tree.delete(ip);
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
