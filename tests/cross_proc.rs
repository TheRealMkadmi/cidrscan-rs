use std::process::Command;
use cidrscan::PatriciaTree;

#[test]
fn two_processes_write() {
    let name = "test_xproc";
    let _ = PatriciaTree::destroy(name);
    // parent inserts
    {
        let tree = PatriciaTree::open(name, 256).unwrap();
        tree.insert(0xdead_beef, 32, 60);
    }
    // child links same tree and looks up
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("child_lookup").arg(name).status().unwrap();
    assert!(status.success());
}