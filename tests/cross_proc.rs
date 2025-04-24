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

#[test]
fn aba_safe_delete_reinsert() {
    // TODO: Implement ABA-safe delete and reinsert test
    todo!();
}

#[test]
fn capacity_reclaims() {
    // TODO: Implement capacity reclaims test
    todo!();
}

#[test]
fn offset_u32() {
    // TODO: Implement offset u32 test
    todo!();
}

#[test]
fn epoch_reader_restart() {
    // TODO: Implement epoch reader restart test
    todo!();
}