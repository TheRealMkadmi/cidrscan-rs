#![cfg_attr(windows, feature(abi_vectorcall))] // req. for PHP on Windows
use ext_php_rs::prelude::*;
use once_cell::sync::OnceCell;
use cidrscan_core::{PatriciaTree, ErrorCode};

static TREE: OnceCell<PatriciaTree> = OnceCell::new();

/* -------- lifecycle helpers -------- */

#[php_function]
pub fn cidr_open_php(capacity: u64) -> bool {
    TREE.set(PatriciaTree::with_capacity(capacity as usize)).is_ok()
}

#[php_function]
pub fn cidr_close_php() -> bool {
    if let Some(tree) = TREE.take() { drop(tree); true } else { false }
}

/* -------- CRUD wrappers -------- */

#[php_function]
pub fn cidr_insert_php(cidr: String, ttl: u64, tag: Option<String>) -> bool {
    let tree = TREE.get().ok_or(()).err().is_none() &&
        match cidr.parse() {
            Ok(net) => TREE.get().unwrap()
                            .insert_net(&net, ttl, tag.as_deref()).is_ok(),
            Err(_)  => false,
        };
    tree
}

#[php_function]
pub fn cidr_lookup_php(addr: String) -> bool {
    TREE.get()
        .map(|t| t.lookup_str(&addr).is_some())
        .unwrap_or(false)
}

#[php_function]
pub fn cidr_available_capacity_php() -> i64 {
    TREE.get().map(|t| t.available_capacity() as i64).unwrap_or(-1)
}

/* -------- module entry -------- */

#[php_module]
pub fn module(module: ModuleBuilder) -> ModuleBuilder { module }
