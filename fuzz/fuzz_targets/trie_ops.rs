#![no_main]

use std::sync::atomic::{AtomicU64, Ordering};

use arbitrary::Arbitrary;
use cidrscan_core::{helpers::canonical, types::PatriciaTree};
use libfuzzer_sys::fuzz_target;

static NEXT_TREE_ID: AtomicU64 = AtomicU64::new(0);
const MAX_OPS: usize = 64;
const TREE_CAPACITY: usize = 256;
const MAX_PROBES: usize = 8;

#[derive(Arbitrary, Debug)]
struct Input {
    ops: Vec<Op>,
}

#[derive(Arbitrary, Debug)]
enum Op {
    Insert { key: u128, prefix_len: u8 },
    Delete { key: u128, prefix_len: u8 },
    Lookup { key: u128 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    key: u128,
    prefix_len: u8,
}

fuzz_target!(|input: Input| {
    if input.ops.len() > MAX_OPS {
        return;
    }

    let name = format!(
        "fuzz_trie_ops_{}_{}",
        std::process::id(),
        NEXT_TREE_ID.fetch_add(1, Ordering::Relaxed)
    );
    let tree = match PatriciaTree::open(&name, TREE_CAPACITY) {
        Ok(tree) => tree,
        Err(_) => return,
    };

    let mut model = Vec::new();
    let mut probes = Vec::new();

    for op in input.ops {
        match op {
            Op::Insert { key, prefix_len } => {
                if prefix_len > 128 {
                    continue;
                }
                let key = canonical(key, prefix_len);
                let _ = tree.insert(key, prefix_len, 0, None);
                model.push(Entry { key, prefix_len });
                remember_probe(&mut probes, key);
            }
            Op::Delete { key, prefix_len } => {
                if prefix_len > 128 {
                    continue;
                }
                let key = canonical(key, prefix_len);
                let _ = tree.delete(key, prefix_len);
                if let Some(idx) = model
                    .iter()
                    .rposition(|entry| entry.key == key && entry.prefix_len == prefix_len)
                {
                    model.remove(idx);
                }
                remember_probe(&mut probes, key);
            }
            Op::Lookup { key } => {
                assert_lookup_matches(&tree, &model, key);
                remember_probe(&mut probes, key);
            }
        }

        for &probe in probes.iter().rev().take(MAX_PROBES) {
            assert_lookup_matches(&tree, &model, probe);
        }
    }
});

fn remember_probe(probes: &mut Vec<u128>, key: u128) {
    probes.push(key);
    if probes.len() > MAX_PROBES * 2 {
        probes.drain(..probes.len() - MAX_PROBES * 2);
    }
}

fn assert_lookup_matches(tree: &PatriciaTree, model: &[Entry], key: u128) {
    let expected = expected_match(model, key);
    let actual = tree.lookup(key).map(|matched| Entry {
        key: matched.cidr_key,
        prefix_len: matched.plen,
    });
    assert_eq!(actual, expected, "lookup mismatch for key {key:032x}");
}

fn expected_match(model: &[Entry], key: u128) -> Option<Entry> {
    model.iter().copied().fold(None, |best, entry| {
        if canonical(key, entry.prefix_len) != entry.key {
            return best;
        }
        match best {
            Some(current) if current.prefix_len >= entry.prefix_len => Some(current),
            _ => Some(entry),
        }
    })
}
