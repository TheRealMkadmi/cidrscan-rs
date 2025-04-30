# CIDRScan-rs

A high-performance, concurrent, memory-resident Patricia (radix) tree for CIDR prefix lookups, built in Rust for robust multi-process and multi-threaded environments. Data is shared via a memory-mapped region, supports per-entry TTL, and provides a C ABI for interoperability.

## Table of Contents

1. [Introduction & Motivation](#introduction--motivation)
2. [Quick Start & Usage](#quick-start--usage)
3. [Design Philosophy & Principles](#design-philosophy--principles)
4. [Architecture Overview](#architecture-overview)
5. [Core Data Structures](#core-data-structures)
6. [Memory Management](#memory-management)
7. [Key Operations](#key-operations)
    - [Insertion](#insertion)
    - [Lookup](#lookup)
    - [Deletion](#deletion)
8. [Concurrency & Safety](#concurrency--safety)
9. [Error Handling & Invariants](#error-handling--invariants)
10. [Testing & Extensibility](#testing--extensibility)

## Introduction & Motivation

CIDRScan-rs was created to solve the problem of fast, concurrent, and memory-efficient prefix matching for IP addresses (both IPv4 and IPv6) in environments where multiple processes or threads need to share and mutate a common data structure. The project leverages Rust's safety and concurrency features, and exposes a C ABI for broad compatibility.

## Quick Start & Usage

This library enables languages such as PHP, Python, and JavaScript/TypeScript to use a memory-resident IP "database"—a high-performance Patricia tree designed for multi-worker environments (e.g., Laravel Octane, Gunicorn, PM2 cluster). It is ideal for scenarios like application firewalls, where fast, concurrent, and shared access to IP prefix data is critical.

### Building

```sh
cargo build --release
```

### Basic Usage

```rust
use cidrscan_rs::PatriciaTree;

fn main() {
    // Open or create a Patricia tree in shared memory
    let tree = PatriciaTree::open("my_tree", 1_048_576).expect("Failed to open PatriciaTree");

    // Insert a key (e.g., IPv4 as u128, prefix length, TTL in seconds)
    let key: u128 = 0x0a000001; // 10.0.0.1 as IPv4-mapped u128
    tree.insert(key, 32, 3600);

    // Lookup the key
    let found = tree.lookup(key);
    println!("Found? {}", found);

    // Tree is automatically closed and unmapped when dropped
}
```
---

## Windows: Cross-Session Sharing & Privileges

> **Windows** – If you run multiple sessions (Remote Desktop / services) and need cross-session sharing, the service that *creates* the tree must hold the **SeCreateGlobalPrivilege** privilege. Grant it in *Local Security Policy → User Rights Assignment* or run under `LocalSystem`. Otherwise the library automatically falls back to a session-local mapping.

- The mapping name is always neutral (e.g., `cidrscan_<hash>`), so the same code path works for all environments.
- Privileged services gain cross-session visibility by default; non-privileged contexts degrade gracefully with no code changes.

### Calling from Other Languages

You can use FFI (Foreign Function Interface) to call these functions from PHP (via FFI), Python (via ctypes or cffi), Node.js (via N-API or ffi-napi), and more. Note: Calls using the same name will share the same memory region, so changes in one process are visible to all processes using that name.

For convenience and cross-language support, the following functions are exported in the generated `.h` file (see [`src/public_api.rs`](./src/public_api.rs)):

```c
int  patricia_open(const uint8_t* name, size_t name_len, size_t capacity);
void patricia_close(int handle);
void patricia_insert(int handle, uint64_t key_high, uint64_t key_low, uint8_t prefix_len, uint64_t ttl);
bool patricia_lookup(int handle, uint64_t key_high, uint64_t key_low);
void patricia_delete(int handle, uint64_t key_high, uint64_t key_low);
void patricia_bulk_insert(int handle, const struct { uint64_t hi; uint64_t lo; uint8_t len; uint64_t ttl; }* items, size_t count);
```



**Example in PHP (using PHP FFI):**
```php
$ffi = FFI::cdef(
    file_get_contents('cidrscan_ffi.h'), // provided in the .zip file
    __DIR__ . '/target/release/libcidrscan_rs.so'
);

$name = "my_tree";
$handle = $ffi->patricia_open($name, strlen($name), 1048576);

$ffi->patricia_insert($handle, 0, 0x0a000001, 32, 3600);

$found = $ffi->patricia_lookup($handle, 0, 0x0a000001);
echo "Found? " . ($found ? "true" : "false") . PHP_EOL;

$ffi->patricia_close($handle);
```

## Design Philosophy & Principles

CIDRScan-rs is built for high performance, concurrency, and robust memory residency. The core design goals and principles are:

- **Performance:** All critical operations are O(k) where k is the prefix length (up to 128 bits).
- **Concurrency:** Lock-free reads, minimal locking for writes, and safe sharing across threads and processes.
- **Memory Residency:** All data lives in a single, cache-line-aligned memory-mapped region, with offset-based node access so the region can be mapped at different addresses in different processes.
- **Robustness:** Strong invariants, panic safety, and explicit error handling.
- **Cache-Line Alignment:** Minimizes false sharing and maximizes cache efficiency.
- **Atomic Root Pointer:** Enables lock-free, high-performance lookups.
- **Rust Safety Features:** Leverages `NonNull`, atomics, and explicit `Send`/`Sync` for safety and performance ([see lines 96-97](./src/lib.rs#L96-L97)).
- **parking_lot Crate:** Provides efficient, fair, and deadlock-resistant synchronization primitives.

## Architecture Overview

CIDRScan-rs is centered around a Patricia tree (see [`src/lib.rs`](./src/lib.rs)), with all nodes and metadata stored in a shared memory region. The tree supports:
- Lock-free lookups via atomic root and child pointers.
- Per-node TTLs for automatic expiry.
- Efficient allocation and recycling of nodes.

The public API (see [`src/public_api.rs`](./src/public_api.rs)) exposes C ABI functions for opening, inserting, looking up, deleting, and bulk-inserting prefixes.

## Core Data Structures

Defined in [`src/lib.rs`](./src/lib.rs):

- **Header** ([lines 61-71](./src/lib.rs#L61-L71)):  
  Holds global metadata, including a magic/version, atomic root pointer, bump allocator index, and synchronization primitives.

- **Node** ([lines 74-82](./src/lib.rs#L74-L82)):  
  Each node stores a 128-bit key, prefix length, atomic child offsets, and an atomic TTL expiry.

- **PatriciaTree** ([lines 84-90](./src/lib.rs#L84-L90)):  
  The main handle, containing pointers to the shared memory region, header, and a mutex-protected free list.

## Memory Management

- **Bump Allocator:**  
  New nodes are allocated by atomically incrementing `node_count` ([see line 170](./src/lib.rs#L170)).
- **Free List:**  
  Deleted nodes are recycled via a mutex-protected free list ([see line 88](./src/lib.rs#L88)).
- **Capacity Enforcement:**  
  All allocations check against the configured capacity, panicking on overflow ([see lines 172-175](./src/lib.rs#L172-L175)).
- **Cache-Line Alignment:**  
  Both `Header` and `Node` are 64-byte aligned for performance.

## Key Operations

### Insertion

Insertion is performed under a write lock ([see `insert` at line 183](./src/lib.rs#L183)). The algorithm:
- Traverses the tree using `common_prefix_len` ([line 6](./src/lib.rs#L6)) and `get_bit` ([line 23](./src/lib.rs#L23)).
- Handles cases for empty links, exact matches, splits, and prefix insertions above or below existing nodes.
- Uses atomics and volatile writes for all pointer updates.

<details>
<summary>Pseudocode</summary>

```text
function insert(key, prefix_len, ttl):
    acquire write lock
    node = root
    while node exists:
        match = common_prefix_len(node.key, key, min(node.prefix_len, prefix_len))
        if match < node.prefix_len:
            split node at match
            insert new branch and leaf
            return
        if match == prefix_len:
            update node.expires
            return
        node = child based on next bit
    allocate new leaf node
    set parent pointer atomically
```
</details>

### Lookup

Lock-free and for high concurrency ([see `lookup` at line 448](./src/lib.rs#L448)):
- Walks the tree by prefix comparison and bit tests.
- Checks TTL at each node; expired nodes are treated as absent.

<details>
<summary>Pseudocode</summary>

```text
function lookup(key):
    node = atomic_load(root_offset)
    while node exists:
        if node.expires != 0 and node.expires < now:
            return false
        match = common_prefix_len(node.key, key, node.prefix_len)
        if match < node.prefix_len:
            return false
        if match == node.prefix_len and match == 128:
            return true
        node = child based on next bit
    return false
```
</details>

### Deletion

Deletion is performed under a write lock ([code](./src/lib.rs)):
- Locates the node, updates parent pointers atomically, and recycles the node offset.
- Handles branch merges when a node’s removal leaves a branch with a single child.

## Concurrency & Safety

- **Lock-Free Reads:**  
  All lookups are lock-free, using atomic root and child pointers.
- **Write Synchronization:**  
  Insertions and deletions use a global `RwLock` for exclusive access.
- **Send/Sync Guarantees:**  
  `PatriciaTree` is explicitly marked as `Send` and `Sync` ([see lines 96-97](./src/lib.rs#L96-L97)).
- **Inter-Process Coordination:**  
  Shared memory can be mapped by multiple processes, with atomics ensuring consistency.

## Error Handling & Invariants

- **Capacity Checks:**  
  All allocations check against `capacity` and panic on overflow.
- **Integrity Checks:**  
  The header includes a magic value and version for ABI compatibility.
- **Panic Safety:**  
  The implementation is panic-safe, with atomic updates and lock-based synchronization ensuring consistency.
- **Invariants:**  
  The tree structure is always valid, with no dangling pointers or cycles.


## Testing & Extensibility

- **Test Coverage:**  
  The test suite ([see [`tests/integration_tests.rs`](./tests/integration_tests.rs)] and [`tests/patricia_tree_tests.rs`](./tests/patricia_tree_tests.rs)) covers TTL expiry, bulk insert, edge cases, and concurrency.



