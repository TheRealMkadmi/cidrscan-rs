# CIDRScan-rs

A high-performance, cross-process, lock-free-read, memory-resident Patricia (radix) tree for CIDR prefix lookups, built in Rust. CIDRScan-rs is designed for robust multi-process and multi-threaded environments, supporting per-entry TTL, atomic operations, and a C ABI for broad interoperability. The library is suitable for use cases such as application firewalls, distributed caches, and any scenario requiring fast, concurrent, and shared access to IP prefix data.

---

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
10. [Platform-Specifics](#platform-specifics)
11. [Testing & Extensibility](#testing--extensibility)

---
## Recent Enhancements (May 2025)

### Opportunistic Pruning on Lookup
- The Patricia tree now performs opportunistic pruning during every lookup. As the tree is traversed, any non-terminal node with only one live child is pruned inline, keeping the tree compact with minimal overhead.

### Structured Logging
- The library now uses the standard [`log`](https://docs.rs/log) facade for all internal logging. By default, `env_logger` is auto-initialized (unless another logger is already set), so log messages go to stdout. You can override this by initializing your own logger (e.g., with `tracing_subscriber`) before calling `PatriciaTree::open`.

### Atomic Resize
- A new method, `PatriciaTree::resize(new_capacity)`, allows atomic resizing of the tree. This creates a new, larger mapping, bulk-copies all live prefixes, and returns a new `PatriciaTree`. The caller can atomically swap the handle (e.g., with `ArcSwap`), and the old tree is dropped asynchronously.

### Dependency Updates
- Added dependencies: `log`, `env_logger`, and `once_cell` for logging and initialization.

#### Example Usage

```rust
// 0) existing tree
let tree = PatriciaTree::open("cidr_prod",  1_000_000)?;

// 1) opportunistic prune now happens automatically on every lookup()

// 2) logging – if you want Laravel’s stack:
tracing_subscriber::registry()
    .with(tracing_subscriber::fmt::layer())
    .init();     // do this *before* first PatriciaTree::open

// 3) atomic resize
let bigger = tree.resize(2_000_000)?;
LET_ARC_SWAP.store(Arc::new(bigger));   // one pointer write → all threads see the new map
```

---
---

## Introduction & Motivation

CIDRScan-rs addresses the need for fast, concurrent, and memory-efficient prefix matching for IP addresses (IPv4 and IPv6) in environments where multiple processes or threads must share and mutate a common data structure. The project leverages Rust's safety and concurrency features, and exposes a C ABI for broad compatibility. The current design is highly modular, with platform-specific logic, robust error handling, and a focus on correctness and performance.

---

## Quick Start & Usage

CIDRScan-rs enables languages such as PHP, Python, and JavaScript/TypeScript to use a memory-resident IP "database"—a high-performance Patricia tree designed for multi-worker environments (e.g., Laravel Octane, Gunicorn, PM2 cluster). It is ideal for scenarios like application firewalls, where fast, concurrent, and shared access to IP prefix data is critical.

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

## Platform-Specifics

- **Windows:** For cross-session sharing, the creator process must hold the `SeCreateGlobalPrivilege`. The library provides a platform-specific function to enable this privilege if possible. If not available, the mapping falls back to session-local.
- **Unix:** Shared memory is managed using POSIX APIs, and resources are cleaned up automatically when the last handle is dropped.

---

## Calling from Other Languages

CIDRScan-rs exposes a C ABI for use via FFI (Foreign Function Interface) in PHP, Python, Node.js, and more. Handles are per-process, but the underlying data is shared via memory-mapped regions. The exported API includes:

```c
ErrorCode patricia_open(const uint8_t* name, size_t name_len, size_t capacity, int32_t* out_handle);
ErrorCode patricia_close(int32_t handle);
ErrorCode patricia_insert(int32_t handle, uint64_t key_high, uint64_t key_low, uint8_t prefix_len, uint64_t ttl);
bool      patricia_lookup(int32_t handle, uint64_t key_high, uint64_t key_low);
ErrorCode patricia_delete(int32_t handle, uint64_t key_high, uint64_t key_low, uint8_t prefix_len);
ErrorCode patricia_bulk_insert(int32_t handle, const struct { uint64_t hi; uint64_t lo; uint8_t len; uint64_t ttl; }* items, size_t count);
ErrorCode patricia_last_error(void);
const char* patricia_strerror(ErrorCode code);
```

Handles are not shared between processes; each process maintains its own registry of open trees, but all processes with the same name map the same shared memory region.

---

## Design Philosophy & Principles

- **Lock-Free Reads:** All lookups are lock-free and wait-free, using atomic root and child pointers and generation counters for ABA safety.
- **Cross-Process Safety:** Writers use a custom cross-process RW-lock in shared memory, ensuring correctness across multiple processes.
- **Memory Residency:** All data lives in a single, cache-line-aligned memory-mapped region, with offset-based node access so the region can be mapped at different addresses in different processes.
- **Robust Error Handling:** Rich error codes are provided via a C ABI, with thread-local last error tracking.
- **Platform Abstraction:** Platform-specific logic is modularized for maintainability and portability.
- **Lock-Free Node Recycling:** Uses `crossbeam-epoch` and a global `SegQueue` for wait-free, lock-free node reclamation.

---

## Architecture Overview

CIDRScan-rs is centered around a compressed-path Patricia tree, with all nodes and metadata stored in a shared memory region. The tree supports:

- Lock-free lookups via atomic root and child pointers.
- Per-node TTLs for automatic expiry.
- Efficient allocation and recycling of nodes using lock-free epoch-based reclamation.
- Cross-process and cross-thread safety via atomic operations and a custom shared-memory RW-lock.

The public API exposes C ABI functions for opening, inserting, looking up, deleting, and bulk-inserting prefixes, as well as error reporting.

---

## Core Data Structures

- **Header:** Holds global metadata, including a magic/version, atomic root pointer, bump allocator index, and a cross-process RW-lock.
- **Node:** Each node stores a 128-bit key, prefix length, atomic child offsets, an atomic TTL expiry, and a generation counter for ABA safety.
- **PatriciaTree:** The main handle, containing pointers to the shared memory region and header. All node management is lock-free and uses offset-based addressing.
- **RawRwLock:** A cross-process, writer-preferring RW-lock that fits in shared memory, used for synchronizing writers.

---

## Memory Management

- **Bump Allocator:** New nodes are allocated by atomically incrementing `next_index` in the header.
- **Lock-Free Free List:** Deleted nodes are recycled via a global, lock-free `SegQueue<Offset>`, with reclamation deferred using `crossbeam-epoch` to ensure no thread is accessing a node before it is reused.
- **Generation Counters:** Each node has a generation counter, incremented on reuse, to prevent ABA hazards and ensure cross-process safety.
- **Capacity Enforcement:** All allocations check against the configured capacity and return errors on overflow.
- **Cache-Line Alignment:** Both `Header` and `Node` are 64-byte aligned for performance.

---

## Key Operations

### Insertion

- Performed under a write lock.
- Traverses the tree using `common_prefix_len` and `get_bit`.
- Handles cases for empty links, exact matches, splits, and prefix insertions above or below existing nodes.
- Uses atomics and volatile writes for all pointer updates.
- Recycles or allocates nodes using the lock-free free list and bump allocator.

### Lookup

- Lock-free and highly concurrent.
- Walks the tree by prefix comparison and bit tests.
- Checks TTL at each node; expired nodes are treated as absent.
- Detects ABA hazards using generation counters and restarts if needed.

### Deletion

- Performed under a write lock.
- Locates the node, marks it as expired, and retires its offset using epoch-based reclamation.
- Handles branch merges when a node’s removal leaves a branch with a single child.
- All node recycling is lock-free and safe for concurrent readers.

---

## Concurrency & Safety

- **Lock-Free Reads:** All lookups are lock-free, using atomic root and child pointers and generation counters for ABA safety.
- **Write Synchronization:** Insertions and deletions use a global cross-process RW-lock for exclusive access, implemented in shared memory.
- **Send/Sync Guarantees:** `PatriciaTree` is explicitly marked as `Send` and `Sync`.
- **Inter-Process Coordination:** Shared memory can be mapped by multiple processes, with atomics ensuring consistency and safety.
- **Epoch-Based Reclamation:** Memory reclamation is handled per-process using `crossbeam-epoch`. Stale pointers in other processes are detected by generation mismatches and retried safely.

---

## Error Handling & Invariants

- **Capacity Checks:** All allocations check against `capacity` and return errors on overflow.
- **Integrity Checks:** The header includes a magic value and version for ABI compatibility.
- **Panic Safety:** The implementation is panic-safe, with atomic updates and lock-based synchronization ensuring consistency.
- **Invariants:** The tree structure is always valid, with no dangling pointers or cycles. ABA hazards are prevented by generation counters.
- **Rich C ABI Error Reporting:** All C ABI functions return detailed error codes, and the last error is tracked per-thread for diagnostics.

---

## Testing & Extensibility

- **Test Coverage:** The test suite covers TTL expiry, bulk insert, edge cases, and concurrency.
- **Extensibility:** The design is ready for future enhancements, such as background compaction to merge redundant internal nodes and further optimizations for large-scale deployments.

---
