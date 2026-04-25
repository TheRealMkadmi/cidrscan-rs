# CIDRScan‑rs

*A shared-memory, lock-free-read Patricia-trie engine for **O(log W)** longest-prefix matching (LPM) with per-prefix TTLs, tags, and a tiny language-agnostic C ABI.*

---

## Table of Contents

1. [Why CIDRScan‑rs?](#why-cidrscan‑rs)
2. [Feature Highlights](#feature-highlights)
3. [Getting Started](#getting-started)
   * [Rust](#rust‑quick‑start)
   * [C / Any‑FFI](#c‑abi‑quick‑start)
4. [Architecture Deep Dive](#architecture-deep-dive)
   * [Memory Layout](#memory-layout)
   * [Node Life‑cycle](#node-life‑cycle)
   * [Cross‑process RW‑Lock](#cross‑process-rw‑lock)
5. [Core Algorithms](#core-algorithms)
   * [Lookup (Wait‑free)](#lookup)
   * [Insert (Writer‑exclusive)](#insert)
   * [Delete (Writer‑exclusive)](#delete)
6. [Design Philosophy](#design-philosophy)
7. [Safety & Correctness](#safety--correctness)
8. [Known Limitations](#known-limitations)
9. [Road‑map](#road‑map)
10. [License](#license)

---

## Why CIDRScan‑rs?

Traditional LPM libraries fall into two camps:

| Camp                               | Limitations                                                              |
| ---------------------------------- | ------------------------------------------------------------------------ |
| **Kernel‑style radix trees**       | Tightly coupled to in‑kernel allocators; not shareable across processes. |
| **User‑space hash / tree hybrids** | Require coarse locks or exotic GC; do not support TTLs.                  |

**CIDRScan‑rs** is aimed at *application‑space firewalls, geo‑fencing, and abuse‑detection engines* that want a single memory-mapped trie with cheap reads and explicit operational tradeoffs. It delivers:

* **Lock‑free reads** – lookups walk atomic pointers without taking the global writer lock; opportunistic TTL GC may briefly attempt a best-effort write lock.
* **Shared-memory arenas** – the trie lives in one POSIX/Win32 shared-memory region that multiple handles can open.
* **Per‑prefix TTLs** – expired prefixes are reclaimed opportunistically.
* **Built‑in C ABI** – call from PHP/Ruby/Node/Python in < 5 lines.
* **Deterministic memory usage** – capacity is fixed up‑front; no heap allocations at runtime.

---

## Feature Highlights

* **Opportunistic pruning**: unary internal nodes are collapsed during lookups; no background compactor is required.
* **ABA‑safe pointers**: every child link stores `(offset, generation)`; stale readers restart instead of following reused nodes.
* **Process-local reclamation queue**: freed offsets are retired locally and become reusable after `flush()` advances the local epoch.
* **In-process resize**: `tree.resize(new_capacity)` copies live prefixes into a bigger mapping, including tags, then swaps the current handle to the new arena.
* **Custom shared RW‑lock** (`RawRwLock`): writer‑preferential, fits entirely in the shared page, and runs on Linux, macOS, and Windows, though owner-death recovery differs by platform.
* **Tiny build‑time footprint**: single `cargo build`, no `unsafe` outside thin FFI & atomics.
* **Language‑agnostic packages**: CI publishes pre‑built `*.zip` bundles with **`.dll` / `.so` / `.dylib` + `cidrscan.h`**.

---

## Getting Started

### Rust Quick Start

```rust
use cidrscan::PatriciaTree;

fn main() -> anyhow::Result<()> {
    // ❶ Map (or create) a 1‑million‑node arena
    let tree = PatriciaTree::open("cidr_prod", 1_000_000)?;

    // ❷ Insert an IPv4 /32 with a 60‑second TTL
    const IP: u32 = 0xC0A8_0001;                // 192.168.0.1
    tree.insert_v4(IP, 32, 60)?;

    // ❸ Lock‑free lookup
    assert!(tree.lookup_v4(IP));

    // ❹ Automatic opportunistic pruning and TTL expiry
    std::thread::sleep(std::time::Duration::from_secs(61));
    assert!(!tree.lookup_v4(IP));

    Ok(())
}
```

Build:

```bash
cargo build --release
```

> **Tip:** enable structured logs with
>
> ```rust
> tracing_subscriber::fmt().with_target(false).init();
> ```

### C ABI Quick Start

```c
#include "cidrscan.h"
#include <stdint.h>
#include <stdio.h>

int main(void) {
    int32_t h;
    if (patricia_open((uint8_t*)"fw", 2, 1<<20, &h) != Success) return 1;

    // 10.0.0.0/8 (IPv4‑mapped to upper bits zero)
    patricia_insert(h, 0, 0x0A000000ull, 32, 300);
    printf("hit? %d\n", patricia_lookup(h, 0, 0x0A000000ull));

    patricia_close(h);
}
```

All symbols are declared in `cidrscan.h`; link with `-lcidrscan`.

---

## Architecture Deep Dive

### Memory Layout

```
┌─────────────────────────────────────────────────────────────────┐
│ Header (64‑byte aligned)                                       │
│ ├── magic, version                                             │
│ ├── RawRwLock   ← cross‑process writer lock                    │
│ ├── next_index  ← bump allocator                               │
│ ├── free_slots  ← #recycled nodes waiting in SegQueue          │
│ ├── root_offset ← packed (off, gen)                            │
│ └── …                                                         │
├─────────────────────────────────────────────────────────────────┤
│ Node[capacity]  (each 64 B, offset‑addressed)                  │
└─────────────────────────────────────────────────────────────────┘
```

Because every pointer is an *offset* from `base`, the region may be mapped at different virtual addresses by different processes.

### Node Life‑cycle

```
 allocate → mutate under write‑lock → publish atomically
       ↘                           ↙
        free (delete / TTL)  ← retire (epoch) ← all readers left
```

A freed node’s offset is retired into a process-local queue and becomes reusable after a later `flush()` advances the handle’s local epoch.

### Cross‑process RW‑Lock

* **Writer preference**: readers spin if `WRITER_BIT` is set.
* **No starvation**: writer blocks new readers and uses an OS event to wait for in‑flight readers to drain.
* Implemented with *raw‑sync* primitives; fits in ≈ 100 bytes.

---

## Core Algorithms

#### Lookup

1. Load packed `root_offset`.
2. Compare common‑prefix length; if shorter, return **miss**.
3. Descend via `get_bit(key, plen)` – *no locks, no branches on the hot path*.
4. On the way *back up*, try `prune(parent)` if the node we just left became unary.
5. TTL expired? opportunistically GC under a best-effort `try_write_lock`.

Time‑complexity: ***O(log W)*** where `W ≤ 128`.

#### Insert

* Single writer acquires the global `RawRwLock`.
* Handles four cases in one tight loop: *empty link*, *exact match*, *insert‑above*, *split*.
* Allocates from **freelist → bump allocator → epoch flush** in that order.
* All pointer installs use CAS **once**; on failure recycle offsets and restart.

#### Delete

* Writer lock.
* Clears `is_terminal / refcnt`; if the node became empty leaf it is unlinked and retired.
* After unlink, runs `try_prune` upwards to collapse obsolete internal nodes.

---

## Design Philosophy

| Principle                        | Practice                                                       |
| -------------------------------- | -------------------------------------------------------------- |
| **Determinism beats heuristics** | Fixed‑size arenas, explicit TTLs, no GC threads.               |
| **Lock‑free reads**              | Hot-path lookups are atomic loads and pointer chases.          |
| **Explainable behaviour**        | Every mutation path is \~200 LOC, fully unit‑tested.           |
| **No surprise allocations**      | All memory comes from the pre‑mapped region.                   |
| **One binary, any language**     | C ABI + pre‑generated headers; no `bindgen` needed at runtime. |

---

## Safety & Correctness

* `#[repr(C, align(64))]` on all shared structs – no padding surprises.
* Header `magic` + `version` checked on every `open`; mismatches fail early.
* Every public API returns an `ErrorCode`; the last error is thread‑local and human‑readable via `patricia_strerror`.
* Property tests and stress tests cover ABA reuse detection, TTL expiry, resize tag preservation, stale-tag reuse, and shared-memory visibility.

---

## Known Limitations

* **Cross-process support is baseline, not fully coordinated**: separate processes can open the same shared-memory arena and observe each other's inserts, but the freelist and epoch queue remain process-local to each handle.
* **`resize()` is in-process only**: it swaps the current handle to a new arena mapping, but other processes do not automatically discover or follow that replacement.
* **TTL cleanup is opportunistic**: expired prefixes are removed during later lookups or explicit maintenance, so an expired entry can remain resident until something touches that branch again.
* **Crash recovery semantics vary by platform**: Linux uses robust pthread mutexes for writer owner-death recovery; macOS does not expose equivalent robust mutex support, so a writer crash is not recovered the same way there. See [`docs/macos-robust-mutex.md`](docs/macos-robust-mutex.md).
* **Capacity is fixed per arena**: the trie does not grow automatically and there is no background compactor, so long-running deployments need explicit capacity planning.

---

## Road‑map

* **Background compaction** – optional cooperative thread collapsing long unary chains.
* **Prefix metadata blobs** – per‑node opaque `u32`/`u64` user fields.
* **Streaming bulk‑loader** – build large trees off‑line and mm‑map read‑only.
* **k‑prefix negative match** – fast *“does *no* prefix match?”* queries.

*Pull requests are very welcome!*

---

## License

Licensed under MIT – see [`LICENSE`](LICENSE) for details.

> *Made with 🌍 in Tunis by **@TheRealMkadmi***
