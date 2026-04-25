# macOS Robust Mutex Notes

`cidrscan_core` uses a shared writer mutex inside `RawRwLock`, but the recovery semantics are not the same on every Unix platform.

## Current implementation

On Linux, [`cidrscan_core/src/platform/unix.rs`](../cidrscan_core/src/platform/unix.rs) initializes the shared mutex with `pthread_mutexattr_setrobust(..., PTHREAD_MUTEX_ROBUST)`. When a writer dies while holding that mutex, [`cidrscan_core/src/shmem_rwlock.rs`](../cidrscan_core/src/shmem_rwlock.rs) detects the `EOWNERDEAD` path and calls `pthread_mutex_consistent` before continuing.

On macOS, `PTHREAD_MUTEX_ROBUST` and `pthread_mutex_consistent` are not available. The current fallback path therefore creates the shared mutex with default pthread attributes via `RawMutex::new(..., ptr::null_mut())`, which means there is no Linux-style owner-death recovery for the shared writer lock.

## What this means operationally

- Healthy processes can still share the same arena and coordinate through the lock.
- A macOS process that crashes or is killed while holding the writer mutex does not leave behind a recoverable "owner dead" state for the next writer.
- After that kind of failure, cross-process mutation should be treated as potentially wedged until the shared-memory segment is recreated by a clean owner.

## Recommended deployment stance

- Prefer Linux for crash-tolerant cross-process writers.
- On macOS, treat cross-process write sharing as best-effort and plan to recreate the arena after abnormal writer termination.
- If macOS support is required, keep the writer lifecycle tightly supervised so crashes trigger a full segment rebuild instead of trying to recover in place.

## Follow-up options

- Replace the pthread-backed writer mutex with a lock that has explicit cross-platform owner-death handling.
- Add a heartbeat-based takeover path for dead writers on platforms without robust pthread support.
- Narrow the documented support matrix so macOS is clearly described as lacking robust writer crash recovery.
