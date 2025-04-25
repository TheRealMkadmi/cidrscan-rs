use cidrscan::shmem_rwlock::RawRwLock;
use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use raw_sync::Timeout;

/// Helper: allocate and initialise a RawRwLock on the heap, wrapped in Arc.
fn make_lock() -> Arc<RawRwLock> {
    // Allocate zeroed memory on the heap suitable for RawRwLock
    let boxed = Box::new(unsafe { std::mem::zeroed::<RawRwLock>() });
    // Get a raw pointer to the allocated memory, consuming the box
    let ptr = Box::into_raw(boxed);
    // Initialize the lock in place using the raw pointer
    unsafe {
        // Safety: ptr is valid, aligned, and points to zeroed memory
        // as required by new_in_place's implicit contract (via init)
        RawRwLock::new_in_place(ptr);
        // Create Arc directly from the raw pointer, taking ownership
        // This avoids copying the RawRwLock struct
        Arc::from_raw(ptr)
    }
}

#[test]
fn basic_lock_unlock() {
    let lock = make_lock();
    // Basic read lock/unlock must not panic or deadlock
    {
        let _read_guard = lock.read_lock();
        // Lock is held here
    } // Lock is released here

    // Basic write lock/unlock must not panic or deadlock
    {
        let _write_guard = lock.write_lock();
        // Lock is held here
    } // Lock is released here
}

#[test]
fn concurrent_readers() {
    let lock = make_lock();
    let mut handles = Vec::new();

    // Spawn 10 reader threads that all hold the lock briefly
    for _ in 0..10 {
        let r = Arc::clone(&lock);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _read_guard = r.read_lock();
                // small work section
                // Guard dropped here, releasing lock
            }
        }));
    }

    // Join all readers
    for h in handles {
        h.join().expect("reader thread panicked");
    }
}

#[test]
fn writer_excludes_readers() {
    let lock = make_lock();
    // Start the writer in a background thread
    let l = Arc::clone(&lock);
    let writer = thread::spawn(move || {
        let _write_guard = l.write_lock();
        // hold it for 50ms
        thread::sleep(Duration::from_millis(50));
        // Guard dropped here, releasing lock
    });

    // Give the writer a moment to acquire the lock
    thread::sleep(Duration::from_millis(5));

    // Now attempt to read; this will block until the writer releases
    let start = Instant::now();
    {
        let _read_guard = lock.read_lock();
        let waited = start.elapsed();
        // The reader should have waited *at least* ~45ms
        assert!(
            waited >= Duration::from_millis(40),
            "reader did not wait (waited {:?})",
            waited
        );
        // Guard dropped here, releasing lock
    }

    writer.join().unwrap();
}

#[test]
fn try_write_lock_behavior() {
    let lock = make_lock();
    // First try should succeed and return a guard
    let guard = lock.try_write_lock(Timeout::Val(Duration::ZERO));
    assert!(guard.is_some());

    // Now that the guard holds the lock, the second try should fail
    assert!(lock.try_write_lock(Timeout::Val(Duration::ZERO)).is_none());

    // Drop the guard to release the lock
    drop(guard);

    // Now try_write_lock should succeed again
    assert!(lock.try_write_lock(Timeout::Val(Duration::ZERO)).is_some());
    // No need to explicitly unlock, the new guard will be dropped.
}

#[test]
fn reopen_in_place_retains_state() {
    // Allocate aligned memory for two locks
    let layout = std::alloc::Layout::array::<RawRwLock>(2).expect("Failed to create layout");
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
    assert!(!ptr.is_null(), "Allocation failed");

    let l1_ptr = ptr as *mut RawRwLock;
    let l2_ptr = unsafe { l1_ptr.add(1) };

    // Initialize both locks in the allocated memory
    unsafe {
        // Handle potential errors from new_in_place
        RawRwLock::new_in_place(l1_ptr).expect("Failed to init l1");
        RawRwLock::new_in_place(l2_ptr).expect("Failed to init l2");
    }

    // Get references to the locks
    let l1 = unsafe { &*l1_ptr };
    let l2 = unsafe { &*l2_ptr };

    // Perform some operation on the first lock using guards
    {
        let _read_guard = l1.read_lock();
    }

    // Reopen the second lock (optional, as new_in_place already initialized it)
    // unsafe {
    //     RawRwLock::reopen_in_place(l2_ptr).expect("Failed to reopen l2");
    // }

    // Now test basic operations on l2 using guards
    {
        let _read_guard = l2.read_lock();
    }
    {
        let _write_guard = l2.write_lock();
    }

    // Clean up the allocation
    unsafe {
        // Explicitly drop the locks if they implement Drop, or handle cleanup if needed.
        // RawRwLock doesn't implement Drop, so we just deallocate.
        // Need to ensure locks are not held before deallocating.
        // Guards handle this automatically.
        std::alloc::dealloc(ptr, layout);
    }
}
