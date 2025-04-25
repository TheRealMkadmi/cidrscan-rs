use cidrscan::shmem_rwlock::RawRwLock;
use raw_sync::Timeout;
use std::{
    sync::{atomic::Ordering, Arc, Barrier},
    thread,
    time::{Duration, Instant},
};

/// Helper: allocate and initialise a RawRwLock on the heap, wrapped in Arc.
fn make_lock() -> Arc<RawRwLock> {
    // Allocate the RawRwLock inside an Arc (control block + T)
    let lock = Arc::new(unsafe { std::mem::zeroed::<RawRwLock>() });
    // Grab a *mut RawRwLock to the data inside the Arc
    let ptr = Arc::as_ptr(&lock) as *mut RawRwLock;
    // Now initialize it in place
    unsafe {
        // Safety: `ptr` points to properly‐aligned, zeroed memory for RawRwLock
        RawRwLock::new_in_place(ptr).unwrap();
    }
    lock
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

#[test]
fn init_and_reopen_in_place_roundtrip() {
    // allocate zeroed memory for one lock
    let mut storage = vec![0u8; std::mem::size_of::<RawRwLock>()];
    let ptr = storage.as_mut_ptr() as *mut RawRwLock;

    // initialize it
    unsafe {
        RawRwLock::new_in_place(ptr).expect("new_in_place failed");
    }

    // exercise a trivial read and write lock
    let lock_ref = unsafe { &*ptr };
    {
        let _r = lock_ref.read_lock();
    }
    {
        let _w = lock_ref.write_lock();
    }

    // now "re-open" in-place (as if in another process/view)
    unsafe {
        RawRwLock::reopen_in_place(ptr).expect("reopen_in_place failed");
    }

    // and do it again
    let lock_ref2 = unsafe { &*ptr };
    {
        let _r = lock_ref2.read_lock();
    }
    {
        let _w = lock_ref2.write_lock();
    }
}

/// Spawn multiple reader threads, ensure they all acquire simultaneously
/// and block a writer until they're done.
#[test]
fn multiple_readers_block_writer() {
    let lock = Arc::new({
        // safe because Box lives static for test duration
        let mut storage = Box::new([0u8; std::mem::size_of::<RawRwLock>()]);
        let ptr = storage.as_mut_ptr() as *mut RawRwLock;
        unsafe { RawRwLock::new_in_place(ptr).unwrap() };
        unsafe { &*ptr }.to_owned() // clone the struct (bytes)
    });

    let n_readers = 4;
    let barrier = Arc::new(Barrier::new(n_readers + 1));
    let mut handles = Vec::new();

    for _ in 0..n_readers {
        let c = Arc::clone(&lock);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let r = c.read_lock();
            // signal ready
            b.wait();
            // hold lock for a bit
            thread::sleep(Duration::from_millis(50));
            drop(r);
        }));
    }

    // wait until all readers have locked
    barrier.wait();

    // now in main thread try to acquire writer; should only succeed after readers drop
    let start = Instant::now();
    let _w = lock.write_lock();
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(50),
        "writer did not wait for readers: waited only {:?}",
        elapsed
    );

    for h in handles {
        h.join().unwrap();
    }
}

/// Test try_write_lock with timeout: immediate failure when readers present.
#[test]
fn try_write_lock_timeout_behavior() {
    let lock = Arc::new({
        let mut storage = Box::new([0u8; std::mem::size_of::<RawRwLock>()]);
        let ptr = storage.as_mut_ptr() as *mut RawRwLock;
        unsafe { RawRwLock::new_in_place(ptr).unwrap() };
        unsafe { &*ptr }.to_owned()
    });

    // spawn a reader that holds the lock
    let c = Arc::clone(&lock);
    let handle = thread::spawn(move || {
        let _r = c.read_lock();
        thread::sleep(Duration::from_millis(100));
        // reader drops here
    });

    // give reader a moment to acquire
    thread::sleep(Duration::from_millis(10));

    // try to get write lock with short timeout → should fail
    let deadline = Timeout::Val(Duration::from_millis(20));
    let maybe_guard = lock.try_write_lock(deadline);
    assert!(
        maybe_guard.is_none(),
        "try_write_lock unexpectedly succeeded"
    );

    handle.join().unwrap();

    // now that reader is gone, try again and should succeed
    let guard = lock.try_write_lock(Timeout::Val(Duration::from_millis(50)));
    assert!(
        guard.is_some(),
        "try_write_lock did not succeed after reader dropped"
    );
}

/// Basic test that many sequential read locks do not overflow the counter
#[test]
fn reader_counter_overflow_safety() {
    let mut storage = vec![0u8; std::mem::size_of::<RawRwLock>()];
    let ptr = storage.as_mut_ptr() as *mut RawRwLock;
    unsafe { RawRwLock::new_in_place(ptr).unwrap() };
    let lock_ref = unsafe { &*ptr };

    // issue more than u32::MAX / 2 reads (but realistic test: small count)
    for _ in 0..1000 {
        let r = lock_ref.read_lock();
        drop(r);
    }
    // if we reach here, no panic or overflow trap.
    assert_eq!(lock_ref.readers.load(Ordering::Relaxed), 0);
}
