use cidrscan::shmem_rwlock::RawRwLock;
use raw_sync::Timeout;
use std::{
    mem::MaybeUninit,
    ptr,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

/// Helper: allocate and initialise a RawRwLock on the heap, wrapped in Arc.
fn make_lock() -> Arc<RawRwLock> {
    // Allocate on the heap
    let mut boxed = Box::new(MaybeUninit::<RawRwLock>::uninit());
    let ptr = boxed.as_mut_ptr() as *mut u8;
    // Zero it, per init contract
    unsafe {
        ptr::write_bytes(ptr, 0, std::mem::size_of::<RawRwLock>());
        RawRwLock::init(ptr, Timeout::Infinite).unwrap();
        // Transmute to initialized
        let raw_ptr = boxed.as_mut_ptr();
        let lock_ref = &mut *raw_ptr;
        // Move out of MaybeUninit, into Box<RawRwLock>
        let boxed_lock: Box<RawRwLock> = Box::from_raw(lock_ref);
        // Prevent double-free by forgetting the original box
        std::mem::forget(boxed);
        Arc::new(*boxed_lock)
    }
}

#[test]
fn basic_lock_unlock() {
    let lock = make_lock();
    // Basic read lock/unlock must not panic or deadlock
    lock.read_lock();
    lock.read_unlock();

    // Basic write lock/unlock must not panic or deadlock
    lock.write_lock();
    lock.write_unlock();
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
                r.read_lock();
                // small work section
                r.read_unlock();
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
        l.write_lock();
        // hold it for 50ms
        thread::sleep(Duration::from_millis(50));
        l.write_unlock();
    });

    // Give the writer a moment to acquire the lock
    thread::sleep(Duration::from_millis(5));

    // Now attempt to read; this will block until the writer releases
    let start = Instant::now();
    lock.read_lock();
    let waited = start.elapsed();
    lock.read_unlock();

    // The reader should have waited *at least* ~45ms
    assert!(
        waited >= Duration::from_millis(40),
        "reader did not wait (waited {:?})",
        waited
    );

    writer.join().unwrap();
}

#[test]
fn try_write_lock_behavior() {
    let lock = make_lock();
    // First try should succeed
    assert!(lock.try_write_lock(Timeout::Val(Duration::ZERO)));
    // Now it holds the mutex: second try with zero timeout fails
    assert!(!lock.try_write_lock(Timeout::Val(Duration::ZERO)));
    // Cleanup
    lock.write_unlock();
}

#[test]
fn reopen_in_place_retains_state() {
    // Allocate two adjacent locks in the same region to simulate reuse
    let mut buf = vec![0u8; 2 * std::mem::size_of::<RawRwLock>()];
    let base = buf.as_mut_ptr();
    // init first lock
    let l1_ptr = base as *mut RawRwLock;
    unsafe {
        RawRwLock::init(base, Timeout::Infinite).unwrap();
    }
    let l1 = unsafe { &*l1_ptr };
    // convert some reader-count
    l1.read_lock();
    l1.read_unlock();

    // 'reopen' into second slot
    let second_ptr = unsafe { base.add(std::mem::size_of::<RawRwLock>()) } as *mut RawRwLock;
    unsafe {
        RawRwLock::reopen_in_place(second_ptr);
    }
    let l2 = unsafe { &*second_ptr };

    // Now test basic operations on l2
    l2.read_lock();
    l2.read_unlock();
    l2.write_lock();
    l2.write_unlock();
}
