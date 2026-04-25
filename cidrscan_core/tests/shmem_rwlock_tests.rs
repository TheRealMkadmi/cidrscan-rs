use cidrscan_core::shmem_rwlock::{LockHandles, RawRwLock};
use raw_sync::Timeout;
use log::info;
use std::{
    sync::{atomic::Ordering, Arc, Barrier},
    thread,
    time::{Duration, Instant},
};
use std::mem::MaybeUninit;

#[test]
fn basic_lock_unlock() {
    info!("Starting test");
    // Safe constructor: no in‐place, no raw memory.
    let (lock, handles) = RawRwLock::new().expect("mutex/event initialization failed");

    {
        let _read_guard = lock.read_lock(&handles);
    }
    info!("Read lock released");

    {
        info!("Write lock: {:p}", lock.as_ref());
        let _write_guard = lock.write_lock(&handles).expect("write_lock failed");
    }
    info!("Write lock released");
}

#[test]
fn basic_lock_unlock_in_place() {
    info!("Starting test");

    // Allocate uninitialized RawRwLock memory
    let mut uninit_lock = MaybeUninit::<RawRwLock>::uninit();
    let lock_ptr = uninit_lock.as_mut_ptr();

    unsafe {
        // SAFETY: 'lock_ptr' points to uninitialized memory; new_in_place zeros it
        RawRwLock::new_in_place(lock_ptr)
            .expect("new_in_place failed: ensure zeroed memory and alignment");
    }

    // SAFETY: Now 'lock_ptr' has been fully initialized by new_in_place()
    let lock: &RawRwLock = unsafe { &*lock_ptr };
    let handles = unsafe { LockHandles::from_existing(lock).expect("from_existing failed") };

    {
        let _read_guard = lock.read_lock(&handles);
    }
    info!("Read lock released");

    {
        info!("Write lock: {:p}", lock as *const _);
        let _write_guard = lock.write_lock(&handles).expect("write_lock failed");
    }
    info!("Write lock released");
}

#[test]
fn concurrent_readers() {
    let (lock, lock_handles) = RawRwLock::new_arc().expect("RawRwLock::new_arc() failed");
    let lock_handles = Arc::new(lock_handles);
    let mut join_handles = Vec::new();

    for _ in 0..10 {
        let r = Arc::clone(&lock);
        let h = Arc::clone(&lock_handles);
        join_handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _read_guard = r.read_lock(&h);
            }
        }));
    }

    for h in join_handles {
        h.join().expect("reader thread panicked");
    }
}

#[test] 
fn writer_excludes_readers() {
    use std::sync::mpsc;

    let (lock, lock_handles) = RawRwLock::new_arc().expect("RawRwLock::new_arc() failed");
    let lock_handles = Arc::new(lock_handles);
    let (ready_tx, ready_rx) = mpsc::channel();

    let l = Arc::clone(&lock);
    let h = Arc::clone(&lock_handles);
    let writer = thread::spawn(move || {
        let _w = l.write_lock(&h).expect("write_lock failed");
        ready_tx.send(()).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    ready_rx.recv().unwrap();

    let start = Instant::now();
    {
        let _r = lock.read_lock(&lock_handles);
    }
    assert!(start.elapsed() >= Duration::from_millis(45));
    writer.join().unwrap();
}

#[test] 
fn try_write_lock_behavior() {
    let (lock, handles) = RawRwLock::new_arc().expect("RawRwLock::new_arc() failed");
    let guard = lock.try_write_lock(&handles, Timeout::Val(Duration::ZERO));
    assert!(guard.is_some());

    assert!(lock.try_write_lock(&handles, Timeout::Val(Duration::ZERO)).is_none());

    drop(guard);

    assert!(lock.try_write_lock(&handles, Timeout::Val(Duration::ZERO)).is_some());
}

#[test]
fn reopen_in_place_retains_state() {
    let layout = std::alloc::Layout::array::<RawRwLock>(2).expect("Failed to create layout");
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
    assert!(!ptr.is_null(), "Allocation failed");

    let l1_ptr = ptr as *mut RawRwLock;
    let l2_ptr = unsafe { l1_ptr.add(1) };

    unsafe {
        RawRwLock::new_in_place(l1_ptr).expect("Failed to init l1");
        RawRwLock::new_in_place(l2_ptr).expect("Failed to init l2");
    }

    let l1 = unsafe { &*l1_ptr };
    let l2 = unsafe { &*l2_ptr };
    let h1 = unsafe { LockHandles::from_existing(l1).expect("Failed to open handles for l1") };
    let h2 = unsafe { LockHandles::from_existing(l2).expect("Failed to open handles for l2") };

    {
        let _read_guard = l1.read_lock(&h1);
    }

    {
        let _read_guard = l2.read_lock(&h2);
    }
    {
        let _write_guard = l2.write_lock(&h2);
    }

    unsafe {
        std::alloc::dealloc(ptr, layout);
    }
}

#[test]
fn init_and_reopen_in_place_roundtrip() {
    let mut storage = vec![0u8; std::mem::size_of::<RawRwLock>()];
    let ptr = storage.as_mut_ptr() as *mut RawRwLock;

    unsafe {
        RawRwLock::new_in_place(ptr).expect("new_in_place failed");
    }

    let lock_ref = unsafe { &*ptr };
    let handles = unsafe { LockHandles::from_existing(lock_ref).expect("from_existing failed") };
    {
        let _r = lock_ref.read_lock(&handles);
    }
    {
        let _w = lock_ref.write_lock(&handles);
    }

    let lock_ref2 = unsafe { &*ptr };
    let handles2 = unsafe { LockHandles::from_existing(lock_ref2).expect("second from_existing failed") };
    {
        let _r = lock_ref2.read_lock(&handles2);
    }
    {
        let _w = lock_ref2.write_lock(&handles2);
    }
}

/// Spawn multiple reader threads, ensure they all acquire simultaneously
/// and block a writer until they're done.
#[test]
fn multiple_readers_block_writer() { 
    let (lock, lock_handles) = RawRwLock::new_arc().expect("RawRwLock::new_arc() failed");
    let lock_handles = Arc::new(lock_handles);

    let n_readers = 4;
    let barrier = Arc::new(Barrier::new(n_readers + 1));
    let mut join_handles = Vec::new();

    for _ in 0..n_readers {
        let c = Arc::clone(&lock);
        let h = Arc::clone(&lock_handles);
        let b = Arc::clone(&barrier);
        join_handles.push(thread::spawn(move || {
            let r = c.read_lock(&h);
            b.wait();
            thread::sleep(Duration::from_millis(50));
            drop(r);
        }));
    }

    barrier.wait();

    let start = Instant::now();
    let _w = lock.write_lock(&lock_handles).expect("write_lock failed");
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(50),
        "writer did not wait for readers: waited only {:?}",
        elapsed
    );

    for h in join_handles {
        h.join().unwrap();
    }
}

/// Test try_write_lock with timeout: immediate failure when readers present.
#[test]
fn try_write_lock_timeout_behavior() { 
    use std::sync::mpsc;

    let (lock, handles) = RawRwLock::new_arc().expect("RawRwLock::new_arc() failed");
    let handles = Arc::new(handles);
    let (ready_tx, ready_rx) = mpsc::channel();

    {
        let c = Arc::clone(&lock);
        let h = Arc::clone(&handles);
        thread::spawn(move || {
            let _r = c.read_lock(&h);
            ready_tx.send(()).unwrap();
            thread::sleep(Duration::from_millis(100));
        });
    }

    ready_rx.recv().unwrap();

    assert!(lock
        .try_write_lock(&handles, Timeout::Val(Duration::from_millis(20)))
        .is_none(),
        "writer should time-out while reader present",
    );

    thread::sleep(Duration::from_millis(110));
    assert!(lock.try_write_lock(&handles, Timeout::Val(Duration::from_millis(50))).is_some());
}

/// Basic test that many sequential read locks do not overflow the counter
#[test]
fn reader_counter_overflow_safety() {
    let mut storage = vec![0u8; std::mem::size_of::<RawRwLock>()];
    let ptr = storage.as_mut_ptr() as *mut RawRwLock;
    unsafe { RawRwLock::new_in_place(ptr).unwrap() };
    let lock_ref = unsafe { &*ptr };
    let handles = unsafe { LockHandles::from_existing(lock_ref).expect("from_existing failed") };

    for _ in 0..1000 {
        let r = lock_ref.read_lock(&handles);
        drop(r);
    }
    assert_eq!(lock_ref.readers.load(Ordering::Relaxed), 0);
}
