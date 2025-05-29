use cidrscan_core::shmem_rwlock::RawRwLock;
use raw_sync::Timeout;
use std::{
    sync::{atomic::Ordering, Arc, Barrier},
    thread,
    time::{Duration, Instant},
};

/// Helper: allocate and initialise a RawRwLock on the heap, wrapped in Arc.
fn make_lock() -> Arc<RawRwLock> {
    print!("make_lock");
    Arc::new(*RawRwLock::new().expect("RawRwLock::new() failed"))
}

#[test]
fn basic_lock_unlock() {
        println!("Starting test");

    let lock = make_lock();
    {
        let _read_guard = lock.read_lock();
    }
    println!("Read lock released");
    {
        print!("Write lock: {:p}\n", lock.as_ref());
        let _write_guard = lock.write_lock();
    }
    println!("Write lock released");
}

#[test]
fn concurrent_readers() {
    let lock = make_lock();
    let mut handles = Vec::new();

    for _ in 0..10 {
        let r = Arc::clone(&lock);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _read_guard = r.read_lock();
            }
        }));
    }

    for h in handles {
        h.join().expect("reader thread panicked");
    }
}

#[test]
fn writer_excludes_readers() {
    use std::sync::mpsc;

    let lock = make_lock();
    let (ready_tx, ready_rx) = mpsc::channel();

    let l = Arc::clone(&lock);
    let writer = thread::spawn(move || {
        let _w = l.write_lock();
        ready_tx.send(()).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    ready_rx.recv().unwrap();

    let start = Instant::now();
    {
        let _r = lock.read_lock();
    }
    assert!(start.elapsed() >= Duration::from_millis(45));
    writer.join().unwrap();
}

#[test]
fn try_write_lock_behavior() {
    let lock = make_lock();
    let guard = lock.try_write_lock(Timeout::Val(Duration::ZERO));
    assert!(guard.is_some());

    assert!(lock.try_write_lock(Timeout::Val(Duration::ZERO)).is_none());

    drop(guard);

    assert!(lock.try_write_lock(Timeout::Val(Duration::ZERO)).is_some());
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

    {
        let _read_guard = l1.read_lock();
    }

    {
        let _read_guard = l2.read_lock();
    }
    {
        let _write_guard = l2.write_lock();
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
    {
        let _r = lock_ref.read_lock();
    }
    {
        let _w = lock_ref.write_lock();
    }

    unsafe {
        RawRwLock::reopen_in_place(ptr).expect("reopen_in_place failed");
    }

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
    let lock = make_lock();

    let n_readers = 4;
    let barrier = Arc::new(Barrier::new(n_readers + 1));
    let mut handles = Vec::new();

    for _ in 0..n_readers {
        let c = Arc::clone(&lock);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let r = c.read_lock();
            b.wait();
            thread::sleep(Duration::from_millis(50));
            drop(r);
        }));
    }

    barrier.wait();

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
    use std::sync::mpsc;

    let lock = make_lock();
    let (ready_tx, ready_rx) = mpsc::channel();

    {
        let c = Arc::clone(&lock);
        thread::spawn(move || {
            let _r = c.read_lock();
            ready_tx.send(()).unwrap();
            thread::sleep(Duration::from_millis(100));
        });
    }

    ready_rx.recv().unwrap();

    assert!(lock
        .try_write_lock(Timeout::Val(Duration::from_millis(20)))
        .is_none(),
        "writer should time-out while reader present",
    );

    thread::sleep(Duration::from_millis(110));
    assert!(lock.try_write_lock(Timeout::Val(Duration::from_millis(50))).is_some());
}

/// Basic test that many sequential read locks do not overflow the counter
#[test]
fn reader_counter_overflow_safety() {
    let mut storage = vec![0u8; std::mem::size_of::<RawRwLock>()];
    let ptr = storage.as_mut_ptr() as *mut RawRwLock;
    unsafe { RawRwLock::new_in_place(ptr).unwrap() };
    let lock_ref = unsafe { &*ptr };

    for _ in 0..1000 {
        let r = lock_ref.read_lock();
        drop(r);
    }
    assert_eq!(lock_ref.readers.load(Ordering::Relaxed), 0);
}
