#![cfg(feature = "loom-tests")]

use loom::{
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
};

const WRITER_BIT: u32 = 0x8000_0000;
const READER_MASK: u32 = WRITER_BIT - 1;

#[derive(Default)]
struct ModelRwLock {
    writer_mutex: Mutex<()>,
    state: AtomicU32,
}

struct ModelReadGuard<'a> {
    lock: &'a ModelRwLock,
}

struct ModelWriteGuard<'a> {
    lock: &'a ModelRwLock,
    _guard: loom::sync::MutexGuard<'a, ()>,
}

impl ModelRwLock {
    fn read_lock(&self) -> ModelReadGuard<'_> {
        loop {
            let current = self.state.load(Ordering::Acquire);
            if current & WRITER_BIT != 0 {
                thread::yield_now();
                continue;
            }
            if self
                .state
                .compare_exchange_weak(
                    current,
                    current.wrapping_add(1),
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return ModelReadGuard { lock: self };
            }
        }
    }

    fn write_lock(&self) -> ModelWriteGuard<'_> {
        let guard = self.writer_mutex.lock().expect("writer mutex poisoned");
        let prev = self.state.fetch_or(WRITER_BIT, Ordering::AcqRel) & READER_MASK;
        if prev != 0 {
            while self.state.load(Ordering::Acquire) != WRITER_BIT {
                thread::yield_now();
            }
        }
        ModelWriteGuard {
            lock: self,
            _guard: guard,
        }
    }
}

impl Drop for ModelReadGuard<'_> {
    fn drop(&mut self) {
        self.lock.state.fetch_sub(1, Ordering::Release);
    }
}

impl Drop for ModelWriteGuard<'_> {
    fn drop(&mut self) {
        self.lock.state.fetch_and(READER_MASK, Ordering::Release);
    }
}

#[test]
fn writer_bit_excludes_new_readers() {
    loom::model(|| {
        let lock = Arc::new(ModelRwLock::default());
        let writer_active = Arc::new(AtomicBool::new(false));
        let reader_seen_inside_writer = Arc::new(AtomicBool::new(false));

        let writer_lock = Arc::clone(&lock);
        let writer_flag = Arc::clone(&writer_active);
        let writer_violation = Arc::clone(&reader_seen_inside_writer);
        let writer = thread::spawn(move || {
            let _guard = writer_lock.write_lock();
            writer_flag.store(true, Ordering::Release);
            thread::yield_now();
            if writer_violation.load(Ordering::Acquire) {
                panic!("reader entered while writer was active");
            }
            writer_flag.store(false, Ordering::Release);
        });

        let reader_lock = Arc::clone(&lock);
        let reader_flag = Arc::clone(&writer_active);
        let reader_violation = Arc::clone(&reader_seen_inside_writer);
        let reader = thread::spawn(move || {
            thread::yield_now();
            let _guard = reader_lock.read_lock();
            if reader_flag.load(Ordering::Acquire) {
                reader_violation.store(true, Ordering::Release);
            }
        });

        writer.join().unwrap();
        reader.join().unwrap();

        assert!(
            !reader_seen_inside_writer.load(Ordering::Acquire),
            "reader should never hold the read lock while the writer section is active"
        );
    });
}

#[test]
fn published_link_exposes_initialized_node_state() {
    loom::model(|| {
        let child_link = Arc::new(AtomicUsize::new(0));
        let prefix_len = Arc::new(AtomicUsize::new(0));
        let key_bits = Arc::new(AtomicUsize::new(0));

        let writer_link = Arc::clone(&child_link);
        let writer_plen = Arc::clone(&prefix_len);
        let writer_key = Arc::clone(&key_bits);
        let writer = thread::spawn(move || {
            writer_plen.store(32, Ordering::Relaxed);
            writer_key.store(0x0a00_0001, Ordering::Relaxed);
            writer_link.store(1, Ordering::Release);
        });

        let reader_link = Arc::clone(&child_link);
        let reader_plen = Arc::clone(&prefix_len);
        let reader_key = Arc::clone(&key_bits);
        let reader = thread::spawn(move || {
            if reader_link.load(Ordering::Acquire) != 0 {
                assert_eq!(reader_plen.load(Ordering::Acquire), 32);
                assert_eq!(reader_key.load(Ordering::Acquire), 0x0a00_0001);
            }
        });

        writer.join().unwrap();
        reader.join().unwrap();
    });
}
