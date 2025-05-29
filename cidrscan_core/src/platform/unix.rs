// Platform-specific OS identifier for shared memory regions
#[cfg(unix)]
pub fn make_os_id(prefix: &str, hash: u64) -> String {
    format!("{}{:016x}", prefix, hash)
}

#[cfg(unix)]
pub fn platform_drop(os_id: &str) {
    use std::ffi::CString;
    unsafe {
        if let Ok(c_name) = CString::new(os_id) {
            let _ = libc::shm_unlink(c_name.as_ptr());
        }
    }
}
#[cfg(unix)]
pub fn robust_mutex(mutex_ptr: *mut u8) -> Result<(raw_sync::locks::Mutex, *mut libc::pthread_mutex_t), i32> {
    use libc::{pthread_mutex_t, pthread_mutexattr_t, pthread_mutexattr_init, pthread_mutexattr_setrobust, PTHREAD_MUTEX_ROBUST};
    use std::ptr;
    use raw_sync::locks::RawMutex;

    let mut attr: pthread_mutexattr_t = unsafe { std::mem::zeroed() };
    let mut mutex_addr = mutex_ptr as *mut pthread_mutex_t;
    unsafe {
        if pthread_mutexattr_init(&mut attr) != 0 {
            return Err(libc::errno());
        }
        if pthread_mutexattr_setrobust(&mut attr, PTHREAD_MUTEX_ROBUST) != 0 {
            return Err(libc::errno());
        }
    }
    // Use raw_sync's RawMutex::new with the robust attribute
    let (mutex, _) = unsafe {
        RawMutex::new(mutex_ptr, &mut attr as *mut _ as _)
            .map_err(|_| libc::errno())?
    };
    Ok((mutex, mutex_addr))
}