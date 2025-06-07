use libc::{pthread_mutex_t, pthread_mutexattr_t, pthread_mutexattr_init};
#[cfg(target_os = "linux")]
use libc::{pthread_mutexattr_setrobust, PTHREAD_MUTEX_ROBUST};
use raw_sync::locks::{Mutex as RawMutex, LockInit};
use errno::errno;
use std::ptr;

/// Generate a unique shared-memory identifier from a prefix and hash.
pub fn make_os_id(prefix: &str, hash: u64) -> String {
    format!("{}{:016x}", prefix, hash)
}

/// Remove a POSIX shared-memory object by name.
pub fn platform_drop(os_id: &str) {
    use std::ffi::CString;
    unsafe {
        if let Ok(c_name) = CString::new(os_id) {
            let _ = libc::shm_unlink(c_name.as_ptr());
        }
    }
}

#[cfg(target_os = "linux")]
pub fn robust_mutex(mutex_ptr: *mut u8) -> Result<(Box<dyn raw_sync::locks::LockImpl>, *mut pthread_mutex_t), i32> {
    let mut attr: pthread_mutexattr_t = unsafe { std::mem::zeroed() };
    let mutex_addr = mutex_ptr as *mut pthread_mutex_t;
    unsafe {
        if pthread_mutexattr_init(&mut attr) != 0 {
            return Err(errno().0);
        }
        if pthread_mutexattr_setrobust(&mut attr, PTHREAD_MUTEX_ROBUST) != 0 {
            return Err(errno().0);
        }
    }
    // Use raw_sync's RawMutex::new with the robust attribute
    let (m_raw, _) = unsafe {
        RawMutex::new(mutex_ptr, &mut attr as *mut _ as _)
            .map_err(|_| errno().0)?
    };
    Ok((m_raw, mutex_addr))
}

#[cfg(not(target_os = "linux"))]
pub fn robust_mutex(mutex_ptr: *mut u8) -> Result<(Box<dyn raw_sync::locks::LockImpl>, *mut pthread_mutex_t), i32> {
    let mutex_addr = mutex_ptr as *mut pthread_mutex_t;
    unsafe {
        let (m_raw, _) = RawMutex::new(mutex_ptr, ptr::null_mut())
            .map_err(|_| errno().0)?;
        Ok((m_raw, mutex_addr))
    }
}