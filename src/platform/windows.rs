//! Windows-specific platform code for cidrscan

#[cfg(all(target_os = "windows", feature = "enable_global_priv"))]
pub fn enable_se_create_global_privilege() {
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Threading::*;

    unsafe {
        let mut token = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) != 0 {
            let luid = {
                let mut l = LUID {
                    LowPart: 0,
                    HighPart: 0,
                };
                LookupPrivilegeValueA(
                    std::ptr::null(),
                    "SeCreateGlobalPrivilege\0".as_ptr() as _,
                    &mut l,
                );
                l
            };
            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            AdjustTokenPrivileges(
                token,
                0,
                &tp as *const _ as _,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            CloseHandle(token);
        }
    }
}

// Windows-specific Drop logic for PatriciaTree
#[cfg(target_os = "windows")]
pub fn platform_drop(_os_id: &str) {
    // No-op for Windows
}