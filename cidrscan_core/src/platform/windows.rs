//! Windows-specific platform code for cidrscan

#[cfg(all(target_os = "windows", feature = "enable_global_priv"))]
fn has_global_priv() -> bool {
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Threading::*;
    unsafe {
        let mut token = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut luid = LUID { LowPart: 0, HighPart: 0 };
        if LookupPrivilegeValueA(
            std::ptr::null(),
            "SeCreateGlobalPrivilege\0".as_ptr() as _,
            &mut luid,
        ) == 0 {
            CloseHandle(token);
            return false;
        }
        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: 0 }],
        };
        let mut ret_len = 0;
        let res = GetTokenInformation(
            token,
            TokenPrivileges,
            &mut tp as *mut _ as _,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        if res == 0 {
            return false;
        }
        tp.Privileges[0].Attributes & SE_PRIVILEGE_ENABLED != 0
    }
}

#[cfg(all(target_os = "windows", feature = "enable_global_priv"))]
pub fn ensure_global_privilege() -> bool {
    if has_global_priv() {
        true
    } else {
        enable_se_create_global_privilege();
        has_global_priv()
    }
}
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
/// On Windows, explicit cleanup of shared memory or resources is not required here.
/// The shared memory crate (such as `memmap2` or similar) handles cleanup automatically
/// when all references are dropped. This function is intentionally a no-op to clarify
/// that no manual resource management is needed for PatriciaTree on Windows.
pub fn platform_drop(_os_id: &str) {
    // No-op for Windows: cleanup is handled by the shared memory crate.
}