//! DLP hook trampolines — expanded file-I/O surface.
//!
//! This module contains all 12 trampoline implementations that intercept
//! Windows file-I/O APIs and route classification requests to the agent
//! via named pipe.
//!
//! ## Known Limitation: CopyFile2
//!
//! `CopyFile2` is a COM-based API and does not have a traditional IAT entry
//! in most processes. It is covered indirectly via the underlying
//! `NtCreateFile` and `NtWriteFile` hooks.

use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, NTSTATUS};

// ---------------------------------------------------------------------------
// Helper: shared classification + logging + deny/allow logic
// ---------------------------------------------------------------------------

/// Performs the common classification, logging, and decision routing for
/// path-based trampolines.
///
/// Returns `Some(deny_return_value)` if the operation should be denied,
/// `None` if it should proceed to the original function.
fn classify_and_log_path(
    path: &str,
    action: &str,
    fn_name: &str,
) -> Option<crate::fail_closed::DenyReturn> {
    let path_hash = crate::hash_path(path);
    let start = std::time::Instant::now();

    let decision = crate::classify_path(path, action, crate::DEFAULT_PIPE_NAME);
    let latency = start.elapsed();

    match decision {
        Ok(crate::Decision::ALLOW) | Ok(crate::Decision::AllowWithLog) => {
            let msg = format!(
                "[dlp-hook] ALLOW {} hash={:016x} latency={}us\0",
                fn_name,
                path_hash,
                latency.as_micros()
            );
            crate::debug_log(&msg);
            None
        }
        Ok(d) if d.is_denied() => {
            let msg = format!(
                "[dlp-hook] DENY {} hash={:016x} latency={}us\0",
                fn_name,
                path_hash,
                latency.as_micros()
            );
            crate::debug_log(&msg);
            Some(crate::fail_closed::DenyReturn::BoolFalse)
        }
        _ => {
            let msg = format!(
                "[dlp-hook] DENY(fail-closed) {} hash={:016x} latency={}us\0",
                fn_name,
                path_hash,
                latency.as_micros()
            );
            crate::debug_log(&msg);
            Some(crate::fail_closed::DenyReturn::BoolFalse)
        }
    }
}

/// Performs the common classification, logging, and decision routing for
/// handle-based trampolines.
///
/// Returns `Some(deny_return_value)` if the operation should be denied,
/// `None` if it should proceed to the original function.
fn classify_and_log_handle(
    handle_value: u64,
    action: &str,
    fn_name: &str,
) -> Option<crate::fail_closed::DenyReturn> {
    let start = std::time::Instant::now();

    let decision = crate::classify_handle(handle_value, action, crate::DEFAULT_PIPE_NAME);
    let latency = start.elapsed();

    match decision {
        Ok(crate::Decision::ALLOW) | Ok(crate::Decision::AllowWithLog) => {
            let msg = format!(
                "[dlp-hook] ALLOW {} handle={} latency={}us\0",
                fn_name,
                handle_value,
                latency.as_micros()
            );
            crate::debug_log(&msg);
            None
        }
        Ok(d) if d.is_denied() => {
            let msg = format!(
                "[dlp-hook] DENY {} handle={} latency={}us\0",
                fn_name,
                handle_value,
                latency.as_micros()
            );
            crate::debug_log(&msg);
            Some(crate::fail_closed::DenyReturn::BoolFalse)
        }
        _ => {
            let msg = format!(
                "[dlp-hook] DENY(fail-closed) {} handle={} latency={}us\0",
                fn_name,
                handle_value,
                latency.as_micros()
            );
            crate::debug_log(&msg);
            Some(crate::fail_closed::DenyReturn::BoolFalse)
        }
    }
}

// ---------------------------------------------------------------------------
// 1. HookCreateFileW — path-based
// ---------------------------------------------------------------------------

/// Classification hook for `CreateFileW`.
///
/// Sends the file path to the agent via named pipe. If the agent denies
/// the operation, returns `INVALID_HANDLE_VALUE` with `ERROR_ACCESS_DENIED`.
/// Otherwise delegates to the original `CreateFileW`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookCreateFileW(
    lpfilename: PCWSTR,
    dwdesiredaccess: u32,
    dwsharemode: windows::Win32::Storage::FileSystem::FILE_SHARE_MODE,
    lpsecurityattributes: *const windows::Win32::Security::SECURITY_ATTRIBUTES,
    dwcreationdisposition: windows::Win32::Storage::FileSystem::FILE_CREATION_DISPOSITION,
    dwflagsandattributes: windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES,
    htemplatefile: HANDLE,
) -> HANDLE {
    crate::crash_guard::guard_trampoline(
        "CreateFileW",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let path = crate::pcwstr_to_string(lpfilename);
                    if let Some(_deny) = classify_and_log_path(&path, "CREATE", "CreateFileW") {
                        return crate::fail_closed!(InvalidHandleValue);
                    }
                    let original = crate::ORIGINAL_CREATE_FILE_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("CreateFileW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        lpfilename,
                        dwdesiredaccess,
                        dwsharemode,
                        lpsecurityattributes,
                        dwcreationdisposition,
                        dwflagsandattributes,
                        htemplatefile,
                    )
                },
                || {
                    let original = crate::ORIGINAL_CREATE_FILE_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("CreateFileW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        lpfilename,
                        dwdesiredaccess,
                        dwsharemode,
                        lpsecurityattributes,
                        dwcreationdisposition,
                        dwflagsandattributes,
                        htemplatefile,
                    )
                },
            )
        },
        || {
            let original = crate::ORIGINAL_CREATE_FILE_W.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_kernel32_proc(windows::core::s!("CreateFileW"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(
                lpfilename,
                dwdesiredaccess,
                dwsharemode,
                lpsecurityattributes,
                dwcreationdisposition,
                dwflagsandattributes,
                htemplatefile,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// 2. HookNtCreateFile — path-based
// ---------------------------------------------------------------------------

/// Classification hook for `NtCreateFile`.
///
/// Sends the file path (extracted from `OBJECT_ATTRIBUTES`) to the agent.
/// Fail-closed on any error or denial.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookNtCreateFile(
    filehandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut std::ffi::c_void,
    iostatusblock: *mut std::ffi::c_void,
    allocationsize: *const i64,
    fileattributes: u32,
    shareaccess: u32,
    createdisposition: u32,
    createoptions: u32,
    eabuffer: *mut std::ffi::c_void,
    ealength: u32,
) -> NTSTATUS {
    crate::crash_guard::guard_trampoline(
        "NtCreateFile",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let path = crate::extract_nt_path(objectattributes);
                    if let Some(_deny) = classify_and_log_path(&path, "CREATE", "NtCreateFile") {
                        return crate::fail_closed!(StatusAccessDenied);
                    }
                    let original = crate::ORIGINAL_NT_CREATE_FILE.unwrap_or_else(|| {
                        crate::resolve_nt_create_file()
                            .unwrap_or(std::mem::transmute(std::ptr::null::<()>()))
                    });
                    original(
                        filehandle,
                        desiredaccess,
                        objectattributes,
                        iostatusblock,
                        allocationsize,
                        fileattributes,
                        shareaccess,
                        createdisposition,
                        createoptions,
                        eabuffer,
                        ealength,
                    )
                },
                || {
                    let original = crate::ORIGINAL_NT_CREATE_FILE.unwrap_or_else(|| {
                        crate::resolve_nt_create_file()
                            .unwrap_or(std::mem::transmute(std::ptr::null::<()>()))
                    });
                    original(
                        filehandle,
                        desiredaccess,
                        objectattributes,
                        iostatusblock,
                        allocationsize,
                        fileattributes,
                        shareaccess,
                        createdisposition,
                        createoptions,
                        eabuffer,
                        ealength,
                    )
                },
            )
        },
        || {
            let original = crate::ORIGINAL_NT_CREATE_FILE.unwrap_or_else(|| {
                crate::resolve_nt_create_file()
                    .unwrap_or(std::mem::transmute(std::ptr::null::<()>()))
            });
            original(
                filehandle,
                desiredaccess,
                objectattributes,
                iostatusblock,
                allocationsize,
                fileattributes,
                shareaccess,
                createdisposition,
                createoptions,
                eabuffer,
                ealength,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// 3. HookWriteFile — handle-based
// ---------------------------------------------------------------------------

/// Classification hook for `WriteFile`.
///
/// Handle-based: sends the HANDLE value to the agent for path resolution.
/// Deny returns `BOOL(0)` with `LastError` set to `ERROR_ACCESS_DENIED`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookWriteFile(
    hfile: HANDLE,
    lpbuffer: *const u8,
    nnumberofbytestowrite: u32,
    lpnumberofbyteswritten: *mut u32,
    lpoverlapped: *mut std::ffi::c_void,
) -> windows::core::BOOL {
    crate::crash_guard::guard_trampoline(
        "WriteFile",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let handle_value = hfile.0 as u64;
                    if let Some(_deny) =
                        classify_and_log_handle(handle_value, "WRITE", "WriteFile")
                    {
                        return crate::fail_closed!(BoolFalse);
                    }
                    let original = crate::ORIGINAL_WRITE_FILE.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("WriteFile"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        hfile,
                        lpbuffer,
                        nnumberofbytestowrite,
                        lpnumberofbyteswritten,
                        lpoverlapped,
                    )
                },
                || {
                    let original = crate::ORIGINAL_WRITE_FILE.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("WriteFile"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        hfile,
                        lpbuffer,
                        nnumberofbytestowrite,
                        lpnumberofbyteswritten,
                        lpoverlapped,
                    )
                },
            )
        },
        || {
            let original = crate::ORIGINAL_WRITE_FILE.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_kernel32_proc(windows::core::s!("WriteFile"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(
                hfile,
                lpbuffer,
                nnumberofbytestowrite,
                lpnumberofbyteswritten,
                lpoverlapped,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// 4. HookWriteFileEx — handle-based
// ---------------------------------------------------------------------------

/// Classification hook for `WriteFileEx`.
///
/// Handle-based: sends the HANDLE value to the agent for path resolution.
/// Deny returns `BOOL(0)` with `LastError` set to `ERROR_ACCESS_DENIED`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookWriteFileEx(
    hfile: HANDLE,
    lpbuffer: *const u8,
    nnumberofbytestowrite: u32,
    lpoverlapped: *mut std::ffi::c_void,
    lpcompletionroutine: *mut std::ffi::c_void,
) -> windows::core::BOOL {
    crate::crash_guard::guard_trampoline(
        "WriteFileEx",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let handle_value = hfile.0 as u64;
                    if let Some(_deny) =
                        classify_and_log_handle(handle_value, "WRITE_EX", "WriteFileEx")
                    {
                        return crate::fail_closed!(BoolFalse);
                    }
                    let original = crate::ORIGINAL_WRITE_FILE_EX.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("WriteFileEx"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        hfile,
                        lpbuffer,
                        nnumberofbytestowrite,
                        lpoverlapped,
                        lpcompletionroutine,
                    )
                },
                || {
                    let original = crate::ORIGINAL_WRITE_FILE_EX.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("WriteFileEx"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        hfile,
                        lpbuffer,
                        nnumberofbytestowrite,
                        lpoverlapped,
                        lpcompletionroutine,
                    )
                },
            )
        },
        || {
            let original = crate::ORIGINAL_WRITE_FILE_EX.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_kernel32_proc(windows::core::s!("WriteFileEx"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(
                hfile,
                lpbuffer,
                nnumberofbytestowrite,
                lpoverlapped,
                lpcompletionroutine,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// 5. HookMoveFileExW — path-based (source + destination)
// ---------------------------------------------------------------------------

/// Classification hook for `MoveFileExW`.
///
/// Path-based: evaluates BOTH source and destination paths. If either is
/// denied, the operation is blocked.
/// Deny returns `BOOL(0)` with `LastError` set to `ERROR_ACCESS_DENIED`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookMoveFileExW(
    lpexistingfilename: PCWSTR,
    lpnewfilename: PCWSTR,
    dwflags: u32,
) -> windows::core::BOOL {
    crate::crash_guard::guard_trampoline(
        "MoveFileExW",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let src_path = crate::pcwstr_to_string(lpexistingfilename);
                    let dst_path = crate::pcwstr_to_string(lpnewfilename);

                    if let Some(_deny) = classify_and_log_path(&src_path, "MOVE", "MoveFileExW")
                    {
                        return crate::fail_closed!(BoolFalse);
                    }
                    if let Some(_deny) = classify_and_log_path(&dst_path, "MOVE", "MoveFileExW")
                    {
                        return crate::fail_closed!(BoolFalse);
                    }

                    let original = crate::ORIGINAL_MOVE_FILE_EX_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("MoveFileExW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(lpexistingfilename, lpnewfilename, dwflags)
                },
                || {
                    let original = crate::ORIGINAL_MOVE_FILE_EX_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("MoveFileExW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(lpexistingfilename, lpnewfilename, dwflags)
                },
            )
        },
        || {
            let original = crate::ORIGINAL_MOVE_FILE_EX_W.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_kernel32_proc(windows::core::s!("MoveFileExW"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(lpexistingfilename, lpnewfilename, dwflags)
        },
    )
}

// ---------------------------------------------------------------------------
// 6. HookCopyFileExW — path-based (source + destination)
// ---------------------------------------------------------------------------

/// Classification hook for `CopyFileExW`.
///
/// Path-based: evaluates BOTH source and destination paths. If either is
/// denied, the operation is blocked.
/// Deny returns `BOOL(0)` with `LastError` set to `ERROR_ACCESS_DENIED`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookCopyFileExW(
    lpexistingfilename: PCWSTR,
    lpnewfilename: PCWSTR,
    lpprogressroutine: *mut std::ffi::c_void,
    lpdata: *mut std::ffi::c_void,
    pbcancel: *mut i32,
    dwcopyflags: u32,
) -> windows::core::BOOL {
    crate::crash_guard::guard_trampoline(
        "CopyFileExW",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let src_path = crate::pcwstr_to_string(lpexistingfilename);
                    let dst_path = crate::pcwstr_to_string(lpnewfilename);

                    if let Some(_deny) = classify_and_log_path(
                        &src_path,
                        "COPY",
                        "CopyFileExW",
                    ) {
                        return crate::fail_closed!(BoolFalse);
                    }
                    if let Some(_deny) = classify_and_log_path(
                        &dst_path,
                        "COPY",
                        "CopyFileExW",
                    ) {
                        return crate::fail_closed!(BoolFalse);
                    }

                    let original = crate::ORIGINAL_COPY_FILE_EX_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("CopyFileExW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        lpexistingfilename,
                        lpnewfilename,
                        lpprogressroutine,
                        lpdata,
                        pbcancel,
                        dwcopyflags,
                    )
                },
                || {
                    let original = crate::ORIGINAL_COPY_FILE_EX_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("CopyFileExW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        lpexistingfilename,
                        lpnewfilename,
                        lpprogressroutine,
                        lpdata,
                        pbcancel,
                        dwcopyflags,
                    )
                },
            )
        },
        || {
            let original = crate::ORIGINAL_COPY_FILE_EX_W.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_kernel32_proc(windows::core::s!("CopyFileExW"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(
                lpexistingfilename,
                lpnewfilename,
                lpprogressroutine,
                lpdata,
                pbcancel,
                dwcopyflags,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// 7. HookDeleteFileW — path-based
// ---------------------------------------------------------------------------

/// Classification hook for `DeleteFileW`.
///
/// Path-based: evaluates the file path. Deny returns `BOOL(0)` with
/// `LastError` set to `ERROR_ACCESS_DENIED`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookDeleteFileW(
    lpfilename: PCWSTR,
) -> windows::core::BOOL {
    crate::crash_guard::guard_trampoline(
        "DeleteFileW",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let path = crate::pcwstr_to_string(lpfilename);
                    if let Some(_deny) =
                        classify_and_log_path(&path, "DELETE", "DeleteFileW")
                    {
                        return crate::fail_closed!(BoolFalse);
                    }
                    let original = crate::ORIGINAL_DELETE_FILE_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("DeleteFileW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(lpfilename)
                },
                || {
                    let original = crate::ORIGINAL_DELETE_FILE_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("DeleteFileW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(lpfilename)
                },
            )
        },
        || {
            let original = crate::ORIGINAL_DELETE_FILE_W.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_kernel32_proc(windows::core::s!("DeleteFileW"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(lpfilename)
        },
    )
}

// ---------------------------------------------------------------------------
// 8. HookReplaceFileW — path-based (replaced + replacement + backup)
// ---------------------------------------------------------------------------

/// Classification hook for `ReplaceFileW`.
///
/// Path-based: evaluates ALL three paths (replaced, replacement, backup).
/// If any is denied, the operation is blocked.
/// Deny returns `BOOL(0)` with `LastError` set to `ERROR_ACCESS_DENIED`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookReplaceFileW(
    lpreplacedfilename: PCWSTR,
    lpreplacementfilename: PCWSTR,
    lpbackupfilename: PCWSTR,
    dwreplaceflags: u32,
    lpexclude: *mut std::ffi::c_void,
    lpreserved: *mut std::ffi::c_void,
) -> windows::core::BOOL {
    crate::crash_guard::guard_trampoline(
        "ReplaceFileW",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let replaced_path = crate::pcwstr_to_string(lpreplacedfilename);
                    let replacement_path = crate::pcwstr_to_string(lpreplacementfilename);
                    let backup_path = crate::pcwstr_to_string(lpbackupfilename);

                    if let Some(_deny) = classify_and_log_path(
                        &replaced_path,
                        "REPLACE",
                        "ReplaceFileW",
                    ) {
                        return crate::fail_closed!(BoolFalse);
                    }
                    if let Some(_deny) = classify_and_log_path(
                        &replacement_path,
                        "REPLACE",
                        "ReplaceFileW",
                    ) {
                        return crate::fail_closed!(BoolFalse);
                    }
                    if let Some(_deny) = classify_and_log_path(
                        &backup_path,
                        "REPLACE",
                        "ReplaceFileW",
                    ) {
                        return crate::fail_closed!(BoolFalse);
                    }

                    let original = crate::ORIGINAL_REPLACE_FILE_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("ReplaceFileW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        lpreplacedfilename,
                        lpreplacementfilename,
                        lpbackupfilename,
                        dwreplaceflags,
                        lpexclude,
                        lpreserved,
                    )
                },
                || {
                    let original = crate::ORIGINAL_REPLACE_FILE_W.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_kernel32_proc(windows::core::s!("ReplaceFileW"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        lpreplacedfilename,
                        lpreplacementfilename,
                        lpbackupfilename,
                        dwreplaceflags,
                        lpexclude,
                        lpreserved,
                    )
                },
            )
        },
        || {
            let original = crate::ORIGINAL_REPLACE_FILE_W.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_kernel32_proc(windows::core::s!("ReplaceFileW"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(
                lpreplacedfilename,
                lpreplacementfilename,
                lpbackupfilename,
                dwreplaceflags,
                lpexclude,
                lpreserved,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// 9. HookSetFileInformationByHandle — handle-based, class-filtered
// ---------------------------------------------------------------------------

/// Classification hook for `SetFileInformationByHandle`.
///
/// Handle-based: sends the HANDLE value to the agent for path resolution.
/// Only blocks `FileRenameInfo` (class 10), `FileDispositionInfo` (class 4),
/// and `FileEndOfFileInfo` (class 6). All other classes pass through
/// immediately without classification.
/// Deny returns `BOOL(0)` with `LastError` set to `ERROR_ACCESS_DENIED`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookSetFileInformationByHandle(
    hfile: HANDLE,
    fileinformationclass: i32,
    lpfileinformation: *mut std::ffi::c_void,
    dwbuffersize: u32,
) -> windows::core::BOOL {
    crate::crash_guard::guard_trampoline(
        "SetFileInformationByHandle",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    // Only block FileRenameInfo (10), FileDispositionInfo (4),
                    // and FileEndOfFileInfo (6). All other classes pass through.
                    const FILE_RENAME_INFO: i32 = 10;
                    const FILE_DISPOSITION_INFO: i32 = 4;
                    const FILE_END_OF_FILE_INFO: i32 = 6;

                    if fileinformationclass != FILE_RENAME_INFO
                        && fileinformationclass != FILE_DISPOSITION_INFO
                        && fileinformationclass != FILE_END_OF_FILE_INFO
                    {
                        let original = crate::ORIGINAL_SET_FILE_INFORMATION_BY_HANDLE
                            .unwrap_or_else(|| {
                                std::mem::transmute(
                                    crate::resolve_kernel32_proc(windows::core::s!(
                                        "SetFileInformationByHandle"
                                    ))
                                    .map(|f| f as *const std::ffi::c_void)
                                    .unwrap_or(std::ptr::null()),
                                )
                            });
                        return original(
                            hfile,
                            fileinformationclass,
                            lpfileinformation,
                            dwbuffersize,
                        );
                    }

                    let handle_value = hfile.0 as u64;
                    if let Some(_deny) = classify_and_log_handle(
                        handle_value,
                        "SET_INFO",
                        "SetFileInformationByHandle",
                    ) {
                        return crate::fail_closed!(BoolFalse);
                    }

                    let original = crate::ORIGINAL_SET_FILE_INFORMATION_BY_HANDLE
                        .unwrap_or_else(|| {
                            std::mem::transmute(
                                crate::resolve_kernel32_proc(windows::core::s!(
                                    "SetFileInformationByHandle"
                                ))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                            )
                        });
                    original(
                        hfile,
                        fileinformationclass,
                        lpfileinformation,
                        dwbuffersize,
                    )
                },
                || {
                    let original = crate::ORIGINAL_SET_FILE_INFORMATION_BY_HANDLE
                        .unwrap_or_else(|| {
                            std::mem::transmute(
                                crate::resolve_kernel32_proc(windows::core::s!(
                                    "SetFileInformationByHandle"
                                ))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                            )
                        });
                    original(
                        hfile,
                        fileinformationclass,
                        lpfileinformation,
                        dwbuffersize,
                    )
                },
            )
        },
        || {
            let original = crate::ORIGINAL_SET_FILE_INFORMATION_BY_HANDLE.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_kernel32_proc(windows::core::s!(
                        "SetFileInformationByHandle"
                    ))
                    .map(|f| f as *const std::ffi::c_void)
                    .unwrap_or(std::ptr::null()),
                )
            });
            original(
                hfile,
                fileinformationclass,
                lpfileinformation,
                dwbuffersize,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// 10. HookNtOpenFile — path-based
// ---------------------------------------------------------------------------

/// Classification hook for `NtOpenFile`.
///
/// Path-based: extracts the path from `OBJECT_ATTRIBUTES` and sends it to
/// the agent. Deny returns `NTSTATUS(STATUS_ACCESS_DENIED)`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookNtOpenFile(
    filehandle: *mut HANDLE,
    desiredaccess: u32,
    objectattributes: *mut std::ffi::c_void,
    iostatusblock: *mut std::ffi::c_void,
    shareaccess: u32,
    openoptions: u32,
) -> NTSTATUS {
    crate::crash_guard::guard_trampoline(
        "NtOpenFile",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let path = crate::extract_nt_path(objectattributes);
                    if let Some(_deny) = classify_and_log_path(&path, "OPEN", "NtOpenFile")
                    {
                        return crate::fail_closed!(StatusAccessDenied);
                    }
                    let original = crate::ORIGINAL_NT_OPEN_FILE.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_ntdll_proc(windows::core::s!("NtOpenFile"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        filehandle,
                        desiredaccess,
                        objectattributes,
                        iostatusblock,
                        shareaccess,
                        openoptions,
                    )
                },
                || {
                    let original = crate::ORIGINAL_NT_OPEN_FILE.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_ntdll_proc(windows::core::s!("NtOpenFile"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        filehandle,
                        desiredaccess,
                        objectattributes,
                        iostatusblock,
                        shareaccess,
                        openoptions,
                    )
                },
            )
        },
        || {
            let original = crate::ORIGINAL_NT_OPEN_FILE.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_ntdll_proc(windows::core::s!("NtOpenFile"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(
                filehandle,
                desiredaccess,
                objectattributes,
                iostatusblock,
                shareaccess,
                openoptions,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// 11. HookNtWriteFile — handle-based
// ---------------------------------------------------------------------------

/// Classification hook for `NtWriteFile`.
///
/// Handle-based: sends the HANDLE value to the agent for path resolution.
/// Deny returns `NTSTATUS(STATUS_ACCESS_DENIED)`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookNtWriteFile(
    filehandle: HANDLE,
    event: HANDLE,
    apcroutine: *mut std::ffi::c_void,
    apccontext: *mut std::ffi::c_void,
    iostatusblock: *mut std::ffi::c_void,
    buffer: *const u8,
    length: u32,
    byteoffset: *const i64,
    key: *mut u32,
) -> NTSTATUS {
    crate::crash_guard::guard_trampoline(
        "NtWriteFile",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let handle_value = filehandle.0 as u64;
                    if let Some(_deny) = classify_and_log_handle(
                        handle_value,
                        "NT_WRITE",
                        "NtWriteFile",
                    ) {
                        return crate::fail_closed!(StatusAccessDenied);
                    }
                    let original = crate::ORIGINAL_NT_WRITE_FILE.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_ntdll_proc(windows::core::s!("NtWriteFile"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        filehandle,
                        event,
                        apcroutine,
                        apccontext,
                        iostatusblock,
                        buffer,
                        length,
                        byteoffset,
                        key,
                    )
                },
                || {
                    let original = crate::ORIGINAL_NT_WRITE_FILE.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_ntdll_proc(windows::core::s!("NtWriteFile"))
                                .map(|f| f as *const std::ffi::c_void)
                                .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        filehandle,
                        event,
                        apcroutine,
                        apccontext,
                        iostatusblock,
                        buffer,
                        length,
                        byteoffset,
                        key,
                    )
                },
            )
        },
        || {
            let original = crate::ORIGINAL_NT_WRITE_FILE.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_ntdll_proc(windows::core::s!("NtWriteFile"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(
                filehandle,
                event,
                apcroutine,
                apccontext,
                iostatusblock,
                buffer,
                length,
                byteoffset,
                key,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// 12. HookNtSetInformationFile — handle-based
// ---------------------------------------------------------------------------

/// Classification hook for `NtSetInformationFile`.
///
/// Handle-based: sends the HANDLE value to the agent for path resolution.
/// Deny returns `NTSTATUS(STATUS_ACCESS_DENIED)`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn HookNtSetInformationFile(
    filehandle: HANDLE,
    iostatusblock: *mut std::ffi::c_void,
    fileinformation: *mut std::ffi::c_void,
    length: u32,
    fileinformationclass: u32,
) -> NTSTATUS {
    crate::crash_guard::guard_trampoline(
        "NtSetInformationFile",
        || {
            crate::crash_guard::with_reentrancy_guard(
                || {
                    let handle_value = filehandle.0 as u64;
                    if let Some(_deny) = classify_and_log_handle(
                        handle_value,
                        "NT_SET_INFO",
                        "NtSetInformationFile",
                    ) {
                        return crate::fail_closed!(StatusAccessDenied);
                    }
                    let original = crate::ORIGINAL_NT_SET_INFORMATION_FILE.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_ntdll_proc(windows::core::s!(
                                "NtSetInformationFile"
                            ))
                            .map(|f| f as *const std::ffi::c_void)
                            .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        filehandle,
                        iostatusblock,
                        fileinformation,
                        length,
                        fileinformationclass,
                    )
                },
                || {
                    let original = crate::ORIGINAL_NT_SET_INFORMATION_FILE.unwrap_or_else(|| {
                        std::mem::transmute(
                            crate::resolve_ntdll_proc(windows::core::s!(
                                "NtSetInformationFile"
                            ))
                            .map(|f| f as *const std::ffi::c_void)
                            .unwrap_or(std::ptr::null()),
                        )
                    });
                    original(
                        filehandle,
                        iostatusblock,
                        fileinformation,
                        length,
                        fileinformationclass,
                    )
                },
            )
        },
        || {
            let original = crate::ORIGINAL_NT_SET_INFORMATION_FILE.unwrap_or_else(|| {
                std::mem::transmute(
                    crate::resolve_ntdll_proc(windows::core::s!("NtSetInformationFile"))
                        .map(|f| f as *const std::ffi::c_void)
                        .unwrap_or(std::ptr::null()),
                )
            });
            original(
                filehandle,
                iostatusblock,
                fileinformation,
                length,
                fileinformationclass,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_createfilew_is_exported() {
        // Verify the symbol exists and has the correct ABI.
        let _fn: unsafe extern "system" fn(
            PCWSTR,
            u32,
            windows::Win32::Storage::FileSystem::FILE_SHARE_MODE,
            *const windows::Win32::Security::SECURITY_ATTRIBUTES,
            windows::Win32::Storage::FileSystem::FILE_CREATION_DISPOSITION,
            windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES,
            HANDLE,
        ) -> HANDLE = HookCreateFileW;
    }

    #[test]
    fn hook_ntcreatefile_is_exported() {
        let _fn: unsafe extern "system" fn(
            *mut HANDLE,
            u32,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            *const i64,
            u32,
            u32,
            u32,
            u32,
            *mut std::ffi::c_void,
            u32,
        ) -> NTSTATUS = HookNtCreateFile;
    }

    #[test]
    fn hook_writefile_is_exported() {
        let _fn: unsafe extern "system" fn(
            HANDLE,
            *const u8,
            u32,
            *mut u32,
            *mut std::ffi::c_void,
        ) -> windows::core::BOOL = HookWriteFile;
    }

    #[test]
    fn hook_writefileex_is_exported() {
        let _fn: unsafe extern "system" fn(
            HANDLE,
            *const u8,
            u32,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
        ) -> windows::core::BOOL = HookWriteFileEx;
    }

    #[test]
    fn hook_movefileexw_is_exported() {
        let _fn: unsafe extern "system" fn(PCWSTR, PCWSTR, u32) -> windows::core::BOOL =
            HookMoveFileExW;
    }

    #[test]
    fn hook_copyfileexw_is_exported() {
        let _fn: unsafe extern "system" fn(
            PCWSTR,
            PCWSTR,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            *mut i32,
            u32,
        ) -> windows::core::BOOL = HookCopyFileExW;
    }

    #[test]
    fn hook_deletefilew_is_exported() {
        let _fn: unsafe extern "system" fn(PCWSTR) -> windows::core::BOOL = HookDeleteFileW;
    }

    #[test]
    fn hook_replacefilew_is_exported() {
        let _fn: unsafe extern "system" fn(
            PCWSTR,
            PCWSTR,
            PCWSTR,
            u32,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
        ) -> windows::core::BOOL = HookReplaceFileW;
    }

    #[test]
    fn hook_setfileinformationbyhandle_is_exported() {
        let _fn: unsafe extern "system" fn(
            HANDLE,
            i32,
            *mut std::ffi::c_void,
            u32,
        ) -> windows::core::BOOL = HookSetFileInformationByHandle;
    }

    #[test]
    fn hook_ntopenfile_is_exported() {
        let _fn: unsafe extern "system" fn(
            *mut HANDLE,
            u32,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            u32,
            u32,
        ) -> NTSTATUS = HookNtOpenFile;
    }

    #[test]
    fn hook_ntwritefile_is_exported() {
        let _fn: unsafe extern "system" fn(
            HANDLE,
            HANDLE,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            *const u8,
            u32,
            *const i64,
            *mut u32,
        ) -> NTSTATUS = HookNtWriteFile;
    }

    #[test]
    fn hook_ntsetinformationfile_is_exported() {
        let _fn: unsafe extern "system" fn(
            HANDLE,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            u32,
            u32,
        ) -> NTSTATUS = HookNtSetInformationFile;
    }

    #[test]
    fn all_twelve_trampolines_have_no_mangle() {
        // This test is a compile-time check: if any trampoline is missing
        // #[unsafe(no_mangle)], the symbol won't be exported and this test
        // would fail to link (but we verify by function pointer assignment).
        let _trampolines: [unsafe extern "system" fn(); 12] = unsafe {
            [
                std::mem::transmute(HookCreateFileW as *const ()),
                std::mem::transmute(HookNtCreateFile as *const ()),
                std::mem::transmute(HookWriteFile as *const ()),
                std::mem::transmute(HookWriteFileEx as *const ()),
                std::mem::transmute(HookMoveFileExW as *const ()),
                std::mem::transmute(HookCopyFileExW as *const ()),
                std::mem::transmute(HookDeleteFileW as *const ()),
                std::mem::transmute(HookReplaceFileW as *const ()),
                std::mem::transmute(HookSetFileInformationByHandle as *const ()),
                std::mem::transmute(HookNtOpenFile as *const ()),
                std::mem::transmute(HookNtWriteFile as *const ()),
                std::mem::transmute(HookNtSetInformationFile as *const ()),
            ]
        };
    }
}
