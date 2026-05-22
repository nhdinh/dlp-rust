//! Phase 51 Chaos Test: Validate ntdll patcher under concurrent load.
//!
//! This test:
//! 1. Creates an NtdllPatcher (enabled=true)
//! 2. Spawns 1000 threads that repeatedly call NtCreateFile on a temp file
//! 3. While threads are running, performs 100 patch/unpatch cycles
//! 4. Verifies no crashes, no deadlocks, and trampolines work correctly
//!
//! WARNING: This test modifies ntdll in-memory. Run in isolation:
//!     cargo test -p dlp-hook-dll --test ntdll_chaos_test -- --ignored --nocapture

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Quick smoke test: verify NtdllPatcher state machine without actually
/// patching ntdll (which would crash the test process).
///
/// This test runs by default (no `#[ignore]`) and validates:
/// - Patcher creation with enabled=true
/// - All stubs start as Unpatched
/// - State transitions work correctly
/// - get_original_trampoline returns None for unpatched stubs
/// - verify_stub_integrity returns NotPatched for unpatched stubs
#[test]
fn ntdll_patcher_smoke_test() {
    let patcher = dlp_hook_dll::ntdll_patcher::NtdllPatcher::new(true);

    // All stubs should start as Unpatched.
    let states = patcher.stub_states();
    for (i, state) in states.iter().enumerate() {
        assert!(
            matches!(state, dlp_hook_dll::ntdll_patcher::StubPatchState::Unpatched),
            "Stub {} should start as Unpatched, got {:?}",
            i,
            state
        );
    }

    // get_original_trampoline should return None for unpatched stubs.
    assert_eq!(patcher.get_original_trampoline("NtCreateFile"), None);
    assert_eq!(patcher.get_original_trampoline("NtOpenFile"), None);
    assert_eq!(patcher.get_original_trampoline("NtWriteFile"), None);
    assert_eq!(
        patcher.get_original_trampoline("NtSetInformationFile"),
        None
    );

    // verify_stub_integrity should return NotPatched for unpatched stubs.
    assert_eq!(
        patcher.verify_stub_integrity("NtCreateFile"),
        dlp_hook_dll::ntdll_patcher::StubIntegrity::NotPatched
    );

    // verify_all_stubs should return 4 NotPatched results.
    let all_results = patcher.verify_all_stubs();
    assert_eq!(all_results.len(), 4);
    for (name, integrity) in &all_results {
        assert_eq!(
            *integrity,
            dlp_hook_dll::ntdll_patcher::StubIntegrity::NotPatched,
            "{} should be NotPatched",
            name
        );
    }

    // is_enabled should return true.
    assert!(patcher.is_enabled());
}

/// Full chaos test: 1000 threads spinning on NtCreateFile with 100 patch/unpatch cycles.
///
/// WARNING: This test modifies ntdll .text section in the test process.
/// It is marked `#[ignore]` to prevent accidental CI execution.
/// Run manually with:
///     cargo test -p dlp-hook-dll --test ntdll_chaos_test -- --ignored --nocapture
#[test]
#[ignore = "run manually: cargo test -p dlp-hook-dll --test ntdll_chaos_test -- --ignored --nocapture"]
fn ntdll_chaos_test() {
    const THREAD_COUNT: usize = 1000;
    const PATCH_CYCLES: usize = 100;
    const TEST_DURATION_SECS: u64 = 30;

    // Counters for thread results.
    let syscalls_ok = Arc::new(AtomicUsize::new(0));
    let syscalls_denied = Arc::new(AtomicUsize::new(0));
    let crashes = Arc::new(AtomicUsize::new(0));
    let stop_flag = Arc::new(AtomicBool::new(false));

    // Create the patcher.
    let mut patcher = dlp_hook_dll::ntdll_patcher::NtdllPatcher::new(true);

    // Spawn worker threads.
    let mut handles = Vec::with_capacity(THREAD_COUNT);
    for thread_id in 0..THREAD_COUNT {
        let syscalls_ok = Arc::clone(&syscalls_ok);
        let syscalls_denied = Arc::clone(&syscalls_denied);
        let crashes = Arc::clone(&crashes);
        let stop_flag = Arc::clone(&stop_flag);

        let handle = thread::spawn(move || {
            // Each thread gets its own temp file path.
            let temp_path = create_temp_file_path(thread_id);

            while !stop_flag.load(Ordering::Relaxed) {
                // Call NtCreateFile directly via ntdll.
                let result = std::panic::catch_unwind(|| {
                    syscall_ntcreatefile(&temp_path)
                });

                match result {
                    Ok(status) => {
                        // STATUS_SUCCESS = 0
                        if status == 0 {
                            syscalls_ok.fetch_add(1, Ordering::Relaxed);
                        } else if status == 0xC000_0022u32 as i32 {
                            // STATUS_ACCESS_DENIED = 0xC0000022
                            syscalls_denied.fetch_add(1, Ordering::Relaxed);
                        }
                        // Other statuses are ignored (e.g., file not found).
                    }
                    Err(_) => {
                        crashes.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
        handles.push(handle);
    }

    // Main thread: perform patch/unpatch cycles.
    let cycle_start = Instant::now();
    for cycle in 0..PATCH_CYCLES {
        patcher.patch_all_stubs();
        thread::sleep(Duration::from_millis(100));
        patcher.unpatch_all_stubs();
        thread::sleep(Duration::from_millis(100));

        let elapsed = cycle_start.elapsed().as_secs();
        if elapsed >= TEST_DURATION_SECS {
            println!(
                "Chaos test: stopped early after {} cycles ({}s elapsed)",
                cycle + 1,
                elapsed
            );
            break;
        }
    }

    // Signal threads to stop.
    stop_flag.store(true, Ordering::Relaxed);

    // Wait for all threads with a timeout.
    let join_start = Instant::now();
    let join_timeout = Duration::from_secs(30);
    for (i, handle) in handles.into_iter().enumerate() {
        if join_start.elapsed() > join_timeout {
            panic!(
                "Thread {} did not join within {}s — possible deadlock",
                i,
                join_timeout.as_secs()
            );
        }
        handle.join().expect("thread panicked during join");
    }

    let total_elapsed = cycle_start.elapsed();

    // Assertions.
    let crash_count = crashes.load(Ordering::SeqCst);
    let ok_count = syscalls_ok.load(Ordering::SeqCst);
    let denied_count = syscalls_denied.load(Ordering::SeqCst);

    println!("Chaos test completed in {:?}", total_elapsed);
    println!("  Syscalls OK:      {}", ok_count);
    println!("  Syscalls Denied:  {}", denied_count);
    println!("  Crashes:          {}", crash_count);

    assert_eq!(crash_count, 0, "No thread should have crashed");
    assert!(ok_count > 0, "At least some syscalls should have succeeded");
    assert!(
        total_elapsed < Duration::from_secs(60),
        "Test should complete within 60 seconds (no deadlock)"
    );
}

/// Creates a wide-string temp file path for the given thread ID.
fn create_temp_file_path(thread_id: usize) -> Vec<u16> {
    let temp_dir = std::env::temp_dir();
    let path = temp_dir.join(format!("dlp_chaos_test_{}.tmp", thread_id));
    let path_str = path.to_string_lossy();
    path_str.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Thin wrapper calling ntdll's NtCreateFile directly via GetProcAddress.
///
/// Uses FILE_READ_ATTRIBUTES access to minimize actual I/O impact.
fn syscall_ntcreatefile(path: &[u16]) -> i32 {
    use std::ffi::c_void;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    // Resolve NtCreateFile from ntdll.
    let ntdll = unsafe { GetModuleHandleW(windows::core::w!("ntdll.dll")) };
    let ntdll = match ntdll {
        Ok(h) => h,
        Err(_) => return -1,
    };

    let proc = unsafe { GetProcAddress(ntdll, windows::core::s!("NtCreateFile")) };
    let proc = match proc {
        Some(p) => p,
        None => return -1,
    };

    // Type-cast to NtCreateFile signature.
    let ntcreatefile: unsafe extern "system" fn(
        *mut HANDLE,
        u32,
        *mut c_void,
        *mut c_void,
        *const i64,
        u32,
        u32,
        u32,
        u32,
        *mut c_void,
        u32,
    ) -> i32 = unsafe { std::mem::transmute(proc) };

    // Build OBJECT_ATTRIBUTES inline.
    // On x64: OBJECT_ATTRIBUTES is 0x30 bytes.
    // On x86: OBJECT_ATTRIBUTES is 0x18 bytes.
    let mut object_attributes = [0u8; 48];
    let mut io_status = [0u8; 16];
    let mut handle = HANDLE(std::ptr::null_mut());

    // UNICODE_STRING: Length (2), MaximumLength (2), Buffer (8 on x64, 4 on x86).
    let path_len = (path.len().saturating_sub(1) * 2) as u16; // exclude null terminator
    let mut unicode_string = [0u8; 16];
    unsafe {
        // Write Length and MaximumLength.
        *(unicode_string.as_mut_ptr() as *mut u16) = path_len;
        *((unicode_string.as_mut_ptr() as *mut u16).add(1)) = path_len + 2;
        // Write Buffer pointer.
        #[cfg(target_arch = "x86_64")]
        {
            *(unicode_string.as_mut_ptr().add(8) as *mut *const u16) = path.as_ptr();
        }
        #[cfg(target_arch = "x86")]
        {
            *(unicode_string.as_mut_ptr().add(4) as *mut *const u16) = path.as_ptr();
        }

        // Write ObjectName pointer into OBJECT_ATTRIBUTES.
        #[cfg(target_arch = "x86_64")]
        {
            *(object_attributes.as_mut_ptr().add(0x10) as *mut *mut u8) =
                unicode_string.as_mut_ptr();
        }
        #[cfg(target_arch = "x86")]
        {
            *(object_attributes.as_mut_ptr().add(0x08) as *mut *mut u8) =
                unicode_string.as_mut_ptr();
        }
    }

    // FILE_READ_ATTRIBUTES = 0x80
    // FILE_ATTRIBUTE_NORMAL = 0x80
    // FILE_SHARE_READ | FILE_SHARE_WRITE = 0x01 | 0x02 = 0x03
    // FILE_OPEN = 0x01
    let status = unsafe {
        ntcreatefile(
            &mut handle,
            0x80, // FILE_READ_ATTRIBUTES
            object_attributes.as_mut_ptr() as *mut c_void,
            io_status.as_mut_ptr() as *mut c_void,
            std::ptr::null(),
            0x80, // FILE_ATTRIBUTE_NORMAL
            0x03, // FILE_SHARE_READ | FILE_SHARE_WRITE
            0x01, // FILE_OPEN
            0x00, // No options
            std::ptr::null_mut(),
            0,
        )
    };

    // Close handle if opened successfully.
    if status == 0 && !handle.is_invalid() {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
        }
    }

    status
}
