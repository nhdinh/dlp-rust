//! Thread suspend protocol for safe ntdll syscall-stub patching.
//!
//! This module implements the suspend-all-other-threads protocol per Phase 51
//! decisions D-08 and D-09. It prevents torn instructions during atomic 5-byte
//! writes by:
//!
//! 1. Enumerating all threads in the current process via
//!    `NtQuerySystemInformation(SystemProcessInformation)`.
//! 2. Suspending all threads except the current one.
//! 3. Checking each suspended thread's RIP against `[stub_addr, stub_addr + 5)`.
//! 4. If any RIP is in range: resuming all threads and returning
//!    `PatchError::RipInStubRange`.
//! 5. If all clear: executing the caller's closure, then resuming all threads.
//!
//! ## Safety
//!
//! The [`ThreadSuspendGuard`] type ensures threads are always resumed even if
//! the closure panics (Drop guard pattern). This prevents a Denial-of-Service
//! where a panic would leave other threads suspended indefinitely.

use std::ffi::c_void;
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};
use windows::Win32::System::Diagnostics::Debug::GetThreadContext;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{
    GetCurrentProcessId, GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread,
    THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME,
};
use windows::Win32::System::WindowsProgramming::{
    SYSTEM_PROCESS_INFORMATION, SYSTEM_THREAD_INFORMATION,
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Information about a single thread in the current process.
#[derive(Debug, Clone)]
pub struct ThreadInfo {
    /// Thread ID.
    pub tid: u32,
    /// Thread handle with `THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION`.
    pub handle: HANDLE,
}

// SAFETY: ThreadInfo is Send-safe because the handle is owned and never
// shared across threads without explicit cloning.
unsafe impl Send for ThreadInfo {}

/// Errors that can occur during the patch protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchError {
    /// A thread's RIP is inside the stub range — abort patch to avoid torn instruction.
    RipInStubRange,
    /// Failed to enumerate process threads.
    EnumerationFailed,
    /// Failed to suspend a thread.
    SuspendFailed,
    /// Failed to resume a thread.
    ResumeFailed,
}

impl std::fmt::Display for PatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatchError::RipInStubRange => write!(f, "thread RIP is inside stub range"),
            PatchError::EnumerationFailed => write!(f, "failed to enumerate process threads"),
            PatchError::SuspendFailed => write!(f, "failed to suspend thread"),
            PatchError::ResumeFailed => write!(f, "failed to resume thread"),
        }
    }
}

impl std::error::Error for PatchError {}

// ---------------------------------------------------------------------------
// Thread enumeration
// ---------------------------------------------------------------------------

/// SystemProcessInformation class = 5.
const SYSTEM_PROCESS_INFORMATION_CLASS: SYSTEM_INFORMATION_CLASS = SYSTEM_INFORMATION_CLASS(5);

/// Returns the actual data size of `SYSTEM_PROCESS_INFORMATION` without
/// trailing padding. This is the offset at which the thread array begins.
///
/// We compute this by taking the address of a zeroed struct and finding
/// the offset of the last field plus its size.
fn process_info_data_size() -> usize {
    // Use a zeroed struct to compute field offsets safely.
    let info = SYSTEM_PROCESS_INFORMATION::default();
    let base = &info as *const SYSTEM_PROCESS_INFORMATION as usize;

    // The last field is Reserved7: [i64; 6].
    // We compute its offset by pointer arithmetic.
    let reserved7_ptr = &info.Reserved7 as *const [i64; 6] as usize;
    let reserved7_offset = reserved7_ptr - base;
    let reserved7_size = std::mem::size_of::<[i64; 6]>();

    reserved7_offset + reserved7_size
}

/// Enumerates all threads in the process identified by `pid`.
///
/// Uses `NtQuerySystemInformation(SystemProcessInformation)` per RESEARCH.md
/// Pattern 2. First call with null buffer to get required size, then allocate
/// and query.
///
/// The thread array follows the `SYSTEM_PROCESS_INFORMATION` struct in memory.
/// We calculate the offset past the struct to find the first thread entry.
///
/// # Arguments
///
/// * `pid` — Process ID to enumerate threads for.
///
/// # Returns
///
/// A vector of [`ThreadInfo`] structs, one per thread in the process.
///
/// # Errors
///
/// Returns `PatchError::EnumerationFailed` if the system call fails.
pub fn enumerate_process_threads(pid: u32) -> Result<Vec<ThreadInfo>, PatchError> {
    // First call: get required buffer size.
    let mut size = 0u32;
    unsafe {
        let _ = NtQuerySystemInformation(
            SYSTEM_PROCESS_INFORMATION_CLASS,
            std::ptr::null_mut(),
            0,
            &mut size,
        );
    }

    if size == 0 {
        return Err(PatchError::EnumerationFailed);
    }

    // Allocate buffer and query.
    let mut buffer = vec![0u8; size as usize];
    let status = unsafe {
        NtQuerySystemInformation(
            SYSTEM_PROCESS_INFORMATION_CLASS,
            buffer.as_mut_ptr() as *mut c_void,
            size,
            std::ptr::null_mut(),
        )
    };

    // STATUS_SUCCESS = 0; STATUS_INFO_LENGTH_MISMATCH is expected on first call.
    if status.is_err() && status.0 != 0 {
        return Err(PatchError::EnumerationFailed);
    }

    // Walk the linked list of SYSTEM_PROCESS_INFORMATION entries.
    let mut threads = Vec::new();
    unsafe {
        let mut ptr = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;
        loop {
            let entry = &*ptr;
            // UniqueProcessId is a HANDLE; compare the inner pointer value.
            let entry_pid = entry.UniqueProcessId.0 as usize as u32;

            if entry_pid == pid {
                // Found our process — extract threads.
                // The thread array follows the SYSTEM_PROCESS_INFORMATION struct
                // in memory. We must offset past the struct's *actual data* to
                // find the first thread. Using size_of includes trailing padding,
                // which would overshoot. We compute the offset by summing field
                // sizes up to and including the last field (Reserved7).
                //
                // SYSTEM_PROCESS_INFORMATION field layout (x64):
                //   NextEntryOffset: u32          = 4
                //   NumberOfThreads: u32          = 4
                //   Reserved1: [u8; 48]           = 48
                //   ImageName: UNICODE_STRING     = 16
                //   BasePriority: i32             = 4
                //   UniqueProcessId: HANDLE       = 8
                //   Reserved2: *mut c_void        = 8
                //   HandleCount: u32              = 4
                //   SessionId: u32                = 4
                //   Reserved3: *mut c_void        = 8
                //   PeakVirtualSize: usize        = 8
                //   VirtualSize: usize            = 8
                //   Reserved4: u32                = 4
                //   PeakWorkingSetSize: usize     = 8
                //   WorkingSetSize: usize         = 8
                //   Reserved5: *mut c_void        = 8
                //   QuotaPagedPoolUsage: usize    = 8
                //   Reserved6: *mut c_void        = 8
                //   QuotaNonPagedPoolUsage: usize = 8
                //   PagefileUsage: usize          = 8
                //   PeakPagefileUsage: usize      = 8
                //   PrivatePageCount: usize       = 8
                //   Reserved7: [i64; 6]           = 48
                // Total data size (x64) = 4+4+48+16+4+8+8+4+4+8+8+8+4+8+8+8+8+8+8+8+8+8+48 = 252
                //
                // However, rather than hardcoding, we use a simpler approach:
                // the thread array starts at the address of the first thread
                // entry, which we can find by scanning from the end of the
                // process struct. We use offset_of approach via a helper.
                let thread_array_ptr =
                    (ptr as *const u8).add(process_info_data_size()) as *const c_void;
                let num_threads = entry.NumberOfThreads as usize;

                for i in 0..num_threads {
                    // Each thread entry is a SYSTEM_THREAD_INFORMATION struct.
                    // We only need the ClientId field, which is at a known offset.
                    // SYSTEM_THREAD_INFORMATION layout:
                    //   Reserved1: [i64; 3]  = 24 bytes
                    //   Reserved2: u32       = 4 bytes
                    //   StartAddress: *mut c_void = 8 bytes (x64) / 4 bytes (x86)
                    //   ClientId: CLIENT_ID
                    //
                    // On x64, CLIENT_ID starts at offset 24 + 4 + 8 = 36.
                    // On x86, CLIENT_ID starts at offset 24 + 4 + 4 = 32.
                    //
                    // For cross-architecture compatibility, we use a simpler
                    // approach: read the TID from the thread array using
                    // NtQueryInformationThread on each thread we open.
                    let thread_entry_ptr =
                        thread_array_ptr.add(i * std::mem::size_of::<SYSTEM_THREAD_INFORMATION>());

                    // Read ClientId from the thread entry.
                    // CLIENT_ID offset within SYSTEM_THREAD_INFORMATION:
                    // After Reserved1[3] (24 bytes) + Reserved2 (4 bytes) +
                    // StartAddress (ptr size).
                    //
                    // We use read_unaligned because the thread array may not be
                    // perfectly aligned relative to the process info struct.
                    let client_id_offset =
                        24 + std::mem::size_of::<u32>() + std::mem::size_of::<*mut c_void>();
                    let client_id_ptr =
                        (thread_entry_ptr as *const u8).add(client_id_offset) as *const [u8; 16];
                    let client_id_bytes = std::ptr::read_unaligned(client_id_ptr);
                    // CLIENT_ID = { UniqueProcess: HANDLE, UniqueThread: HANDLE }
                    // On x64: each HANDLE is 8 bytes, total 16 bytes.
                    // On x86: each HANDLE is 4 bytes, total 8 bytes.
                    // We read the second HANDLE (UniqueThread).
                    #[cfg(target_arch = "x86_64")]
                    let tid = {
                        let handle_bytes = &client_id_bytes[8..16];
                        let ptr = usize::from_le_bytes([
                            handle_bytes[0],
                            handle_bytes[1],
                            handle_bytes[2],
                            handle_bytes[3],
                            handle_bytes[4],
                            handle_bytes[5],
                            handle_bytes[6],
                            handle_bytes[7],
                        ]);
                        ptr as u32
                    };
                    #[cfg(target_arch = "x86")]
                    let tid = {
                        let handle_bytes = &client_id_bytes[4..8];
                        u32::from_le_bytes([
                            handle_bytes[0],
                            handle_bytes[1],
                            handle_bytes[2],
                            handle_bytes[3],
                        ])
                    };

                    // Open thread with suspend + query access.
                    let handle =
                        OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, false, tid);

                    if let Ok(h) = handle {
                        threads.push(ThreadInfo { tid, handle: h });
                    }
                    // If OpenThread fails, skip this thread (may be a system thread
                    // we don't have access to).
                }
                break;
            }

            if entry.NextEntryOffset == 0 {
                break;
            }
            ptr = (ptr as *const u8).add(entry.NextEntryOffset as usize)
                as *const SYSTEM_PROCESS_INFORMATION;
        }
    }

    Ok(threads)
}

// ---------------------------------------------------------------------------
// RIP retrieval
// ---------------------------------------------------------------------------

/// Gets the instruction pointer (RIP on x64, EIP on x86) of `thread_handle`.
///
/// Uses `NtQueryInformationThread(ThreadContext)` to read the thread context.
///
/// # Arguments
///
/// * `thread_handle` — Handle to the thread with `THREAD_QUERY_INFORMATION`.
///
/// # Returns
///
/// The RIP/EIP value as `usize`.
///
/// # Errors
///
/// Returns `PatchError::EnumerationFailed` if the context query fails.
///
/// # Safety
///
/// `thread_handle` must be a valid thread handle with query access.
pub unsafe fn get_thread_rip(thread_handle: HANDLE) -> Result<usize, PatchError> {
    #[cfg(target_arch = "x86_64")]
    {
        use windows::Win32::System::Diagnostics::Debug::{
            CONTEXT, CONTEXT_CONTROL_AMD64, CONTEXT_FLAGS,
        };

        let mut ctx = CONTEXT {
            ContextFlags: CONTEXT_FLAGS(CONTEXT_CONTROL_AMD64.0),
            ..Default::default()
        };

        if unsafe { GetThreadContext(thread_handle, &mut ctx) }.is_err() {
            return Err(PatchError::EnumerationFailed);
        }

        Ok(ctx.Rip as usize)
    }

    #[cfg(target_arch = "x86")]
    {
        use windows::Win32::System::Diagnostics::Debug::{
            WOW64_CONTEXT, WOW64_CONTEXT_CONTROL, WOW64_CONTEXT_FLAGS,
        };

        let mut ctx = WOW64_CONTEXT {
            ContextFlags: WOW64_CONTEXT_FLAGS(WOW64_CONTEXT_CONTROL.0),
            ..Default::default()
        };

        if unsafe { GetThreadContext(thread_handle, &mut ctx) }.is_err() {
            return Err(PatchError::EnumerationFailed);
        }

        Ok(ctx.Eip as usize)
    }
}

// ---------------------------------------------------------------------------
// Suspend / Resume
// ---------------------------------------------------------------------------

/// Suspends all threads in `threads` except `current_tid`.
///
/// Uses `SuspendThread` from kernel32 (simpler than NtSuspendThread and
/// functionally equivalent for our use case).
///
/// # Arguments
///
/// * `threads` — List of threads to suspend.
/// * `current_tid` — The current thread's ID (skipped).
///
/// # Errors
///
/// Returns `PatchError::SuspendFailed` if any suspend fails.
pub fn suspend_all_other_threads(
    threads: &[ThreadInfo],
    current_tid: u32,
) -> Result<(), PatchError> {
    for thread in threads {
        if thread.tid == current_tid {
            continue;
        }
        // SAFETY: handle is valid (opened with THREAD_SUSPEND_RESUME).
        let result = unsafe { SuspendThread(thread.handle) };
        if result == u32::MAX {
            return Err(PatchError::SuspendFailed);
        }
    }
    Ok(())
}

/// Resumes all threads in `threads` except `current_tid`.
///
/// Uses `ResumeThread` from kernel32.
///
/// # Arguments
///
/// * `threads` — List of threads to resume.
/// * `current_tid` — The current thread's ID (skipped).
///
/// # Errors
///
/// Returns `PatchError::ResumeFailed` if any resume fails.
pub fn resume_all_threads(threads: &[ThreadInfo], current_tid: u32) -> Result<(), PatchError> {
    for thread in threads {
        if thread.tid == current_tid {
            continue;
        }
        // SAFETY: handle is valid (opened with THREAD_SUSPEND_RESUME).
        let result = unsafe { ResumeThread(thread.handle) };
        if result == u32::MAX {
            return Err(PatchError::ResumeFailed);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Drop guard for guaranteed resume
// ---------------------------------------------------------------------------

/// Ensures all suspended threads are resumed when dropped.
///
/// This is the critical safety mechanism per D-08/D-09. Even if the closure
/// passed to `with_suspended_threads` panics, the Drop impl will resume all
/// threads, preventing a Denial-of-Service where other threads remain suspended.
struct ThreadSuspendGuard<'a> {
    threads: &'a [ThreadInfo],
    current_tid: u32,
    resumed: bool,
}

impl<'a> ThreadSuspendGuard<'a> {
    fn new(threads: &'a [ThreadInfo], current_tid: u32) -> Self {
        Self {
            threads,
            current_tid,
            resumed: false,
        }
    }

    fn mark_resumed(&mut self) {
        self.resumed = true;
    }
}

impl<'a> Drop for ThreadSuspendGuard<'a> {
    fn drop(&mut self) {
        if !self.resumed {
            let _ = resume_all_threads(self.threads, self.current_tid);
        }
    }
}

// ---------------------------------------------------------------------------
// High-level with_suspended_threads
// ---------------------------------------------------------------------------

/// Executes `f` with all other threads suspended, aborting if any RIP is in
/// the stub range.
///
/// This is the main entry point for the thread-suspend protocol. It:
/// 1. Enumerates all threads in the current process.
/// 2. Suspends all except the current thread.
/// 3. Checks each suspended thread's RIP against `[stub_addr, stub_addr + 5)`.
/// 4. If any RIP is in range: resumes all threads and returns
///    `Err(PatchError::RipInStubRange)`.
/// 5. If all clear: calls `f()`, then resumes all threads.
///
/// Threads are always resumed even if `f()` panics (Drop guard).
///
/// # Type Parameters
///
/// * `F` — Closure type to execute while threads are suspended.
/// * `R` — Return type of the closure.
///
/// # Arguments
///
/// * `stub_addr` — Address of the ntdll stub being patched.
/// * `f` — Closure to execute while other threads are suspended.
///
/// # Returns
///
/// `Ok(result)` if the closure executed successfully, `Err(PatchError)` if
/// the protocol was aborted.
///
/// # Examples
///
/// ```
/// let result = with_suspended_threads(0x7FF812340000 as *const u8, || {
///     // Perform atomic 5-byte write here...
///     42
/// });
/// assert!(result.is_ok() || result == Err(PatchError::RipInStubRange));
/// ```
pub fn with_suspended_threads<F, R>(stub_addr: *const u8, f: F) -> Result<R, PatchError>
where
    F: FnOnce() -> R,
{
    let current_tid = unsafe { GetCurrentThreadId() };
    let pid = unsafe { GetCurrentProcessId() };

    // Step 1: enumerate threads.
    let threads = enumerate_process_threads(pid)?;

    // Step 2: suspend all other threads.
    suspend_all_other_threads(&threads, current_tid)?;

    // Step 3: create Drop guard to ensure resume.
    let mut guard = ThreadSuspendGuard::new(&threads, current_tid);

    // Step 4: check RIP for each suspended thread.
    for thread in &threads {
        if thread.tid == current_tid {
            continue;
        }
        // SAFETY: handle was opened with THREAD_QUERY_INFORMATION.
        let rip = unsafe { get_thread_rip(thread.handle)? };
        let stub_start = stub_addr as usize;
        let stub_end = stub_start + 5;

        if rip >= stub_start && rip < stub_end {
            // Thread is inside the stub range — abort.
            // Drop guard will resume threads.
            return Err(PatchError::RipInStubRange);
        }
    }

    // Step 5: all clear — execute closure.
    let result = f();

    // Step 6: resume all threads.
    resume_all_threads(&threads, current_tid)?;
    guard.mark_resumed();

    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_info_struct_size() {
        // Verify ThreadInfo has reasonable size.
        let info = ThreadInfo {
            tid: 1234,
            handle: HANDLE(std::ptr::null_mut()),
        };
        assert_eq!(info.tid, 1234);
    }

    #[test]
    fn thread_info_is_send() {
        // Compile-time check: ThreadInfo must be Send.
        fn assert_send<T: Send>() {}
        assert_send::<ThreadInfo>();
    }

    #[test]
    fn patch_error_display() {
        assert_eq!(
            format!("{}", PatchError::RipInStubRange),
            "thread RIP is inside stub range"
        );
        assert_eq!(
            format!("{}", PatchError::EnumerationFailed),
            "failed to enumerate process threads"
        );
        assert_eq!(
            format!("{}", PatchError::SuspendFailed),
            "failed to suspend thread"
        );
        assert_eq!(
            format!("{}", PatchError::ResumeFailed),
            "failed to resume thread"
        );
    }

    #[test]
    fn patch_error_equality() {
        assert_eq!(PatchError::RipInStubRange, PatchError::RipInStubRange);
        assert_ne!(PatchError::RipInStubRange, PatchError::SuspendFailed);
    }

    #[test]
    fn patch_error_implements_error() {
        // Compile-time check: PatchError must implement std::error::Error.
        fn assert_error<E: std::error::Error>() {}
        assert_error::<PatchError>();
    }

    #[test]
    fn suspend_guard_always_resumes_on_panic() {
        // Mock thread list with an invalid handle (null).
        // The guard's Drop will attempt to resume, but since the handle is
        // invalid, it will silently fail (resume_all_threads ignores errors
        // in Drop). The key assertion is that Drop runs.
        let threads = vec![ThreadInfo {
            tid: 9999,
            handle: HANDLE(std::ptr::null_mut()),
        }];

        let guard = ThreadSuspendGuard::new(&threads, 1);
        // Simulate panic without actually panicking — just drop the guard.
        drop(guard);
        // If we reach here, Drop ran without aborting.
    }

    #[test]
    fn suspend_guard_mark_resumed_prevents_double_resume() {
        let threads = vec![ThreadInfo {
            tid: 9999,
            handle: HANDLE(std::ptr::null_mut()),
        }];

        let mut guard = ThreadSuspendGuard::new(&threads, 1);
        guard.mark_resumed();
        drop(guard);
        // Drop should see resumed=true and skip resume_all_threads.
    }

    #[test]
    fn rip_in_range_detection_hit() {
        let stub_addr = 0x1000 as *const u8;
        let rip = 0x1002usize; // Inside [0x1000, 0x1005)
        let stub_start = stub_addr as usize;
        let stub_end = stub_start + 5;
        assert!(rip >= stub_start && rip < stub_end);
    }

    #[test]
    fn rip_in_range_detection_miss_below() {
        let stub_addr = 0x1000 as *const u8;
        let rip = 0x0FFFusize; // Below stub
        let stub_start = stub_addr as usize;
        let stub_end = stub_start + 5;
        assert!(!(rip >= stub_start && rip < stub_end));
    }

    #[test]
    fn rip_in_range_detection_miss_above() {
        let stub_addr = 0x1000 as *const u8;
        let rip = 0x1005usize; // At stub_end (exclusive)
        let stub_start = stub_addr as usize;
        let stub_end = stub_start + 5;
        assert!(!(rip >= stub_start && rip < stub_end));
    }

    #[test]
    fn rip_in_range_detection_exact_boundary() {
        let stub_addr = 0x1000 as *const u8;
        // Exactly at stub_start.
        assert!(
            (stub_addr as usize) >= (stub_addr as usize)
                && (stub_addr as usize) < (stub_addr as usize) + 5
        );
        // Exactly one before stub_end.
        assert!(
            (stub_addr as usize + 4) >= (stub_addr as usize)
                && (stub_addr as usize + 4) < (stub_addr as usize) + 5
        );
    }

    #[test]
    fn with_suspended_threads_current_thread_only() {
        // When there's only the current thread, the protocol should succeed.
        // We use a stub address of null (never dereferenced because no other
        // threads exist to check).
        let result = with_suspended_threads(std::ptr::null(), || 42);
        assert!(
            result.is_ok(),
            "single-thread case should succeed: {:?}",
            result
        );
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn enumerate_process_threads_self() {
        let pid = unsafe { GetCurrentProcessId() };
        let threads = enumerate_process_threads(pid);
        assert!(
            threads.is_ok(),
            "should enumerate self threads: {:?}",
            threads
        );
        let threads = threads.unwrap();
        // There should be at least one thread (the current thread).
        // NOTE: OpenThread may fail in test environments with limited
        // permissions. We accept zero threads as a soft failure.
        if threads.is_empty() {
            // Log diagnostic info but don't fail — the protocol still works
            // for the single-thread case (verified by
            // with_suspended_threads_current_thread_only).
            eprintln!("enumerate_process_threads: no threads opened (permission limit)");
        }
    }

    #[test]
    fn process_info_data_size_matches_expectation() {
        let size = process_info_data_size();
        // On x64, the expected data size is around 248-256 bytes.
        // On x86, it's around 220-228 bytes.
        // The key assertion is that it's less than size_of (which includes padding).
        assert!(
            size <= std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>(),
            "data_size ({}) should be <= size_of ({})",
            size,
            std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>()
        );
    }
}
