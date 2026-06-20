//! Background thread for ISOLATED-state RESYNC detection and trampoline
//! integrity verification.
//!
//! Polls the shared-memory cache version word every 100ms when the fail-mode
//! state machine is in ISOLATED or RESYNC states. Triggers automatic recovery
//! when a fresh cache version is detected.
//!
//! Additionally verifies ntdll trampoline integrity every 30 seconds per D-11.
//! Detects when EDR overwrites our trampolines and emits HookOverwritten alerts.
//!
//! # Design
//!
//! - Lazy initialization via `std::sync::OnceLock` on first hook call (NOT
//!   from `DllMain` to avoid loader-lock deadlock).
//! - Uses `CreateEventW` for clean shutdown signaling.
//! - Only polls when in ISOLATED or RESYNC state to minimize CPU usage.
//! - 100ms polling interval balances latency vs CPU (10 checks/second).
//! - Trampoline verification runs every 300 ticks (30 seconds) as an additional
//!   task in the same timer loop per D-11.
//!
//! # Thread State Machine
//!
//! All thread lifecycle transitions are atomic under a single `Mutex`:
//!
//! ```text
//! NotStarted --start--> Starting --spawn--> Running --shutdown--> NotStarted
//! ```
//!
//! The `Starting` state prevents the race where `shutdown_background_thread`
//! runs between the `THREAD_STARTED` swap and the `BACKGROUND_THREAD` mutex lock.
//!
//! # Cache Non-Authoritative Invariant
//!
//! The cache stores classification **HINT only**. ABAC authority is never
//! bypassed.

use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::classification_cache::CacheHeader;
use crate::fail_mode::{FailModeState, FailState};

/// Interval between trampoline integrity checks in milliseconds.
///
/// Per D-11: verify trampoline integrity every 30 seconds.
const TRAMPOLINE_VERIFY_INTERVAL_MS: u32 = 30_000;

/// Number of 100ms loop iterations between trampoline verification checks.
///
/// 30_000ms / 100ms = 300 ticks.
const TRAMPOLINE_VERIFY_TICKS: u32 = TRAMPOLINE_VERIFY_INTERVAL_MS / 100;

// ---------------------------------------------------------------------------
// Unified thread state
// ---------------------------------------------------------------------------

/// Lifecycle state of the background thread.
///
/// All transitions are atomic under `BACKGROUND_THREAD_STATE` mutex.
/// This prevents the split-brain between a separate `AtomicBool` and
/// `Mutex<Option<BackgroundThread>>` that existed in the original design.
enum BackgroundThreadState {
    /// No thread is running. Safe to start a new one.
    NotStarted,
    /// Thread creation is in progress. Prevents concurrent start attempts
    /// and protects against shutdown racing with spawn.
    Starting,
    /// Thread is running and can be signaled for shutdown.
    Running(BackgroundThread),
}

/// Global background thread state.
///
/// Uses a `Mutex` to make all lifecycle transitions atomic. In production,
/// the mutex is only accessed during init and shutdown, so the overhead is
/// negligible.
static BACKGROUND_THREAD_STATE: std::sync::Mutex<BackgroundThreadState> =
    std::sync::Mutex::new(BackgroundThreadState::NotStarted);

/// Background thread for ISOLATED-state RESYNC detection.
pub struct BackgroundThread {
    /// Handle to the shutdown event (signaled to stop the thread).
    #[allow(dead_code)]
    shutdown_event: windows::Win32::Foundation::HANDLE,
    /// Thread handle for joining.
    #[allow(dead_code)]
    thread_handle: std::thread::JoinHandle<()>,
}

// SAFETY: BackgroundThread is Send + Sync because the HANDLE is only used
// for shutdown signaling and the JoinHandle is only accessed during shutdown.
// Both are created and owned by this struct; no other thread accesses them.
unsafe impl Send for BackgroundThread {}
unsafe impl Sync for BackgroundThread {}

/// Start the background thread for RESYNC detection and trampoline verification.
///
/// This is a no-op if the thread is already running or starting. Called lazily
/// on the first hook call (not from `DllMain`).
///
/// # Arguments
///
/// * `cache_header` - Pointer to the shared-memory cache header.
/// * `fail_state` - Shared fail-mode state machine.
/// * `verify_fn` - Optional callback for trampoline integrity verification.
///   Called every 300 ticks (30 seconds). Pass `None` if ntdll patching is
///   not enabled.
/// * `mapping_valid` - Optional `Arc<AtomicBool>` that signals whether the
///   shared-memory mapping is still valid. The background thread checks this
///   before dereferencing `cache_header`. If `None`, the caller is responsible
///   for ensuring the mapping outlives the thread.
pub fn start_background_thread(
    cache_header: *const CacheHeader,
    fail_state: Arc<FailModeState>,
    verify_fn: Option<fn()>,
    mapping_valid: Option<Arc<AtomicBool>>,
) {
    let mut guard = BACKGROUND_THREAD_STATE.lock().unwrap();

    match &*guard {
        BackgroundThreadState::NotStarted => {
            // Transition to Starting so no other thread can race us.
            *guard = BackgroundThreadState::Starting;
        }
        BackgroundThreadState::Starting | BackgroundThreadState::Running(_) => {
            // Already started or starting — idempotent no-op.
            return;
        }
    }

    // SAFETY: Windows API calls to create event.
    let shutdown_event = unsafe {
        use windows::Win32::System::Threading::CreateEventW;

        match CreateEventW(None, false, false, None) {
            Ok(h) => h,
            Err(_) => {
                // Revert to NotStarted so a future call can retry.
                *guard = BackgroundThreadState::NotStarted;
                return;
            }
        }
    };

    let fail_state_clone = Arc::clone(&fail_state);
    // Store raw pointers as usize for Send safety across thread boundary.
    let header_addr = cache_header as usize;
    let event_addr = shutdown_event.0 as usize;
    let mapping_valid_clone = mapping_valid.map(|mv| Arc::clone(&mv));

    let thread_handle = std::thread::spawn(move || {
        let header_ptr = header_addr as *const CacheHeader;
        let event_handle =
            windows::Win32::Foundation::HANDLE(event_addr as *mut std::ffi::c_void);
        background_thread_loop(header_ptr, fail_state_clone, event_handle, verify_fn, mapping_valid_clone);
    });

    let bt = BackgroundThread {
        shutdown_event,
        thread_handle,
    };

    // Store the running thread under the mutex.
    *guard = BackgroundThreadState::Running(bt);
    // Lock released here after thread is fully registered.
}

/// Shutdown the background thread.
///
/// Signals the shutdown event and waits up to 5 seconds for the thread to exit
/// using `WaitForSingleObject` on the thread handle. If the timeout expires,
/// logs a warning and detaches the thread rather than blocking forever.
#[allow(dead_code)]
pub fn shutdown_background_thread() {
    let mut guard = BACKGROUND_THREAD_STATE.lock().unwrap();

    let handle = match &mut *guard {
        BackgroundThreadState::Running(bt) => {
            // SAFETY: SetEvent on a valid event handle.
            unsafe {
                use windows::Win32::System::Threading::SetEvent;
                let _ = SetEvent(bt.shutdown_event);
            }
            // Take ownership of the JoinHandle so we can join.
            Some(std::mem::replace(
                &mut bt.thread_handle,
                std::thread::spawn(|| {}), // placeholder — never used
            ))
        }
        BackgroundThreadState::NotStarted | BackgroundThreadState::Starting => {
            // Nothing to shut down.
            return;
        }
    };

    // Drop the lock before waiting so other operations can proceed.
    drop(guard);

    if let Some(handle) = handle {
        // Use WaitForSingleObject on the thread handle for precise timeout.
        let thread_handle_raw = handle.as_raw_handle() as isize;
        let wait_result = unsafe {
            use windows::Win32::System::Threading::WaitForSingleObject;
            WaitForSingleObject(
                windows::Win32::Foundation::HANDLE(thread_handle_raw as *mut std::ffi::c_void),
                5000, // 5 seconds
            )
        };

        if wait_result == windows::Win32::Foundation::WAIT_OBJECT_0 {
            // Thread exited cleanly — join to clean up resources.
            let _ = handle.join();
        } else {
            // Timeout — log warning and detach (drop without join).
            tracing::warn!(
                "background_thread shutdown timed out after 5s; detaching thread"
            );
            // Dropping the JoinHandle without calling join() detaches the thread.
            drop(handle);
        }
    }
}

/// Reset the background thread for test use.
///
/// Must only be called after `shutdown_background_thread()` has joined the
/// thread. This is test-only and gated by `#[cfg(any(test, feature = "test-helpers"))]`.
#[cfg(any(test, feature = "test-helpers"))]
pub fn reset_background_thread_for_test() {
    let mut guard = BACKGROUND_THREAD_STATE.lock().unwrap();
    *guard = BackgroundThreadState::NotStarted;
}

/// Background thread main loop.
///
/// Polls the cache version word every 100ms when in ISOLATED or RESYNC state.
/// Additionally calls the optional trampoline verification callback every 300
/// ticks (30 seconds) per D-11.
///
/// # Arguments
///
/// * `cache_header` - Pointer to the shared-memory cache header.
/// * `fail_state` - Shared fail-mode state machine.
/// * `shutdown_event` - Windows event handle for clean shutdown.
/// * `verify_fn` - Optional callback for trampoline integrity verification.
/// * `mapping_valid` - Optional `Arc<AtomicBool>` signaling mapping validity.
fn background_thread_loop(
    cache_header: *const CacheHeader,
    fail_state: Arc<FailModeState>,
    shutdown_event: windows::Win32::Foundation::HANDLE,
    verify_fn: Option<fn()>,
    mapping_valid: Option<Arc<AtomicBool>>,
) {
    // Defensive: if no cache is available, just wait for shutdown.
    if cache_header.is_null() {
        unsafe {
            use windows::Win32::Foundation::WAIT_OBJECT_0;
            use windows::Win32::System::Threading::WaitForSingleObject;
            loop {
                let wait_result = WaitForSingleObject(shutdown_event, 100);
                if wait_result == WAIT_OBJECT_0 {
                    break;
                }
            }
        }
        return;
    }

    // SAFETY: WaitForSingleObject on valid handles.
    unsafe {
        use windows::Win32::Foundation::WAIT_OBJECT_0;
        use windows::Win32::System::Threading::WaitForSingleObject;

        let mut tick_counter: u32 = 0;

        loop {
            // Wait 100ms for shutdown signal.
            let wait_result = WaitForSingleObject(shutdown_event, 100);
            if wait_result == WAIT_OBJECT_0 {
                // Shutdown signaled.
                break;
            }

            tick_counter += 1;

            // Trampoline verification: every 300 ticks (30 seconds).
            if tick_counter >= TRAMPOLINE_VERIFY_TICKS {
                tick_counter = 0;
                if let Some(f) = verify_fn {
                    f();
                }
            }

            let current_state = fail_state.current_state();

            match current_state {
                FailState::Isolated => {
                    // Check if cache has a fresher version.
                    // Verify mapping is still valid before dereferencing.
                    if cache_header.is_null() {
                        continue;
                    }
                    if let Some(ref valid) = mapping_valid {
                        if !valid.load(Ordering::Acquire) {
                            continue;
                        }
                    }

                    let version_word = (*cache_header).version_word.load(Ordering::Acquire);

                    // Odd version means writer is building — skip this cycle.
                    if version_word & 1 != 0 {
                        continue;
                    }

                    let version = version_word >> 1;
                    let last_seen = fail_state.cache_version_seen_at();

                    if version > last_seen {
                        // Fresh version detected — trigger RESYNC transition.
                        // record_pipe_success will check version > last_seen
                        // and transition ISOLATED -> RESYNC.
                        fail_state.record_pipe_success(version);
                    }
                }
                FailState::Resync => {
                    // In RESYNC: check if we can transition to Healthy.
                    // Exit conditions: successes >= 5 (hysteresis).
                    // The record_pipe_success handles this when called.
                    // We attempt a pipe ping here to accumulate successes.
                    // For now, we rely on the trampolines' pipe successes
                    // to drive the transition. The background thread just
                    // ensures we don't miss a fresh version while ISOLATED.
                }
                _ => {
                    // HEALTHY or DEGRADED: no polling needed.
                    // Thread can sleep longer to save CPU.
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn background_thread_stub_exists() {
        // Verify the module compiles and functions are callable.
        let state = Arc::new(FailModeState::new());
        start_background_thread(std::ptr::null(), state, None, None);
        shutdown_background_thread();
    }

    #[test]
    fn resync_detection_logic() {
        // Simulate the ISOLATED -> RESYNC detection logic without a real
        // shared-memory mapping.
        let state = Arc::new(FailModeState::new());

        // Enter Isolated.
        for _ in 0..10 {
            state.record_pipe_failure();
        }
        assert_eq!(state.current_state(), FailState::Isolated);

        // Simulate what the background thread would do:
        // Detect fresh version and call record_pipe_success.
        // Use the public method to set the version.
        state.record_pipe_success(1); // sets cache_version_seen_at to 1
        state.record_pipe_success(2); // version 2 > 1, triggers RESYNC

        assert_eq!(state.current_state(), FailState::Resync);
    }

    #[test]
    fn thread_start_is_idempotent() {
        let state = Arc::new(FailModeState::new());

        // Reset state for test.
        {
            let mut guard = BACKGROUND_THREAD_STATE.lock().unwrap();
            *guard = BackgroundThreadState::NotStarted;
        }

        // First start should succeed.
        start_background_thread(std::ptr::null(), Arc::clone(&state), None, None);

        // Second start should be a no-op.
        start_background_thread(std::ptr::null(), state, None, None);

        // Clean up.
        shutdown_background_thread();
    }

    #[test]
    fn trampoline_verify_interval_is_300_ticks() {
        assert_eq!(TRAMPOLINE_VERIFY_INTERVAL_MS, 30_000);
        assert_eq!(TRAMPOLINE_VERIFY_TICKS, 300);
    }

    #[test]
    fn trampoline_verify_ticks_math() {
        // Verify the constant math is correct: 30s / 100ms = 300.
        assert_eq!(TRAMPOLINE_VERIFY_TICKS, TRAMPOLINE_VERIFY_INTERVAL_MS / 100);
    }
}
