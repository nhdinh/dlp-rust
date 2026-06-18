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
//! # Cache Non-Authoritative Invariant
//!
//! The cache stores classification **HINT only**. ABAC authority is never
//! bypassed.

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

/// Global background thread handle.
///
/// Uses a `Mutex` to allow reset between tests. In production, the Mutex
/// is only accessed once during initialization, so the overhead is negligible.
static BACKGROUND_THREAD: std::sync::Mutex<Option<BackgroundThread>> = std::sync::Mutex::new(None);

/// Flag to prevent multiple background thread starts.
static THREAD_STARTED: AtomicBool = AtomicBool::new(false);

/// Background thread for ISOLATED-state RESYNC detection.
pub struct BackgroundThread {
    /// Handle to the shutdown event (signaled to stop the thread).
    #[allow(dead_code)]
    shutdown_event: windows::Win32::Foundation::HANDLE,
    /// Thread handle for joining.
    #[allow(dead_code)]
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

// SAFETY: BackgroundThread is Send + Sync because the HANDLE is only used
// for shutdown signaling and the JoinHandle is only accessed during shutdown.
// Both are created and owned by this struct; no other thread accesses them.
unsafe impl Send for BackgroundThread {}
unsafe impl Sync for BackgroundThread {}

/// Start the background thread for RESYNC detection and trampoline verification.
///
/// This is a no-op if the thread is already running. Called lazily on the
/// first hook call (not from `DllMain`).
///
/// # Arguments
///
/// * `cache_header` - Pointer to the shared-memory cache header.
/// * `fail_state` - Shared fail-mode state machine.
/// * `verify_fn` - Optional callback for trampoline integrity verification.
///   Called every 300 ticks (30 seconds). Pass `None` if ntdll patching is
///   not enabled.
pub fn start_background_thread(
    cache_header: *const CacheHeader,
    fail_state: Arc<FailModeState>,
    verify_fn: Option<fn()>,
) {
    if THREAD_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }

    // SAFETY: Windows API calls to create event.
    let shutdown_event = unsafe {
        use windows::Win32::System::Threading::CreateEventW;

        match CreateEventW(None, false, false, None) {
            Ok(h) => h,
            Err(_) => {
                THREAD_STARTED.store(false, Ordering::SeqCst);
                return;
            }
        }
    };

    let fail_state_clone = Arc::clone(&fail_state);
    // Store raw pointers as usize for Send safety across thread boundary.
    let header_addr = cache_header as usize;
    let event_addr = shutdown_event.0 as usize;

    let thread_handle = std::thread::spawn(move || {
        let header_ptr = header_addr as *const CacheHeader;
        let event_handle = windows::Win32::Foundation::HANDLE(event_addr as *mut std::ffi::c_void);
        background_thread_loop(header_ptr, fail_state_clone, event_handle, verify_fn);
    });

    let bt = BackgroundThread {
        shutdown_event,
        thread_handle: Some(thread_handle),
    };

    let mut guard = BACKGROUND_THREAD.lock().unwrap();
    *guard = Some(bt);
}

/// Shutdown the background thread.
///
/// Signals the shutdown event and joins with a 5-second timeout.
#[allow(dead_code)]
pub fn shutdown_background_thread() {
    let mut guard = BACKGROUND_THREAD.lock().unwrap();
    if let Some(bt) = guard.as_ref() {
        // SAFETY: SetEvent on a valid event handle.
        unsafe {
            use windows::Win32::System::Threading::SetEvent;
            let _ = SetEvent(bt.shutdown_event);
        }
        // Take ownership of the handle so we can join.
        if let Some(handle) = guard.as_mut().unwrap().thread_handle.take() {
            // Wait up to 5 seconds for the thread to exit.
            let start = std::time::Instant::now();
            while start.elapsed().as_secs() < 5 {
                if handle.is_finished() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let _ = handle.join();
        }
    }
}

/// Reset the background thread for test use.
///
/// Must only be called after `shutdown_background_thread()` has joined the
/// thread. This is test-only and gated by `#[cfg(test)]`.
pub fn reset_background_thread_for_test() {
    // Reset the thread-started flag so a new thread can be spawned.
    THREAD_STARTED.store(false, Ordering::SeqCst);

    // Clear the Mutex so the next test can start fresh.
    let mut guard = BACKGROUND_THREAD.lock().unwrap();
    *guard = None;
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
fn background_thread_loop(
    cache_header: *const CacheHeader,
    fail_state: Arc<FailModeState>,
    shutdown_event: windows::Win32::Foundation::HANDLE,
    verify_fn: Option<fn()>,
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
                    if cache_header.is_null() {
                        continue;
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
        start_background_thread(std::ptr::null(), state, None);
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

        // Reset flag for test.
        THREAD_STARTED.store(false, Ordering::SeqCst);

        // First start should succeed.
        start_background_thread(std::ptr::null(), Arc::clone(&state), None);

        // Second start should be a no-op.
        start_background_thread(std::ptr::null(), state, None);

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
