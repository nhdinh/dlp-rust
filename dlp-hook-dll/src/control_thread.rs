//! Unified control-poll and watchdog thread for the hook DLL.
//!
//! This thread is started from a safe post-attach path (NOT from `DllMain`)
//! after the first hook call. It performs two responsibilities:
//!
//! 1. **Control poll**: Every `CONTROL_POLL_INTERVAL_MS`, the DLL sends a
//!    `PollControl` message to the agent over the named pipe. If the agent
//!    replies with `ControlResponse { command: Some(UnhookCommand) }`, the DLL
//!    acknowledges with `UnhookAck` and initiates cooperative self-unhook.
//!
//! 2. **Watchdog**: If the agent pipe fails `MAX_FAILURES` consecutive polls
//!    and the cumulative time since the first failure reaches
//!    `WATCHDOG_TIMEOUT_MS`, the DLL assumes the agent has died/exited and
//!    self-unhooks to avoid leaving stale hooks in the host process. This
//!    consecutive-failure + grace-window design avoids false-positive unhooks
//!    during short agent restarts. Evidence of the watchdog self-unload is
//!    persisted to disk for the agent to reconcile on restart.
//!
//! # Safety
//!
//! The thread must never be started from `DllMain` because it calls into the
//! pipe client, which may trigger loader-lock issues. It is started lazily from
//! `enter_hook_call` after the hook DLL is fully attached.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{CreateEventW, SetEvent, WaitForSingleObject};

use dlp_common::hook_ipc::{ControlResponse, PollControl, UnhookAck, UnhookCommand, UnhookReason};

/// Set to true by tests to capture watchdog self-unload intent without actually
/// unloading the DLL. Always false in release builds.
#[cfg(test)]
static WATCHDOG_TRIGGERED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Watchdog timeout override for tests (milliseconds).
#[cfg(test)]
static WATCHDOG_TIMEOUT_MS_TEST: std::sync::Mutex<u64> = std::sync::Mutex::new(WATCHDOG_TIMEOUT_MS);

/// Reset test-only watchdog state and timeout.
#[cfg(test)]
pub(crate) fn reset_watchdog_test_state() {
    WATCHDOG_TRIGGERED.store(false, Ordering::SeqCst);
    *WATCHDOG_TIMEOUT_MS_TEST.lock().unwrap() = WATCHDOG_TIMEOUT_MS;
    CONTROL_THREAD_STOPPING.store(false, Ordering::SeqCst);
}

/// Set the watchdog timeout used by the control loop in test builds.
#[cfg(test)]
pub(crate) fn set_watchdog_timeout_for_test(ms: u64) {
    *WATCHDOG_TIMEOUT_MS_TEST.lock().unwrap() = ms;
}

/// Returns true if the watchdog self-unload path was triggered in a test.
#[cfg(test)]
pub(crate) fn is_watchdog_triggered() -> bool {
    WATCHDOG_TRIGGERED.load(Ordering::SeqCst)
}

/// Returns the current watchdog timeout in milliseconds.
fn watchdog_timeout_ms() -> u64 {
    #[cfg(test)]
    {
        *WATCHDOG_TIMEOUT_MS_TEST
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }
    #[cfg(not(test))]
    {
        WATCHDOG_TIMEOUT_MS
    }
}

/// Interval between control polls in milliseconds.
const CONTROL_POLL_INTERVAL_MS: u32 = 1_000;

/// Watchdog timeout: if the agent does not respond for this long, self-unhook.
const WATCHDOG_TIMEOUT_MS: u64 = 30_000;

/// Maximum consecutive poll failures before the watchdog is eligible to fire.
const MAX_FAILURES: u32 = 3;

/// Maximum time to wait for the control thread to exit during shutdown.
#[allow(dead_code)]
const SHUTDOWN_WAIT_MS: u32 = 5_000;

/// Directory where watchdog self-unload evidence is persisted.
#[cfg(not(test))]
const WATCHDOG_EVIDENCE_DIR: &str = r"C:\ProgramData\DLP\WatchdogSelfUnload";

#[cfg(test)]
const WATCHDOG_EVIDENCE_DIR: &str = r"C:\ProgramData\DLP\WatchdogSelfUnload_Test";

/// Lifecycle state of the control/watchdog thread.
enum ControlThreadState {
    /// No thread is running. Safe to start a new one.
    NotStarted,
    /// Thread creation is in progress.
    Starting,
    /// Thread is running and can be signaled for shutdown.
    #[allow(dead_code)]
    Running(ControlThread),
}

/// Global control/watchdog thread state.
static CONTROL_THREAD_STATE: Mutex<ControlThreadState> = Mutex::new(ControlThreadState::NotStarted);

/// Set to true when the control thread has been asked to stop.
static CONTROL_THREAD_STOPPING: AtomicBool = AtomicBool::new(false);

/// Handle to the running control thread and its shutdown event.
struct ControlThread {
    shutdown_event: HANDLE,
    #[allow(dead_code)]
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

// SAFETY: ControlThread owns the handles and is only accessed through the
// global mutex during lifecycle transitions.
unsafe impl Send for ControlThread {}
unsafe impl Sync for ControlThread {}

impl Drop for ControlThread {
    fn drop(&mut self) {
        if !self.shutdown_event.is_invalid() {
            let _ = unsafe { CloseHandle(self.shutdown_event) };
        }
    }
}

/// Start the unified control-poll/watchdog thread.
///
/// Idempotent: if the thread is already running or starting, this is a no-op.
/// Must be called from outside `DllMain`.
pub fn start_control_thread() {
    let mut guard = match CONTROL_THREAD_STATE.lock() {
        Ok(g) => g,
        Err(e) => {
            crate::debug_log("[dlp-hook] control thread: state mutex poisoned\0");
            e.into_inner()
        }
    };

    match &*guard {
        ControlThreadState::NotStarted => {
            // Reset the stopping flag in case a previous shutdown left it set
            // (e.g., an in-process DLL reload or service restart).
            CONTROL_THREAD_STOPPING.store(false, Ordering::SeqCst);
            *guard = ControlThreadState::Starting;
        }
        ControlThreadState::Starting | ControlThreadState::Running(_) => {
            return;
        }
    }

    let shutdown_event = unsafe {
        match CreateEventW(None, false, false, None) {
            Ok(h) => h,
            Err(_) => {
                *guard = ControlThreadState::NotStarted;
                return;
            }
        }
    };

    let event_addr = shutdown_event.0 as usize;
    let thread_handle = std::thread::spawn(move || {
        let event = HANDLE(event_addr as *mut std::ffi::c_void);
        control_thread_loop(event);
    });

    let ct = ControlThread {
        shutdown_event,
        thread_handle: Some(thread_handle),
    };

    *guard = ControlThreadState::Running(ct);
}

/// Signal the control/watchdog thread to stop and wait for it to exit.
#[allow(dead_code)]
pub fn shutdown_control_thread() {
    CONTROL_THREAD_STOPPING.store(true, Ordering::SeqCst);

    let (event, handle) = {
        let mut guard = match CONTROL_THREAD_STATE.lock() {
            Ok(g) => g,
            Err(e) => {
                crate::debug_log("[dlp-hook] control thread shutdown: state mutex poisoned\0");
                e.into_inner()
            }
        };

        match &mut *guard {
            ControlThreadState::Running(ct) => {
                let event = ct.shutdown_event;
                let handle = ct.thread_handle.take();
                *guard = ControlThreadState::NotStarted;
                (event, handle)
            }
            ControlThreadState::NotStarted | ControlThreadState::Starting => {
                *guard = ControlThreadState::NotStarted;
                // No thread was running, but ensure the stopping flag is cleared
                // so a future start is not immediately suppressed.
                CONTROL_THREAD_STOPPING.store(false, Ordering::SeqCst);
                return;
            }
        }
    };

    unsafe {
        let _ = SetEvent(event);
    }

    if let Some(handle) = handle {
        let deadline = Instant::now() + Duration::from_millis(SHUTDOWN_WAIT_MS as u64);
        while Instant::now() < deadline {
            if handle.is_finished() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if handle.is_finished() {
            let _ = handle.join();
        }
    }

    // Reset the flag so a subsequent start_control_thread (e.g., after an
    // in-process service restart or DLL reload) can run the loop.
    CONTROL_THREAD_STOPPING.store(false, Ordering::SeqCst);
}

/// Main loop for the control/watchdog thread.
fn control_thread_loop(shutdown_event: HANDLE) {
    let mut last_poll_attempt = Instant::now();
    let mut consecutive_failures: u32 = 0;
    let mut first_failure_time: Option<Instant> = None;

    loop {
        // Wait until the next poll interval or the watchdog grace deadline,
        // whichever comes first. This avoids the ~1 s granularity delay when
        // the watchdog is about to fire (WR-09).
        let now = Instant::now();
        let wait_ms = {
            let next_poll =
                last_poll_attempt + Duration::from_millis(CONTROL_POLL_INTERVAL_MS as u64);
            let mut next_wake = next_poll;

            // If we have accumulated enough consecutive failures, also wake at
            // the grace deadline so the watchdog fires promptly.
            if consecutive_failures >= MAX_FAILURES {
                if let Some(first_failure) = first_failure_time {
                    let grace_deadline =
                        first_failure + Duration::from_millis(watchdog_timeout_ms());
                    if grace_deadline < next_wake {
                        next_wake = grace_deadline;
                    }
                }
            }

            if now >= next_wake {
                0
            } else {
                let remaining_ms = (next_wake - now).as_millis() as u32;
                remaining_ms.min(CONTROL_POLL_INTERVAL_MS)
            }
        };

        let wait_result = unsafe { WaitForSingleObject(shutdown_event, wait_ms) };
        if wait_result == WAIT_OBJECT_0 {
            break;
        }

        if CONTROL_THREAD_STOPPING.load(Ordering::SeqCst) {
            break;
        }

        last_poll_attempt = Instant::now();

        let pid = std::process::id();
        let creation_time = match process_creation_time() {
            Some(t) => t,
            None => {
                crate::debug_log("[dlp-hook] control thread: cannot read process creation time\0");
                continue;
            }
        };

        let poll = PollControl { pid, creation_time };

        match crate::pipe_client::poll_control(crate::DEFAULT_PIPE_NAME, &poll, 1_000) {
            Ok(ControlResponse { command: Some(cmd) }) => {
                consecutive_failures = 0;
                first_failure_time = None;
                handle_unhook_command(cmd, pid, creation_time);
            }
            Ok(ControlResponse { command: None }) => {
                consecutive_failures = 0;
                first_failure_time = None;
            }
            Err(_) => {
                consecutive_failures += 1;
                if first_failure_time.is_none() {
                    first_failure_time = Some(Instant::now());
                }

                // Only self-unload after MAX_FAILURES consecutive failures AND
                // the cumulative grace window has elapsed. This prevents a
                // single transient error or short agent restart from evicting
                // a healthy hook.
                if consecutive_failures >= MAX_FAILURES {
                    if let Some(first_failure) = first_failure_time {
                        if first_failure.elapsed().as_millis() as u64 >= watchdog_timeout_ms() {
                            crate::debug_log(
                                "[dlp-hook] watchdog: agent unresponsive, initiating self-unhook\0",
                            );
                            persist_watchdog_evidence(pid, creation_time);
                            crate::UnhookAll();
                            #[cfg(test)]
                            {
                                WATCHDOG_TRIGGERED.store(true, Ordering::SeqCst);
                                break;
                            }
                            #[cfg(not(test))]
                            unsafe {
                                if !crate::self_unload() {
                                    crate::debug_log(
                                        "[dlp-hook] watchdog: self_unload aborted -- remaining loaded but unhooked\0",
                                    );
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Process an `UnhookCommand` from the agent.
pub(crate) fn handle_unhook_command(cmd: UnhookCommand, pid: u32, creation_time: u64) {
    let reason_str = match cmd.reason {
        UnhookReason::AgentShutdown => "agent_shutdown",
        UnhookReason::WatchdogTimeout => "watchdog_timeout",
    };
    let msg = format!(
        "[dlp-hook] control thread: received UnhookCommand reason={}\0",
        reason_str
    );
    crate::debug_log(&msg);

    let unhook_ok = crate::unhook_all_internal();

    let ack = UnhookAck {
        pid,
        creation_time,
        success: unhook_ok,
        error: if unhook_ok {
            None
        } else {
            Some("UnhookAll failed".to_string())
        },
    };
    let _ = crate::pipe_client::send_unhook_ack(crate::DEFAULT_PIPE_NAME, &ack);

    // Only unload the DLL if unhook succeeded. If unhook failed, remain loaded
    // so the agent can retry or escalate instead of leaving the process with
    // partially restored IAT entries.
    if unhook_ok {
        #[cfg(test)]
        {}
        #[cfg(not(test))]
        unsafe {
            if !crate::self_unload() {
                crate::debug_log(
                    "[dlp-hook] handle_unhook_command: self_unload aborted -- remaining loaded but unhooked\0",
                );
            }
        }
    }
}

/// Persist evidence of a watchdog-triggered self-unload to disk.
///
/// The agent reconciles these files on restart to emit audit events for
/// processes that unhooked themselves because the agent was unreachable.
fn persist_watchdog_evidence(pid: u32, creation_time: u64) {
    use std::io::Write;

    let evidence = WatchdogEvidence {
        pid,
        creation_time,
        timestamp_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        reason: "watchdog_timeout".to_string(),
    };

    let json = match serde_json::to_string(&evidence) {
        Ok(j) => j,
        Err(e) => {
            let msg = format!("[dlp-hook] watchdog evidence serialization failed: {}\0", e);
            crate::debug_log(&msg);
            return;
        }
    };

    let dir = std::path::Path::new(WATCHDOG_EVIDENCE_DIR);
    if let Err(e) = std::fs::create_dir_all(dir) {
        let msg = format!("[dlp-hook] watchdog evidence dir create failed: {}\0", e);
        crate::debug_log(&msg);
        return;
    }

    let path = dir.join(format!("{}_{}.evidence.json", pid, creation_time));
    match std::fs::File::create(&path) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(json.as_bytes()) {
                let msg = format!("[dlp-hook] watchdog evidence write failed: {}\0", e);
                crate::debug_log(&msg);
            }
        }
        Err(e) => {
            let msg = format!("[dlp-hook] watchdog evidence file create failed: {}\0", e);
            crate::debug_log(&msg);
        }
    }
}

/// Evidence persisted when the watchdog triggers self-unload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WatchdogEvidence {
    pid: u32,
    creation_time: u64,
    timestamp_secs: u64,
    reason: String,
}

/// Read the current process creation time.
///
/// Returns the raw 64-bit FILETIME value (100-ns intervals since 1601-01-01)
/// so it matches the agent's registry [`ProcessKey.creation_time`]. Returns
/// `None` on failure.
fn process_creation_time() -> Option<u64> {
    unsafe {
        let mut creation: i64 = 0;
        let mut exit: i64 = 0;
        let mut kernel: i64 = 0;
        let mut user: i64 = 0;
        let result = windows::Win32::System::Threading::GetProcessTimes(
            HANDLE(-1isize as *mut std::ffi::c_void),
            &mut creation as *mut _ as *mut windows::Win32::Foundation::FILETIME,
            &mut exit as *mut _ as *mut windows::Win32::Foundation::FILETIME,
            &mut kernel as *mut _ as *mut windows::Win32::Foundation::FILETIME,
            &mut user as *mut _ as *mut windows::Win32::Foundation::FILETIME,
        );
        if result.is_err() {
            return None;
        }
        // Return the raw FILETIME so it matches the agent registry key.
        Some(creation as u64)
    }
}

/// Test-only helper that runs the control loop with a mocked poll queue until
/// the queue is exhausted, an unhook command is handled, or the watchdog fires.
///
/// Returns the number of iterations executed and whether the watchdog path
/// was triggered.
#[cfg(test)]
pub(crate) fn run_control_loop_for_test(
    poll_results: Vec<Result<ControlResponse, crate::pipe_client::PipeError>>,
    test_watchdog_timeout_ms: u64,
    max_iterations: usize,
) -> (usize, bool) {
    use windows::Win32::System::Threading::CreateEventW;

    reset_watchdog_test_state();
    set_watchdog_timeout_for_test(test_watchdog_timeout_ms);

    // Seed the mock poll queue.
    {
        let mut mock = crate::pipe_client::MOCK_POLL_CONTROL.lock().unwrap();
        mock.clear();
        mock.extend(poll_results);
    }

    let shutdown_event = unsafe {
        match CreateEventW(None, false, false, None) {
            Ok(h) => h,
            Err(_) => return (0, false),
        }
    };

    let mut last_poll_attempt = Instant::now();
    let mut consecutive_failures: u32 = 0;
    let mut first_failure_time: Option<Instant> = None;
    let mut iterations = 0usize;

    while iterations < max_iterations {
        let now = Instant::now();
        let wait_ms = {
            let next_poll =
                last_poll_attempt + Duration::from_millis(CONTROL_POLL_INTERVAL_MS as u64);
            let mut next_wake = next_poll;

            if consecutive_failures >= MAX_FAILURES {
                if let Some(first_failure) = first_failure_time {
                    let grace_deadline =
                        first_failure + Duration::from_millis(watchdog_timeout_ms());
                    if grace_deadline < next_wake {
                        next_wake = grace_deadline;
                    }
                }
            }

            if now >= next_wake {
                0
            } else {
                let remaining_ms = (next_wake - now).as_millis() as u32;
                remaining_ms.min(CONTROL_POLL_INTERVAL_MS)
            }
        };

        let wait_result = unsafe { WaitForSingleObject(shutdown_event, wait_ms) };
        if wait_result == WAIT_OBJECT_0 {
            break;
        }

        last_poll_attempt = Instant::now();

        let pid = std::process::id();
        let creation_time = match process_creation_time() {
            Some(t) => t,
            None => continue,
        };
        let poll = PollControl { pid, creation_time };

        match crate::pipe_client::poll_control(crate::DEFAULT_PIPE_NAME, &poll, 1_000) {
            Ok(ControlResponse { command: Some(cmd) }) => {
                handle_unhook_command(cmd, pid, creation_time);
                iterations += 1;
                break;
            }
            Ok(ControlResponse { command: None }) => {
                consecutive_failures = 0;
                first_failure_time = None;
            }
            Err(_) => {
                consecutive_failures += 1;
                if first_failure_time.is_none() {
                    first_failure_time = Some(Instant::now());
                }

                if consecutive_failures >= MAX_FAILURES {
                    if let Some(first_failure) = first_failure_time {
                        if first_failure.elapsed().as_millis() as u64 >= watchdog_timeout_ms() {
                            crate::debug_log(
                                "[dlp-hook] watchdog: agent unresponsive, initiating self-unhook\0",
                            );
                            persist_watchdog_evidence(pid, creation_time);
                            crate::UnhookAll();
                            WATCHDOG_TRIGGERED.store(true, Ordering::SeqCst);
                            iterations += 1;
                            break;
                        }
                    }
                }
            }
        }
        iterations += 1;
    }

    unsafe {
        let _ = CloseHandle(shutdown_event);
    }

    (iterations, is_watchdog_triggered())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_thread_start_is_idempotent() {
        let _guard = crate::tests::PHASE_58_5_TEST_LOCK.lock().unwrap();
        start_control_thread();
        start_control_thread();
        shutdown_control_thread();
    }

    #[test]
    fn shutdown_control_thread_when_not_started() {
        let _guard = crate::tests::PHASE_58_5_TEST_LOCK.lock().unwrap();
        shutdown_control_thread();
    }

    #[test]
    fn watchdog_evidence_serialization_roundtrip() {
        let evidence = WatchdogEvidence {
            pid: 1234,
            creation_time: 42,
            timestamp_secs: 99,
            reason: "watchdog_timeout".to_string(),
        };
        let json = serde_json::to_string(&evidence).expect("serialize");
        let parsed: WatchdogEvidence = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.pid, 1234);
        assert_eq!(parsed.creation_time, 42);
        assert_eq!(parsed.timestamp_secs, 99);
        assert_eq!(parsed.reason, "watchdog_timeout");
    }

    #[test]
    fn process_creation_time_returns_some() {
        assert!(process_creation_time().is_some());
    }
}
