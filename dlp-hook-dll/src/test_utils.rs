//! Test-only helpers for `dlp-hook-dll`.
//!
//! Available in unit tests (`cfg(test)`) and integration tests that enable the
//! `test-helpers` feature.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Monotonic counter for unique pipe names within a process.
static PIPE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique named-pipe path for the current test.
///
/// The returned name includes the process ID and a per-process counter so that
/// multiple tests in the same process, or the same test run repeatedly, never
/// collide.
pub fn unique_pipe_name(prefix: &str) -> String {
    format!(
        r"\\.\pipe\DlpHookPipeTest_{prefix}_{}_{}",
        std::process::id(),
        PIPE_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Install `name` as the pipe used by [`crate::current_pipe_name`].
///
/// The name is leaked into a `&'static str` so that `current_pipe_name()` can
/// return a `'static` reference without keeping a lock. Leaking one string per
/// test is acceptable for test code.
pub fn set_test_pipe_name(name: &str) {
    let leaked: &'static str = Box::leak(name.to_string().into_boxed_str());
    let mut guard = crate::TEST_PIPE_OVERRIDE
        .lock()
        .expect("TEST_PIPE_OVERRIDE lock");
    *guard = Some(leaked);
}

/// Reset all process-global state used by tests.
///
/// Call this at the start of every test that touches global Windows state
/// (mock agent servers, shared-memory mappings, control/background threads,
/// fail-mode state, diagnostic ring, LRU cache, pipe mocks).
pub fn reset_for_test() {
    crate::set_shutting_down_for_test(false);
    crate::reset_hook_globals();
    crate::trampolines::reset_fail_state_for_test();
    crate::perf_telemetry::reset_perf_counters();
    crate::pipe_client::reset_pipe_client_mocks();
    crate::diagnostic_ring::drain_all_snapshots();
    crate::classification_cache::lru::clear_all();
    crate::volume_class_cache::invalidate_cache();
    crate::classification_cache::unmap_cache();
    crate::hook_journal::unmap_journal();
    crate::control_thread::shutdown_control_thread();
    crate::background_thread::reset_background_thread_for_test();
    *crate::TEST_PIPE_OVERRIDE
        .lock()
        .expect("TEST_PIPE_OVERRIDE lock") = None;
}

/// Drop guard that starts a mock agent server on a unique pipe and shuts it
/// down when dropped.
///
/// The server runs on a dedicated thread. On drop, the shutdown token is set
/// and a dummy client connection is made to wake the blocked
/// `ConnectNamedPipe` call so the thread exits cleanly.
pub struct MockAgentServer {
    shutdown: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    pipe_name: String,
}

impl MockAgentServer {
    /// Start a mock agent server on a unique pipe.
    ///
    /// The handler is invoked for every `HookRequest` received on the pipe.
    /// The server installs the unique pipe name as the test override before
    /// returning, so code that calls [`crate::current_pipe_name`] will target
    /// this server.
    pub fn start(
        handler: Arc<dyn Fn(dlp_common::HookRequest) -> dlp_common::HookResponse + Send + Sync>,
    ) -> Self {
        let pipe_name = unique_pipe_name("mock_agent");
        set_test_pipe_name(&pipe_name);
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);
        let name = pipe_name.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let server = dlp_agent::hook_ipc::HookIpcServer::new(name, handler)
                .with_shutdown_token(shutdown_clone);
            let _ = server.run_with_ready(|| {
                let _ = ready_tx.send(());
            });
        });
        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("mock server did not become ready");
        Self {
            shutdown,
            thread: Some(thread),
            pipe_name,
        }
    }
}

impl Drop for MockAgentServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        wake_named_pipe(&self.pipe_name);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Best-effort wake of a named-pipe server blocked in `ConnectNamedPipe`.
///
/// Connects a client handle and immediately closes it. Errors are ignored
/// because this is only a shutdown hint.
fn wake_named_pipe(pipe_name: &str) {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        FILE_SHARE_NONE, OPEN_EXISTING,
    };

    let name_wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        if let Ok(handle) = CreateFileW(
            PCWSTR::from_raw(name_wide.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        ) {
            let _ = CloseHandle(handle);
        }
    }
}
