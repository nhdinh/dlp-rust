//! Integration tests for DIFF-01 hook-DLL override request emission.
//!
//! These tests prove that denied file operations emit a one-way
//! `IpcPayloadV1::RequestOverride` frame, that repeated denials are throttled
//! by the per-path/action cooldown, that approved overrides suppress the
//! prompt, and that non-pipe deny branches (fail-mode) also trigger emission.

use serial_test::serial;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver};
use std::sync::Arc;
use std::time::Duration;

use dlp_common::hook_ipc::OverrideRequest;
use dlp_common::{Decision, HookRequest, HookResponse};

/// Default deny response used by the mock agent.
fn deny_response() -> HookResponse {
    HookResponse {
        decision: Decision::DENY,
        reason: "test deny".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    }
}

/// Drop guard that owns a mock override server and joins its thread on drop.
struct MockOverrideServer {
    pipe_name: String,
    shutdown: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl MockOverrideServer {
    /// Resets hook-DLL globals, installs `pipe_name` as the test pipe, then
    /// starts a `HookIpcServer` on that pipe. Returns the override receiver.
    ///
    /// The mock request handler is invoked for every `HookRequest`; the override
    /// handler forwards every `RequestOverride` to the returned channel.
    fn start(
        prefix: &str,
        handler: Arc<dyn Fn(HookRequest) -> HookResponse + Send + Sync>,
    ) -> (Self, Receiver<OverrideRequest>, String) {
        dlp_hook_dll::reset_for_test();
        dlp_hook_dll::reset_override_cooldown();

        let pipe_name = dlp_hook_dll::unique_pipe_name(prefix);
        dlp_hook_dll::set_test_pipe_name(&pipe_name);

        let (override_tx, override_rx) = sync_channel(1);
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);
        let name = pipe_name.clone();

        let override_handler: dlp_agent::hook_ipc::OverrideHandler = Arc::new(move |req| {
            let _ = override_tx.send(req);
        });

        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let server = dlp_agent::hook_ipc::HookIpcServer::new(name.clone(), handler)
                .with_override_handler(override_handler)
                .with_shutdown_token(shutdown_clone);
            let _ = server.run_with_ready(|| {
                let _ = ready_tx.send(());
            });
        });
        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("mock server did not become ready");

        (
            Self {
                pipe_name: pipe_name.clone(),
                shutdown,
                thread: Some(thread),
            },
            override_rx,
            pipe_name,
        )
    }
}

impl Drop for MockOverrideServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        wake_named_pipe(&self.pipe_name);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Best-effort wake of a named-pipe server blocked in `ConnectNamedPipe`.
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

#[test]
#[serial]
fn request_override_is_emitted_on_deny() {
    let handler = Arc::new(|_req: HookRequest| deny_response());
    let (server, override_rx, _pipe_name) = MockOverrideServer::start("override_emit", handler);

    let test_path = r"C:\TestData\emit.txt";
    let decision = dlp_hook_dll::classify_and_log_path_for_test(
        test_path,
        "CREATE",
        "TestCreate",
        0,
        1,
        None,
        None,
    );
    assert!(decision.is_some(), "operation should be denied");

    let req = override_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("override request should be emitted");
    assert_eq!(req.action, "CREATE");
    assert_eq!(req.resource_path, test_path);
    assert_eq!(req.data_object_id, test_path);
    assert!(!req.requester_sid.is_empty());
    // WR-01: the override classification must be sourced from the resolved
    // data tier, never from the deny-return enum's `Debug` (previously this
    // yielded `"BoolFalse"`). This deny is a cache-miss pipe round-trip, so no
    // tier is resolved locally and the honest fallback is `"Unknown"`.
    assert_eq!(req.classification, "Unknown");

    drop(server);
}

#[test]
#[serial]
fn request_override_respects_cooldown() {
    let handler = Arc::new(|_req: HookRequest| deny_response());
    let (server, override_rx, _pipe_name) = MockOverrideServer::start("override_cooldown", handler);

    let test_path = r"C:\TestData\cooldown.txt";

    // First deny emits the override request.
    let decision1 = dlp_hook_dll::classify_and_log_path_for_test(
        test_path,
        "CREATE",
        "TestCreate",
        0,
        1,
        None,
        None,
    );
    assert!(decision1.is_some());
    let _ = override_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("first override request should be emitted");

    // Second deny on the same path/action within the cooldown window is suppressed.
    let decision2 = dlp_hook_dll::classify_and_log_path_for_test(
        test_path,
        "CREATE",
        "TestCreate",
        0,
        1,
        None,
        None,
    );
    assert!(decision2.is_some(), "operation should still be denied");
    let second = override_rx.recv_timeout(Duration::from_millis(200));
    assert!(
        second.is_err(),
        "second override request should be suppressed by cooldown"
    );

    drop(server);
}

#[test]
#[serial]
fn approved_override_suppresses_request_override() {
    let handler = Arc::new(|_req: HookRequest| HookResponse {
        decision: Decision::DENY,
        reason: "test deny with override".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: Some(true),
    });
    let (server, override_rx, _pipe_name) = MockOverrideServer::start("override_approved", handler);

    let test_path = r"C:\TestData\approved.txt";
    let decision = dlp_hook_dll::classify_and_log_path_for_test(
        test_path,
        "CREATE",
        "TestCreate",
        0,
        1,
        None,
        None,
    );
    assert!(
        decision.is_none(),
        "approved override should allow the operation"
    );

    let req = override_rx.recv_timeout(Duration::from_millis(200));
    assert!(
        req.is_err(),
        "no override request should be emitted when approval_override is true"
    );

    drop(server);
}

#[test]
#[serial]
fn non_pipe_deny_branch_emits_request_override() {
    let handler = Arc::new(|_req: HookRequest| deny_response());
    let (server, override_rx, _pipe_name) = MockOverrideServer::start("override_isolated", handler);

    // Force the non-pipe Isolated fail-mode branch. In this state a Write with
    // no cached classification is denied locally without a pipe round-trip.
    dlp_hook_dll::set_fail_state_for_test(dlp_hook_dll::FailState::Isolated);

    let test_path = r"C:\TestData\isolated.txt";
    let decision = dlp_hook_dll::classify_and_log_path_for_test(
        test_path,
        "WRITE",
        "TestWrite",
        0,
        2,
        None,
        None,
    );
    assert!(
        decision.is_some(),
        "Isolated fail-mode Write should be denied"
    );

    let req = override_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("override request should be emitted from Isolated deny branch");
    assert_eq!(req.action, "WRITE");
    assert_eq!(req.resource_path, test_path);

    drop(server);
}
