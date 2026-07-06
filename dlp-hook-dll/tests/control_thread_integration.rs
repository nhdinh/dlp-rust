//! Integration tests for the control-poll/watchdog thread.
//!
//! These tests exercise the control thread lifecycle, the watchdog grace
//! window, unhook command handling, and the exported `StartDlpControlThread`
//! symbol.

use dlp_common::hook_ipc::{ControlResponse, UnhookCommand, UnhookReason};
use dlp_hook_dll::{
    enter_hook_call, exit_hook_call, reset_for_test, reset_hook_globals, StartDlpControlThread,
};
use std::os::windows::ffi::OsStrExt;

#[test]
#[serial_test::serial]
fn control_poll_thread_starts_from_post_attach_path() {
    let _guard = dlp_hook_dll::PHASE_58_5_TEST_LOCK.lock();
    reset_for_test();
    dlp_hook_dll::shutdown_control_thread();

    dlp_hook_dll::set_shutting_down_for_test(false);
    let started = enter_hook_call();
    assert!(started);

    std::thread::sleep(std::time::Duration::from_millis(50));

    exit_hook_call();
    dlp_hook_dll::shutdown_control_thread();
}

#[test]
#[serial_test::serial]
fn control_poll_thread_triggers_after_grace_and_failures() {
    let _guard = dlp_hook_dll::PHASE_58_5_TEST_LOCK.lock();
    reset_for_test();
    dlp_hook_dll::reset_watchdog_test_state();
    dlp_hook_dll::set_shutting_down_for_test(false);

    let failures: Vec<_> = (0..32)
        .map(|_| Err(dlp_hook_dll::pipe_client::PipeError::ConnectionRefused))
        .collect();

    let (iterations, triggered) = dlp_hook_dll::run_control_loop_for_test(failures, 2_500, 64);

    assert!(triggered, "watchdog should trigger after grace period");
    assert!(
        iterations >= 3,
        "should take at least three iterations to exceed the window"
    );

    dlp_hook_dll::set_shutting_down_for_test(false);
}

#[test]
#[serial_test::serial]
fn control_poll_thread_resets_on_success() {
    let _guard = dlp_hook_dll::PHASE_58_5_TEST_LOCK.lock();
    reset_for_test();
    dlp_hook_dll::reset_watchdog_test_state();
    dlp_hook_dll::set_shutting_down_for_test(false);

    let results = vec![
        Err(dlp_hook_dll::pipe_client::PipeError::ConnectionRefused),
        Err(dlp_hook_dll::pipe_client::PipeError::ConnectionRefused),
        Ok(ControlResponse { command: None }),
    ];

    let (_iterations, triggered) = dlp_hook_dll::run_control_loop_for_test(results, 5_000, 16);

    assert!(
        !triggered,
        "successful poll should reset failure counter and avoid watchdog"
    );

    dlp_hook_dll::set_shutting_down_for_test(false);
}

#[test]
#[serial_test::serial]
fn control_poll_thread_handles_unhook_command() {
    let _guard = dlp_hook_dll::PHASE_58_5_TEST_LOCK.lock();
    reset_for_test();
    dlp_hook_dll::reset_watchdog_test_state();
    dlp_hook_dll::set_shutting_down_for_test(false);
    std::env::set_var("DLP_HOOK_TEST_MOCK_ACK", "1");

    let results = vec![Ok(ControlResponse {
        command: Some(UnhookCommand {
            reason: UnhookReason::AgentShutdown,
            timestamp_secs: 1_700_000_000,
        }),
    })];

    let (_iterations, triggered) = dlp_hook_dll::run_control_loop_for_test(results, 30_000, 5);

    assert!(!triggered);
    let captured = {
        let mut sink = dlp_hook_dll::pipe_client::MOCK_UNHOOK_ACK_SINK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sink.pop()
    };
    assert!(captured.is_some(), "expected an UnhookAck");
    let captured = captured.unwrap();
    assert!(captured.success);

    std::env::remove_var("DLP_HOOK_TEST_MOCK_ACK");
    dlp_hook_dll::set_shutting_down_for_test(false);
}

#[test]
#[serial_test::serial]
fn start_dlp_control_thread_export_is_reachable() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().expect("workspace root");
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let dll_path = workspace_root
        .join("target")
        .join(profile)
        .join("dlp_hook_dll.dll");

    if !dll_path.exists() {
        eprintln!(
            "Skipping export reachability test: DLL not found at {}. Run `cargo build -p dlp-hook-dll` first.",
            dll_path.display()
        );
        return;
    }

    let dll_wide: Vec<u16> = dll_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let module = unsafe {
        windows::Win32::System::LibraryLoader::LoadLibraryExW(
            windows::core::PCWSTR(dll_wide.as_ptr()),
            None,
            windows::Win32::System::LibraryLoader::DONT_RESOLVE_DLL_REFERENCES,
        )
    };

    assert!(
        module.is_ok(),
        "LoadLibraryExW should succeed for built DLL"
    );
    let module = module.unwrap();

    let proc = unsafe {
        windows::Win32::System::LibraryLoader::GetProcAddress(
            module,
            windows::core::s!("StartDlpControlThread"),
        )
    };
    assert!(
        proc.is_some(),
        "StartDlpControlThread export should be resolvable in built DLL"
    );
}

#[test]
#[serial_test::serial]
fn start_dlp_control_thread_starts_thread_and_is_idempotent() {
    let _guard = dlp_hook_dll::PHASE_58_5_TEST_LOCK.lock();
    reset_hook_globals();
    dlp_hook_dll::shutdown_control_thread();
    dlp_hook_dll::reset_watchdog_test_state();

    let result = StartDlpControlThread();
    assert_eq!(
        result, 0,
        "StartDlpControlThread should return 0 on success"
    );

    std::thread::sleep(std::time::Duration::from_millis(50));

    let result2 = StartDlpControlThread();
    assert_eq!(result2, 0, "StartDlpControlThread should be idempotent");

    dlp_hook_dll::shutdown_control_thread();
}
