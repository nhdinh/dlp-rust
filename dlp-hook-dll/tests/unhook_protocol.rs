//! Integration tests for the Phase 58.5 unhook protocol.
//!
//! These tests exercise `UnhookAll`, `handle_unhook_command`, and the
//! ack-sink machinery that reports success/failure back to the agent.

use dlp_common::hook_ipc::{UnhookCommand, UnhookReason};
use dlp_hook_dll::{background_thread, handle_unhook_command, reset_for_test};
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[test]
#[serial_test::serial]
fn unhook_all_is_idempotent() {
    let _guard = dlp_hook_dll::PHASE_58_5_TEST_LOCK.lock();
    reset_for_test();
    dlp_hook_dll::UnhookAll();
    dlp_hook_dll::UnhookAll();
}

#[test]
#[serial_test::serial]
fn unhook_all_sets_shutting_down() {
    let _guard = dlp_hook_dll::PHASE_58_5_TEST_LOCK.lock();
    reset_for_test();
    dlp_hook_dll::UnhookAll();
    assert!(dlp_hook_dll::SHUTTING_DOWN.load(Ordering::SeqCst));
    dlp_hook_dll::set_shutting_down_for_test(false);
}

#[test]
#[serial_test::serial]
fn unhook_all_unpatches_ntdll_stubs() {
    let _guard = dlp_hook_dll::PHASE_58_5_TEST_LOCK.lock();
    reset_for_test();
    dlp_hook_dll::SHUTTING_DOWN.store(false, Ordering::SeqCst);
    dlp_hook_dll::INITIALISED.store(true, Ordering::SeqCst);

    let _ = dlp_hook_dll::lazy_init_ntdll_patcher(true);
    if let Some(patcher_lock) = dlp_hook_dll::NTDLL_PATCHER.get() {
        let mut patcher = patcher_lock.lock().unwrap();
        patcher.set_stub_state_for_test(
            dlp_hook_dll::ntdll_patcher::StubName::NtCreateFile,
            dlp_hook_dll::ntdll_patcher::StubPatchState::Patched,
        );
        patcher.set_stub_state_for_test(
            dlp_hook_dll::ntdll_patcher::StubName::NtOpenFile,
            dlp_hook_dll::ntdll_patcher::StubPatchState::Patched,
        );
    }

    dlp_hook_dll::UnhookAll();

    if let Some(patcher_lock) = dlp_hook_dll::NTDLL_PATCHER.get() {
        let patcher = patcher_lock.lock().unwrap();
        assert_eq!(
            *patcher.stub_state(dlp_hook_dll::ntdll_patcher::StubName::NtCreateFile),
            dlp_hook_dll::ntdll_patcher::StubPatchState::Unpatched
        );
        assert_eq!(
            *patcher.stub_state(dlp_hook_dll::ntdll_patcher::StubName::NtOpenFile),
            dlp_hook_dll::ntdll_patcher::StubPatchState::Unpatched
        );
    }

    dlp_hook_dll::set_shutting_down_for_test(false);
}

#[test]
#[serial_test::serial]
fn unhook_all_unmaps_shared_memory() {
    let _guard = dlp_hook_dll::PHASE_58_5_TEST_LOCK.lock();
    reset_for_test();
    dlp_hook_dll::SHUTTING_DOWN.store(false, Ordering::SeqCst);

    dlp_hook_dll::unmap_journal();
    dlp_hook_dll::unmap_cache();

    dlp_hook_dll::UnhookAll();

    assert!(dlp_hook_dll::HookJournal::get().is_none());
    assert!(dlp_hook_dll::CacheLookup::get().is_none());
}

#[test]
#[serial_test::serial]
fn unhook_all_infallible_per_stub() {
    let _guard = dlp_hook_dll::PHASE_58_5_TEST_LOCK.lock();
    reset_for_test();
    dlp_hook_dll::SHUTTING_DOWN.store(false, Ordering::SeqCst);
    dlp_hook_dll::INITIALISED.store(true, Ordering::SeqCst);

    unsafe {
        let page = windows::Win32::System::Memory::VirtualAlloc(
            None,
            4096,
            windows::Win32::System::Memory::MEM_COMMIT
                | windows::Win32::System::Memory::MEM_RESERVE,
            windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
        );
        assert!(!page.is_null());
        let iat = page as *mut usize;
        *iat = 0xDEADBEEF;

        dlp_hook_dll::IAT_CREATE_FILE_W = Some(iat);
        let original_ptr = std::ptr::addr_of_mut!(dlp_hook_dll::ORIGINAL_CREATE_FILE_W);
        *original_ptr = Some(std::mem::transmute::<usize, _>(0xBEEFDEAD_usize));

        dlp_hook_dll::UnhookAll();

        assert_eq!(*iat, 0xBEEFDEAD);

        dlp_hook_dll::IAT_CREATE_FILE_W = None;
        dlp_hook_dll::ORIGINAL_CREATE_FILE_W = None;

        let _ = windows::Win32::System::Memory::VirtualFree(
            page,
            0,
            windows::Win32::System::Memory::VIRTUAL_FREE_TYPE(0x8000),
        );
    }

    dlp_hook_dll::set_shutting_down_for_test(false);
}

#[test]
#[serial_test::serial]
fn handle_unhook_command_sends_success_ack() {
    let _guard = dlp_hook_dll::PHASE_58_5_TEST_LOCK.lock();
    reset_for_test();
    dlp_hook_dll::SHUTTING_DOWN.store(false, Ordering::SeqCst);
    dlp_hook_dll::reset_watchdog_test_state();
    dlp_hook_dll::ACTIVE_CALLS.store(0, Ordering::SeqCst);

    unsafe {
        dlp_hook_dll::IAT_CREATE_FILE_W = None;
        dlp_hook_dll::ORIGINAL_CREATE_FILE_W = None;
    }

    std::env::set_var("DLP_HOOK_TEST_MOCK_ACK", "1");
    let cmd = UnhookCommand {
        reason: UnhookReason::AgentShutdown,
        timestamp_secs: 1_700_000_000,
    };
    handle_unhook_command(cmd, std::process::id(), 12345);
    std::env::remove_var("DLP_HOOK_TEST_MOCK_ACK");

    let captured = {
        let mut sink = dlp_hook_dll::pipe_client::MOCK_UNHOOK_ACK_SINK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sink.pop()
    };
    assert!(captured.is_some(), "expected an UnhookAck to be sent");
    let captured = captured.unwrap();
    assert!(captured.success);
    assert_eq!(captured.pid, std::process::id());
    assert_eq!(captured.creation_time, 12345);

    dlp_hook_dll::set_shutting_down_for_test(false);
}

#[test]
#[serial_test::serial]
fn handle_unhook_command_sends_failure_ack() {
    let _guard = dlp_hook_dll::PHASE_58_5_TEST_LOCK.lock();
    reset_for_test();
    dlp_hook_dll::SHUTTING_DOWN.store(false, Ordering::SeqCst);
    dlp_hook_dll::reset_watchdog_test_state();
    dlp_hook_dll::ACTIVE_CALLS.store(0, Ordering::SeqCst);

    std::env::set_var("DLP_HOOK_TEST_MOCK_ACK", "1");
    let mut dummy_iat: usize = 0;
    unsafe {
        dlp_hook_dll::IAT_CREATE_FILE_W = Some(&mut dummy_iat as *mut usize);
        dlp_hook_dll::ORIGINAL_CREATE_FILE_W = None;
    }
    let cmd = UnhookCommand {
        reason: UnhookReason::AgentShutdown,
        timestamp_secs: 1_700_000_000,
    };
    handle_unhook_command(cmd, std::process::id(), 12345);
    std::env::remove_var("DLP_HOOK_TEST_MOCK_ACK");

    unsafe {
        dlp_hook_dll::IAT_CREATE_FILE_W = None;
        dlp_hook_dll::ORIGINAL_CREATE_FILE_W = None;
    }

    let captured = {
        let mut sink = dlp_hook_dll::pipe_client::MOCK_UNHOOK_ACK_SINK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sink.pop()
    };
    assert!(captured.is_some(), "expected an UnhookAck to be sent");
    let captured = captured.unwrap();
    assert!(
        !captured.success,
        "expected ack.success == false when UnhookAll fails"
    );

    dlp_hook_dll::set_shutting_down_for_test(false);
}

#[test]
#[serial_test::serial]
fn handle_unhook_command_sends_failure_ack_when_background_thread_times_out() {
    let _guard = dlp_hook_dll::PHASE_58_5_TEST_LOCK.lock();
    reset_for_test();
    dlp_hook_dll::SHUTTING_DOWN.store(false, Ordering::SeqCst);
    dlp_hook_dll::reset_watchdog_test_state();
    dlp_hook_dll::ACTIVE_CALLS.store(0, Ordering::SeqCst);

    background_thread::reset_background_thread_for_test();
    let state = Arc::new(dlp_hook_dll::FailModeState::new());
    background_thread::start_background_thread(std::ptr::null(), Arc::clone(&state), None, None);
    background_thread::force_shutdown_timeout_for_test(true);

    std::env::set_var("DLP_HOOK_TEST_MOCK_ACK", "1");
    let cmd = UnhookCommand {
        reason: UnhookReason::AgentShutdown,
        timestamp_secs: 1_700_000_000,
    };
    handle_unhook_command(cmd, std::process::id(), 12345);
    std::env::remove_var("DLP_HOOK_TEST_MOCK_ACK");

    let captured = {
        let mut sink = dlp_hook_dll::pipe_client::MOCK_UNHOOK_ACK_SINK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sink.pop()
    };
    assert!(captured.is_some(), "expected an UnhookAck to be sent");
    let captured = captured.unwrap();
    assert!(
        !captured.success,
        "expected ack.success == false when background thread shutdown times out"
    );

    background_thread::reset_background_thread_for_test();
    dlp_hook_dll::set_shutting_down_for_test(false);
}
