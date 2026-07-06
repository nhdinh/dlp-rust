//! Integration tests for self-unload safety checks.
//!
//! These tests verify that `self_unload` aborts when active calls remain or
//! when the DLL instance was never captured, and that `UnhookAll` drains
//! active calls before returning.

use dlp_hook_dll::{reset_for_test, ActiveCallGuard};
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[test]
#[serial_test::serial]
fn self_unload_check_returns_captured_instance_or_none_in_tests() {
    let _guard = dlp_hook_dll::PHASE_58_5_TEST_LOCK.lock();
    reset_for_test();

    let instance = dlp_hook_dll::self_unload_check();
    assert!(
        instance.is_none(),
        "self_unload_check should return None when DllMain has not captured an instance"
    );
}

#[test]
#[serial_test::serial]
fn self_unload_aborts_when_active_calls_remain() {
    let _guard = dlp_hook_dll::PHASE_58_5_TEST_LOCK.lock();
    reset_for_test();
    dlp_hook_dll::set_shutting_down_for_test(false);
    dlp_hook_dll::ACTIVE_CALLS.store(0, Ordering::SeqCst);

    let guard = ActiveCallGuard::new();
    assert!(guard.is_active());

    let result = unsafe { dlp_hook_dll::self_unload() };
    assert!(
        !result,
        "self_unload should abort while active hook calls remain"
    );

    drop(guard);
    assert_eq!(dlp_hook_dll::ACTIVE_CALLS.load(Ordering::SeqCst), 0);
    dlp_hook_dll::set_shutting_down_for_test(false);
}

#[test]
#[serial_test::serial]
fn self_unload_aborts_when_dll_instance_not_captured() {
    let _guard = dlp_hook_dll::PHASE_58_5_TEST_LOCK.lock();
    reset_for_test();
    dlp_hook_dll::set_shutting_down_for_test(false);
    dlp_hook_dll::ACTIVE_CALLS.store(0, Ordering::SeqCst);

    assert!(dlp_hook_dll::self_unload_check().is_none());

    let result = unsafe { dlp_hook_dll::self_unload() };
    assert!(
        !result,
        "self_unload should abort when the DLL instance is unknown"
    );
    dlp_hook_dll::set_shutting_down_for_test(false);
}

#[test]
#[serial_test::serial]
fn unhook_all_drains_active_calls() {
    let _guard = dlp_hook_dll::PHASE_58_5_TEST_LOCK.lock();
    reset_for_test();
    dlp_hook_dll::set_shutting_down_for_test(false);
    dlp_hook_dll::ACTIVE_CALLS.store(0, Ordering::SeqCst);

    let barrier = Arc::new(std::sync::Barrier::new(2));
    let barrier_clone = Arc::clone(&barrier);

    let handle = std::thread::spawn(move || {
        dlp_hook_dll::ACTIVE_CALLS.fetch_add(1, Ordering::SeqCst);
        barrier_clone.wait();
        std::thread::sleep(std::time::Duration::from_millis(50));
        dlp_hook_dll::ACTIVE_CALLS.fetch_sub(1, Ordering::SeqCst);
    });

    barrier.wait();
    std::thread::sleep(std::time::Duration::from_millis(10));
    assert!(dlp_hook_dll::ACTIVE_CALLS.load(Ordering::SeqCst) > 0);

    dlp_hook_dll::UnhookAll();

    handle.join().unwrap();
    assert_eq!(dlp_hook_dll::ACTIVE_CALLS.load(Ordering::SeqCst), 0);
    dlp_hook_dll::set_shutting_down_for_test(false);
}
