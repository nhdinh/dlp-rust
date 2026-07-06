//! Integration tests for the hook DLL named-pipe client.
//!
//! These tests spin up a mock agent server on a unique pipe and verify that
//! `pipe_client::send_request` and the high-level `classify_path` helper
//! correctly route requests and responses.

use dlp_common::{Decision, HookRequest, HookResponse};
use dlp_hook_dll::{classify_path, current_pipe_name, reset_for_test, MockAgentServer};
use std::sync::Arc;
use std::time::Duration;

#[test]
#[serial_test::serial]
fn pipe_client_connection_refused_when_no_server() {
    reset_for_test();
    let req = HookRequest {
        path: r"C:\test.txt".to_string(),
        action: "CREATE".to_string(),
        ..Default::default()
    };
    let result =
        dlp_hook_dll::pipe_client::send_request(r"\\.\pipe\DlpHookPipeTestNoServer", &req, 100);
    assert!(
        matches!(
            result,
            Err(dlp_hook_dll::pipe_client::PipeError::ConnectionRefused)
        ),
        "expected ConnectionRefused, got {:?}",
        result
    );
}

#[test]
#[serial_test::serial]
fn pipe_client_roundtrip_deny() {
    reset_for_test();
    let handler = Arc::new(|req: HookRequest| HookResponse {
        decision: Decision::DENY,
        reason: format!("blocked: {}", req.path),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });
    let _server = MockAgentServer::start(handler);
    std::thread::sleep(Duration::from_millis(50));

    let req = HookRequest {
        path: r"C:\secret.txt".to_string(),
        action: "CREATE".to_string(),
        ..Default::default()
    };
    let resp = dlp_hook_dll::pipe_client::send_request(current_pipe_name(), &req, 1000)
        .expect("send_request should succeed");
    assert_eq!(resp.decision, Decision::DENY);
    assert_eq!(resp.reason, "blocked: C:\\secret.txt");
}

#[test]
#[serial_test::serial]
fn pipe_client_roundtrip_allow() {
    reset_for_test();
    let handler = Arc::new(|_req: HookRequest| HookResponse {
        decision: Decision::ALLOW,
        reason: "allowed".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });
    let _server = MockAgentServer::start(handler);
    std::thread::sleep(Duration::from_millis(50));

    let req = HookRequest {
        path: r"C:\public.txt".to_string(),
        action: "CREATE".to_string(),
        ..Default::default()
    };
    let resp = dlp_hook_dll::pipe_client::send_request(current_pipe_name(), &req, 1000)
        .expect("send_request should succeed");
    assert_eq!(resp.decision, Decision::ALLOW);
    assert_eq!(resp.reason, "allowed");
}

#[test]
#[serial_test::serial]
fn hook_createfilew_fail_closed_on_deny() {
    reset_for_test();
    let handler = Arc::new(|_req: HookRequest| HookResponse {
        decision: Decision::DENY,
        reason: "denied".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });
    let _server = MockAgentServer::start(handler);
    std::thread::sleep(Duration::from_millis(50));

    let result = classify_path(r"C:\secret.txt", "CREATE", current_pipe_name(), None, None);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().decision, Decision::DENY);
}

#[test]
#[serial_test::serial]
fn hook_createfilew_allow_when_allowed() {
    reset_for_test();
    let handler = Arc::new(|_req: HookRequest| HookResponse {
        decision: Decision::ALLOW,
        reason: "allowed".to_string(),
        cache_hint: None,
        cache_version: 0,
        approval_override: None,
    });
    let _server = MockAgentServer::start(handler);
    std::thread::sleep(Duration::from_millis(50));

    let result = classify_path(r"C:\public.txt", "CREATE", current_pipe_name(), None, None);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().decision, Decision::ALLOW);
}
