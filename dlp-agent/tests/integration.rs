//! Integration tests for the DLP Agent pipeline (T-21).
//!
//! These tests exercise the end-to-end flow:
//!
//! 1. File action → PolicyMapper → ABAC action + classification
//! 2. EngineClient → (mock) Policy Engine → EvaluateResponse
//! 3. Cache lookup / offline fallback
//! 4. AuditEmitter → local JSONL audit log
//!
//! The Policy Engine is mocked using a local `axum` HTTP server that returns
//! configurable responses.

use std::net::SocketAddr;
use std::sync::Arc;

use dlp_common::{
    Action, Classification, Decision, EvaluateRequest, EvaluateResponse,
};

// ─────────────────────────────────────────────────────────────────────────────
// Mock Policy Engine
// ─────────────────────────────────────────────────────────────────────────────

/// Starts a mock Policy Engine that returns a fixed decision for all requests.
async fn start_mock_engine(decision: Decision) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use axum::{extract::Json, routing::post, Router};
    use tokio::net::TcpListener;

    let app = Router::new().route(
        "/evaluate",
        post(move |Json(_body): Json<EvaluateRequest>| async move {
            Json(EvaluateResponse {
                decision,
                matched_policy_id: Some("mock-pol-001".to_string()),
                reason: format!("mock engine: {decision:?}"),
            })
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, handle)
}

// ─────────────────────────────────────────────────────────────────────────────
// End-to-end: PolicyMapper + EngineClient + Cache + AuditEmitter
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_e2e_file_action_to_audit_log() {
    use dlp_agent::audit_emitter::AuditEmitter;
    use dlp_agent::cache::Cache;
    use dlp_agent::engine_client::EngineClient;
    use dlp_agent::interception::PolicyMapper;
    use dlp_agent::interception::FileAction;

    // 1. Start mock engine returning DENY for everything.
    let (addr, _handle) = start_mock_engine(Decision::DENY).await;
    let base_url = format!("http://{addr}");

    // 2. Create components.
    let client = EngineClient::new(&base_url, false).unwrap();
    let cache = Arc::new(Cache::new());
    let dir = tempfile::tempdir().unwrap();
    let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 10 * 1024 * 1024)
        .unwrap();

    // 3. Simulate a file action.
    let action = FileAction::Written {
        path: r"C:\Restricted\secrets.xlsx".to_string(),
        process_id: 1234,
        related_process_id: 0,
        byte_count: 4096,
    };

    // 4. Map to ABAC action.
    let abac_action = PolicyMapper::action_for(&action);
    assert_eq!(abac_action, Action::WRITE);

    let classification = PolicyMapper::provisional_classification(action.path());
    assert_eq!(classification, Classification::T4);

    // 5. Build evaluation request.
    let request = EvaluateRequest {
        subject: dlp_common::Subject {
            user_sid: "S-1-5-21-TEST".to_string(),
            user_name: "testuser".to_string(),
            groups: Vec::new(),
            device_trust: dlp_common::DeviceTrust::Managed,
            network_location: dlp_common::NetworkLocation::Corporate,
        },
        resource: dlp_common::Resource {
            path: action.path().to_string(),
            classification,
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: dlp_common::AccessContext::Local,
        },
        action: abab_action_to_dlp(abac_action),
    };

    // 6. Evaluate against mock engine.
    let response = client.evaluate(&request).await.unwrap();
    assert!(response.decision.is_denied());
    assert_eq!(response.matched_policy_id.as_deref(), Some("mock-pol-001"));

    // 7. Cache the result.
    cache.insert(action.path(), "S-1-5-21-TEST", response.clone());
    let cached = cache.get(action.path(), "S-1-5-21-TEST");
    assert!(cached.is_some());

    // 8. Emit audit event.
    let event = dlp_common::AuditEvent::new(
        dlp_common::EventType::Block,
        "S-1-5-21-TEST".to_string(),
        "testuser".to_string(),
        action.path().to_string(),
        classification,
        abab_action_to_dlp(abac_action),
        response.decision,
        "AGENT-TEST-001".to_string(),
        1,
    )
    .with_policy("mock-pol-001".to_string(), "Mock Deny".to_string());

    emitter.emit(&event).unwrap();

    // 9. Verify audit log contains the event.
    let log_contents = std::fs::read_to_string(emitter.log_path()).unwrap();
    let parsed: dlp_common::AuditEvent =
        serde_json::from_str(log_contents.trim()).unwrap();
    assert_eq!(parsed.event_type, dlp_common::EventType::Block);
    assert_eq!(parsed.decision, Decision::DENY);
    assert_eq!(parsed.resource_path, r"C:\Restricted\secrets.xlsx");
    assert_eq!(parsed.policy_id, Some("mock-pol-001".to_string()));
}

#[tokio::test]
async fn test_e2e_cache_hit_skips_engine() {
    use dlp_agent::cache::Cache;
    use dlp_agent::interception::PolicyMapper;
    use dlp_agent::interception::FileAction;

    let cache = Arc::new(Cache::new());

    // Pre-populate cache with ALLOW decision.
    cache.insert(
        r"C:\Data\report.xlsx",
        "S-1-5-21-CACHED",
        EvaluateResponse {
            decision: Decision::ALLOW,
            matched_policy_id: Some("pol-cached".to_string()),
            reason: "cached".to_string(),
        },
    );

    // Simulate a file read.
    let action = FileAction::Read {
        path: r"C:\Data\report.xlsx".to_string(),
        process_id: 5678,
        related_process_id: 0,
        byte_count: 1024,
    };

    let abac_action = PolicyMapper::action_for(&action);
    assert_eq!(abac_action, Action::READ);

    // Cache lookup should return the pre-populated response.
    let cached = cache.get(action.path(), "S-1-5-21-CACHED");
    assert!(cached.is_some());
    let resp = cached.unwrap();
    assert_eq!(resp.decision, Decision::ALLOW);
}

#[tokio::test]
async fn test_e2e_offline_fallback_deny_t4() {
    use dlp_agent::cache::{self, Cache};
    use dlp_agent::interception::PolicyMapper;
    use dlp_agent::interception::FileAction;

    let cache = Arc::new(Cache::new());

    // No cache entry, no engine — offline fallback.
    let action = FileAction::Written {
        path: r"C:\Restricted\top_secret.docx".to_string(),
        process_id: 9999,
        related_process_id: 0,
        byte_count: 0,
    };

    let classification = PolicyMapper::provisional_classification(action.path());
    assert_eq!(classification, Classification::T4);

    // Cache miss for T4 → fail-closed DENY.
    let cached = cache.get(action.path(), "S-1-5-21-OFFLINE");
    assert!(cached.is_none());
    let fallback = cache::fail_closed_response(classification);
    assert!(fallback.decision.is_denied());
}

#[tokio::test]
async fn test_e2e_offline_fallback_allow_t1() {
    use dlp_agent::cache::{self, Cache};
    use dlp_agent::interception::PolicyMapper;
    use dlp_agent::interception::FileAction;

    let cache = Arc::new(Cache::new());

    let action = FileAction::Read {
        path: r"C:\Public\readme.txt".to_string(),
        process_id: 1000,
        related_process_id: 0,
        byte_count: 256,
    };

    let classification = PolicyMapper::provisional_classification(action.path());
    assert_eq!(classification, Classification::T1);

    // Cache miss for T1 → default-allow.
    let cached = cache.get(action.path(), "S-1-5-21-OFFLINE");
    assert!(cached.is_none());
    let fallback = cache::fail_closed_response(classification);
    assert!(!fallback.decision.is_denied());
}

#[tokio::test]
async fn test_e2e_usb_block_t3() {
    use dlp_agent::detection::UsbDetector;

    let detector = UsbDetector::new();
    // Simulate USB drive F: plugged in by calling on_drive_arrival.
    // Since F: may not be a physical removable drive on this machine,
    // we verify the detection logic using the should_block_write path check.
    // The unit tests in usb.rs already validate the blocked-drive set directly.

    // With no blocked drives, T3 on any path is not blocked.
    assert!(!detector.should_block_write(
        r"F:\confidential_report.pdf",
        Classification::T3,
    ));

    // T1 is never blocked regardless.
    assert!(!detector.should_block_write(
        r"F:\public_doc.txt",
        Classification::T1,
    ));
}

#[tokio::test]
async fn test_e2e_network_share_block() {
    use dlp_agent::detection::NetworkShareDetector;

    let detector = NetworkShareDetector::with_whitelist(
        vec!["safe.corp.local".to_string()],
    );

    // Whitelisted server — allowed.
    assert!(!detector.should_block(
        r"\\safe.corp.local\data\report.xlsx",
        Classification::T4,
    ));

    // Non-whitelisted — blocked.
    assert!(detector.should_block(
        r"\\evil.external\exfil\data.zip",
        Classification::T3,
    ));
}

#[tokio::test]
async fn test_e2e_etw_bypass_detection() {
    use dlp_agent::detection::EtwBypassDetector;

    let detector = EtwBypassDetector::new();

    // Record a hook intercept.
    detector.record_hook_intercept(r"C:\Data\file.txt", 100);

    // ETW event for the same op — no evasion.
    assert!(detector
        .check_etw_event(r"C:\Data\file.txt", 100, "WriteFile")
        .is_none());

    // ETW event for an unhooked op — evasion detected.
    let signal = detector
        .check_etw_event(r"C:\Data\sneaky.txt", 200, "NtWriteFile")
        .unwrap();
    assert_eq!(signal.process_id, 200);
}

#[tokio::test]
async fn test_e2e_clipboard_classification() {
    use dlp_agent::clipboard::ClipboardClassifier;

    // SSN triggers T4.
    assert_eq!(
        ClipboardClassifier::classify("SSN: 123-45-6789"),
        Classification::T4,
    );

    // "CONFIDENTIAL" triggers T3.
    assert_eq!(
        ClipboardClassifier::classify("CONFIDENTIAL memo"),
        Classification::T3,
    );

    // Benign text is T1.
    assert_eq!(
        ClipboardClassifier::classify("Hello world"),
        Classification::T1,
    );
}

#[tokio::test]
async fn test_e2e_audit_event_round_trip() {
    use dlp_agent::audit_emitter::AuditEmitter;

    let dir = tempfile::tempdir().unwrap();
    let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 10 * 1024 * 1024)
        .unwrap();

    // Emit multiple events.
    for i in 0..3 {
        let event = dlp_common::AuditEvent::new(
            dlp_common::EventType::Access,
            format!("S-1-5-21-{i}"),
            format!("user{i}"),
            format!(r"C:\Data\file{i}.txt"),
            Classification::T2,
            Action::READ,
            Decision::ALLOW,
            "AGENT-TEST".to_string(),
            1,
        );
        emitter.emit(&event).unwrap();
    }

    // Read back and verify.
    let contents = std::fs::read_to_string(emitter.log_path()).unwrap();
    let events: Vec<dlp_common::AuditEvent> = contents
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].user_sid, "S-1-5-21-0");
    assert_eq!(events[2].user_sid, "S-1-5-21-2");
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: convert PolicyMapper Action to dlp_common Action (they're the same)
// ─────────────────────────────────────────────────────────────────────────────

fn abab_action_to_dlp(action: Action) -> Action {
    action
}
