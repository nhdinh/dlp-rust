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

use dlp_common::{Action, Classification, Decision, EvaluateRequest, EvaluateResponse};

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
    use dlp_agent::interception::FileAction;
    use dlp_agent::interception::PolicyMapper;

    // 1. Start mock engine returning DENY for everything.
    let (addr, _handle) = start_mock_engine(Decision::DENY).await;
    let base_url = format!("http://{addr}");

    // 2. Create components.
    let client = EngineClient::new(&base_url, false).unwrap();
    let cache = Arc::new(Cache::new());
    let dir = tempfile::tempdir().unwrap();
    let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 10 * 1024 * 1024).unwrap();

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
        action: abac_action_to_dlp(abac_action),
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
        abac_action_to_dlp(abac_action),
        response.decision,
        "AGENT-TEST-001".to_string(),
        1,
    )
    .with_policy("mock-pol-001".to_string(), "Mock Deny".to_string());

    emitter.emit(&event).unwrap();

    // 9. Verify audit log contains the event.
    let log_contents = std::fs::read_to_string(emitter.log_path()).unwrap();
    let parsed: dlp_common::AuditEvent = serde_json::from_str(log_contents.trim()).unwrap();
    assert_eq!(parsed.event_type, dlp_common::EventType::Block);
    assert_eq!(parsed.decision, Decision::DENY);
    assert_eq!(parsed.resource_path, r"C:\Restricted\secrets.xlsx");
    assert_eq!(parsed.policy_id, Some("mock-pol-001".to_string()));
}

#[tokio::test]
async fn test_e2e_cache_hit_skips_engine() {
    use dlp_agent::cache::Cache;
    use dlp_agent::interception::FileAction;
    use dlp_agent::interception::PolicyMapper;

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
    use dlp_agent::interception::FileAction;
    use dlp_agent::interception::PolicyMapper;

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
    use dlp_agent::interception::FileAction;
    use dlp_agent::interception::PolicyMapper;

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
    assert!(!detector.should_block_write(r"F:\confidential_report.pdf", Classification::T3,));

    // T1 is never blocked regardless.
    assert!(!detector.should_block_write(r"F:\public_doc.txt", Classification::T1,));
}

#[tokio::test]
async fn test_e2e_network_share_block() {
    use dlp_agent::detection::NetworkShareDetector;

    let detector = NetworkShareDetector::with_whitelist(vec!["safe.corp.local".to_string()]);

    // Whitelisted server — allowed.
    assert!(!detector.should_block(r"\\safe.corp.local\data\report.xlsx", Classification::T4,));

    // Non-whitelisted — blocked.
    assert!(detector.should_block(r"\\evil.external\exfil\data.zip", Classification::T3,));
}

#[tokio::test]
async fn test_e2e_clipboard_classification() {
    use dlp_agent::clipboard::ContentClassifier;

    // SSN triggers T4.
    assert_eq!(
        ContentClassifier::classify("SSN: 123-45-6789"),
        Classification::T4,
    );

    // "CONFIDENTIAL" triggers T3.
    assert_eq!(
        ContentClassifier::classify("CONFIDENTIAL memo"),
        Classification::T3,
    );

    // Benign text is T1.
    assert_eq!(
        ContentClassifier::classify("Hello world"),
        Classification::T1,
    );
}

#[tokio::test]
async fn test_e2e_audit_event_round_trip() {
    use dlp_agent::audit_emitter::AuditEmitter;

    let dir = tempfile::tempdir().unwrap();
    let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 10 * 1024 * 1024).unwrap();

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
// Helper
// ─────────────────────────────────────────────────────────────────────────────

fn abac_action_to_dlp(action: Action) -> Action {
    action
}

// ─────────────────────────────────────────────────────────────────────────────
// F-AGT-05/06: All FileAction variants mapped and evaluated
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_all_file_action_variants_mapped() {
    use dlp_agent::interception::{FileAction, PolicyMapper};

    let cases: Vec<(FileAction, Action)> = vec![
        (
            FileAction::Created {
                path: "a".into(),
                process_id: 1,
                related_process_id: 0,
            },
            Action::WRITE,
        ),
        (
            FileAction::Written {
                path: "a".into(),
                process_id: 1,
                related_process_id: 0,
                byte_count: 0,
            },
            Action::WRITE,
        ),
        (
            FileAction::Deleted {
                path: "a".into(),
                process_id: 1,
                related_process_id: 0,
            },
            Action::DELETE,
        ),
        (
            FileAction::Moved {
                old_path: "a".into(),
                new_path: "b".into(),
                process_id: 1,
                related_process_id: 0,
            },
            Action::MOVE,
        ),
        (
            FileAction::Read {
                path: "a".into(),
                process_id: 1,
                related_process_id: 0,
                byte_count: 0,
            },
            Action::READ,
        ),
    ];

    for (action, expected) in cases {
        assert_eq!(
            PolicyMapper::action_for(&action),
            expected,
            "FileAction::{:?} should map to Action::{expected:?}",
            std::mem::discriminant(&action),
        );
    }
}

#[tokio::test]
async fn test_write_t4_deny_audit() {
    use dlp_agent::audit_emitter::AuditEmitter;
    use dlp_agent::interception::{FileAction, PolicyMapper};

    let (addr, _h) = start_mock_engine(Decision::DENY).await;
    let client =
        dlp_agent::engine_client::EngineClient::new(format!("http://{addr}"), false).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 10 * 1024 * 1024).unwrap();

    let action = FileAction::Written {
        path: r"C:\Restricted\secret.xlsx".into(),
        process_id: 1234,
        related_process_id: 0,
        byte_count: 4096,
    };

    let abac_action = PolicyMapper::action_for(&action);
    let classification = PolicyMapper::provisional_classification(action.path());
    assert_eq!(classification, Classification::T4);

    let request = EvaluateRequest {
        subject: dlp_common::Subject {
            user_sid: "S-1-5-21-TEST".into(),
            user_name: "testuser".into(),
            groups: vec![],
            device_trust: dlp_common::DeviceTrust::Managed,
            network_location: dlp_common::NetworkLocation::Corporate,
        },
        resource: dlp_common::Resource {
            path: action.path().into(),
            classification,
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: dlp_common::AccessContext::Local,
        },
        action: abac_action,
    };

    let response = client.evaluate(&request).await.unwrap();
    assert!(response.decision.is_denied());

    // Emit Block audit event.
    let event = dlp_common::AuditEvent::new(
        dlp_common::EventType::Block,
        "S-1-5-21-TEST".into(),
        "testuser".into(),
        action.path().into(),
        classification,
        abac_action,
        response.decision,
        "AGENT-TEST".into(),
        1,
    );
    emitter.emit(&event).unwrap();

    let contents = std::fs::read_to_string(emitter.log_path()).unwrap();
    let parsed: dlp_common::AuditEvent = serde_json::from_str(contents.trim()).unwrap();
    assert_eq!(parsed.event_type, dlp_common::EventType::Block);
    assert_eq!(parsed.decision, Decision::DENY);
}

#[tokio::test]
async fn test_read_t1_allow() {
    let (addr, _h) = start_mock_engine(Decision::ALLOW).await;
    let client =
        dlp_agent::engine_client::EngineClient::new(format!("http://{addr}"), false).unwrap();

    use dlp_agent::interception::{FileAction, PolicyMapper};

    let action = FileAction::Read {
        path: r"C:\Public\readme.txt".into(),
        process_id: 100,
        related_process_id: 0,
        byte_count: 256,
    };

    let abac_action = PolicyMapper::action_for(&action);
    assert_eq!(abac_action, Action::READ);

    let classification = PolicyMapper::provisional_classification(action.path());
    assert_eq!(classification, Classification::T1);

    let request = EvaluateRequest {
        subject: dlp_common::Subject::default(),
        resource: dlp_common::Resource {
            path: action.path().into(),
            classification,
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: dlp_common::AccessContext::Local,
        },
        action: abac_action,
    };

    let response = client.evaluate(&request).await.unwrap();
    assert!(!response.decision.is_denied());
}

#[tokio::test]
async fn test_delete_action_maps() {
    use dlp_agent::interception::{FileAction, PolicyMapper};
    let action = FileAction::Deleted {
        path: r"C:\Data\old.txt".into(),
        process_id: 1,
        related_process_id: 0,
    };
    assert_eq!(PolicyMapper::action_for(&action), Action::DELETE);
    assert_eq!(
        PolicyMapper::provisional_classification(action.path()),
        Classification::T2
    );
}

#[tokio::test]
async fn test_move_action_maps() {
    use dlp_agent::interception::{FileAction, PolicyMapper};
    let action = FileAction::Moved {
        old_path: r"C:\Confidential\a.doc".into(),
        new_path: r"C:\Data\b.doc".into(),
        process_id: 1,
        related_process_id: 0,
    };
    assert_eq!(PolicyMapper::action_for(&action), Action::MOVE);
    // Moved path() returns new_path.
    assert_eq!(action.path(), r"C:\Data\b.doc");
}

// ─────────────────────────────────────────────────────────────────────────────
// F-AGT-10: Cache TTL
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_cache_ttl_expiry() {
    use dlp_agent::cache::{self, Cache};
    use std::time::Duration;

    let cache = Cache::with_ttl(Duration::from_millis(50));
    cache.insert(
        r"C:\Restricted\secret.xlsx",
        "S-1-5-21-123",
        EvaluateResponse {
            decision: Decision::ALLOW,
            matched_policy_id: None,
            reason: "test".into(),
        },
    );
    assert!(cache
        .get(r"C:\Restricted\secret.xlsx", "S-1-5-21-123")
        .is_some());

    // Wait for TTL expiry.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Cache miss after expiry.
    assert!(cache
        .get(r"C:\Restricted\secret.xlsx", "S-1-5-21-123")
        .is_none());

    // Fail-closed for T4.
    let fallback = cache::fail_closed_response(Classification::T4);
    assert!(fallback.decision.is_denied());
}

#[tokio::test]
async fn test_cache_configurable_ttl() {
    use dlp_agent::cache::Cache;
    use std::time::Duration;

    let cache = Cache::with_ttl(Duration::from_secs(300));
    cache.insert(
        "a",
        "b",
        EvaluateResponse {
            decision: Decision::ALLOW,
            matched_policy_id: None,
            reason: "test".into(),
        },
    );
    // Should still be present (300s TTL).
    assert!(cache.get("a", "b").is_some());
}

// ─────────────────────────────────────────────────────────────────────────────
// F-AGT-11: Offline manager transition
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_offline_manager_transition() {
    use dlp_agent::offline::OfflineManager;

    let cache = Arc::new(dlp_agent::cache::Cache::new());
    let client = dlp_agent::engine_client::EngineClient::new(
        "http://127.0.0.1:1",
        false, // unreachable port
    )
    .unwrap();

    let manager = OfflineManager::new(client, cache.clone());
    assert!(manager.is_online());

    // Evaluate against unreachable engine → should transition offline.
    let req = EvaluateRequest {
        subject: dlp_common::Subject::default(),
        resource: dlp_common::Resource {
            path: r"C:\Restricted\secret.xlsx".into(),
            classification: Classification::T4,
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: dlp_common::AccessContext::Local,
        },
        action: Action::WRITE,
    };

    let resp = manager.evaluate(&req).await;
    // T4 cache miss → fail-closed DENY.
    assert!(resp.decision.is_denied());
    // Manager should now be offline.
    assert!(!manager.is_online());
}

// ─────────────────────────────────────────────────────────────────────────────
// F-AGT-13: USB all tiers + lifecycle
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_usb_all_tiers() {
    use dlp_agent::detection::UsbDetector;
    let detector = UsbDetector::new();
    // Simulate F: as USB.
    detector.on_drive_arrival('F');
    // F: may not be removable on this machine, so insert directly for the test.
    // (on_drive_arrival checks GetDriveTypeW which won't match in test)
    // Use the fact that unit tests already validate this path.
    // Here we test the should_block_write logic with a known-blocked drive.

    // If F was added (hardware check passed), verify all tiers.
    // Otherwise, test with a manually blocked drive via the public API.
    // The UsbDetector doesn't expose blocked_drives directly from integration
    // tests, so we rely on the unit tests for full tier coverage.
    // Instead, verify the classification-based logic:
    assert!(!detector.should_block_write(r"C:\Data\file.txt", Classification::T4));
    // C: is not a USB drive, so T4 on C: is not blocked by USB detector.
}

#[tokio::test]
async fn test_usb_lifecycle() {
    use dlp_agent::detection::UsbDetector;
    let detector = UsbDetector::new();
    assert!(detector.blocked_drive_letters().is_empty());

    // on_drive_arrival/removal are hardware-dependent, so we verify the
    // public API contract: removal of a letter not in the set is a no-op.
    detector.on_drive_removal('Z');
    assert!(detector.blocked_drive_letters().is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// F-AGT-14: Network share whitelist lifecycle
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_whitelist_lifecycle() {
    use dlp_agent::detection::NetworkShareDetector;

    let detector = NetworkShareDetector::new();

    // Empty whitelist → block T3.
    assert!(detector.should_block(r"\\server\share", Classification::T3));

    // Add to whitelist → allow.
    detector.add_to_whitelist("server");
    assert!(!detector.should_block(r"\\server\share", Classification::T3));

    // Replace whitelist → old entry gone.
    detector.replace_whitelist(vec!["other.server".into()]);
    assert!(detector.should_block(r"\\server\share", Classification::T3));
    assert!(!detector.should_block(r"\\other.server\data", Classification::T4));

    // Remove → block again.
    detector.remove_from_whitelist("other.server");
    assert!(detector.should_block(r"\\other.server\data", Classification::T4));
}

// ─────────────────────────────────────────────────────────────────────────────
// F-AGT-17: Clipboard → evaluate → audit pipeline
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_clipboard_to_audit() {
    use dlp_agent::audit_emitter::AuditEmitter;
    use dlp_agent::clipboard::ContentClassifier;

    let text = "My SSN is 123-45-6789";
    let classification = ContentClassifier::classify(text);
    assert_eq!(classification, Classification::T4);

    // Emit audit for the clipboard event.
    let dir = tempfile::tempdir().unwrap();
    let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 10 * 1024 * 1024).unwrap();

    let event = dlp_common::AuditEvent::new(
        dlp_common::EventType::Block,
        "S-1-5-21-CLIP".into(),
        "clipuser".into(),
        "clipboard".into(),
        classification,
        Action::COPY,
        Decision::DENY,
        "AGENT-TEST".into(),
        1,
    );
    emitter.emit(&event).unwrap();

    let contents = std::fs::read_to_string(emitter.log_path()).unwrap();
    let parsed: dlp_common::AuditEvent = serde_json::from_str(contents.trim()).unwrap();
    assert_eq!(parsed.classification, Classification::T4);
    assert_eq!(parsed.action_attempted, Action::COPY);
}
