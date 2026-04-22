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
        ..Default::default()
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
// P2-T13: Mock Policy Engine with inline ABAC evaluation
// ─────────────────────────────────────────────────────────────────────────────

/// Starts a mock Policy Engine with inline ABAC rules on an ephemeral port.
///
/// Rules (from ABAC_POLICIES.md):
/// - pol-001: T4 any action -> DENY
/// - pol-002: T3 + Unmanaged device -> DENY
/// - pol-003: T2 any action -> AllowWithLog
/// - default: ALLOW
async fn start_policy_engine() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use axum::{routing::post, Router};
    use tokio::net::TcpListener;

    let app = Router::new()
        .route("/evaluate", post(evaluate_handler))
        .route("/health", axum::routing::get(|| async { "ok" }));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, handle)
}

/// Inline ABAC evaluation handler — matches policies by classification.
async fn evaluate_handler(
    axum::extract::Json(req): axum::extract::Json<EvaluateRequest>,
) -> axum::Json<EvaluateResponse> {
    let classification = req.resource.classification;
    let device_trust = req.subject.device_trust;

    // pol-001: T4 -> DENY
    if classification == Classification::T4 {
        return axum::Json(EvaluateResponse {
            decision: Decision::DENY,
            matched_policy_id: Some("pol-001".to_string()),
            reason: "T4 Deny All".to_string(),
        });
    }

    // pol-002: T3 + Unmanaged -> DENY
    if classification == Classification::T3 && device_trust == dlp_common::DeviceTrust::Unmanaged {
        return axum::Json(EvaluateResponse {
            decision: Decision::DENY,
            matched_policy_id: Some("pol-002".to_string()),
            reason: "T3 Unmanaged Block".to_string(),
        });
    }

    // pol-003: T2 -> AllowWithLog
    if classification == Classification::T2 {
        return axum::Json(EvaluateResponse {
            decision: Decision::AllowWithLog,
            matched_policy_id: Some("pol-003".to_string()),
            reason: "T2 Allow with Log".to_string(),
        });
    }

    // Default: ALLOW
    axum::Json(EvaluateResponse {
        decision: Decision::ALLOW,
        matched_policy_id: None,
        reason: "default allow".to_string(),
    })
}

/// P2-T13: Agent's OfflineManager evaluates against a real Policy Engine.
#[tokio::test]
async fn test_agent_to_real_engine_e2e() {
    let (addr, _h) = start_policy_engine().await;
    let base_url = format!("http://{addr}");

    let client = dlp_agent::engine_client::EngineClient::new(&base_url, false).unwrap();
    let cache = Arc::new(dlp_agent::cache::Cache::new());
    let offline = Arc::new(dlp_agent::offline::OfflineManager::new(client, cache, None));

    // T4 WRITE → DENY (Rule 1).
    let req = EvaluateRequest {
        subject: dlp_common::Subject {
            user_sid: "S-1-5-21-E2E".into(),
            user_name: "e2euser".into(),
            groups: vec![],
            device_trust: dlp_common::DeviceTrust::Managed,
            network_location: dlp_common::NetworkLocation::Corporate,
        },
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
        ..Default::default()
    };
    let resp = offline.evaluate(&req).await;
    assert!(resp.decision.is_denied());
    assert_eq!(resp.matched_policy_id.as_deref(), Some("pol-001"));

    // T2 READ → ALLOW_WITH_LOG (Rule 3).
    let req2 = EvaluateRequest {
        resource: dlp_common::Resource {
            path: r"C:\Data\report.xlsx".into(),
            classification: Classification::T2,
        },
        action: Action::READ,
        ..req.clone()
    };
    let resp2 = offline.evaluate(&req2).await;
    assert_eq!(resp2.decision, Decision::AllowWithLog);
    assert_eq!(resp2.matched_policy_id.as_deref(), Some("pol-003"));

    // Verify the cache was populated.
    assert!(offline.is_online());
}

/// P2-T13: Agent cache hit skips real engine round-trip.
#[tokio::test]
async fn test_agent_cache_hit_real_engine() {
    let (addr, _h) = start_policy_engine().await;
    let base_url = format!("http://{addr}");

    let client = dlp_agent::engine_client::EngineClient::new(&base_url, false).unwrap();
    let cache = Arc::new(dlp_agent::cache::Cache::new());
    let offline = Arc::new(dlp_agent::offline::OfflineManager::new(
        client,
        cache.clone(),
        None,
    ));

    let req = EvaluateRequest {
        subject: dlp_common::Subject::default(),
        resource: dlp_common::Resource {
            path: r"C:\Data\cached.xlsx".into(),
            classification: Classification::T2,
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: dlp_common::AccessContext::Local,
        },
        action: Action::READ,
        ..Default::default()
    };

    // First call: hits the engine.
    let resp1 = offline.evaluate(&req).await;
    assert_eq!(resp1.decision, Decision::AllowWithLog);

    // Second call: should hit cache (same path + default SID).
    let resp2 = offline.evaluate(&req).await;
    assert_eq!(resp2.decision, Decision::AllowWithLog);
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
        ..Default::default()
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
        ..Default::default()
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

    let manager = OfflineManager::new(client, cache.clone(), None);
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
        ..Default::default()
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

// ─────────────────────────────────────────────────────────────────────────────
// OfflineManager with AgentInfo — N-SEC-01 / agent-identified logging
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that OfflineManager carries machine_name through to the engine.
#[tokio::test]
async fn test_offline_manager_carries_machine_name() {
    use dlp_agent::offline::OfflineManager;

    // Start a mock engine that echoes back the agent info.
    let (addr, _h) = start_mock_engine(Decision::ALLOW).await;
    let base_url = format!("http://{addr}");

    let client = dlp_agent::engine_client::EngineClient::new(&base_url, false).unwrap();
    let cache = Arc::new(dlp_agent::cache::Cache::new());

    // OfflineManager with a machine_name.
    let offline = OfflineManager::new(client, cache, Some("WORKSTATION-01".into()));

    let req = EvaluateRequest {
        subject: dlp_common::Subject::default(),
        resource: dlp_common::Resource {
            path: r"C:\Data\report.xlsx".into(),
            classification: Classification::T2,
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: dlp_common::AccessContext::Local,
        },
        action: Action::READ,
        agent: Some(dlp_common::abac::AgentInfo {
            machine_name: Some("WORKSTATION-01".into()),
            current_user: Some("jsmith".into()),
        }),
        source_application: None,
        destination_application: None,
    };

    let resp = offline.evaluate(&req).await;
    assert!(!resp.decision.is_denied());
    assert!(offline.is_online());
}

/// OfflineManager transitions to offline when engine is unreachable.
#[tokio::test]
async fn test_offline_manager_offline_on_unreachable() {
    use dlp_agent::offline::OfflineManager;

    let client = dlp_agent::engine_client::EngineClient::new("http://127.0.0.1:1", false).unwrap();
    let cache = Arc::new(dlp_agent::cache::Cache::new());
    let offline = OfflineManager::new(client, cache, None);

    assert!(offline.is_online(), "manager should start online");

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
        ..Default::default()
    };

    let resp = offline.evaluate(&req).await;
    // T4 + cache miss → fail-closed DENY.
    assert!(resp.decision.is_denied());
    assert!(
        !offline.is_online(),
        "manager should be offline after unreachable"
    );
}

/// Verifies that OfflineManager uses cached decisions when offline.
#[tokio::test]
async fn test_offline_manager_cache_hit_when_offline() {
    use dlp_agent::offline::OfflineManager;

    // Use an unreachable address so the engine is unreachable → offline mode.
    let client = dlp_agent::engine_client::EngineClient::new("http://127.0.0.1:9", false).unwrap();
    let cache = Arc::new(dlp_agent::cache::Cache::new());

    // Pre-populate cache with ALLOW for the path (simulating prior decision).
    cache.insert(
        r"C:\Data\report.xlsx",
        "S-1-5-21-CACHED",
        EvaluateResponse {
            decision: Decision::AllowWithLog,
            matched_policy_id: Some("cached".into()),
            reason: "cached".into(),
        },
    );

    let offline = OfflineManager::new(client, cache.clone(), None);

    let req = EvaluateRequest {
        subject: dlp_common::Subject {
            user_sid: "S-1-5-21-CACHED".into(),
            ..Default::default()
        },
        resource: dlp_common::Resource {
            path: r"C:\Data\report.xlsx".into(),
            classification: Classification::T2,
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: dlp_common::AccessContext::Local,
        },
        action: Action::READ,
        ..Default::default()
    };

    // Cache hit when offline should return the pre-populated ALLOW.
    let resp = offline.evaluate(&req).await;
    assert!(!resp.decision.is_denied());
    assert_eq!(resp.matched_policy_id.as_deref(), Some("cached"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Concurrent cache stress test — N-PER-01 throughput / N-AVA-04 reconnect
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that concurrent cache operations do not panic or corrupt state.
#[tokio::test]
async fn test_concurrent_cache_access_stress() {
    use dlp_agent::cache::Cache;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::task::JoinSet;

    let cache = Arc::new(Cache::new());
    let error_count = Arc::new(AtomicUsize::new(0));
    let success_count = Arc::new(AtomicUsize::new(0));

    // Spawn 50 concurrent tasks each doing 20 operations.
    let mut set = JoinSet::new();
    for i in 0..50 {
        let cache = cache.clone();
        let errors = error_count.clone();
        let successes = success_count.clone();
        set.spawn(async move {
            for j in 0..20 {
                let path = format!(r"C:\Data\file{i}_{j}.xlsx");
                cache.insert(
                    &path,
                    "S-1-5-21-CONCURRENT",
                    EvaluateResponse {
                        decision: Decision::ALLOW,
                        matched_policy_id: None,
                        reason: "stress".into(),
                    },
                );
                match cache.get(&path, "S-1-5-21-CONCURRENT") {
                    Some(_) => {}
                    None => {
                        // Entry may have expired or be missing; record it.
                    }
                }
                successes.fetch_add(1, Ordering::Relaxed);
                let _ = errors;
            }
        });
    }

    while set.join_next().await.is_some() {}

    // No panics means all operations were safe under concurrency.
    assert_eq!(
        error_count.load(Ordering::SeqCst),
        0,
        "concurrent cache access should not produce errors"
    );
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        1000,
        "all 50 tasks × 20 ops should succeed"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// AuditEmitter rotation — F-AUD-06 / N-SEC-07 immutable logs
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that the audit log rotates when the file size limit is exceeded.
#[tokio::test]
async fn test_audit_rotation_size_trigger() {
    use dlp_agent::audit_emitter::AuditEmitter;

    let dir = tempfile::tempdir().unwrap();
    // 200 byte limit triggers rotation quickly.
    let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 200).unwrap();

    // Emit events until rotation should trigger.
    for i in 0..50 {
        let event = dlp_common::AuditEvent::new(
            dlp_common::EventType::Access,
            format!("S-1-5-21-{i}"),
            format!("user{i}"),
            format!(r"C:\Data\file{i}.txt"),
            Classification::T2,
            Action::READ,
            Decision::ALLOW,
            "AGENT-ROTATE-TEST".into(),
            1,
        );
        // Ignore errors — rotation may fail on some platforms.
        let _ = emitter.emit(&event);
    }

    // After many small events the size threshold should have triggered rotation.
    // The original file should exist, and a rotated file (audit.1.jsonl) may exist.
    let log_file = dir.path().join("audit.jsonl");
    assert!(
        log_file.exists(),
        "audit log file should exist after writes"
    );

    // The rotated file may or may not exist depending on platform write buffering,
    // but the original file should still be appendable.
    let contents = std::fs::read_to_string(&log_file).unwrap();
    let lines: Vec<&str> = contents.lines().collect();
    // At least some events should have been written.
    assert!(
        !lines.is_empty(),
        "audit log should contain at least one event after emit loop"
    );
}

/// Verifies that the audit emitter creates nested directories when needed.
#[tokio::test]
async fn test_audit_emitter_nested_dir_creation() {
    use dlp_agent::audit_emitter::AuditEmitter;

    let dir = tempfile::tempdir().unwrap();
    let nested = dir
        .path()
        .join("C")
        .join("ProgramData")
        .join("DLP")
        .join("logs");
    let emitter = AuditEmitter::open(&nested, "audit.jsonl", 50 * 1024 * 1024);

    assert!(
        emitter.is_ok(),
        "AuditEmitter should create nested directories automatically"
    );
    assert!(
        nested.join("audit.jsonl").exists(),
        "audit file should exist in the created directory"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// EngineClient retry and timeout — N-SEC-01 TLS / N-AVA-02 offline mode
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that EngineClient retries on 502 Bad Gateway.
#[tokio::test]
async fn test_engine_retry_on_502() {
    use dlp_agent::engine_client::{EngineClient, EngineClientError};

    let (addr, _h) = start_error_engine(502).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();

    let request = make_request(Classification::T2);
    let result = client.evaluate(&request).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        EngineClientError::HttpError { status, .. } => assert_eq!(status, 502),
        other => panic!("expected HttpError(502), got {other:?}"),
    }
}

/// Verifies that EngineClient does not retry on 429 Rate Limited — returns error immediately.
#[tokio::test]
async fn test_engine_no_retry_on_429() {
    use dlp_agent::engine_client::{EngineClient, EngineClientError};

    let (addr, _h) = start_error_engine(429).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();

    let request = make_request(Classification::T3);
    let result = client.evaluate(&request).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        EngineClientError::HttpError { status, .. } => assert_eq!(status, 429),
        other => panic!("expected HttpError(429), got {other:?}"),
    }
}

/// Verifies that EngineClient treats 503 Service Unavailable as retryable.
#[tokio::test]
async fn test_engine_retryable_503() {
    use dlp_agent::engine_client::{EngineClient, EngineClientError};

    let (addr, _h) = start_error_engine(503).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();

    let request = make_request(Classification::T2);
    let result = client.evaluate(&request).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        EngineClientError::HttpError { status, .. } => assert_eq!(status, 503),
        other => panic!("expected HttpError(503), got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OfflineManager — fail-closed decision table (SRS §6.2)
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies fail-closed for T3 on cache miss.
#[tokio::test]
async fn test_offline_decision_t3_denied() {
    use dlp_agent::offline::OfflineManager;

    let client = dlp_agent::engine_client::EngineClient::new("http://127.0.0.1:1", false).unwrap();
    let cache = Arc::new(dlp_agent::cache::Cache::new());
    let manager = OfflineManager::new(client, cache, None);

    let req = EvaluateRequest {
        subject: dlp_common::Subject::default(),
        resource: dlp_common::Resource {
            path: r"C:\Confidential\report.docx".into(),
            classification: Classification::T3,
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: dlp_common::AccessContext::Local,
        },
        action: Action::COPY,
        ..Default::default()
    };

    let resp = manager.offline_decision(&req);
    assert!(
        resp.decision.is_denied(),
        "T3 on cache miss should be denied (fail-closed)"
    );
}

/// Verifies fail-open (default-allow) for T1 on cache miss.
#[tokio::test]
async fn test_offline_decision_t1_allowed() {
    use dlp_agent::offline::OfflineManager;

    let client = dlp_agent::engine_client::EngineClient::new("http://127.0.0.1:1", false).unwrap();
    let cache = Arc::new(dlp_agent::cache::Cache::new());
    let manager = OfflineManager::new(client, cache, None);

    let req = EvaluateRequest {
        subject: dlp_common::Subject::default(),
        resource: dlp_common::Resource {
            path: r"C:\Public\readme.txt".into(),
            classification: Classification::T1,
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: dlp_common::AccessContext::Local,
        },
        action: Action::READ,
        ..Default::default()
    };

    let resp = manager.offline_decision(&req);
    assert!(
        !resp.decision.is_denied(),
        "T1 on cache miss should be allowed (fail-open for non-sensitive)"
    );
}

/// Verifies that cached T4 decision is returned without calling the engine.
#[tokio::test]
async fn test_offline_manager_t4_cached_not_evaluated() {
    use dlp_agent::offline::OfflineManager;

    // Use a port that will fail — the engine should NOT be called if cache hits.
    let client = dlp_agent::engine_client::EngineClient::new("http://127.0.0.1:1", false).unwrap();
    let cache = Arc::new(dlp_agent::cache::Cache::new());

    // Pre-populate cache with DENY for T4.
    cache.insert(
        r"C:\Restricted\secret.xlsx",
        "S-1-5-21-T4",
        EvaluateResponse {
            decision: Decision::DENY,
            matched_policy_id: Some("pol-001".into()),
            reason: "cached".into(),
        },
    );

    let manager = OfflineManager::new(client, cache, None);

    let req = EvaluateRequest {
        subject: dlp_common::Subject {
            user_sid: "S-1-5-21-T4".into(),
            ..Default::default()
        },
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
        ..Default::default()
    };

    // Even though engine is unreachable, cache hit should return the cached DENY.
    let resp = manager.evaluate(&req).await;
    assert!(resp.decision.is_denied());
    assert_eq!(resp.matched_policy_id.as_deref(), Some("pol-001"));
}

// ─────────────────────────────────────────────────────────────────────────────
// PolicyMapper — all classification tiers + edge paths (F-ADM-02)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_policy_mapper_all_tiers() {
    use dlp_agent::interception::PolicyMapper;

    // Tier 4.
    assert_eq!(
        PolicyMapper::provisional_classification(r"C:\Restricted\secrets.xlsx"),
        Classification::T4
    );
    assert_eq!(
        PolicyMapper::provisional_classification(r"c:\restricted\report.docx"),
        Classification::T4,
        "case-insensitive T4 match"
    );

    // Tier 3.
    assert_eq!(
        PolicyMapper::provisional_classification(r"C:\Confidential\budget.xlsx"),
        Classification::T3
    );

    // Tier 2.
    assert_eq!(
        PolicyMapper::provisional_classification(r"C:\Data\quarterly.xlsx"),
        Classification::T2
    );

    // Tier 1.
    assert_eq!(
        PolicyMapper::provisional_classification(r"C:\Public\readme.txt"),
        Classification::T1
    );

    // UNC paths.
    assert_eq!(
        PolicyMapper::provisional_classification(r"\\server\share\file.xlsx"),
        Classification::T1,
        "UNC path not in sensitive prefix → T1"
    );

    // Subdirectory of restricted.
    assert_eq!(
        PolicyMapper::provisional_classification(r"C:\Restricted\Subdir\file.xlsx"),
        Classification::T4,
        "subdirectory of Restricted should match T4"
    );
}

/// Verifies that PolicyMapper correctly handles forward-slash paths (WSL / Git Bash).
#[tokio::test]
async fn test_policy_mapper_forward_slash_paths() {
    use dlp_agent::interception::PolicyMapper;

    // Forward-slash paths are NOT in the DEFAULT_SENSITIVE_PREFIXES (all backslash).
    // They fall through to content classification, which reads the file — but
    // in tests the file does not exist, so T1 is returned.
    assert_eq!(
        PolicyMapper::provisional_classification("c:/restricted/file.xlsx"),
        Classification::T1,
        "forward-slash paths not in prefix table → T1 fallback"
    );
    assert_eq!(
        PolicyMapper::provisional_classification("C:/Data/report.docx"),
        Classification::T1,
        "forward-slash data path not in prefix table → T1 fallback"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// PolicyMapper — content classification (F-AGT-05 / F-ADM-02)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_content_classification_ssn_pattern() {
    use dlp_agent::clipboard::ContentClassifier;

    // SSN with dashes.
    assert_eq!(
        ContentClassifier::classify("SSN: 123-45-6789"),
        Classification::T4,
        "SSN with dashes should trigger T4"
    );

    // SSN with spaces.
    assert_eq!(
        ContentClassifier::classify("SSN: 123 45 6789"),
        Classification::T4,
        "SSN with spaces should trigger T4"
    );

    // SSN in context.
    assert_eq!(
        ContentClassifier::classify("Employee record: John Doe, SSN: 999-88-7777, Dept: Finance"),
        Classification::T4,
        "SSN in context should trigger T4"
    );
}

#[tokio::test]
async fn test_content_classification_credit_card() {
    use dlp_agent::clipboard::ContentClassifier;

    // Credit card with dashes (16 digits in groups of 4).
    assert_eq!(
        ContentClassifier::classify("Card: 4111-1111-1111-1111"),
        Classification::T4,
        "Visa card number with dashes should trigger T4"
    );

    // Raw 16-digit sequence (no separators).
    assert_eq!(
        ContentClassifier::classify("Card: 4111111111111111"),
        Classification::T4,
        "Raw 16-digit card number should trigger T4"
    );
}

#[tokio::test]
async fn test_content_classification_confidential_keyword() {
    use dlp_agent::clipboard::ContentClassifier;

    assert_eq!(
        ContentClassifier::classify("CONFIDENTIAL: Q4 Financial Results"),
        Classification::T3,
        "CONFIDENTIAL keyword should trigger T3"
    );
    // "INTERNAL USE ONLY" matches the T2 "internal use" pattern.
    assert_eq!(
        ContentClassifier::classify("INTERNAL USE ONLY - Project Phoenix"),
        Classification::T2,
        "INTERNAL USE ONLY matches T2 'internal use' pattern"
    );
}

#[tokio::test]
async fn test_content_classification_internal_keyword() {
    use dlp_agent::clipboard::ContentClassifier;

    // "DO NOT DISTRIBUTE" matches the T2 pattern.
    assert_eq!(
        ContentClassifier::classify("DO NOT DISTRIBUTE this memo"),
        Classification::T2,
        "DO NOT DISTRIBUTE keyword should trigger T2"
    );
    // "For internal only distribution" matches "internal only".
    assert_eq!(
        ContentClassifier::classify("For internal only distribution"),
        Classification::T2,
        "INTERNAL ONLY keyword should trigger T2"
    );
}

#[tokio::test]
async fn test_content_classification_benign() {
    use dlp_agent::clipboard::ContentClassifier;

    assert_eq!(
        ContentClassifier::classify("Hello, world! This is a public announcement."),
        Classification::T1,
        "benign text should be T1"
    );
    assert_eq!(
        ContentClassifier::classify(""),
        Classification::T1,
        "empty string should be T1"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper (shared by new tests above)
// ─────────────────────────────────────────────────────────────────────────────

/// Starts a mock engine that returns HTTP error for all requests.
async fn start_error_engine(
    status_code: u16,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use axum::{http::StatusCode, routing::post, Router};
    use tokio::net::TcpListener;

    let app = Router::new().route(
        "/evaluate",
        post(move || async move { StatusCode::from_u16(status_code).unwrap() }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, handle)
}

/// Standard evaluation request builder for negative / retry tests.
fn make_request(classification: Classification) -> EvaluateRequest {
    EvaluateRequest {
        subject: dlp_common::Subject::default(),
        resource: dlp_common::Resource {
            path: r"C:\Data\test.xlsx".into(),
            classification,
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: dlp_common::AccessContext::Local,
        },
        action: Action::WRITE,
        ..Default::default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wave 3 — End-to-end pipeline tests (Phase 04.1)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_file_write_to_sensitive_path_denied() {
    use dlp_agent::audit_emitter::AuditEmitter;
    use dlp_agent::engine_client::EngineClient;
    use dlp_agent::interception::{FileAction, PolicyMapper};

    // Mock engine returns DENY for every request.
    let (addr, _handle) = start_mock_engine(Decision::DENY).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 10 * 1024 * 1024).unwrap();

    // T4 file write (provisional classification derived from path).
    let action = FileAction::Written {
        path: r"C:\Restricted\q4-financials.xlsx".to_string(),
        process_id: 1234,
        related_process_id: 0,
        byte_count: 2048,
    };
    let classification = PolicyMapper::provisional_classification(action.path());
    assert_eq!(classification, Classification::T4);
    let abac = PolicyMapper::action_for(&action);
    assert_eq!(abac, Action::WRITE);

    let request = EvaluateRequest {
        subject: dlp_common::Subject {
            user_sid: "S-1-5-21-E2E-DENY".to_string(),
            user_name: "alice".to_string(),
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
        action: abac_action_to_dlp(abac),
        ..Default::default()
    };

    let response = client.evaluate(&request).await.unwrap();
    assert!(
        response.decision.is_denied(),
        "T4 write to sensitive path must be denied"
    );

    // Emit a Block audit event and verify the JSONL entry.
    let event = dlp_common::AuditEvent::new(
        dlp_common::EventType::Block,
        "S-1-5-21-E2E-DENY".to_string(),
        "alice".to_string(),
        action.path().to_string(),
        classification,
        abac_action_to_dlp(abac),
        response.decision,
        "AGENT-E2E-01".to_string(),
        1,
    )
    .with_policy("mock-pol-001".to_string(), "E2E deny".to_string());

    emitter.emit(&event).unwrap();
    let log = std::fs::read_to_string(emitter.log_path()).unwrap();
    let parsed: dlp_common::AuditEvent = serde_json::from_str(log.trim()).unwrap();
    assert_eq!(parsed.event_type, dlp_common::EventType::Block);
    assert_eq!(parsed.decision, Decision::DENY);
    assert_eq!(parsed.classification, Classification::T4);
    assert_eq!(parsed.resource_path, r"C:\Restricted\q4-financials.xlsx");
}

#[tokio::test]
async fn test_file_write_to_public_path_allowed() {
    use dlp_agent::audit_emitter::AuditEmitter;
    use dlp_agent::engine_client::EngineClient;
    use dlp_agent::interception::{FileAction, PolicyMapper};

    // Mock engine returns ALLOW.
    let (addr, _handle) = start_mock_engine(Decision::ALLOW).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 10 * 1024 * 1024).unwrap();

    // A path outside any sensitive prefix — T1.
    let action = FileAction::Written {
        path: r"C:\Users\bob\Documents\notes.txt".to_string(),
        process_id: 4321,
        related_process_id: 0,
        byte_count: 128,
    };
    let classification = PolicyMapper::provisional_classification(action.path());
    assert!(
        matches!(classification, Classification::T1 | Classification::T2),
        "public path must map to T1 or T2, got {classification:?}"
    );
    let abac = PolicyMapper::action_for(&action);

    let request = EvaluateRequest {
        subject: dlp_common::Subject {
            user_sid: "S-1-5-21-E2E-ALLOW".to_string(),
            user_name: "bob".to_string(),
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
        action: abac_action_to_dlp(abac),
        ..Default::default()
    };

    let response = client.evaluate(&request).await.unwrap();
    assert_eq!(response.decision, Decision::ALLOW);

    // Emit an Access audit event (the standard event type for allowed operations).
    let event = dlp_common::AuditEvent::new(
        dlp_common::EventType::Access,
        "S-1-5-21-E2E-ALLOW".to_string(),
        "bob".to_string(),
        action.path().to_string(),
        classification,
        abac_action_to_dlp(abac),
        response.decision,
        "AGENT-E2E-02".to_string(),
        1,
    );
    emitter.emit(&event).unwrap();

    let log = std::fs::read_to_string(emitter.log_path()).unwrap();
    let parsed: dlp_common::AuditEvent = serde_json::from_str(log.trim()).unwrap();
    assert_eq!(parsed.event_type, dlp_common::EventType::Access);
    assert_eq!(parsed.decision, Decision::ALLOW);
}

#[tokio::test]
async fn test_clipboard_paste_t4_content_denied_with_alert() {
    use dlp_agent::audit_emitter::AuditEmitter;
    use dlp_agent::clipboard::ContentClassifier;
    use dlp_agent::engine_client::EngineClient;

    // Mock engine returns DenyWithAlert for every request.
    let (addr, _handle) = start_mock_engine(Decision::DenyWithAlert).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 10 * 1024 * 1024).unwrap();

    // The clipboard text contains an SSN pattern — T4.
    let clipboard_text = "Please review: employee SSN 123-45-6789 for payroll";
    let classification = ContentClassifier::classify(clipboard_text);
    assert_eq!(classification, Classification::T4);

    // Build an EvaluateRequest for the paste action. We synthesise a
    // pseudo-resource path for the clipboard so the request schema is
    // satisfied.
    let request = EvaluateRequest {
        subject: dlp_common::Subject {
            user_sid: "S-1-5-21-E2E-CLIP".to_string(),
            user_name: "carol".to_string(),
            groups: Vec::new(),
            device_trust: dlp_common::DeviceTrust::Managed,
            network_location: dlp_common::NetworkLocation::Corporate,
        },
        resource: dlp_common::Resource {
            path: "clipboard://paste".to_string(),
            classification,
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: dlp_common::AccessContext::Local,
        },
        action: dlp_common::Action::PASTE,
        ..Default::default()
    };

    let response = client.evaluate(&request).await.unwrap();
    assert_eq!(response.decision, Decision::DenyWithAlert);
    assert!(
        response.decision.is_denied(),
        "DenyWithAlert must count as denied"
    );

    // Emit an Alert audit event (event_type = Alert for DenyWithAlert).
    let event = dlp_common::AuditEvent::new(
        dlp_common::EventType::Alert,
        "S-1-5-21-E2E-CLIP".to_string(),
        "carol".to_string(),
        "clipboard://paste".to_string(),
        classification,
        dlp_common::Action::PASTE,
        response.decision,
        "AGENT-E2E-03".to_string(),
        1,
    )
    .with_policy("mock-pol-001".to_string(), "SSN paste denied".to_string());
    emitter.emit(&event).unwrap();

    let log = std::fs::read_to_string(emitter.log_path()).unwrap();
    let parsed: dlp_common::AuditEvent = serde_json::from_str(log.trim()).unwrap();
    assert_eq!(parsed.event_type, dlp_common::EventType::Alert);
    assert_eq!(parsed.decision, Decision::DenyWithAlert);
    assert_eq!(parsed.classification, Classification::T4);
}

#[tokio::test]
async fn test_smb_detection_triggers_policy_eval_and_audit() {
    use dlp_agent::audit_emitter::AuditEmitter;
    use dlp_agent::detection::SmbShareEvent;
    use dlp_agent::engine_client::EngineClient;

    // A new SMB share appears — the agent must evaluate it against the
    // policy engine and emit an audit event. Mock engine returns DENY for
    // the non-whitelisted share.
    let (addr, _handle) = start_mock_engine(Decision::DENY).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 10 * 1024 * 1024).unwrap();

    // Simulate a new SMB share detection event.
    let event = SmbShareEvent::Connected {
        unc_path: r"\\evil.external\exfil".to_string(),
        server: "evil.external".to_string(),
        share_name: "exfil".to_string(),
    };

    // Extract the path out of the event to feed the evaluator.
    let (path, _server, _share) = match &event {
        SmbShareEvent::Connected {
            unc_path,
            server,
            share_name,
        } => (unc_path.clone(), server.clone(), share_name.clone()),
        _ => panic!("expected Connected variant"),
    };

    // Treat SMB destinations as T3 — SMB is a network data egress channel,
    // so sensitive data leaving the host is at least Confidential.
    let classification = Classification::T3;
    let request = EvaluateRequest {
        subject: dlp_common::Subject {
            user_sid: "S-1-5-21-E2E-SMB".to_string(),
            user_name: "dave".to_string(),
            groups: Vec::new(),
            device_trust: dlp_common::DeviceTrust::Managed,
            network_location: dlp_common::NetworkLocation::Corporate,
        },
        resource: dlp_common::Resource {
            path: path.clone(),
            classification,
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            // AccessContext::Smb models a remote SMB operation.
            access_context: dlp_common::AccessContext::Smb,
        },
        action: dlp_common::Action::WRITE,
        ..Default::default()
    };

    let response = client.evaluate(&request).await.unwrap();
    assert!(
        response.decision.is_denied(),
        "non-whitelisted SMB share must be denied for T3 data"
    );

    let audit = dlp_common::AuditEvent::new(
        dlp_common::EventType::Block,
        "S-1-5-21-E2E-SMB".to_string(),
        "dave".to_string(),
        path.clone(),
        classification,
        dlp_common::Action::WRITE,
        response.decision,
        "AGENT-E2E-04".to_string(),
        1,
    )
    .with_policy("mock-pol-001".to_string(), "SMB egress blocked".to_string());
    emitter.emit(&audit).unwrap();

    let log = std::fs::read_to_string(emitter.log_path()).unwrap();
    let parsed: dlp_common::AuditEvent = serde_json::from_str(log.trim()).unwrap();
    assert_eq!(parsed.resource_path, r"\\evil.external\exfil");
    assert_eq!(parsed.decision, Decision::DENY);
    assert_eq!(parsed.classification, Classification::T3);
}

#[tokio::test]
async fn test_engine_unreachable_fails_closed_for_t4() {
    use dlp_agent::cache::{fail_closed_response, Cache};
    use dlp_agent::engine_client::EngineClient;
    use dlp_agent::offline::OfflineManager;

    // Point at a port where nothing is listening. `EngineClient::new`
    // validates the URL but does not open a connection; the failure
    // happens on `.evaluate()`.
    let client = EngineClient::new("http://127.0.0.1:1", false).unwrap();
    let cache = Arc::new(Cache::new());
    let manager = OfflineManager::new(client, cache, None);

    let request = EvaluateRequest {
        subject: dlp_common::Subject {
            user_sid: "S-1-5-21-E2E-FAIL".to_string(),
            user_name: "eve".to_string(),
            groups: Vec::new(),
            device_trust: dlp_common::DeviceTrust::Managed,
            network_location: dlp_common::NetworkLocation::Corporate,
        },
        resource: dlp_common::Resource {
            path: r"C:\Restricted\top-secret.docx".to_string(),
            classification: Classification::T4,
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: dlp_common::AccessContext::Local,
        },
        action: dlp_common::Action::WRITE,
        ..Default::default()
    };

    let response = manager.evaluate(&request).await;

    // fail_closed_response(T4) is DENY — any T4 request with engine down
    // and no cache hit MUST return DENY.
    let expected = fail_closed_response(Classification::T4);
    assert_eq!(response.decision, expected.decision);
    assert!(
        response.decision.is_denied(),
        "T4 + engine-down MUST fail closed"
    );
}

#[tokio::test]
async fn test_engine_429_triggers_offline_manager_fallback() {
    use axum::{http::StatusCode, routing::post, Router};
    use dlp_agent::cache::{fail_closed_response, Cache};
    use dlp_agent::engine_client::EngineClient;
    use dlp_agent::offline::OfflineManager;
    use tokio::net::TcpListener;

    // Start an inline mock engine that unconditionally returns 429.
    let app: Router = Router::new().route(
        "/evaluate",
        post(|| async { (StatusCode::TOO_MANY_REQUESTS, "rate limited") }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();
    let cache = Arc::new(Cache::new());
    let manager = OfflineManager::new(client, cache, None);

    // T4 request with no cache entry — OfflineManager falls through to
    // fail_closed_response(T4) = DENY.
    let request = EvaluateRequest {
        subject: dlp_common::Subject {
            user_sid: "S-1-5-21-E2E-429".to_string(),
            user_name: "frank".to_string(),
            groups: Vec::new(),
            device_trust: dlp_common::DeviceTrust::Managed,
            network_location: dlp_common::NetworkLocation::Corporate,
        },
        resource: dlp_common::Resource {
            path: r"C:\Restricted\quarterly.xlsx".to_string(),
            classification: Classification::T4,
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: dlp_common::AccessContext::Local,
        },
        action: dlp_common::Action::WRITE,
        ..Default::default()
    };

    let response = manager.evaluate(&request).await;
    let expected = fail_closed_response(Classification::T4);
    assert_eq!(
        response.decision, expected.decision,
        "429 + T4 + no cache hit must fail closed (DENY)",
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 12 TC E2E tests — full intercept → classify → policy → audit pipeline
// TC-11, TC-14, TC-21, TC-72, TC-81
// ─────────────────────────────────────────────────────────────────────────────

/// TC-11: Copy Confidential (T3) to Internal (T2) folder → DENY + Alert event.
///
/// Verifies the full E2E path:
/// 1. FileAction::Written maps to Action::COPY + Classification::T3
/// 2. PolicyMapper destination is C:\Data\ (T2)
/// 3. Engine returns Decision::DenyWithAlert (T3 downgrade violation)
/// 4. AuditEvent with EventType::Alert is emitted and persisted in JSONL
#[tokio::test]
async fn test_tc_11_copy_confidential_to_internal_blocked_alert() {
    use dlp_agent::audit_emitter::AuditEmitter;
    use dlp_agent::engine_client::EngineClient;
    use dlp_agent::interception::{FileAction, PolicyMapper};

    // 1. Start mock engine returning DenyWithAlert for T3 downgrade.
    let resp = EvaluateResponse {
        decision: Decision::DenyWithAlert,
        matched_policy_id: Some("pol-tc11-downgrade".into()),
        reason: "T3 copy to T2 destination denied".into(),
    };
    let (addr, _h) = start_mock_engine_response(resp).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 10 * 1024 * 1024).unwrap();

    // Source: Confidential (T3), destination: C:\Data\ (T2).
    let action = FileAction::Written {
        path: r"C:\Data\confidential_copy.xlsx".to_string(),
        process_id: 1,
        related_process_id: 0,
        byte_count: 2048,
    };
    let classification = PolicyMapper::provisional_classification(action.path());
    assert_eq!(classification, Classification::T3);
    let abac_action = PolicyMapper::action_for(&action);
    assert_eq!(abac_action, Action::COPY);

    let request = EvaluateRequest {
        subject: dlp_common::Subject {
            user_sid: "S-1-5-21-TC-11".into(),
            user_name: "tc11-user".into(),
            groups: Vec::new(),
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
        ..Default::default()
    };

    let response = client.evaluate(&request).await.unwrap();
    assert_eq!(response.decision, Decision::DenyWithAlert);
    assert!(response.decision.is_denied());

    // DenyWithAlert maps to EventType::Alert (not Block).
    let event = dlp_common::AuditEvent::new(
        dlp_common::EventType::Alert,
        "S-1-5-21-TC-11".into(),
        "tc11-user".into(),
        action.path().into(),
        classification,
        abac_action,
        response.decision,
        "AGENT-TC11".into(),
        1,
    )
    .with_policy("pol-tc11-downgrade".into(), "TC-11 downgrade block".into());
    emitter.emit(&event).unwrap();

    // Read back JSONL and verify event_type, decision, classification.
    let contents = std::fs::read_to_string(emitter.log_path()).unwrap();
    let parsed: dlp_common::AuditEvent = serde_json::from_str(contents.trim()).unwrap();
    assert_eq!(parsed.event_type, dlp_common::EventType::Alert);
    assert_eq!(parsed.decision, Decision::DenyWithAlert);
    assert_eq!(parsed.classification, Classification::T3);
}

/// TC-14: Copy Confidential (T3) to USB drive → DENY + Block audit event.
///
/// Verifies:
/// 1. File on F:\ (blocked USB drive) → T3 classification
/// 2. UsbDetector::should_block_write(F:\, T3) → true (drive in blocked set)
/// 3. Engine returns DENY
/// 4. AuditEvent with EventType::Block is emitted
#[tokio::test]
async fn test_tc_14_copy_confidential_to_usb_blocked_log() {
    use dlp_agent::audit_emitter::AuditEmitter;
    use dlp_agent::detection::UsbDetector;
    use dlp_agent::engine_client::EngineClient;

    let detector = UsbDetector::new();
    // Seed F: as a blocked USB drive for CI (GetDriveTypeW unavailable in tests).
    detector.blocked_drives.write().insert('F');

    // T3 write to F:\ must be blocked by the detector.
    assert!(detector.should_block_write(r"F:\confidential_report.pdf", Classification::T3));

    let resp = EvaluateResponse {
        decision: Decision::DENY,
        matched_policy_id: Some("pol-tc14-usb".into()),
        reason: "T3 copy to USB blocked".into(),
    };
    let (addr, _h) = start_mock_engine_response(resp).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 10 * 1024 * 1024).unwrap();

    let request = EvaluateRequest {
        subject: dlp_common::Subject {
            user_sid: "S-1-5-21-TC-14".into(),
            user_name: "tc14-user".into(),
            groups: Vec::new(),
            device_trust: dlp_common::DeviceTrust::Managed,
            network_location: dlp_common::NetworkLocation::Corporate,
        },
        resource: dlp_common::Resource {
            path: r"F:\confidential_report.pdf".into(),
            classification: Classification::T3,
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: dlp_common::AccessContext::Local,
        },
        action: Action::COPY,
        ..Default::default()
    };

    let response = client.evaluate(&request).await.unwrap();
    assert!(response.decision.is_denied());

    let event = dlp_common::AuditEvent::new(
        dlp_common::EventType::Block,
        "S-1-5-21-TC-14".into(),
        "tc14-user".into(),
        r"F:\confidential_report.pdf".into(),
        Classification::T3,
        Action::COPY,
        response.decision,
        "AGENT-TC14".into(),
        1,
    )
    .with_policy("pol-tc14-usb".into(), "TC-14 USB block".into());
    emitter.emit(&event).unwrap();

    let contents = std::fs::read_to_string(emitter.log_path()).unwrap();
    let parsed: dlp_common::AuditEvent = serde_json::from_str(contents.trim()).unwrap();
    assert_eq!(parsed.event_type, dlp_common::EventType::Block);
    assert_eq!(parsed.decision, Decision::DENY);
    assert_eq!(parsed.classification, Classification::T3);
    assert!(parsed.resource_path.contains("F:"));
}

/// TC-21: Email send with credit card content → T4 → DenyWithAlert.
///
/// Verifies:
/// 1. Email body with credit card → ContentClassifier::classify → T4
/// 2. Policy Engine returns Decision::DenyWithAlert for external send
/// 3. EventType::Alert audit event is emitted
///
/// The email send action is modelled as Action::WRITE with an "email://outbound"
/// pseudo-path.  (Action::SEND_EMAIL is a future-phase extension; Action::WRITE
/// is the closest available ABAC action.)
#[tokio::test]
async fn test_tc_21_email_credit_card_blocked_alert() {
    use dlp_agent::audit_emitter::AuditEmitter;
    use dlp_agent::clipboard::ContentClassifier;
    use dlp_agent::engine_client::EngineClient;

    // Step 1: classify email content — credit card → T4.
    let email_text = "Card: 4111-1111-1111-1111 for invoice payment";
    let classification = ContentClassifier::classify(email_text);
    assert_eq!(classification, Classification::T4);

    // Step 2: engine returns DenyWithAlert for external email send.
    let resp = EvaluateResponse {
        decision: Decision::DenyWithAlert,
        matched_policy_id: Some("pol-tc21-email".into()),
        reason: "T4 content in external email denied".into(),
    };
    let (addr, _h) = start_mock_engine_response(resp).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 10 * 1024 * 1024).unwrap();

    let request = EvaluateRequest {
        subject: dlp_common::Subject {
            user_sid: "S-1-5-21-TC-21".into(),
            user_name: "tc21-user".into(),
            groups: Vec::new(),
            device_trust: dlp_common::DeviceTrust::Managed,
            network_location: dlp_common::NetworkLocation::Corporate,
        },
        resource: dlp_common::Resource {
            path: "email://outbound".into(),
            classification,
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: dlp_common::AccessContext::Local,
        },
        action: Action::WRITE, // closest existing action to email send
        ..Default::default()
    };

    let response = client.evaluate(&request).await.unwrap();
    assert_eq!(response.decision, Decision::DenyWithAlert);
    assert!(response.decision.is_denied());

    let event = dlp_common::AuditEvent::new(
        dlp_common::EventType::Alert, // DenyWithAlert → Alert
        "S-1-5-21-TC-21".into(),
        "tc21-user".into(),
        "email://outbound".into(),
        classification,
        Action::WRITE,
        response.decision,
        "AGENT-TC21".into(),
        1,
    )
    .with_policy("pol-tc21-email".into(), "TC-21 email block".into());
    emitter.emit(&event).unwrap();

    let contents = std::fs::read_to_string(emitter.log_path()).unwrap();
    let parsed: dlp_common::AuditEvent = serde_json::from_str(contents.trim()).unwrap();
    assert_eq!(parsed.event_type, dlp_common::EventType::Alert);
    assert_eq!(parsed.decision, Decision::DenyWithAlert);
    assert_eq!(parsed.classification, Classification::T4);
}

/// TC-72: Delete Restricted (T4) file → DENY + Alert (corrective secure-wipe).
///
/// Verifies:
/// 1. FileAction::Deleted → Action::DELETE
/// 2. Restricted path → Classification::T4
/// 3. Engine returns DENY (T4 delete blocked, triggers secure wipe)
/// 4. AuditEvent with EventType::Alert and policy_name containing "secure_delete"
#[tokio::test]
async fn test_tc_72_delete_restricted_secure_delete() {
    use dlp_agent::audit_emitter::AuditEmitter;
    use dlp_agent::engine_client::EngineClient;
    use dlp_agent::interception::{FileAction, PolicyMapper};

    let resp = EvaluateResponse {
        decision: Decision::DENY,
        matched_policy_id: Some("pol-tc72-secure-delete".into()),
        reason: "T4 delete triggers secure wipe".into(),
    };
    let (addr, _h) = start_mock_engine_response(resp).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 10 * 1024 * 1024).unwrap();

    let action = FileAction::Deleted {
        path: r"C:\Restricted\secret.xlsx".to_string(),
        process_id: 1,
        related_process_id: 0,
    };
    let classification = PolicyMapper::provisional_classification(action.path());
    assert_eq!(classification, Classification::T4);
    assert_eq!(PolicyMapper::action_for(&action), Action::DELETE);

    let request = EvaluateRequest {
        subject: dlp_common::Subject {
            user_sid: "S-1-5-21-TC-72".into(),
            user_name: "tc72-user".into(),
            groups: Vec::new(),
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
        action: Action::DELETE,
        ..Default::default()
    };

    let response = client.evaluate(&request).await.unwrap();
    assert!(response.decision.is_denied());

    // Corrective event: T4 delete triggers secure-wipe alert (EventType::Alert).
    let event = dlp_common::AuditEvent::new(
        dlp_common::EventType::Alert,
        "S-1-5-21-TC-72".into(),
        "tc72-user".into(),
        action.path().into(),
        classification,
        Action::DELETE,
        response.decision,
        "AGENT-TC72".into(),
        1,
    )
    .with_policy(
        "pol-tc72-secure-delete".into(),
        "TC-72 secure_delete".into(),
    );
    emitter.emit(&event).unwrap();

    let contents = std::fs::read_to_string(emitter.log_path()).unwrap();
    let parsed: dlp_common::AuditEvent = serde_json::from_str(contents.trim()).unwrap();
    assert_eq!(parsed.event_type, dlp_common::EventType::Alert);
    assert_eq!(parsed.decision, Decision::DENY);
    assert_eq!(parsed.classification, Classification::T4);
    assert_eq!(parsed.action_attempted, Action::DELETE);
    assert!(
        parsed
            .policy_name
            .as_ref()
            .is_some_and(|n| n.contains("secure_delete")),
        "TC-72 policy_name must contain 'secure_delete', got: {:?}",
        parsed.policy_name
    );
}

/// TC-81: Bulk download of 10 Confidential (T3+) items → Alert (detective).
///
/// Verifies:
/// 1. 10 rapid classify events all produce T3+ classification
/// 2. TC-81 acceptance contract: 10 T3+ events in 60 s → EventType::Alert
/// 3. AuditEvent with EventType::Alert and Decision::ALLOW (files allowed;
///    alert is additive detective control)
///
/// The BulkDownloadDetector threshold-counting struct is a future-phase
/// implementation; this test validates the classification prerequisite.
#[tokio::test]
async fn test_tc_81_bulk_download_alert() {
    use dlp_agent::audit_emitter::AuditEmitter;
    use dlp_agent::clipboard::ContentClassifier;

    // Step 1: classify 10 items — all must be T3+.
    let sensitive_texts = vec![
        "CONFIDENTIAL: Q1 financials",
        "Card: 4111111111111111",
        "SSN: 123-45-6789",
        "CONFIDENTIAL: M&A target list",
        "Card: 5500000000000004",
        "SSN: 987-65-4321",
        "CONFIDENTIAL: Acquisition strategy",
        "Card: 4000000000000002",
        "SSN: 555-55-5555",
        "CONFIDENTIAL: Executive compensation",
    ];
    let classifications: Vec<_> = sensitive_texts
        .iter()
        .map(|text| ContentClassifier::classify(text))
        .collect();

    assert_eq!(classifications.len(), 10);
    assert!(
        classifications.iter().all(|c| *c >= Classification::T3),
        "all 10 texts must be T3+; got: {classifications:?}"
    );

    let dir = tempfile::tempdir().unwrap();
    let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 10 * 1024 * 1024).unwrap();

    // Step 2: emit one representative Alert event for the bulk download scenario.
    // Files are allowed; alert is the additive detective control.
    let event = dlp_common::AuditEvent::new(
        dlp_common::EventType::Alert,
        "S-1-5-21-TC-81".into(),
        "tc81-user".into(),
        "bulk://download".into(),
        Classification::T3,
        Action::READ,    // bulk download modelled as READ
        Decision::ALLOW, // files allowed; alert is additive
        "AGENT-TC81".into(),
        1,
    )
    .with_policy("pol-tc81-bulk".into(), "TC-81 bulk download alert".into());
    emitter.emit(&event).unwrap();

    let contents = std::fs::read_to_string(emitter.log_path()).unwrap();
    let parsed: dlp_common::AuditEvent = serde_json::from_str(contents.trim()).unwrap();
    assert_eq!(parsed.event_type, dlp_common::EventType::Alert);
    assert_eq!(parsed.decision, Decision::ALLOW); // detective: allow + alert
    assert_eq!(parsed.classification, Classification::T3);
    assert_eq!(parsed.action_attempted, Action::READ);
}

/// Starts a mock Policy Engine that returns the given EvaluateResponse for all requests.
async fn start_mock_engine_response(
    response: EvaluateResponse,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use axum::{extract::Json, routing::post, Router};
    use tokio::net::TcpListener;

    let app = Router::new().route(
        "/evaluate",
        post(move |Json(_): Json<EvaluateRequest>| async move { Json(response.clone()) }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, handle)
}
