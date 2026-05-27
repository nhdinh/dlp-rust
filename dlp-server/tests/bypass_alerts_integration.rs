//! Integration tests for the bypass alerts API.
//!
//! Exercises POST /audit/bypass, GET /admin/bypass-alerts, and
//! POST /admin/bypass-alerts/{id}/ack via tower::ServiceExt::oneshot.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use chrono::Utc;
use dlp_server::admin_api::admin_router;
use dlp_server::admin_auth::{set_jwt_secret, Claims};
use dlp_server::{alert_router, db, policy_store, siem_connector, AppState};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::Value;
use tempfile::NamedTempFile;
use tower::ServiceExt;

const TEST_JWT_SECRET: &str = "dlp-server-dev-secret-change-me";

/// Builds a fresh test router backed by a temporary SQLite file.
fn build_test_app() -> (axum::Router, Arc<db::Pool>) {
    let _ = set_jwt_secret(TEST_JWT_SECRET.to_string());
    let tmp = NamedTempFile::new().expect("create temp db");
    let pool = Arc::new(db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
    let crypto = std::sync::Arc::new(dlp_server::crypto::SecretCrypto::from_kek(
        [0x77; 32],
        dlp_server::crypto::ENVELOPE_VERSION_V1,
    ));
    dlp_server::secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
        .expect("Phase 47 migration");
    let siem = siem_connector::SiemConnector::new(
        std::sync::Arc::clone(&pool),
        std::sync::Arc::clone(&crypto),
    );
    let alert = alert_router::AlertRouter::new(
        std::sync::Arc::clone(&pool),
        std::sync::Arc::clone(&crypto),
    );
    let ps = Arc::new(policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"));
    let label_service = Arc::new(dlp_server::label_service::LabelService::new(Arc::clone(
        &pool,
    )));
    let approval_token_crypto = dlp_server::crypto::SecretCrypto::from_kek([0x77; 32], 1);
    let approval_token_conn = pool.get().expect("pool");
    let approval_token_service = Arc::new(
        dlp_server::approval_token::ApprovalTokenService::new(
            &approval_token_crypto,
            &approval_token_conn,
        )
        .expect("approval token service"),
    );
    let syslog = dlp_server::syslog_connector::SyslogConnector::new(
        std::sync::Arc::clone(&pool),
        std::sync::Arc::clone(&crypto),
    );
    // Seed an admin user so the ack FK constraint resolves.
    {
        let conn = pool.get().expect("conn");
        conn.execute(
            "INSERT INTO admin_users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
            ["test-admin", "hash", "2026-01-01T00:00:00Z"],
        )
        .expect("seed admin user");
    }

    let state = Arc::new(AppState {
        pool: Arc::clone(&pool),
        crypto: std::sync::Arc::clone(&crypto),
        policy_store: ps,
        siem,
        alert,
        ad: None,
        label_service,
        approval_token_service,
        syslog,
        label_aware_enabled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        protected_paths: std::sync::Arc::new(
            dlp_server::db::repositories::protected_paths::ProtectedPathsRepository,
        ),
        bypass_alerts: std::sync::Arc::new(
            dlp_server::db::repositories::bypass_alerts::BypassAlertsRepository,
        ),
    });
    (admin_router(state), pool)
}

/// Mints a valid admin JWT for the test secret.
fn mint_jwt() -> String {
    let claims = Claims {
        sub: "test-admin".to_string(),
        exp: (Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
        iss: "dlp-server".to_string(),
        sid: None,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .expect("mint JWT")
}

/// Helper: POST /audit/bypass with a batch of alerts.
async fn post_bypass_batch(
    app: axum::Router,
    agent_id: &str,
    batch_id: &str,
    alerts: Vec<serde_json::Value>,
) -> (StatusCode, Value) {
    let body = serde_json::json!({
        "agent_id": agent_id,
        "batch_id": batch_id,
        "alerts": alerts,
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/audit/bypass")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("send request");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

/// Helper: make a single bypass alert JSON value.
fn make_alert(
    pid: u32,
    file_path: &str,
    severity: &str,
    reason: &str,
) -> serde_json::Value {
    serde_json::json!({
        "reason": reason,
        "stub_name": "NtCreateFile",
        "pid": pid,
        "timestamp_secs": 1700000000,
        "version": 2,
        "agent_id": "agent-test",
        "image_path": r"C:\Test\app.exe",
        "image_sha256": null,
        "file_path": file_path,
        "operation": "Create",
        "file_object": 0,
        "qpc_timestamp": 1000,
        "severity": severity,
        "correlation_reason": "NoHookJournal",
    })
}

// ---------------------------------------------------------------------------
// Test 1: batch ingest success
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_batch_ingest_success() {
    let (mut app, _pool) = build_test_app();

    let alerts = vec![
        make_alert(1234, r"C:\file1.txt", "crit", "NoHookJournal"),
        make_alert(1235, r"C:\file2.txt", "warn", "OpMismatch"),
    ];
    let (status, json) = post_bypass_batch(app.clone(), "agent-1", "batch-001", alerts).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["inserted"], 2);
    assert_eq!(json["skipped"], 0);
}

// ---------------------------------------------------------------------------
// Test 2: batch size capped at 100
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_batch_ingest_max_100() {
    let (mut app, _pool) = build_test_app();

    let mut alerts = Vec::new();
    for i in 0..101 {
        alerts.push(make_alert(1000 + i, &format!(r"C:\file{i}.txt"), "info", "NoHookJournal"));
    }
    let (status, json) = post_bypass_batch(app.clone(), "agent-1", "batch-002", alerts).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(json["error"].as_str().unwrap().contains("exceeds maximum"));
}

// ---------------------------------------------------------------------------
// Test 3: deduplication via unique constraint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_batch_ingest_deduplication() {
    let (mut app, _pool) = build_test_app();

    let alerts = vec![make_alert(1234, r"C:\file1.txt", "crit", "NoHookJournal")];
    let (status1, json1) = post_bypass_batch(app.clone(), "agent-1", "batch-003", alerts.clone()).await;
    assert_eq!(status1, StatusCode::OK);
    assert_eq!(json1["inserted"], 1);

    let (status2, json2) = post_bypass_batch(app.clone(), "agent-1", "batch-004", alerts).await;
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(json2["inserted"], 0);
    assert_eq!(json2["skipped"], 1);
}

// ---------------------------------------------------------------------------
// Test 4: batch_id stored
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_batch_ingest_batch_id_stored() {
    let (mut app, pool) = build_test_app();

    let alerts = vec![make_alert(1234, r"C:\file1.txt", "crit", "NoHookJournal")];
    let (status, _) = post_bypass_batch(app.clone(), "agent-1", "batch-005", alerts).await;
    assert_eq!(status, StatusCode::OK);

    // Verify in DB.
    let conn = pool.get().expect("conn");
    let batch_id: String = conn
        .query_row(
            "SELECT batch_id FROM bypass_alerts WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .expect("query");
    assert_eq!(batch_id, "batch-005");
}

// ---------------------------------------------------------------------------
// Test 5: v1 backward compatibility (missing fields get defaults)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_batch_ingest_v1_backward_compat() {
    let (mut app, _pool) = build_test_app();

    // Phase 51 v1 alert: only original fields, no file_object, version, etc.
    let v1_alert = serde_json::json!({
        "reason": "HookOverwritten",
        "stub_name": "NtCreateFile",
        "pid": 1234,
        "timestamp_secs": 1700000000,
    });
    let (status, json) = post_bypass_batch(app.clone(), "agent-1", "batch-006", vec![v1_alert]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["inserted"], 1);
}

// ---------------------------------------------------------------------------
// Test 6: list bypass alerts with pagination
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_bypass_alerts_pagination() {
    let (mut app, _pool) = build_test_app();

    // Insert 10 alerts.
    let mut alerts = Vec::new();
    for i in 0..10 {
        alerts.push(make_alert(1000 + i, &format!(r"C:\file{i}.txt"), "info", "NoHookJournal"));
    }
    let (status, _) = post_bypass_batch(app.clone(), "agent-1", "batch-007", alerts).await;
    assert_eq!(status, StatusCode::OK);

    // GET with limit=5.
    let jwt = mint_jwt();
    let req = Request::builder()
        .method(Method::GET)
        .uri("/admin/bypass-alerts?limit=5")
        .header("Authorization", format!("Bearer {jwt}"))
        .body(Body::empty())
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
    let json: Value = serde_json::from_slice(&bytes).expect("parse json");
    assert_eq!(json["alerts"].as_array().unwrap().len(), 5);
}

// ---------------------------------------------------------------------------
// Test 7: list bypass alerts filter by severity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_bypass_alerts_filter_severity() {
    let (mut app, _pool) = build_test_app();

    let alerts = vec![
        make_alert(1234, r"C:\file1.txt", "crit", "NoHookJournal"),
        make_alert(1235, r"C:\file2.txt", "warn", "NoHookJournal"),
        make_alert(1236, r"C:\file3.txt", "info", "NoHookJournal"),
    ];
    let (status, _) = post_bypass_batch(app.clone(), "agent-1", "batch-008", alerts).await;
    assert_eq!(status, StatusCode::OK);

    let jwt = mint_jwt();
    let req = Request::builder()
        .method(Method::GET)
        .uri("/admin/bypass-alerts?severity=crit")
        .header("Authorization", format!("Bearer {jwt}"))
        .body(Body::empty())
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
    let json: Value = serde_json::from_slice(&bytes).expect("parse json");
    let alerts_arr = json["alerts"].as_array().unwrap();
    assert_eq!(alerts_arr.len(), 1);
    assert_eq!(alerts_arr[0]["severity"], "crit");
}

// ---------------------------------------------------------------------------
// Test 8: list bypass alerts filter by PID
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_bypass_alerts_filter_pid() {
    let (mut app, _pool) = build_test_app();

    let alerts = vec![
        make_alert(1234, r"C:\file1.txt", "crit", "NoHookJournal"),
        make_alert(5678, r"C:\file2.txt", "warn", "NoHookJournal"),
    ];
    let (status, _) = post_bypass_batch(app.clone(), "agent-1", "batch-009", alerts).await;
    assert_eq!(status, StatusCode::OK);

    let jwt = mint_jwt();
    let req = Request::builder()
        .method(Method::GET)
        .uri("/admin/bypass-alerts?pid=1234")
        .header("Authorization", format!("Bearer {jwt}"))
        .body(Body::empty())
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
    let json: Value = serde_json::from_slice(&bytes).expect("parse json");
    let alerts_arr = json["alerts"].as_array().unwrap();
    assert_eq!(alerts_arr.len(), 1);
    assert_eq!(alerts_arr[0]["pid"], 1234);
}

// ---------------------------------------------------------------------------
// Test 9: ack bypass alert
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_ack_bypass_alert() {
    let (mut app, _pool) = build_test_app();

    let alerts = vec![make_alert(1234, r"C:\file1.txt", "crit", "NoHookJournal")];
    let (status, _) = post_bypass_batch(app.clone(), "agent-1", "batch-010", alerts).await;
    assert_eq!(status, StatusCode::OK);

    let jwt = mint_jwt();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/admin/bypass-alerts/1/ack")
        .header("Authorization", format!("Bearer {jwt}"))
        .body(Body::empty())
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Test 10: ack bypass alert idempotent
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_ack_bypass_alert_idempotent() {
    let (mut app, _pool) = build_test_app();

    let alerts = vec![make_alert(1234, r"C:\file1.txt", "crit", "NoHookJournal")];
    let (status, _) = post_bypass_batch(app.clone(), "agent-1", "batch-011", alerts).await;
    assert_eq!(status, StatusCode::OK);

    let jwt = mint_jwt();
    for _ in 0..2 {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/admin/bypass-alerts/1/ack")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build request");
        let resp = app.clone().oneshot(req).await.expect("send request");
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

// ---------------------------------------------------------------------------
// Test 11: ack non-existent alert returns 404
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_ack_bypass_alert_not_found() {
    let (mut app, _pool) = build_test_app();

    let jwt = mint_jwt();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/admin/bypass-alerts/9999/ack")
        .header("Authorization", format!("Bearer {jwt}"))
        .body(Body::empty())
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Test 12: empty batch returns 400
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_batch_ingest_empty_returns_400() {
    let (mut app, _pool) = build_test_app();

    let (status, json) = post_bypass_batch(app.clone(), "agent-1", "batch-012", vec![]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(json["error"].as_str().unwrap().contains("must not be empty"));
}

// ---------------------------------------------------------------------------
// Test 13: admin routes require JWT
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_bypass_alerts_requires_auth() {
    let (mut app, _pool) = build_test_app();

    let req = Request::builder()
        .method(Method::GET)
        .uri("/admin/bypass-alerts")
        .body(Body::empty())
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_ack_bypass_alert_requires_auth() {
    let (mut app, _pool) = build_test_app();

    let req = Request::builder()
        .method(Method::POST)
        .uri("/admin/bypass-alerts/1/ack")
        .body(Body::empty())
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
