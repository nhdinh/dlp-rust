//! Integration tests for agent health/diagnostics ingest and admin dashboard (DIFF-04).
//!
//! Exercises the authenticated round-trips:
//! - POST /agents/{id}/health  ->  GET /admin/health
//! - POST /agents/{id}/diagnostics  ->  GET /admin/diagnostics
//! along with auth failure cases.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use chrono::Utc;
use dlp_server::admin_api::admin_router;
use dlp_server::admin_auth::{set_jwt_secret, Claims};
use dlp_server::{
    alert_router, db, diagnostic_store, health_snapshot_store, policy_store, siem_connector, AppState,
};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::Value;
use tempfile::NamedTempFile;
use tower::ServiceExt;

const TEST_JWT_SECRET: &str = "dlp-server-dev-secret-change-me";
const TEST_AGENT_AUTH_HASH: &str = "$2a$12$dlp.test.hash.for.agent.auth";
const TEST_AGENT_ID: &str = "integration-test-agent";

/// Builds a fresh test router backed by a temporary SQLite file.
///
/// Seeds an admin user and the agent auth hash so both JWT-protected admin
/// endpoints and agent-authenticated ingest endpoints work.
fn build_test_app() -> (axum::Router, Arc<db::Pool>) {
    set_jwt_secret(TEST_JWT_SECRET.to_string());
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

    // Seed admin user (required for admin JWT auth) and agent auth hash.
    {
        let conn = pool.get().expect("conn");
        conn.execute(
            "INSERT INTO admin_users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
            ["test-admin", "hash", "2026-01-01T00:00:00Z"],
        )
        .expect("seed admin user");
        conn.execute(
            "INSERT INTO agent_credentials (key, value, updated_at) VALUES (?1, ?2, ?3)",
            ["DLPAuthHash", TEST_AGENT_AUTH_HASH, "2026-01-01T00:00:00Z"],
        )
        .expect("seed agent auth hash");
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
        diagnostic_store: Some(Arc::new(diagnostic_store::DiagnosticSnapshotStore::new())),
        health_snapshot_store: Some(Arc::new(health_snapshot_store::HealthSnapshotStore::new())),
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

/// Builds the `Authorization: DLP-AGENT {agent_id}:{hash}` header value.
fn agent_auth_header(agent_id: &str, hash: &str) -> String {
    format!("DLP-AGENT {}:{}", agent_id, hash)
}

// ---------------------------------------------------------------------------
// Test 1: health snapshot ingest surfaces in admin dashboard
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_agent_health_surfaces_in_admin_health() {
    let (app, _pool) = build_test_app();

    let snapshot = dlp_common::hook_ipc::HookHealthSnapshot {
        injected_pids: 3,
        patched_modules: 7,
        pipe_round_trips_60s: 42,
        cache_hit_rate_60s: 0.95,
        current_fail_state: 0,
        timestamp_secs: 1_700_000_000,
    };
    let payload = serde_json::json!({ "snapshot": snapshot });

    // Agent-authenticated ingest.
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("/agents/{}/health", TEST_AGENT_ID))
        .header("authorization", agent_auth_header(TEST_AGENT_ID, TEST_AGENT_AUTH_HASH))
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .expect("build request");

    let resp = app.clone().oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert_eq!(json["received"], true);

    // Admin dashboard reflects the ingested snapshot.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/admin/health")
        .header("authorization", format!("Bearer {}", mint_jwt()))
        .body(Body::empty())
        .expect("build request");

    let resp = app.oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    assert!(
        json["snapshot"].is_object(),
        "admin health snapshot should be present"
    );
    let status = json["snapshot"]["overall_status"]
        .as_str()
        .expect("overall_status should be a string");
    assert!(
        ["healthy", "degraded", "critical"].contains(&status),
        "unexpected overall_status: {status}"
    );

    let history = json["history"].as_array().expect("history array");
    assert!(!history.is_empty(), "history should contain at least one entry");
    assert_eq!(history[0]["injected_pids"], 3);
    assert_eq!(history[0]["patched_modules"], 7);
}

// ---------------------------------------------------------------------------
// Test 2: diagnostics ingest surfaces in admin diagnostics
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_agent_diagnostics_surfaces_in_admin_diagnostics() {
    let (app, _pool) = build_test_app();

    let diag = dlp_common::hook_ipc::DiagnosticSnapshot {
        hook_function: "WriteFile".to_string(),
        classification_source: dlp_common::hook_ipc::ClassificationSource::CacheHit,
        classification_age_ms: 42,
        abac_resource: r"C:\Data\secret.txt".to_string(),
        abac_action: "WRITE".to_string(),
        abac_environment: "local".to_string(),
        matched_policy_id: Some("pol-001".to_string()),
        enforcement_mode: Some("Block".to_string()),
        decision_latency_us: 150,
        timestamp_qpc: 1_000_000,
        timestamp_secs: 1_000_000,
        user_sid: "S-1-5-21-1".to_string(),
    };
    let payload = serde_json::json!({
        "pid": 1234,
        "snapshots": [diag],
    });

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("/agents/{}/diagnostics", TEST_AGENT_ID))
        .header("authorization", agent_auth_header(TEST_AGENT_ID, TEST_AGENT_AUTH_HASH))
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .expect("build request");

    let resp = app.clone().oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert_eq!(json["received"], true);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/admin/diagnostics")
        .header("authorization", format!("Bearer {}", mint_jwt()))
        .body(Body::empty())
        .expect("build request");

    let resp = app.oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    let snapshots = json["snapshots"].as_array().expect("snapshots array");
    assert!(
        !snapshots.is_empty(),
        "admin diagnostics should contain at least one snapshot"
    );
    assert_eq!(snapshots[0]["hook_function"], "WriteFile");
    assert_eq!(snapshots[0]["user_sid"], "S-1-5-21-1");
}

// ---------------------------------------------------------------------------
// Test 3: unauthenticated health ingest is rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_agent_health_rejects_unauthenticated() {
    let (app, _pool) = build_test_app();

    let payload = serde_json::json!({
        "snapshot": dlp_common::hook_ipc::HookHealthSnapshot::default(),
    });

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("/agents/{}/health", TEST_AGENT_ID))
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .expect("build request");

    let resp = app.oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Test 4: mismatched agent_id is rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_agent_health_rejects_mismatched_agent_id() {
    let (app, _pool) = build_test_app();

    let payload = serde_json::json!({
        "snapshot": dlp_common::hook_ipc::HookHealthSnapshot::default(),
    });

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("/agents/{}/health", TEST_AGENT_ID))
        .header(
            "authorization",
            agent_auth_header("different-agent", TEST_AGENT_AUTH_HASH),
        )
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .expect("build request");

    let resp = app.oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
