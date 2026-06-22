//! Integration tests for the admin diagnostics API (Phase 58, DIFF-02).
//!
//! Exercises GET /admin/diagnostics via tower::ServiceExt::oneshot.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use chrono::Utc;
use dlp_server::admin_api::admin_router;
use dlp_server::admin_auth::{set_jwt_secret, Claims};
use dlp_server::{alert_router, db, diagnostic_store, policy_store, siem_connector, AppState};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::Value;
use tempfile::NamedTempFile;
use tower::ServiceExt;

const TEST_JWT_SECRET: &str = "dlp-server-dev-secret-change-me";

/// Builds a fresh test router backed by a temporary SQLite file.
///
/// When `with_diagnostic_store` is true, the AppState includes a
/// DiagnosticSnapshotStore so the /admin/diagnostics endpoint returns
/// real data. When false, it returns an empty list (standalone mode).
fn build_test_app(with_diagnostic_store: bool) -> (axum::Router, Arc<db::Pool>) {
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
    // Seed an admin user so the ack FK constraint resolves.
    {
        let conn = pool.get().expect("conn");
        conn.execute(
            "INSERT INTO admin_users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
            ["test-admin", "hash", "2026-01-01T00:00:00Z"],
        )
        .expect("seed admin user");
    }

    let diagnostic_store = if with_diagnostic_store {
        Some(Arc::new(diagnostic_store::DiagnosticSnapshotStore::new()))
    } else {
        None
    };

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
        diagnostic_store,
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

// ---------------------------------------------------------------------------
// Test 1: standalone mode returns empty list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_diagnostics_standalone_returns_empty() {
    let (app, _pool) = build_test_app(false);

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

    assert_eq!(json["total"], 0);
    assert_eq!(json["snapshots"].as_array().map(|a| a.len()), Some(0));
}

// ---------------------------------------------------------------------------
// Test 2: with data returns snapshots
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_diagnostics_with_data_returns_snapshots() {
    let (_app, _pool) = build_test_app(true);

    // Ingest a snapshot into the diagnostic store.
    // We need to access the store via the AppState, but it's already moved
    // into the router. Instead, we build a separate store, ingest, then
    // build the app with that store.
    let store = Arc::new(diagnostic_store::DiagnosticSnapshotStore::new());
    let snapshot = dlp_common::hook_ipc::DiagnosticSnapshot {
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
        user_sid: "S-1-5-21-1".to_string(),
    };
    store.ingest("AGENT-01", 1234, vec![snapshot]);

    // Rebuild the app with the populated store.
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
        diagnostic_store: Some(store),
    });
    let app = admin_router(state);

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

    assert_eq!(json["total"], 1);
    let snapshots = json["snapshots"].as_array().expect("snapshots array");
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0]["user_sid"], "S-1-5-21-1");
    assert_eq!(snapshots[0]["hook_function"], "WriteFile");
}

// ---------------------------------------------------------------------------
// Test 3: pagination works
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_diagnostics_pagination() {
    let store = Arc::new(diagnostic_store::DiagnosticSnapshotStore::new());
    let mut snapshots = Vec::new();
    for i in 0..5 {
        snapshots.push(dlp_common::hook_ipc::DiagnosticSnapshot {
            hook_function: "WriteFile".to_string(),
            classification_source: dlp_common::hook_ipc::ClassificationSource::CacheHit,
            classification_age_ms: 42,
            abac_subject: format!("S-1-5-21-{}", i),
            abac_resource: r"C:\Data\secret.txt".to_string(),
            abac_action: "WRITE".to_string(),
            abac_environment: "local".to_string(),
            matched_policy_id: Some("pol-001".to_string()),
            enforcement_mode: Some("Block".to_string()),
            decision_latency_us: 150,
            timestamp_qpc: i as u64 * 1000,
            user_sid: format!("S-1-5-21-{}", i),
        });
    }
    store.ingest("AGENT-01", 1234, snapshots);

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
        diagnostic_store: Some(store),
    });
    let app = admin_router(state);

    // Request first page with limit=2.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/admin/diagnostics?limit=2&offset=0")
        .header("authorization", format!("Bearer {}", mint_jwt()))
        .body(Body::empty())
        .expect("build request");

    let resp = app.clone().oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    assert_eq!(json["total"], 5);
    let snapshots = json["snapshots"].as_array().expect("snapshots array");
    assert_eq!(snapshots.len(), 2);
    // Sorted descending by QPC, so first page has highest values.
    assert_eq!(snapshots[0]["timestamp_qpc"], 4000);
    assert_eq!(snapshots[1]["timestamp_qpc"], 3000);
}

// ---------------------------------------------------------------------------
// Test 4: requires authentication
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_diagnostics_requires_auth() {
    let (app, _pool) = build_test_app(false);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/admin/diagnostics")
        .body(Body::empty())
        .expect("build request");

    let resp = app.oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Test 5: filtering by user_sid
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_diagnostics_filter_by_user_sid() {
    let store = Arc::new(diagnostic_store::DiagnosticSnapshotStore::new());
    store.ingest(
        "AGENT-01",
        1234,
        vec![
            dlp_common::hook_ipc::DiagnosticSnapshot {
                hook_function: "WriteFile".to_string(),
                classification_source: dlp_common::hook_ipc::ClassificationSource::CacheHit,
                classification_age_ms: 42,
                abac_resource: r"C:\Data\secret.txt".to_string(),
                abac_action: "WRITE".to_string(),
                abac_environment: "local".to_string(),
                matched_policy_id: Some("pol-001".to_string()),
                enforcement_mode: Some("Block".to_string()),
                decision_latency_us: 150,
                timestamp_qpc: 1000,
                user_sid: "S-1-5-21-A".to_string(),
            },
            dlp_common::hook_ipc::DiagnosticSnapshot {
                hook_function: "NtCreateFile".to_string(),
                classification_source: dlp_common::hook_ipc::ClassificationSource::CacheHit,
                classification_age_ms: 10,
                abac_resource: r"C:\Data\other.txt".to_string(),
                abac_action: "CREATE".to_string(),
                abac_environment: "local".to_string(),
                matched_policy_id: Some("pol-002".to_string()),
                enforcement_mode: Some("Audit".to_string()),
                decision_latency_us: 200,
                timestamp_qpc: 2000,
                user_sid: "S-1-5-21-B".to_string(),
            },
        ],
    );

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
        diagnostic_store: Some(store),
    });
    let app = admin_router(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/admin/diagnostics?user_sid=S-1-5-21-A")
        .header("authorization", format!("Bearer {}", mint_jwt()))
        .body(Body::empty())
        .expect("build request");

    let resp = app.oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    assert_eq!(json["total"], 1);
    let snapshots = json["snapshots"].as_array().expect("snapshots array");
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0]["user_sid"], "S-1-5-21-A");
    assert_eq!(snapshots[0]["hook_function"], "WriteFile");
}
