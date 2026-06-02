//! Integration tests for Phase 55 enforcement mode round-trip.
//!
//! Proves that:
//!   - Creating and updating a policy via the admin API round-trips all three
//!     enforcement modes (Audit, Block, AuditAndBlock).
//!   - The agent config endpoint includes the correct `global_enforcement_mode`.
//!   - The global enforcement mode admin API endpoints (GET/PUT) work correctly.
//!   - Backward compatibility: a policy created without `enforcement_mode`
//!     defaults to `Block`.
//!   - Global override forces Audit mode regardless of per-policy mode.
//!
//! Harness (`test_app`, `seed_admin_user`, `mint_jwt`) is copied verbatim
//! from `admin_audit_integration.rs` and `mode_end_to_end.rs`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use dlp_common::abac::PolicyMode;
use dlp_common::EnforcementMode;
use dlp_server::admin_api::{admin_router, PolicyPayload};
use dlp_server::admin_auth::{set_jwt_secret, Claims};
use dlp_server::{alert_router, db, policy_store, siem_connector, AppState};
use jsonwebtoken::{encode, EncodingKey, Header};
use tempfile::NamedTempFile;
use tower::ServiceExt;

const TEST_JWT_SECRET: &str = "dlp-server-dev-secret-change-me";

fn test_app() -> (axum::Router, Arc<db::Pool>) {
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
    let policy_store =
        Arc::new(policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"));
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
    let syslog =
        dlp_server::syslog_connector::SyslogConnector::new(Arc::clone(&pool), Arc::clone(&crypto));
    let state = Arc::new(AppState {
        pool: Arc::clone(&pool),
        crypto: std::sync::Arc::clone(&crypto),
        policy_store,
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
        diagnostic_store: None,
    });
    (admin_router(state), pool)
}

fn seed_admin_user(pool: &db::Pool, username: &str, password_plain: &str) {
    let hash = bcrypt::hash(password_plain, 4).expect("bcrypt hash in tests");
    let now = Utc::now().to_rfc3339();
    let conn = pool.get().expect("acquire connection");
    conn.execute(
        "INSERT INTO admin_users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![username, hash, now],
    )
    .expect("seed admin user");
}

fn mint_jwt(username: &str) -> String {
    let claims = Claims {
        sub: username.to_string(),
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

async fn read_body_as_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 8192)
        .await
        .expect("read response body");
    serde_json::from_slice(&bytes).expect("parse response as JSON")
}

/// Round-trip all three enforcement modes through the admin API.
#[tokio::test]
async fn test_enforcement_mode_round_trip() {
    let (app, _pool) = test_app();
    seed_admin_user(&_pool, "mode-admin", "pw");
    let jwt = mint_jwt("mode-admin");

    // Step 1: Create policy with enforcement_mode = Audit.
    let payload = PolicyPayload {
        id: "policy-mode-rt".to_string(),
        name: "mode round-trip test".to_string(),
        description: None,
        priority: 1,
        conditions: serde_json::json!([]),
        action: "DENY".to_string(),
        enabled: true,
        mode: PolicyMode::ALL,
        enforcement_mode: EnforcementMode::Audit,
    };
    let body = serde_json::to_vec(&payload).expect("serialise payload");
    let req = Request::builder()
        .method("POST")
        .uri("/admin/policies")
        .header("Authorization", format!("Bearer {jwt}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("oneshot create");
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "create should return 201"
    );
    let json = read_body_as_json(resp).await;
    assert_eq!(
        json["enforcement_mode"], "Audit",
        "create response should contain Audit"
    );

    // Step 2: Update to Block.
    let payload = PolicyPayload {
        id: "policy-mode-rt".to_string(),
        name: "mode round-trip test".to_string(),
        description: None,
        priority: 1,
        conditions: serde_json::json!([]),
        action: "DENY".to_string(),
        enabled: true,
        mode: PolicyMode::ALL,
        enforcement_mode: EnforcementMode::Block,
    };
    let body = serde_json::to_vec(&payload).expect("serialise payload");
    let req = Request::builder()
        .method("PUT")
        .uri("/admin/policies/policy-mode-rt")
        .header("Authorization", format!("Bearer {jwt}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("oneshot update");
    assert_eq!(resp.status(), StatusCode::OK, "update should return 200");
    let json = read_body_as_json(resp).await;
    assert_eq!(
        json["enforcement_mode"], "Block",
        "update response should contain Block"
    );

    // Step 3: Update to AuditAndBlock.
    let payload = PolicyPayload {
        id: "policy-mode-rt".to_string(),
        name: "mode round-trip test".to_string(),
        description: None,
        priority: 1,
        conditions: serde_json::json!([]),
        action: "DENY".to_string(),
        enabled: true,
        mode: PolicyMode::ALL,
        enforcement_mode: EnforcementMode::AuditAndBlock,
    };
    let body = serde_json::to_vec(&payload).expect("serialise payload");
    let req = Request::builder()
        .method("PUT")
        .uri("/admin/policies/policy-mode-rt")
        .header("Authorization", format!("Bearer {jwt}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("oneshot update");
    assert_eq!(resp.status(), StatusCode::OK, "update should return 200");
    let json = read_body_as_json(resp).await;
    assert_eq!(
        json["enforcement_mode"], "AuditAndBlock",
        "update response should contain AuditAndBlock"
    );

    // Step 4: Fetch agent config and verify global_enforcement_mode defaults to PerPolicy.
    let req = Request::builder()
        .method("GET")
        .uri("/agent-config/test-agent-01")
        .body(Body::empty())
        .expect("build request");
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("oneshot agent config");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "agent config should return 200"
    );
    let json = read_body_as_json(resp).await;
    assert_eq!(
        json["global_enforcement_mode"], "PerPolicy",
        "agent config should default to PerPolicy"
    );
}

/// Backward compatibility: policy created without enforcement_mode defaults to Block.
#[tokio::test]
async fn test_enforcement_mode_backward_compat() {
    let (app, _pool) = test_app();
    seed_admin_user(&_pool, "mode-admin", "pw");
    let jwt = mint_jwt("mode-admin");

    // Create policy WITHOUT enforcement_mode in the payload.
    let raw = serde_json::json!({
        "id": "policy-compat",
        "name": "compat test",
        "description": null,
        "priority": 1,
        "conditions": [],
        "action": "DENY",
        "enabled": true,
        "mode": "ALL"
    });
    let body = serde_json::to_vec(&raw).expect("serialise raw payload");
    let req = Request::builder()
        .method("POST")
        .uri("/admin/policies")
        .header("Authorization", format!("Bearer {jwt}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .expect("build request");
    let resp = app.oneshot(req).await.expect("oneshot create");
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "create should return 201"
    );
    let json = read_body_as_json(resp).await;
    assert_eq!(
        json["enforcement_mode"], "Block",
        "absent enforcement_mode should default to Block"
    );
}

/// Global enforcement mode admin API round-trip and validation.
#[tokio::test]
async fn test_global_enforcement_mode_admin_api() {
    let (app, _pool) = test_app();
    seed_admin_user(&_pool, "mode-admin", "pw");
    let jwt = mint_jwt("mode-admin");

    // Step 1: GET on fresh DB returns PerPolicy.
    let req = Request::builder()
        .method("GET")
        .uri("/admin/config/global-enforcement-mode")
        .header("Authorization", format!("Bearer {jwt}"))
        .body(Body::empty())
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("oneshot get");
    assert_eq!(resp.status(), StatusCode::OK, "get should return 200");
    let json = read_body_as_json(resp).await;
    assert_eq!(
        json["mode"], "PerPolicy",
        "fresh DB should return PerPolicy"
    );

    // Step 2: PUT with Audit returns success.
    let body = serde_json::json!({ "mode": "Audit" });
    let body = serde_json::to_vec(&body).expect("serialise payload");
    let req = Request::builder()
        .method("PUT")
        .uri("/admin/config/global-enforcement-mode")
        .header("Authorization", format!("Bearer {jwt}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("oneshot put");
    assert_eq!(resp.status(), StatusCode::OK, "put should return 200");
    let json = read_body_as_json(resp).await;
    assert_eq!(json["mode"], "Audit", "put response should contain Audit");

    // Step 3: GET again returns Audit.
    let req = Request::builder()
        .method("GET")
        .uri("/admin/config/global-enforcement-mode")
        .header("Authorization", format!("Bearer {jwt}"))
        .body(Body::empty())
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("oneshot get");
    assert_eq!(resp.status(), StatusCode::OK, "get should return 200");
    let json = read_body_as_json(resp).await;
    assert_eq!(
        json["mode"], "Audit",
        "get should return Audit after update"
    );

    // Step 4: PUT with invalid mode returns 400.
    let body = serde_json::json!({ "mode": "InvalidMode" });
    let body = serde_json::to_vec(&body).expect("serialise payload");
    let req = Request::builder()
        .method("PUT")
        .uri("/admin/config/global-enforcement-mode")
        .header("Authorization", format!("Bearer {jwt}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .expect("build request");
    let resp = app.oneshot(req).await.expect("oneshot put invalid");
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "invalid mode should return 400"
    );
}

/// Global override forces Audit mode for all policies regardless of per-policy mode.
#[tokio::test]
async fn test_global_override_forces_audit_mode() {
    let (app, _pool) = test_app();
    seed_admin_user(&_pool, "mode-admin", "pw");
    let jwt = mint_jwt("mode-admin");

    // Create a policy with Block mode.
    let payload = PolicyPayload {
        id: "policy-block".to_string(),
        name: "block mode policy".to_string(),
        description: None,
        priority: 1,
        conditions: serde_json::json!([
            { "attribute": "classification", "op": "eq", "value": "T3" }
        ]),
        action: "DENY".to_string(),
        enabled: true,
        mode: PolicyMode::ALL,
        enforcement_mode: EnforcementMode::Block,
    };
    let body = serde_json::to_vec(&payload).expect("serialise payload");
    let req = Request::builder()
        .method("POST")
        .uri("/admin/policies")
        .header("Authorization", format!("Bearer {jwt}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("oneshot create");
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "create should return 201"
    );

    // Set global mode to Audit.
    let body = serde_json::json!({ "mode": "Audit" });
    let body = serde_json::to_vec(&body).expect("serialise payload");
    let req = Request::builder()
        .method("PUT")
        .uri("/admin/config/global-enforcement-mode")
        .header("Authorization", format!("Bearer {jwt}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("oneshot put");
    assert_eq!(resp.status(), StatusCode::OK, "put should return 200");

    // Evaluate a request that matches the policy.
    // In Audit global mode, the policy should return ALLOW with would_have_denied=true.
    let eval_body = serde_json::json!({
        "subject": {
            "user_sid": "S-1-5-21-1",
            "user_name": "tester",
            "groups": [],
            "device_trust": "Unknown",
            "network_location": "Unknown"
        },
        "resource": {
            "path": "C:\\test.txt",
            "classification": "T3"
        },
        "environment": {
            "timestamp": "2026-04-20T00:00:00Z",
            "session_id": 1,
            "access_context": "local"
        },
        "action": "READ"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/evaluate")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&eval_body).expect("serialise eval request"),
        ))
        .expect("build evaluate request");
    let resp = app.clone().oneshot(req).await.expect("oneshot evaluate");
    assert_eq!(resp.status(), StatusCode::OK, "evaluate should return 200");
    let json = read_body_as_json(resp).await;
    assert_eq!(
        json["decision"], "ALLOW",
        "global Audit mode should force ALLOW even though policy is Block"
    );
    assert_eq!(
        json["would_have_denied"], true,
        "would_have_denied should be true in Audit mode"
    );

    // Verify agent config reflects the global mode.
    let req = Request::builder()
        .method("GET")
        .uri("/agent-config/test-agent-02")
        .body(Body::empty())
        .expect("build request");
    let resp = app.oneshot(req).await.expect("oneshot agent config");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "agent config should return 200"
    );
    let json = read_body_as_json(resp).await;
    assert_eq!(
        json["global_enforcement_mode"], "Audit",
        "agent config should reflect global Audit mode"
    );
}
