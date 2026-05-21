//! Phase 47 Task 47-11 — End-to-end admin-API round-trip + DB-level
//! encrypted-blob check (success criterion #1).
//!
//! Drives the real admin-API surface (built via
//! `dlp_server::admin_api::admin_router`) end-to-end:
//!
//! * Admin login -> JWT.
//! * POST /admin/alert-config with a fixture password -> 200.
//! * GET /admin/alert-config -> the response field carries the
//!   ALERT_SECRET_MASK sentinel, NOT the plaintext.
//! * Direct SQLite query: `*_encrypted` column is a non-empty BLOB;
//!   the cleartext column is GONE (`PRAGMA table_info` rejects).
//! * Mask-round-trip preservation: PUT with mask in the password field
//!   plus a different non-secret field changed -> internal
//!   `get_secrets` decrypts to the ORIGINAL password (Task 47-07
//!   regression cover).
//!
//! Windows-only: bootstrap uses DPAPI via the test crypto path. We use
//! a deterministic test KEK to keep the test runnable on dev machines.

#![cfg(windows)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::Utc;
use dlp_server::admin_api::{admin_router, AlertRouterConfigPayload, SiemConfigPayload};
use dlp_server::admin_auth::{set_jwt_secret, Claims};
use dlp_server::crypto::{SecretCrypto, ENVELOPE_VERSION_V1};
use dlp_server::{alert_router, db, policy_store, secrets_migration, siem_connector, AppState};
use jsonwebtoken::{encode, EncodingKey, Header};
use tempfile::NamedTempFile;
use tower::ServiceExt;

/// Mirrors `admin_api::ALERT_SECRET_MASK` (which is `pub(crate)`). The
/// literal is fixed by the public contract — changing it would be a
/// breaking API change.
const ALERT_SECRET_MASK: &str = "***MASKED***";

/// Test JWT secret (same as `admin_audit_integration.rs`).
const TEST_JWT_SECRET: &str = "dlp-server-dev-secret-change-me";

/// Builds a fresh router backed by a file-backed DB. Returns the temp
/// file (must outlive the test), the router, and the pool so the test
/// can do direct SQLite queries.
fn test_app() -> (NamedTempFile, axum::Router, Arc<db::Pool>) {
    set_jwt_secret(TEST_JWT_SECRET.to_string());
    let tmp = NamedTempFile::new().expect("create temp DB file");
    let pool =
        Arc::new(db::new_pool(tmp.path().to_str().expect("UTF-8 temp path")).expect("init pool"));

    // Use a deterministic KEK to avoid DPAPI involvement at the unit
    // level; the rotation integration test exercises the real DPAPI
    // bootstrap path.
    let crypto = Arc::new(SecretCrypto::from_kek([0xC3; 32], ENVELOPE_VERSION_V1));

    secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
        .expect("Phase 47 migration");

    let siem = siem_connector::SiemConnector::new(Arc::clone(&pool), Arc::clone(&crypto));
    let alert = alert_router::AlertRouter::new(Arc::clone(&pool), Arc::clone(&crypto));
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
        crypto,
        policy_store,
        siem,
        alert,
        ad: None,
        label_service,
        approval_token_service,
        syslog,
        label_aware_enabled: std::sync::Arc::new(
            std::sync::atomic::AtomicBool::new(false),
        ),
    });
    (tmp, admin_router(state), pool)
}

/// Seeds a single admin user with a known bcrypt hash.
fn seed_admin_user(pool: &db::Pool, username: &str, password_plain: &str) {
    let hash = bcrypt::hash(password_plain, 4).expect("bcrypt");
    let now = Utc::now().to_rfc3339();
    let conn = pool.get().expect("acquire");
    conn.execute(
        "INSERT INTO admin_users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![username, hash, now],
    )
    .expect("seed admin");
}

/// Mints a valid JWT for `username` signed with `TEST_JWT_SECRET`.
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
    .expect("mint jwt")
}

/// Helper: PUT a JSON body to a path with a Bearer JWT.
async fn put_json<T: serde::Serialize>(
    app: axum::Router,
    path: &str,
    jwt: &str,
    body: &T,
) -> axum::response::Response {
    let body_bytes = serde_json::to_vec(body).expect("serialise");
    let req = Request::builder()
        .method("PUT")
        .uri(path)
        .header("Authorization", format!("Bearer {jwt}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body_bytes))
        .expect("build req");
    app.oneshot(req).await.expect("oneshot")
}

/// Helper: GET a JSON body from a path with a Bearer JWT, deserialising
/// the response into `T`.
async fn get_json<T: serde::de::DeserializeOwned>(app: axum::Router, path: &str, jwt: &str) -> T {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header("Authorization", format!("Bearer {jwt}"))
        .body(Body::empty())
        .expect("build req");
    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK, "GET {path} must be 200");
    let body = to_bytes(resp.into_body(), 1 << 16).await.expect("body");
    serde_json::from_slice(&body).expect("deserialise body")
}

#[tokio::test]
async fn test_admin_api_round_trip_smtp_password() {
    let (_keep, app, pool) = test_app();
    seed_admin_user(&pool, "encrypted-admin", "pw");
    let jwt = mint_jwt("encrypted-admin");

    // PUT alert-config with a fixture password.
    let payload = AlertRouterConfigPayload {
        smtp_host: "smtp.example.com".to_string(),
        smtp_port: 587,
        smtp_username: "alert@example.com".to_string(),
        smtp_password: "fixture-smtp-plaintext".to_string(),
        smtp_from: "alert@example.com".to_string(),
        smtp_to: "ops@example.com".to_string(),
        smtp_enabled: true,
        webhook_url: String::new(),
        webhook_secret: String::new(),
        webhook_enabled: false,
    };
    let resp = put_json(app.clone(), "/admin/alert-config", &jwt, &payload).await;
    assert_eq!(resp.status(), StatusCode::OK, "PUT must succeed");

    // GET alert-config -> the password field must be the mask, never
    // the plaintext.
    let got: AlertRouterConfigPayload = get_json(app.clone(), "/admin/alert-config", &jwt).await;
    assert_eq!(
        got.smtp_password, ALERT_SECRET_MASK,
        "GET response must return the mask sentinel, not plaintext"
    );

    // ---- DB-level: encrypted blob is populated. ---------------------
    let conn = pool.get().expect("acquire");
    let blob: Vec<u8> = conn
        .query_row(
            "SELECT smtp_password_encrypted FROM alert_router_config WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .expect("query encrypted column");
    assert!(
        !blob.is_empty(),
        "smtp_password_encrypted must contain ciphertext"
    );

    // ---- DB-level: cleartext column is GONE. ------------------------
    // After migrate_secrets_to_encrypted runs in test_app(), the
    // cleartext column has been dropped. Querying it must fail.
    let err = conn
        .query_row(
            "SELECT smtp_password FROM alert_router_config WHERE id = 1",
            [],
            |_| Ok(()),
        )
        .expect_err("cleartext column must not exist after migration");
    let msg = err.to_string();
    assert!(
        msg.contains("no such column") || msg.contains("smtp_password"),
        "expected 'no such column' style error, got: {msg}"
    );
}

#[tokio::test]
async fn test_admin_api_mask_round_trip_preserves_existing() {
    let (_keep, app, pool) = test_app();
    seed_admin_user(&pool, "mask-admin", "pw");
    let jwt = mint_jwt("mask-admin");

    // Write password A.
    let mut payload = AlertRouterConfigPayload {
        smtp_host: "smtp.example.com".to_string(),
        smtp_port: 587,
        smtp_username: "alert@example.com".to_string(),
        smtp_password: "password-A-original".to_string(),
        smtp_from: "alert@example.com".to_string(),
        smtp_to: "ops@example.com".to_string(),
        smtp_enabled: true,
        webhook_url: String::new(),
        webhook_secret: String::new(),
        webhook_enabled: false,
    };
    let resp = put_json(app.clone(), "/admin/alert-config", &jwt, &payload).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // GET back -> mask.
    let got: AlertRouterConfigPayload = get_json(app.clone(), "/admin/alert-config", &jwt).await;
    assert_eq!(got.smtp_password, ALERT_SECRET_MASK);

    // PUT again with the mask in the password slot + a non-secret
    // field changed. The repository must preserve password A.
    payload.smtp_password = ALERT_SECRET_MASK.to_string();
    payload.smtp_to = "different-ops@example.com".to_string();
    let resp = put_json(app.clone(), "/admin/alert-config", &jwt, &payload).await;
    assert_eq!(resp.status(), StatusCode::OK, "mask-PUT must succeed");

    // Internal repository read: the stored password is STILL A.
    let conn = pool.get().expect("acquire");
    let (ct, nonce): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT smtp_password_encrypted, smtp_password_nonce \
             FROM alert_router_config WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("query");
    let mut nonce_arr = [0u8; dlp_server::crypto::envelope::NONCE_LEN];
    nonce_arr.copy_from_slice(&nonce);
    let env =
        dlp_server::crypto::Envelope::new(ENVELOPE_VERSION_V1, nonce_arr, ct).expect("envelope");
    let aad = dlp_server::crypto::aad_for("alert_router_config", "smtp_password");
    // Use the same test KEK the AppState was built with.
    let test_crypto = SecretCrypto::from_kek([0xC3; 32], ENVELOPE_VERSION_V1);
    let recovered = test_crypto.decrypt(&env, &aad).expect("decrypt");
    use secrecy::ExposeSecret as _;
    assert_eq!(
        recovered.expose_secret(),
        "password-A-original",
        "mask round-trip MUST preserve the original password (TOCTOU-safe)"
    );

    // Also confirm the GET still hides the value.
    let got2: AlertRouterConfigPayload = get_json(app.clone(), "/admin/alert-config", &jwt).await;
    assert_eq!(got2.smtp_password, ALERT_SECRET_MASK);
    assert_eq!(got2.smtp_to, "different-ops@example.com");
}

#[tokio::test]
async fn test_admin_api_siem_tokens_round_trip() {
    let (_keep, app, pool) = test_app();
    seed_admin_user(&pool, "siem-admin", "pw");
    let jwt = mint_jwt("siem-admin");

    let payload = SiemConfigPayload {
        splunk_url: "https://splunk.example.com".to_string(),
        splunk_token: "fixture-splunk-token".to_string(),
        splunk_enabled: true,
        elk_url: "https://elk.example.com".to_string(),
        elk_index: "dlp-events".to_string(),
        elk_api_key: "fixture-elk-api-key".to_string(),
        elk_enabled: true,
    };
    let resp = put_json(app.clone(), "/admin/siem-config", &jwt, &payload).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // GET -> masks (assuming SiemConfig handler follows the same mask
    // pattern; see admin_api::get_siem_config_handler).
    let got: SiemConfigPayload = get_json(app.clone(), "/admin/siem-config", &jwt).await;
    assert_eq!(got.splunk_token, ALERT_SECRET_MASK);
    assert_eq!(got.elk_api_key, ALERT_SECRET_MASK);

    // DB-level: encrypted blobs populated, cleartext columns absent.
    let conn = pool.get().expect("acquire");
    let splunk_blob: Vec<u8> = conn
        .query_row(
            "SELECT splunk_token_encrypted FROM siem_config WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .expect("query splunk");
    assert!(!splunk_blob.is_empty());
    let elk_blob: Vec<u8> = conn
        .query_row(
            "SELECT elk_api_key_encrypted FROM siem_config WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .expect("query elk");
    assert!(!elk_blob.is_empty());
    let err = conn
        .query_row(
            "SELECT splunk_token FROM siem_config WHERE id = 1",
            [],
            |_| Ok(()),
        )
        .expect_err("cleartext splunk_token must be gone");
    assert!(err.to_string().contains("no such column"));
}
