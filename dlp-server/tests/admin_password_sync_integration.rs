//! Integration tests for admin password hash synchronization.
//!
//! Verifies that creating or changing the dlp-admin password automatically
//! propagates the same bcrypt hash to agent_credentials.DLPAuthHash.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use dlp_server::admin_api::admin_router;
use dlp_server::admin_auth::{create_admin_user, set_jwt_secret, Claims};
use dlp_server::db::repositories::{AdminUserRepository, CredentialsRepository};
use dlp_server::{alert_router, db, policy_store, siem_connector, AppState};
use jsonwebtoken::{encode, EncodingKey, Header};
use tempfile::NamedTempFile;
use tower::ServiceExt;

const TEST_JWT_SECRET: &str = "dlp-server-dev-secret-change-me";

/// Builds a test router backed by a fresh in-memory database.
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

/// Seeds a single admin user with a known bcrypt hash.
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

/// Mints a valid JWT for the given username.
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

/// Verifies that create_admin_user populates both admin_users and
/// agent_credentials.DLPAuthHash with the same bcrypt hash.
#[tokio::test]
async fn test_create_admin_user_seeds_agent_auth_hash() {
    let (_router, pool) = test_app();

    create_admin_user(&pool, "dlp-admin", "secret123").expect("create admin user");

    let admin_hash =
        AdminUserRepository::get_password_hash(&pool, "dlp-admin").expect("get admin hash");
    let cred_row = CredentialsRepository::get(&pool, "DLPAuthHash").expect("get agent auth hash");

    assert!(
        bcrypt::verify("secret123", &admin_hash).expect("verify admin hash"),
        "admin_users password hash should verify"
    );
    assert_eq!(
        admin_hash, cred_row.value,
        "admin_users.password_hash and agent_credentials.DLPAuthHash must match"
    );
}

/// Verifies that PUT /auth/password updates both admin_users and
/// agent_credentials.DLPAuthHash with the same new bcrypt hash.
#[tokio::test]
async fn test_password_change_updates_agent_auth_hash() {
    let (router, pool) = test_app();
    seed_admin_user(&pool, "dlp-admin", "old-password");

    let jwt = mint_jwt("dlp-admin");
    let body = serde_json::json!({
        "current_password": "old-password",
        "new_password": "new-password"
    });

    let response = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/auth/password")
                .header("Authorization", format!("Bearer {}", jwt))
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "password change should return 200"
    );

    let admin_hash = AdminUserRepository::get_password_hash(&pool, "dlp-admin")
        .expect("get admin hash after change");
    let cred_row =
        CredentialsRepository::get(&pool, "DLPAuthHash").expect("get agent auth hash after change");

    assert!(
        bcrypt::verify("new-password", &admin_hash).expect("verify new admin hash"),
        "new password should verify against admin_users"
    );
    assert!(
        !bcrypt::verify("old-password", &admin_hash).expect("verify old hash"),
        "old password should no longer verify"
    );
    assert_eq!(
        admin_hash, cred_row.value,
        "after password change, both stores must contain the same hash"
    );
}
