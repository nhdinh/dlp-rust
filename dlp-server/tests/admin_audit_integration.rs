//! Integration tests for admin audit logging (Phase 09).
//!
//! Tests that policy CRUD and password-change operations emit audit events
//! with `EventType::AdminAction`, stored in the `audit_events` table.
//!
//! Each test:
//!   1. Spins up an in-memory server with a fresh DB and seeded admin user.
//!   2. Issues a valid JWT for the admin.
//!   3. Performs the HTTP operation.
//!   4. Queries `audit_events` directly via SQLite (not HTTP) to verify the
//!      exact field values: event_type, action_attempted, resource_path,
//!      user_name, decision, agent_id.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use dlp_server::admin_api::{admin_router, PolicyPayload};
use dlp_server::admin_auth::{set_jwt_secret, Claims};
use dlp_server::{alert_router, db, policy_store, siem_connector, AppState};
use jsonwebtoken::{encode, EncodingKey, Header};
use tempfile::NamedTempFile;
use tower::ServiceExt;

/// Shared test JWT secret — must match what `set_jwt_secret` initialises.
/// Using the same literal as `admin_auth::DEV_JWT_SECRET` so that
/// `set_jwt_secret` call below always converges on one value.
const TEST_JWT_SECRET: &str = "dlp-server-dev-secret-change-me";

/// Builds a test router backed by a fresh in-memory database.
///
/// Every test MUST call this (or `set_jwt_secret` before it) to ensure the
/// process-level OnceLock is populated — otherwise JWT verification silently
/// fails and all authenticated requests return 401.
fn test_app() -> (axum::Router, Arc<db::Pool>) {
    set_jwt_secret(TEST_JWT_SECRET.to_string());
    let tmp = NamedTempFile::new().expect("create temp db");
    let pool = Arc::new(db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
    let siem = siem_connector::SiemConnector::new(Arc::clone(&pool));
    let alert = alert_router::AlertRouter::new(Arc::clone(&pool));
    let policy_store = Arc::new(
        policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"),
    );
    let state = Arc::new(AppState {
        pool: Arc::clone(&pool),
        policy_store,
        siem,
        alert,
        ad: None,
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

/// Mints a valid JWT for the given username, signed with the test secret.
fn mint_jwt(username: &str) -> String {
    let claims = Claims {
        sub: username.to_string(),
        exp: (Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
        iss: "dlp-server".to_string(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .expect("mint JWT")
}

/// Checks the audit_events table and asserts the expected field values.
fn assert_admin_audit_event(
    pool: &db::Pool,
    action_attempted: &str,
    resource_path_prefix: &str,
    user_name: &str,
) {
    // Enum variants are stored as JSON-quoted strings, so encode the expected value.
    let action_filter = format!("\"{action_attempted}\"");
    let conn = pool.get().expect("acquire connection");
    let row: (String, String, String, String, String, String) = conn
        .query_row(
            "SELECT event_type, action_attempted, resource_path, user_name, decision, agent_id \
             FROM audit_events \
             WHERE action_attempted = ?1",
            [&action_filter],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .expect("audit event must exist");

    // Note: enum variants are stored as JSON-quoted strings via serde_json.
    assert_eq!(
        row.0, "\"ADMIN_ACTION\"",
        "event_type should be ADMIN_ACTION"
    );
    assert_eq!(
        row.1,
        format!("\"{action_attempted}\""),
        "action_attempted mismatch"
    );
    assert!(
        row.2.starts_with(resource_path_prefix),
        "resource_path '{0}' should start with '{1}'",
        row.2,
        resource_path_prefix
    );
    assert_eq!(row.3, user_name, "user_name mismatch");
    assert_eq!(row.4, "\"ALLOW\"", "decision should be ALLOW");
    assert_eq!(row.5, "server", "agent_id should be 'server'");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `POST /admin/policies` emits an AdminAction audit event.
#[tokio::test]
async fn test_policy_create_emits_admin_audit_event() {
    let (app, pool) = test_app();
    seed_admin_user(&pool, "audit-admin", "currentpass");

    let jwt = mint_jwt("audit-admin");
    let policy_id = "test-policy-create-audit";

    let payload = PolicyPayload {
        id: policy_id.to_string(),
        name: "Create Audit Test".to_string(),
        description: Some("testing policy-create audit".to_string()),
        priority: 100,
        conditions: serde_json::json!([]),
        action: "DENY".to_string(),
        enabled: true,
    };
    let body = serde_json::to_vec(&payload).expect("serialise payload");

    let req = Request::builder()
        .method("POST")
        .uri("/admin/policies")
        .header("Authorization", format!("Bearer {jwt}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .expect("build request");

    let resp = app.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    if status != StatusCode::CREATED {
        let body = axum::body::to_bytes(resp.into_body(), 1024)
            .await
            .unwrap_or_default();
        eprintln!(
            "create failed: {} — {:?}",
            status,
            String::from_utf8_lossy(&body)
        );
    }
    assert_eq!(status, StatusCode::CREATED, "create should return 201");

    assert_admin_audit_event(&pool, "PolicyCreate", "policy:", "audit-admin");
}

/// `PUT /admin/policies/{id}` emits an AdminAction audit event.
#[tokio::test]
async fn test_policy_update_emits_admin_audit_event() {
    let (app, pool) = test_app();
    seed_admin_user(&pool, "audit-admin", "currentpass");

    // Seed a policy first so the update has something to hit.
    let policy_id = "test-policy-update-audit";
    {
        let conn = pool.get().expect("acquire connection");
        conn.execute(
            "INSERT INTO policies (id, name, description, priority, conditions, action, enabled, version, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                policy_id,
                "Original Name",
                None::<String>,
                50_i32,
                r#"[]"#,
                "ALLOW",
                true,
                1_i64,
                Utc::now().to_rfc3339(),
            ],
        )
        .expect("seed policy");
    }

    let jwt = mint_jwt("audit-admin");

    let payload = PolicyPayload {
        id: policy_id.to_string(),
        name: "Updated Name".to_string(),
        description: Some("updated via test".to_string()),
        priority: 75,
        conditions: serde_json::json!([]),
        action: "DENY".to_string(),
        enabled: true,
    };
    let body = serde_json::to_vec(&payload).expect("serialise payload");

    let req = Request::builder()
        .method("PUT")
        .uri(format!("/admin/policies/{policy_id}"))
        .header("Authorization", format!("Bearer {jwt}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .expect("build request");

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK, "update should return 200");

    assert_admin_audit_event(&pool, "PolicyUpdate", "policy:", "audit-admin");
}

/// `DELETE /admin/policies/{id}` emits an AdminAction audit event.
#[tokio::test]
async fn test_policy_delete_emits_admin_audit_event() {
    let (app, pool) = test_app();
    seed_admin_user(&pool, "audit-admin", "currentpass");

    // Seed a policy first so the delete has something to hit.
    let policy_id = "test-policy-delete-audit";
    {
        let conn = pool.get().expect("acquire connection");
        conn.execute(
            "INSERT INTO policies (id, name, description, priority, conditions, action, enabled, version, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                policy_id,
                "Delete Me",
                None::<String>,
                50_i32,
                r#"[]"#,
                "ALLOW",
                true,
                1_i64,
                Utc::now().to_rfc3339(),
            ],
        )
        .expect("seed policy");
    }

    let jwt = mint_jwt("audit-admin");

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/admin/policies/{policy_id}"))
        .header("Authorization", format!("Bearer {jwt}"))
        .body(Body::empty())
        .expect("build request");

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "delete should return 204"
    );

    assert_admin_audit_event(&pool, "PolicyDelete", "policy:", "audit-admin");
}

/// `PUT /auth/password` emits an AdminAction audit event after a successful change.
#[tokio::test]
async fn test_password_change_emits_admin_audit_event() {
    let (app, pool) = test_app();
    seed_admin_user(&pool, "audit-admin", "currentpass");

    let jwt = mint_jwt("audit-admin");

    let payload = serde_json::json!({
        "current_password": "currentpass",
        "new_password": "newpassword123"
    });
    let body = serde_json::to_vec(&payload).expect("serialise payload");

    let req = Request::builder()
        .method("PUT")
        .uri("/auth/password")
        .header("Authorization", format!("Bearer {jwt}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .expect("build request");

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "password change should return 200"
    );

    assert_admin_audit_event(&pool, "PasswordChange", "password_change:", "audit-admin");
}
