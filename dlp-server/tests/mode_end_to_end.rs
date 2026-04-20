//! End-to-end integration tests for Phase 19 boolean mode.
//!
//! Proves that:
//!   - Creating a policy with `mode=ALL` requires ALL conditions to match
//!     for the policy to fire on `/evaluate`.
//!   - `mode=ANY` fires when at least one condition matches.
//!   - `mode=NONE` fires when no condition matches.
//!   - Serializing and deserializing a `PolicyPayload` round-trips the mode
//!     verbatim for all three variants.
//!
//! Harness (`test_app`, `seed_admin_user`, `mint_jwt`) is copied verbatim
//! from `admin_audit_integration.rs` — same in-memory SQLite pool, same
//! admin_router, same JWT secret constant.
//!
//! `/evaluate` is unauthenticated (admin_api.rs public_routes), so the evaluate
//! requests below omit the Authorization header.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use dlp_common::abac::PolicyMode;
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
    let siem = siem_connector::SiemConnector::new(Arc::clone(&pool));
    let alert = alert_router::AlertRouter::new(Arc::clone(&pool));
    let policy_store =
        Arc::new(policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"));
    let state = Arc::new(AppState {
        pool: Arc::clone(&pool),
        policy_store,
        siem,
        alert,
        ad: None,
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
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .expect("mint JWT")
}

/// Builds a POST /admin/policies request with the given typed payload.
fn build_create_policy_request(jwt: &str, payload: &PolicyPayload) -> Request<Body> {
    let body = serde_json::to_vec(payload).expect("serialise policy payload");
    Request::builder()
        .method("POST")
        .uri("/admin/policies")
        .header("Authorization", format!("Bearer {jwt}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .expect("build create request")
}

/// Builds a POST /evaluate request (unauthenticated).
fn build_evaluate_request(eval_body: &serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/evaluate")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_vec(eval_body).expect("serialise eval request"),
        ))
        .expect("build evaluate request")
}

/// Reads the full HTTP response body and parses it as JSON.
async fn read_body_as_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 8192)
        .await
        .expect("read response body");
    serde_json::from_slice(&bytes).expect("parse response as JSON")
}

/// Builds a test EvaluateRequest body exercising classification and access_context.
///
/// `classification` must be a valid serde name for `dlp_common::Classification`
/// (e.g. `"T1"`, `"T3"`, `"T4"`).
///
/// `access_context` must be a valid serde name for `dlp_common::abac::AccessContext`
/// (e.g. `"local"`, `"smb"` — lowercase per `#[serde(rename_all = "lowercase")]`).
fn evaluate_body(classification: &str, access_context: &str) -> serde_json::Value {
    serde_json::json!({
        "subject": {
            "user_sid": "S-1-5-21-1",
            "user_name": "tester",
            "groups": [],
            "device_trust": "Unknown",
            "network_location": "Unknown"
        },
        "resource": {
            "path": "C:\\test.txt",
            "classification": classification
        },
        "environment": {
            "timestamp": "2026-04-20T00:00:00Z",
            "session_id": 1,
            "access_context": access_context
        },
        "action": "READ"
    })
}

/// A policy with `mode=ALL` fires only when ALL conditions match.
///
/// Policy has two conditions: classification=T3 AND access_context=local.
/// The evaluate request satisfies both — the policy must fire (DENY).
#[tokio::test]
async fn test_mode_all_matches_when_all_conditions_hit() {
    let (app, pool) = test_app();
    seed_admin_user(&pool, "mode-admin", "pw");
    let jwt = mint_jwt("mode-admin");

    // Conditions use the internal serde tag `"attribute"` format expected by
    // `PolicyCondition`'s `#[serde(tag = "attribute", rename_all = "snake_case")]`.
    // AccessContext variant → tag value "access_context"; value "local" (lowercase).
    let payload = PolicyPayload {
        id: "policy-all".to_string(),
        name: "all mode test".to_string(),
        description: None,
        priority: 1,
        conditions: serde_json::json!([
            { "attribute": "classification", "op": "eq", "value": "T3" },
            { "attribute": "access_context",  "op": "eq", "value": "local" }
        ]),
        action: "DENY".to_string(),
        enabled: true,
        mode: PolicyMode::ALL,
    };

    let resp = app
        .clone()
        .oneshot(build_create_policy_request(&jwt, &payload))
        .await
        .expect("oneshot create");
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "policy create should return 201"
    );

    // Both conditions match: classification=T3 AND access_context=local.
    let eval = evaluate_body("T3", "local");
    let resp = app
        .oneshot(build_evaluate_request(&eval))
        .await
        .expect("oneshot evaluate");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_body_as_json(resp).await;
    assert_eq!(
        body["decision"], "DENY",
        "ALL mode should fire when all conditions match"
    );
    assert_eq!(body["matched_policy_id"], "policy-all");
}

/// A policy with `mode=ANY` fires when at least one condition matches.
///
/// Policy has two conditions: classification=T3 OR access_context=smb.
/// The evaluate request satisfies ONLY the first (T3, not smb) — the policy must fire.
#[tokio::test]
async fn test_mode_any_matches_when_one_condition_hits() {
    let (app, pool) = test_app();
    seed_admin_user(&pool, "mode-admin", "pw");
    let jwt = mint_jwt("mode-admin");

    let payload = PolicyPayload {
        id: "policy-any".to_string(),
        name: "any mode test".to_string(),
        description: None,
        priority: 1,
        conditions: serde_json::json!([
            { "attribute": "classification", "op": "eq", "value": "T3" },
            { "attribute": "access_context",  "op": "eq", "value": "smb" }
        ]),
        action: "DENY".to_string(),
        enabled: true,
        mode: PolicyMode::ANY,
    };

    let resp = app
        .clone()
        .oneshot(build_create_policy_request(&jwt, &payload))
        .await
        .expect("oneshot create");
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "policy create should return 201"
    );

    // Only the FIRST condition matches: classification=T3 but access_context=local (not smb).
    let eval = evaluate_body("T3", "local");
    let resp = app
        .oneshot(build_evaluate_request(&eval))
        .await
        .expect("oneshot evaluate");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_body_as_json(resp).await;
    assert_eq!(
        body["decision"], "DENY",
        "ANY mode should fire when exactly one condition matches"
    );
    assert_eq!(body["matched_policy_id"], "policy-any");
}

/// A policy with `mode=NONE` fires when NO conditions match.
///
/// Policy has two conditions: classification=T4 AND access_context=smb (in NONE sense:
/// fires when NEITHER matches). The evaluate request satisfies neither (T1, local).
#[tokio::test]
async fn test_mode_none_matches_when_no_conditions_hit() {
    let (app, pool) = test_app();
    seed_admin_user(&pool, "mode-admin", "pw");
    let jwt = mint_jwt("mode-admin");

    let payload = PolicyPayload {
        id: "policy-none".to_string(),
        name: "none mode test".to_string(),
        description: None,
        priority: 1,
        conditions: serde_json::json!([
            { "attribute": "classification", "op": "eq", "value": "T4" },
            { "attribute": "access_context",  "op": "eq", "value": "smb" }
        ]),
        action: "DENY".to_string(),
        enabled: true,
        mode: PolicyMode::NONE,
    };

    let resp = app
        .clone()
        .oneshot(build_create_policy_request(&jwt, &payload))
        .await
        .expect("oneshot create");
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "policy create should return 201"
    );

    // Neither condition matches: classification=T1 (not T4) and access_context=local (not smb).
    let eval = evaluate_body("T1", "local");
    let resp = app
        .oneshot(build_evaluate_request(&eval))
        .await
        .expect("oneshot evaluate");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_body_as_json(resp).await;
    assert_eq!(
        body["decision"], "DENY",
        "NONE mode should fire when no condition matches"
    );
    assert_eq!(body["matched_policy_id"], "policy-none");
}

/// `PolicyPayload` serializes and deserializes the `mode` field correctly for
/// all three variants, verifying the JSON wire format used by import/export.
#[test]
fn test_policy_payload_roundtrip_preserves_all_three_modes() {
    let policies = vec![
        PolicyPayload {
            id: "p1".into(),
            name: "all".into(),
            description: None,
            priority: 1,
            conditions: serde_json::json!([]),
            action: "DENY".into(),
            enabled: true,
            mode: PolicyMode::ALL,
        },
        PolicyPayload {
            id: "p2".into(),
            name: "any".into(),
            description: None,
            priority: 2,
            conditions: serde_json::json!([]),
            action: "DENY".into(),
            enabled: true,
            mode: PolicyMode::ANY,
        },
        PolicyPayload {
            id: "p3".into(),
            name: "none".into(),
            description: None,
            priority: 3,
            conditions: serde_json::json!([]),
            action: "DENY".into(),
            enabled: true,
            mode: PolicyMode::NONE,
        },
    ];

    let json = serde_json::to_string_pretty(&policies).expect("serialize");
    assert!(
        json.contains("\"mode\": \"ALL\""),
        "expected ALL in json: {json}"
    );
    assert!(
        json.contains("\"mode\": \"ANY\""),
        "expected ANY in json: {json}"
    );
    assert!(
        json.contains("\"mode\": \"NONE\""),
        "expected NONE in json: {json}"
    );

    let round_trip: Vec<PolicyPayload> = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(round_trip.len(), 3);
    assert_eq!(round_trip[0].mode, PolicyMode::ALL);
    assert_eq!(round_trip[1].mode, PolicyMode::ANY);
    assert_eq!(round_trip[2].mode, PolicyMode::NONE);
}
