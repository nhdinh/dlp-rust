//! Integration tests for the managed-origins CRUD API.
//!
//! Each test spins up a fresh in-memory server backed by a temporary SQLite
//! database and exercises the `GET /admin/managed-origins`,
//! `POST /admin/managed-origins`, and `DELETE /admin/managed-origins/{id}`
//! endpoints via `tower::ServiceExt::oneshot`.
//!
//! Tests 1–7 together verify the full POST->GET->DELETE->GET round-trip
//! contract, plus the 401/409/404 error paths specified in 28-05-PLAN.md.

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

/// Shared JWT secret — must match the `OnceLock` initialised by `set_jwt_secret`.
/// Using the same literal as `admin_auth::DEV_JWT_SECRET` so that multiple
/// test binaries running in the same process do not conflict on the first-set-wins
/// OnceLock.
const TEST_JWT_SECRET: &str = "dlp-server-dev-secret-change-me";

/// Builds a fresh test router backed by a temporary SQLite file.
///
/// Returns the `Router` and the underlying pool so callers can verify the DB
/// directly when needed.
///
/// # OnceLock constraint
///
/// `set_jwt_secret` uses a `OnceLock` internally: the first call wins and all
/// subsequent calls are silently ignored. `cargo test` runs tests in parallel
/// by default, so call order is non-deterministic. This is safe here because
/// every test file in this binary uses the same `TEST_JWT_SECRET` constant,
/// which matches `admin_auth::DEV_JWT_SECRET`. If you introduce a second test
/// binary that sets a different secret, tokens minted in *this* binary may fail
/// validation if that binary's `set_jwt_secret` call wins the race.
///
/// The `let _ = ...` assignment explicitly acknowledges the ignored return value
/// on subsequent calls (the `OnceLock` already holds the correct secret).
fn build_test_app() -> (axum::Router, Arc<db::Pool>) {
    let _ = set_jwt_secret(TEST_JWT_SECRET.to_string());
    let tmp = NamedTempFile::new().expect("create temp db");
    let pool = Arc::new(db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
    let siem = siem_connector::SiemConnector::new(Arc::clone(&pool));
    let alert = alert_router::AlertRouter::new(Arc::clone(&pool));
    let ps = Arc::new(policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"));
    let state = Arc::new(AppState {
        pool: Arc::clone(&pool),
        policy_store: ps,
        siem,
        alert,
        ad: None,
    });
    (admin_router(state), pool)
}

/// Mints a valid admin JWT for the test secret.
fn mint_jwt() -> String {
    let claims = Claims {
        sub: "test-admin".to_string(),
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

// ---------------------------------------------------------------------------
// Test 1: GET on empty DB returns 200 + empty array
// ---------------------------------------------------------------------------

/// Test 1: `GET /admin/managed-origins` on an empty database returns HTTP 200
/// with a JSON body of `[]`.
#[tokio::test]
async fn test_get_empty_origins_returns_200_and_empty_array() {
    let (app, _pool) = build_test_app();

    let req = Request::builder()
        .method(Method::GET)
        .uri("/admin/managed-origins")
        .body(Body::empty())
        .expect("build request");

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = to_bytes(resp.into_body(), 8 * 1024)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&bytes).expect("parse JSON");
    assert!(json.is_array(), "expected JSON array");
    assert_eq!(json.as_array().unwrap().len(), 0, "expected empty array");
}

// ---------------------------------------------------------------------------
// Test 2: POST with valid JWT + valid body returns 200 with id and origin
// ---------------------------------------------------------------------------

/// Test 2: `POST /admin/managed-origins` with a valid JWT and a well-formed
/// body returns HTTP 200 and a response containing a non-empty `id` and the
/// submitted `origin` string.
#[tokio::test]
async fn test_post_creates_origin_returns_200_with_id() {
    let (app, _pool) = build_test_app();
    let token = mint_jwt();

    let body = serde_json::json!({ "origin": "https://example.com/*" });

    let req = Request::builder()
        .method(Method::POST)
        .uri("/admin/managed-origins")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .expect("build request");

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = to_bytes(resp.into_body(), 8 * 1024)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&bytes).expect("parse JSON");

    // Response must include a server-generated id (UUID string).
    assert!(
        json["id"].is_string() && !json["id"].as_str().unwrap().is_empty(),
        "expected non-empty id"
    );
    assert_eq!(json["origin"], "https://example.com/*");
}

// ---------------------------------------------------------------------------
// Test 3: POST without JWT returns 401
// ---------------------------------------------------------------------------

/// Test 3: `POST /admin/managed-origins` without an `Authorization` header
/// returns HTTP 401 Unauthorized.
#[tokio::test]
async fn test_post_without_jwt_returns_401() {
    let (app, _pool) = build_test_app();

    let body = serde_json::json!({ "origin": "https://no-auth.example.com/*" });

    let req = Request::builder()
        .method(Method::POST)
        .uri("/admin/managed-origins")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .expect("build request");

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Test 4: GET after POST returns array with the posted entry
// ---------------------------------------------------------------------------

/// Test 4: After a successful `POST`, `GET /admin/managed-origins` returns
/// an array containing exactly 1 entry matching the posted origin.
#[tokio::test]
async fn test_get_after_post_returns_one_entry() {
    let (app, _pool) = build_test_app();
    let token = mint_jwt();

    let origin = "https://company.sharepoint.com/*";
    let body = serde_json::json!({ "origin": origin });

    // POST the origin.
    let post_req = Request::builder()
        .method(Method::POST)
        .uri("/admin/managed-origins")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .expect("build POST request");

    let post_resp = app.clone().oneshot(post_req).await.expect("POST oneshot");
    assert_eq!(post_resp.status(), StatusCode::OK, "POST should return 200");

    // GET the list.
    let get_req = Request::builder()
        .method(Method::GET)
        .uri("/admin/managed-origins")
        .body(Body::empty())
        .expect("build GET request");

    let get_resp = app.oneshot(get_req).await.expect("GET oneshot");
    assert_eq!(get_resp.status(), StatusCode::OK);

    let bytes = to_bytes(get_resp.into_body(), 8 * 1024)
        .await
        .expect("read body");
    let list: Vec<Value> = serde_json::from_slice(&bytes).expect("parse JSON array");

    assert_eq!(list.len(), 1, "expected exactly 1 entry");
    assert_eq!(list[0]["origin"], origin, "origin must match posted value");
    assert!(
        list[0]["id"].is_string() && !list[0]["id"].as_str().unwrap().is_empty(),
        "entry must have a non-empty id"
    );
}

// ---------------------------------------------------------------------------
// Test 5: DELETE removes entry; subsequent GET returns empty array
// ---------------------------------------------------------------------------

/// Test 5: `DELETE /admin/managed-origins/{id}` with a valid JWT returns
/// HTTP 204. A subsequent `GET` returns an empty array, confirming deletion.
#[tokio::test]
async fn test_delete_removes_entry_and_get_returns_empty() {
    let (app, _pool) = build_test_app();
    let token = mint_jwt();

    // POST to create an entry.
    let body = serde_json::json!({ "origin": "https://delete-me.example.com/*" });

    let post_req = Request::builder()
        .method(Method::POST)
        .uri("/admin/managed-origins")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .expect("build POST request");

    let post_resp = app.clone().oneshot(post_req).await.expect("POST oneshot");
    assert_eq!(post_resp.status(), StatusCode::OK, "POST should return 200");

    let post_bytes = to_bytes(post_resp.into_body(), 8 * 1024)
        .await
        .expect("read body");
    let created: Value = serde_json::from_slice(&post_bytes).expect("parse POST body");
    let id = created["id"]
        .as_str()
        .expect("id must be a string")
        .to_string();

    // DELETE the entry.
    let delete_req = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/admin/managed-origins/{id}"))
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("build DELETE request");

    let delete_resp = app
        .clone()
        .oneshot(delete_req)
        .await
        .expect("DELETE oneshot");
    assert_eq!(
        delete_resp.status(),
        StatusCode::NO_CONTENT,
        "DELETE must return 204"
    );

    // GET: expect empty list.
    let get_req = Request::builder()
        .method(Method::GET)
        .uri("/admin/managed-origins")
        .body(Body::empty())
        .expect("build GET request");

    let get_resp = app.oneshot(get_req).await.expect("GET oneshot");
    let bytes = to_bytes(get_resp.into_body(), 8 * 1024)
        .await
        .expect("read body");
    let list: Vec<Value> = serde_json::from_slice(&bytes).expect("parse JSON array");
    assert_eq!(list.len(), 0, "list must be empty after DELETE");
}

// ---------------------------------------------------------------------------
// Test 6: DELETE with nonexistent UUID returns 404
// ---------------------------------------------------------------------------

/// Test 6: `DELETE /admin/managed-origins/{id}` where the UUID does not exist
/// returns HTTP 404 Not Found.
#[tokio::test]
async fn test_delete_nonexistent_uuid_returns_404() {
    let (app, _pool) = build_test_app();
    let token = mint_jwt();

    let nonexistent_id = "00000000-0000-0000-0000-000000000000";
    let req = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/admin/managed-origins/{nonexistent_id}"))
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("build request");

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Test 7: POST duplicate origin returns 409 Conflict
// ---------------------------------------------------------------------------

/// Test 7: Posting the same `origin` string twice returns HTTP 409 Conflict
/// on the second call, enforcing the `UNIQUE` constraint on the `origin` column.
#[tokio::test]
async fn test_post_duplicate_origin_returns_409() {
    let (app, _pool) = build_test_app();
    let token = mint_jwt();

    let body = serde_json::json!({ "origin": "https://dup.example.com/*" });

    // First POST: must succeed.
    let req1 = Request::builder()
        .method(Method::POST)
        .uri("/admin/managed-origins")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .expect("build first POST request");

    let resp1 = app.clone().oneshot(req1).await.expect("first POST oneshot");
    assert_eq!(resp1.status(), StatusCode::OK, "first POST must return 200");

    // Second POST: same origin — must return 409 CONFLICT.
    let req2 = Request::builder()
        .method(Method::POST)
        .uri("/admin/managed-origins")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .expect("build second POST request");

    let resp2 = app.oneshot(req2).await.expect("second POST oneshot");
    assert_eq!(
        resp2.status(),
        StatusCode::CONFLICT,
        "duplicate origin must return 409"
    );
}
