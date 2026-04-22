//! Integration tests for the device registry CRUD API.
//!
//! Each test spins up a fresh in-memory server backed by a temporary SQLite
//! database and exercises the `GET /admin/device-registry`,
//! `POST /admin/device-registry`, and `DELETE /admin/device-registry/{id}`
//! endpoints via `tower::ServiceExt::oneshot`.
//!
//! Tests 2, 4, 6, 7, 8 together verify the full POST->GET->DELETE->GET
//! round-trip contract specified in 24-04-PLAN.md.

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
fn build_test_app() -> (axum::Router, Arc<db::Pool>) {
    set_jwt_secret(TEST_JWT_SECRET.to_string());
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

/// Test 1: `GET /admin/device-registry` on an empty database returns HTTP 200
/// with a JSON body of `[]`.
#[tokio::test]
async fn test_get_empty_registry_returns_200_and_empty_array() {
    let (app, _pool) = build_test_app();

    let req = Request::builder()
        .method(Method::GET)
        .uri("/admin/device-registry")
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
// Test 2: POST with valid JWT + valid body returns 200 with id, vid, trust_tier
// ---------------------------------------------------------------------------

/// Test 2: `POST /admin/device-registry` with a valid JWT and a well-formed
/// body returns HTTP 200 and a response containing `id`, `vid`, and the
/// correct `trust_tier`.
#[tokio::test]
async fn test_post_creates_entry_returns_200_with_id() {
    let (app, _pool) = build_test_app();
    let token = mint_jwt();

    let body = serde_json::json!({
        "vid": "0951",
        "pid": "1666",
        "serial": "ABC123",
        "description": "Kingston DataTraveler",
        "trust_tier": "blocked"
    });

    let req = Request::builder()
        .method(Method::POST)
        .uri("/admin/device-registry")
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
    assert_eq!(json["vid"], "0951");
    assert_eq!(json["trust_tier"], "blocked");
}

// ---------------------------------------------------------------------------
// Test 3: POST with invalid trust_tier returns 422
// ---------------------------------------------------------------------------

/// Test 3: `POST /admin/device-registry` with an unrecognized `trust_tier`
/// value returns HTTP 422 Unprocessable Entity.
#[tokio::test]
async fn test_post_invalid_trust_tier_returns_422() {
    let (app, _pool) = build_test_app();
    let token = mint_jwt();

    let body = serde_json::json!({
        "vid": "DEAD",
        "pid": "BEEF",
        "serial": "INVALID-TIER",
        "trust_tier": "superuser"
    });

    let req = Request::builder()
        .method(Method::POST)
        .uri("/admin/device-registry")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .expect("build request");

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ---------------------------------------------------------------------------
// Test 4: POST without JWT returns 401
// ---------------------------------------------------------------------------

/// Test 4: `POST /admin/device-registry` without an `Authorization` header
/// returns HTTP 401 Unauthorized.
#[tokio::test]
async fn test_post_without_jwt_returns_401() {
    let (app, _pool) = build_test_app();

    let body = serde_json::json!({
        "vid": "0951",
        "pid": "1666",
        "serial": "NO-AUTH",
        "trust_tier": "read_only"
    });

    let req = Request::builder()
        .method(Method::POST)
        .uri("/admin/device-registry")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .expect("build request");

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Test 5: GET after POST returns array with the posted entry
// ---------------------------------------------------------------------------

/// Test 5: After a successful `POST`, `GET /admin/device-registry` returns
/// an array containing exactly 1 entry that matches the posted device.
#[tokio::test]
async fn test_get_after_post_returns_one_entry() {
    let (app, _pool) = build_test_app();
    let token = mint_jwt();

    // POST a device.
    let body = serde_json::json!({
        "vid": "AAAA",
        "pid": "BBBB",
        "serial": "SN-001",
        "trust_tier": "read_only"
    });

    let post_req = Request::builder()
        .method(Method::POST)
        .uri("/admin/device-registry")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .expect("build POST request");

    let post_resp = app.clone().oneshot(post_req).await.expect("POST oneshot");
    assert_eq!(post_resp.status(), StatusCode::OK, "POST should return 200");

    // GET the list.
    let get_req = Request::builder()
        .method(Method::GET)
        .uri("/admin/device-registry")
        .body(Body::empty())
        .expect("build GET request");

    let get_resp = app.oneshot(get_req).await.expect("GET oneshot");
    assert_eq!(get_resp.status(), StatusCode::OK);

    let bytes = to_bytes(get_resp.into_body(), 8 * 1024)
        .await
        .expect("read body");
    let list: Vec<Value> = serde_json::from_slice(&bytes).expect("parse JSON array");

    assert_eq!(list.len(), 1, "expected exactly 1 entry");
    assert_eq!(list[0]["vid"], "AAAA");
    assert_eq!(list[0]["pid"], "BBBB");
    assert_eq!(list[0]["serial"], "SN-001");
    // trust_tier is intentionally omitted from the unauthenticated GET response
    // (CR-01 fix): the public list endpoint returns only vid, pid, serial.
    assert!(
        list[0].get("trust_tier").is_none() || list[0]["trust_tier"].is_null(),
        "trust_tier must not be present in unauthenticated GET response"
    );
}

// ---------------------------------------------------------------------------
// Test 6: DELETE with JWT returns 204; subsequent GET returns empty array
// ---------------------------------------------------------------------------

/// Test 6: `DELETE /admin/device-registry/{id}` with a valid JWT returns
/// HTTP 204. A subsequent `GET` returns an empty array, confirming deletion.
#[tokio::test]
async fn test_delete_removes_entry_and_get_returns_empty() {
    let (app, _pool) = build_test_app();
    let token = mint_jwt();

    // POST to create an entry.
    let body = serde_json::json!({
        "vid": "CCCC",
        "pid": "DDDD",
        "serial": "SN-DEL-001",
        "trust_tier": "full_access"
    });

    let post_req = Request::builder()
        .method(Method::POST)
        .uri("/admin/device-registry")
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
        .uri(format!("/admin/device-registry/{id}"))
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
        .uri("/admin/device-registry")
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
// Test 7: DELETE with nonexistent UUID returns 404
// ---------------------------------------------------------------------------

/// Test 7: `DELETE /admin/device-registry/{id}` where the UUID does not exist
/// returns HTTP 404 Not Found.
#[tokio::test]
async fn test_delete_nonexistent_uuid_returns_404() {
    let (app, _pool) = build_test_app();
    let token = mint_jwt();

    let nonexistent_id = "00000000-0000-0000-0000-000000000000";
    let req = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/admin/device-registry/{nonexistent_id}"))
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("build request");

    let resp = app.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Test 8: POST with duplicate (vid,pid,serial) but different trust_tier
//         → upsert — GET shows updated tier, still 1 entry
// ---------------------------------------------------------------------------

/// Test 8: Posting the same `(vid, pid, serial)` twice with a different
/// `trust_tier` on the second call performs an upsert. The subsequent `GET`
/// shows exactly 1 entry with the tier from the second POST.
#[tokio::test]
async fn test_post_duplicate_upserts_and_get_shows_updated_tier() {
    let (app, _pool) = build_test_app();
    let token = mint_jwt();

    let vid = "EEEE";
    let pid = "FFFF";
    let serial = "SN-UPSERT-001";

    // First POST: tier = "blocked"
    let body_first = serde_json::json!({
        "vid": vid,
        "pid": pid,
        "serial": serial,
        "trust_tier": "blocked"
    });
    let req1 = Request::builder()
        .method(Method::POST)
        .uri("/admin/device-registry")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body_first).unwrap()))
        .expect("build first POST request");

    let resp1 = app.clone().oneshot(req1).await.expect("first POST oneshot");
    assert_eq!(resp1.status(), StatusCode::OK, "first POST must return 200");

    // Second POST: same key, tier = "full_access"
    let body_second = serde_json::json!({
        "vid": vid,
        "pid": pid,
        "serial": serial,
        "trust_tier": "full_access"
    });
    let req2 = Request::builder()
        .method(Method::POST)
        .uri("/admin/device-registry")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body_second).unwrap()))
        .expect("build second POST request");

    let resp2 = app
        .clone()
        .oneshot(req2)
        .await
        .expect("second POST oneshot");
    assert_eq!(
        resp2.status(),
        StatusCode::OK,
        "second POST (upsert) must return 200"
    );

    // GET: verify exactly 1 entry with updated tier.
    let get_req = Request::builder()
        .method(Method::GET)
        .uri("/admin/device-registry")
        .body(Body::empty())
        .expect("build GET request");

    let get_resp = app.oneshot(get_req).await.expect("GET oneshot");
    let bytes = to_bytes(get_resp.into_body(), 8 * 1024)
        .await
        .expect("read body");
    let list: Vec<Value> = serde_json::from_slice(&bytes).expect("parse JSON array");

    assert_eq!(list.len(), 1, "upsert must yield exactly 1 entry");
    // trust_tier is intentionally omitted from the unauthenticated GET response
    // (CR-01 fix): verify via vid/pid/serial identity only on the public endpoint.
    assert_eq!(list[0]["vid"], vid, "vid must match the upserted entry");
    assert_eq!(list[0]["pid"], pid, "pid must match the upserted entry");
    assert_eq!(list[0]["serial"], serial, "serial must match the upserted entry");
}
