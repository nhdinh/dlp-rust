---
wave: 4
depends_on: [wave3]
order: 4
description: Update spawn_admin_app() and other test helpers to inject PolicyStore, then run full test suite, clippy, and sonar-scanner.
files_modified:
  - dlp-server/src/admin_api.rs    (modify — spawn_admin_app and other test helpers)
---

# Wave 4: Testing and Test Infrastructure Updates

## Objective

Fix the `spawn_admin_app()` helper in `admin_api.rs` so it constructs and injects a real `PolicyStore`, update integration tests that depend on it, then run the full test suite, clippy, format checks, and sonar-scanner.

---

## Task 4.1 — Fix `spawn_admin_app()` to inject `PolicyStore`

### Purpose

The existing `spawn_admin_app()` helper in the `#[cfg(test)]` module constructs `AppState` without a `policy_store` field. Now that `AppState` requires `policy_store: Arc<PolicyStore>`, the helper must be updated or it will fail to compile.

### `<read_first>`

```
dlp-server/src/admin_api.rs                              (spawn_admin_app function)
dlp-server/src/policy_store.rs                          (PolicyStore::new signature)
dlp-server/src/lib.rs                                   (AppState fields)
```

Read the current `spawn_admin_app()` function. Also read any other test helpers that directly construct `AppState` (there are at least two more: `test_get_alert_config_requires_auth` and `test_put_alert_config_roundtrip`).

### `<action>`

Update `spawn_admin_app()` to construct and inject a `PolicyStore`:

```rust
fn spawn_admin_app() -> axum::Router {
    crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
    let tmp = tempfile::NamedTempFile::new().expect("create temp db");
    let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
    let policy_store = Arc::new(
        crate::policy_store::PolicyStore::new(Arc::clone(&pool))
            .expect("build policy store"),
    );
    let siem = crate::siem_connector::SiemConnector::new(Arc::clone(&pool));
    let alert = crate::alert_router::AlertRouter::new(Arc::clone(&pool));
    let state = Arc::new(AppState {
        pool,
        policy_store,
        siem,
        alert,
        ad: None,
    });
    admin_router(state)
}
```

Also update all other test helper patterns in the file that directly construct `AppState` (there are at least two more: `test_get_alert_config_requires_auth` and `test_put_alert_config_roundtrip`). Apply the same fix to each one — add `policy_store` construction using the same in-memory pool.

### `<acceptance_criteria>`

- [ ] `spawn_admin_app()` compiles without errors
- [ ] All test functions that construct `AppState` directly also include `policy_store`
- [ ] `cargo build -p dlp-server` — no warnings, no errors
- [ ] `cargo test -p dlp-server admin_api::tests::spawn_admin_app` — no compile errors

---

## Task 4.2 — Integration tests: `POST /evaluate` handler

### Purpose

Verify the endpoint responds correctly when the policy store is empty (tiered default-deny) and when a matching policy exists. These tests are placed in Wave 4 because they depend on `spawn_admin_app()` being updated in Task 4.1.

### `<read_first>`

```
dlp-server/src/admin_api.rs                            (test module, spawn_admin_app from Task 4.1)
dlp-server/src/policy_store.rs                         (PolicyStore test helpers)
dlp-common/src/abac.rs                                 (EvaluateRequest JSON format, Action serde)
```

Read the existing test module in `admin_api.rs` to understand the `spawn_admin_app()` pattern and JWT helper.

Read `Action` in `dlp-common/src/abac.rs` to verify the serde format used for the `action` field (e.g., `"READ"` or `"read"` or unit variant) in the JSON request body.

### `<action>`

Add the following tests to the `#[cfg(test)]` module in `admin_api.rs`. These tests use `spawn_admin_app()` (which must first be updated to inject a `PolicyStore` — see Task 4.1) and send real HTTP requests to the router.

```rust
#[tokio::test]
async fn test_evaluate_returns_decision() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
    let tmp = tempfile::NamedTempFile::new().expect("create temp db");
    let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
    let policy_store = Arc::new(
        crate::policy_store::PolicyStore::new(Arc::clone(&pool))
            .expect("build policy store"),
    );
    let siem = crate::siem_connector::SiemConnector::new(Arc::clone(&pool));
    let alert = crate::alert_router::AlertRouter::new(Arc::clone(&pool));
    let state = Arc::new(AppState {
        pool,
        policy_store,
        siem,
        alert,
        ad: None,
    });
    let app = admin_router(state);

    // POST a T3 request (no policies) → expects 200 with DENY (default-deny)
    let request_body = serde_json::json!({
        "subject": {
            "user_sid": "S-1-5-21-1",
            "username": "testuser",
            "display_name": "Test User",
            "groups": [],
            "device_trust": "Unknown",
            "network_location": "Unknown"
        },
        "resource": {
            "path": r"C:\test\confidential.txt",
            "classification": "T3"
        },
        "environment": { "access_context": "local" },
        "action": "READ"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/evaluate")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .expect("build request");

    let resp = app.oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let body_val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body_val["decision"], "DENY");
    assert!(body_val["matched_policy_id"].is_null());
}

#[tokio::test]
async fn test_evaluate_returns_allow_for_t1() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
    let tmp = tempfile::NamedTempFile::new().expect("create temp db");
    let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
    let policy_store = Arc::new(
        crate::policy_store::PolicyStore::new(Arc::clone(&pool))
            .expect("build policy store"),
    );
    let siem = crate::siem_connector::SiemConnector::new(Arc::clone(&pool));
    let alert = crate::alert_router::AlertRouter::new(Arc::clone(&pool));
    let state = Arc::new(AppState {
        pool,
        policy_store,
        siem,
        alert,
        ad: None,
    });
    let app = admin_router(state);

    // POST a T1 request (no policies) → expects 200 with ALLOW (default-allow)
    let request_body = serde_json::json!({
        "subject": {
            "user_sid": "S-1-5-21-1",
            "username": "testuser",
            "display_name": "Test User",
            "groups": [],
            "device_trust": "Unknown",
            "network_location": "Unknown"
        },
        "resource": {
            "path": r"C:\test\public.txt",
            "classification": "T1"
        },
        "environment": { "access_context": "local" },
        "action": "READ"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/evaluate")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .expect("build request");

    let resp = app.oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let body_val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body_val["decision"], "ALLOW");
}

#[tokio::test]
async fn test_evaluate_invalidation_on_policy_create() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
    let tmp = tempfile::NamedTempFile::new().expect("create temp db");
    let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
    let policy_store = Arc::new(
        crate::policy_store::PolicyStore::new(Arc::clone(&pool))
            .expect("build policy store"),
    );
    let siem = crate::siem_connector::SiemConnector::new(Arc::clone(&pool));
    let alert = crate::alert_router::AlertRouter::new(Arc::clone(&pool));
    let state = Arc::new(AppState {
        pool: Arc::clone(&pool),
        policy_store: Arc::clone(&policy_store),
        siem,
        alert,
        ad: None,
    });
    let app = admin_router(state);

    // 1. Evaluate a T2 request → default-allow (no policy)
    let request_body = serde_json::json!({
        "subject": {
            "user_sid": "S-1-5-21-1",
            "username": "testuser",
            "display_name": "Test User",
            "groups": [],
            "device_trust": "Unknown",
            "network_location": "Unknown"
        },
        "resource": {
            "path": r"C:\test\internal.txt",
            "classification": "T2"
        },
        "environment": { "access_context": "local" },
        "action": "READ"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/evaluate")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Create a policy that DENYs T2
    let policy_body = serde_json::json!({
        "id": "deny-t2",
        "name": "Deny T2",
        "priority": 1,
        "conditions": [
            { "attribute": "classification", "op": "eq", "value": "T2" }
        ],
        "action": "Deny",
        "enabled": true
    });
    let admin_token = mint_admin_jwt();
    let req = Request::builder()
        .method("POST")
        .uri("/policies")
        .header(http::header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&policy_body).unwrap()))
        .expect("build request");
    let resp = app.clone().oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 3. Evaluate T2 again → should now DENY (cache was invalidated)
    let req = Request::builder()
        .method("POST")
        .uri("/evaluate")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .expect("build request");
    let resp = app.oneshot(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let body_val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body_val["decision"], "DENY");
    assert_eq!(body_val["matched_policy_id"], "deny-t2");
}
```

### `<acceptance_criteria>`

- [ ] `test_evaluate_returns_decision` — POST /evaluate with T3 returns `decision: "DENY"`, 200 OK
- [ ] `test_evaluate_returns_allow_for_t1` — POST /evaluate with T1 returns `decision: "ALLOW"`, 200 OK
- [ ] `test_evaluate_invalidation_on_policy_create` — creates a policy, then evaluates → sees updated decision
- [ ] All three integration tests pass: `cargo test -p dlp-server admin_api::tests::test_evaluate`
- [ ] `cargo test -p dlp-server` — no regressions

---

## Task 4.3 — Run full test suite

### Purpose

Verify no regressions from any of the previous waves. All tests must pass before considering the phase complete.

### `<read_first>`

```
dlp-server/Cargo.toml                         (check test dependencies)
```

Verify that `tempfile` and `tokio` (with `full` features) are available in `dev-dependencies`.

### `<action>`

Run the full test suite:

```bash
cargo test -p dlp-server
```

Fix any test failures. Common issues:
- Missing `parking_lot` in `Cargo.toml` dependencies
- Incorrect JSON serialization of enum variants (e.g., `"T3"` vs `3`)
- `policy_store.rs` `#[cfg(test)]` module accessing private helper functions

### `<acceptance_criteria>`

- [ ] `cargo test -p dlp-server` — all tests pass
- [ ] `cargo build -p dlp-server` — no warnings, no errors
- [ ] No test panics or timeouts

---

## Task 4.4 — Run clippy and format checks

### Purpose

Enforce Rust coding standards from `CLAUDE.md § 9.15`.

### `<read_first>`

```
dlp-server/Cargo.toml
dlp-server/src/policy_store.rs               (check for clippy hints)
dlp-server/src/policy_engine_error.rs
```

### `<action>`

```bash
cargo fmt --check -p dlp-server
cargo clippy -p dlp-server -- -D warnings
```

Fix any clippy lints or format violations. Common issues:
- `redundant_closure` clippy warning in `condition_matches` match arm
- Missing `#[allow(dead_code)]` if `deserialize_policy_row` is only used in tests

### `<acceptance_criteria>`

- [ ] `cargo fmt --check -p dlp-server` — passes (no diff)
- [ ] `cargo clippy -p dlp-server -- -D warnings` — no warnings, no errors

---

## Task 4.5 — Run sonar-scanner and verify Quality Gate

### Purpose

Static analysis scan per `CLAUDE.md § 9.16`. Only push when Quality Gate passes.

### `<read_first>`

```
C:\Users\nhdinh\dev\dlp-rust\.sonar\sonar-project.properties      (scanner config)
```

Verify the `SONAR_TOKEN` environment variable is available.

### `<action>`

```bash
cd /c/Users/nhdinh/dev/dlp-rust
sonar-scanner
```

After the scan completes, check the Quality Gate status. If SonarQube reports:
- **Bugs** or **Code Smells**: Fix them immediately, re-scan
- **Low test coverage** on `policy_store.rs` or `admin_api.rs`: Add or expand unit/integration tests until coverage is acceptable
- **Security Hotspots**: Review and mark as reviewed if appropriate

### `<acceptance_criteria>`

- [ ] `sonar-scanner` completes without error
- [ ] SonarQube Quality Gate: **PASSES**
- [ ] No open **Bugs** or **Code Smells** in `dlp-server/src/policy_store.rs` or `dlp-server/src/admin_api.rs`
- [ ] Test coverage on new files is above the project threshold
- [ ] All security hotspots reviewed and resolved
