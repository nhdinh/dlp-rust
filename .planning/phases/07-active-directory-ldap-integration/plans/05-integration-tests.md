---
wave: 3
depends_on:
  - "01-ad-client-crate"
  - "02-db-schema-and-admin-api"
  - "03-server-ad-client-construction"
  - "04-agent-integration"
requirements:
  - R-05
files_modified:
  - dlp-common/src/ad_client.rs
  - dlp-server/tests/ldap_config_api.rs (NEW)
autonomous: false
---

# Plan 05: Integration Tests + Quality Gate

## Goal

Ensure the full integration path works end-to-end: AD client crate compiles and has comprehensive unit tests; DB schema initializes correctly; admin API routes respond; agent compiles and tests pass. All verified via `cargo test --workspace`.

---

## must_haves

- `cargo test --workspace` → exit code 0, no warnings
- `cargo build --workspace` → exit code 0, no warnings
- `cargo clippy -- -D warnings` → no warnings
- `cargo fmt --check` → all files formatted
- `cargo test -p dlp-common` → all ad_client tests pass
- `cargo test -p dlp-server` → db tests pass including `test_ldap_config_seed_row`
- `cargo test -p dlp-agent` → all agent tests pass
- Integration test: `GET /admin/ldap-config` returns JSON with correct shape
- Integration test: `PUT /admin/ldap-config` updates and returns the new config

---

## Tasks

### Task 1: Verify `cargo test -p dlp-common`

<read_first>
`dlp-common/src/ad_client.rs`
</read_first>

<action>
Run `cargo test -p dlp-common` and address any compilation errors or test failures. Common issues to check:

1. **`parse_sid_bytes`**: ensure it handles zero subauthorities correctly (S-1 alone is valid: the Well-Known SID namespace)
2. **`GroupCache::evict_expired`**: must not panic on empty map
3. **Windows feature gates**: `get_device_trust` and `get_network_location` must be `#[cfg(windows)]` so the crate compiles on non-Windows CI
4. **`LdapConfig` serde derives**: ensure Debug, Clone are derived

Fix any failures. If tests fail due to missing imports or incomplete implementations from Plan 01, complete the implementation.
</action>

<acceptance_criteria>
- `cargo test -p dlp-common` → exit code 0
- `test_parse_sid_bytes_*` tests all pass
- `test_group_cache_*` tests all pass
- `test_vpn_subnet_parsing` passes
</acceptance_criteria>

---

### Task 2: Verify `cargo test -p dlp-server`

<read_first>
`dlp-server/src/db.rs` — tests module
</read_first>

<action>
Run `cargo test -p dlp-server` and verify:
1. `test_ldap_config_seed_row` passes
2. `test_tables_created` includes `ldap_config` in the list
3. All existing tests continue to pass

If the `test_tables_created` test has a hardcoded table list that doesn't include `ldap_config`, update the test to include it (this is an oversight that must be fixed).
</action>

<acceptance_criteria>
- `cargo test -p dlp-server` → exit code 0
- `test_ldap_config_seed_row` → passes
- `test_tables_created` → passes with `ldap_config` in the expected table list
</acceptance_criteria>

---

### Task 3: Add integration test for `GET /admin/ldap-config` and `PUT /admin/ldap-config`

<read_first>
`dlp-server/tests/` directory structure — look for existing integration test files
`dlp-server/src/admin_api.rs` — GET/PUT handler signatures
</read_first>

<action>
Create `dlp-server/tests/ldap_config_api.rs` with integration tests for the LDAP config admin API:

```rust
//! Integration tests for the LDAP config admin API.
//!
//! Tests GET /admin/ldap-config and PUT /admin/ldap-config endpoints.

use dlp_server::admin_api::{LdapConfigPayload, admin_router};
use dlp_server::admin_auth::AdminAuth;
use dlp_server::alert_router::AlertRouter;
use dlp_server::db::Database;
use dlp_server::siem_connector::SiemConnector;
use dlp_server::AppState;

use std::sync::Arc;
use axum::Router;
use axum::http::{StatusCode, header};
use axum::body::Body;
use http_body_util::BodyExt;

// Helper: build a test app with a temp database.
fn test_app() -> Router {
    let db = Database::open(":memory:").expect("open in-memory db");
    let state = Arc::new(AppState {
        db: Arc::new(db),
        siem: SiemConnector::default(),
        alert: AlertRouter::default(),
        ad: None,  // server-side AD not tested here
    });
    admin_router(state)
}

// Helper: valid JWT for a dummy admin user.
fn auth_header() -> header::HeaderMap {
    let mut headers = header::HeaderMap::new();
    // TODO: generate a real test JWT with the same secret used in tests.
    // Use the same JWT secret as the test harness.
    let token = generate_test_jwt("admin", "admin_secret");
    headers.insert(
        header::AUTHORIZATION,
        header::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    headers
}

#[tokio::test]
async fn get_ldap_config_returns_defaults() {
    let app = test_app();
    let response = app
        .oneshot(
            http::Request::builder()
                .uri("/admin/ldap-config")
                .method("GET")
                .extension(auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let config: LdapConfigPayload = serde_json::from_slice(&body).unwrap();

    assert_eq!(config.ldap_url, "ldaps://dc.corp.internal:636");
    assert_eq!(config.base_dn, "");
    assert!(config.require_tls);
    assert_eq!(config.cache_ttl_secs, 300);
    assert_eq!(config.vpn_subnets, "");
}

#[tokio::test]
async fn put_ldap_config_updates_and_returns_new_config() {
    let app = test_app();
    let payload = LdapConfigPayload {
        ldap_url: "ldaps://new-dc.corp.internal:636".to_string(),
        base_dn: "DC=newdomain,DC=corp".to_string(),
        require_tls: false,
        cache_ttl_secs: 600,
        vpn_subnets: "10.10.0.0/16".to_string(),
    };

    let body = serde_json::to_string(&payload).unwrap();
    let response = app
        .oneshot(
            http::Request::builder()
                .uri("/admin/ldap-config")
                .method("PUT")
                .header(header::CONTENT_TYPE, "application/json")
                .extension(auth_header())
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let returned: LdapConfigPayload = serde_json::from_slice(&body).unwrap();

    assert_eq!(returned.ldap_url, "ldaps://new-dc.corp.internal:636");
    assert_eq!(returned.cache_ttl_secs, 600);
    assert!(!returned.require_tls);  // changed from default
}

#[tokio::test]
async fn put_ldap_config_rejects_cache_ttl_too_low() {
    let app = test_app();
    let payload = LdapConfigPayload {
        ldap_url: "ldaps://dc.corp.internal:636".to_string(),
        base_dn: "DC=corp,DC=internal".to_string(),
        require_tls: true,
        cache_ttl_secs: 30,  // below minimum of 60
        vpn_subnets: "".to_string(),
    };

    let body = serde_json::to_string(&payload).unwrap();
    let response = app
        .oneshot(
            http::Request::builder()
                .uri("/admin/ldap-config")
                .method("PUT")
                .header(header::CONTENT_TYPE, "application/json")
                .extension(auth_header())
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_ldap_config_requires_auth() {
    let app = test_app();
    let response = app
        .oneshot(
            http::Request::builder()
                .uri("/admin/ldap-config")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Without auth header, should get 401 Unauthorized.
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
```

**Note**: The test helper JWT generation depends on the actual JWT signing implementation. If the existing test infrastructure has a `test_jwt_secret()` helper, use it. Otherwise, create a local `generate_test_jwt` function using `jsonwebtoken` with the same secret used by the test harness.
</action>

<acceptance_criteria>
- `dlp-server/tests/ldap_config_api.rs` exists
- `grep -n "async fn get_ldap_config_returns_defaults" dlp-server/tests/ldap_config_api.rs` returns the test
- `grep -n "async fn put_ldap_config_updates_and_returns_new_config" dlp-server/tests/ldap_config_api.rs` returns the test
- `grep -n "async fn put_ldap_config_rejects_cache_ttl_too_low" dlp-server/tests/ldap_config_api.rs` returns the test
- `grep -n "async fn get_ldap_config_requires_auth" dlp-server/tests/ldap_config_api.rs` returns the test
</acceptance_criteria>

---

### Task 4: Full workspace build and test

<read_first>
None — verify the full workspace
</read_first>

<action>
Run the full suite of quality gates in sequence:

```bash
# 1. Format check
cargo fmt --check

# 2. Clippy
cargo clippy --workspace --all-targets -- -D warnings

# 3. Build
cargo build --workspace

# 4. Tests
cargo test --workspace
```

Address any failures. If clippy reports warnings, fix them. If tests fail, diagnose and fix.

Common expected fixes after Plan 01–04:
- Missing `impl Debug for LdapConfigPayload` (derive it)
- Missing field initializers in test structs
- Type mismatches between `i64` and `u64` for `cache_ttl_secs`
- `#[cfg(windows)]` not covering all Windows-only types causing compile errors on non-Windows targets
</action>

<acceptance_criteria>
- `cargo fmt --check` → exit code 0 (all formatted)
- `cargo clippy --workspace --all-targets -- -D warnings` → exit code 0, no warnings
- `cargo build --workspace` → exit code 0, no warnings
- `cargo test --workspace` → exit code 0, no test failures
</acceptance_criteria>

---

### Task 5: `sonar-scanner` — static analysis

<read_first>
None
</read_first>

<action>
Run `sonar-scanner` to verify the quality gate. Use the `SONAR_TOKEN` that was exported in the session context.

```bash
sonar-scanner
```

After the scan completes, check the SonarQube quality gate status. If the gate fails due to:
- **Bugs or code smells**: fix the reported issues and re-scan
- **Low test coverage on `ad_client.rs`**: add more unit tests targeting uncovered branches (fail-open paths, error branches in `resolve_user_groups`, etc.)
- **Coverage on new files**: aim for >80% line coverage on `dlp-common/src/ad_client.rs`

If the quality gate passes, Phase 7 is complete.
</action>

<acceptance_criteria>
- `sonar-scanner` → scan completes without error
- SonarQube quality gate: **PASSES**
- `dlp-common/src/ad_client.rs` has >80% line coverage (or the highest achievable without a live AD)
- No **Blocker** or **Critical** bugs reported
- No **Security Hotspot** rated **High**
</acceptance_criteria>

---

## Verification

After all tasks complete:
- All 5 quality gate commands pass (fmt, clippy, build, test, sonar)
- Phase 7 is complete when all acceptance criteria pass