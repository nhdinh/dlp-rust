# Testing Patterns

**Analysis Date:** 2026-07-03

## Test Framework

**Runner:**
- Rust built-in test harness via `cargo test`.
- Async runtime: `tokio` with `#[tokio::test]` (283+ async tests).
- Config: No separate framework config; test organization follows Cargo conventions.

**Assertion Library:**
- Standard `assert!`, `assert_eq!`, `assert_ne!`, `assert!(matches!(...))` only.

**Run Commands:**
```bash
cargo test                                 # Run all tests in workspace
cargo test -p dlp-common                   # Test specific package
cargo test -p dlp-server                   # Test server crate only
cargo test --lib                           # Unit tests only (#[cfg(test)] modules)
cargo test --test '*'                      # Integration tests only (tests/ directory)
cargo test -- --nocapture                  # Show println/tracing output
cargo test -- --test-threads=1             # Serial execution for stateful tests
cargo test -- --include-ignored            # Run ignored tests
```

## Test File Organization

**Location:**
- Unit tests: co-located in source files inside `#[cfg(test)] mod tests { ... }`.
- Integration tests: `tests/*.rs` at crate root.
- E2E tests: `dlp-e2e/tests/*.rs`.

**Naming:**
- Unit test module: `mod tests { ... }`.
- Integration test files: descriptive suffixes, e.g., `admin_audit_integration.rs`, `mode_end_to_end.rs`.
- Test functions: prefix with `test_`, e.g., `test_e2e_file_action_to_audit_log`.

**Structure:**
```
dlp-server/
├── src/
│   └── *.rs              # #[cfg(test)] modules co-located
└── tests/
    ├── admin_audit_integration.rs
    ├── mode_end_to_end.rs
    └── secrets_*.rs

dlp-agent/
├── src/
│   └── *.rs              # #[cfg(test)] modules co-located
└── tests/
    ├── integration.rs
    ├── comprehensive.rs
    ├── negative.rs
    └── chrome_pipe.rs

dlp-e2e/
└── tests/
    ├── phase50_requirements.rs
    ├── cache_benchmark.rs
    ├── bincode_compat.rs
    └── tui_*.rs
```

## Test Structure

**Suite Organization:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_is_denied() {
        assert!(!Decision::ALLOW.is_denied());
        assert!(Decision::DENY.is_denied());
    }

    #[tokio::test]
    async fn test_async_handler() {
        let app = test_app();
        let response = app.oneshot(build_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
```

**Patterns:**
- Arrange-Act-Assert.
- Serialization round-trips for all wire types.
- Backward compatibility tests with legacy JSON.
- Error-path tests with mock failures.

## Mocking

**Framework:** No dedicated mock framework; use in-process test doubles.

**Patterns:**
```rust
async fn start_mock_engine(decision: Decision) -> (SocketAddr, JoinHandle<()>) {
    let app = Router::new().route("/evaluate", post(
        move |Json(_body): Json<EvaluateRequest>| async move {
            Json(EvaluateResponse {
                decision,
                matched_policy_id: Some("mock-pol-001".to_string()),
                reason: format!("mock engine: {decision:?}"),
                enforcement_mode: None,
                would_have_denied: decision.is_denied(),
            })
        }
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle)
}
```

**What to Mock:**
- External HTTP services (policy engine, SIEM endpoints).
- Time sources when deterministic TTL behavior is required.
- Windows APIs in non-Windows test builds via `#[cfg(not(windows))]` stubs.

**What NOT to Mock:**
- Core logic (`PolicyMapper`, `Cache`, `AuditEmitter`) — test real implementation.
- Serialization (serde) — round-trip tests verify actual behavior.
- Repository SQL — tests use real SQLite in-memory databases.

## Fixtures and Factories

**Test Data:**
```rust
fn make_request(classification: Classification) -> EvaluateRequest {
    EvaluateRequest {
        subject: Subject {
            user_sid: "S-1-5-21-TEST".to_string(),
            user_name: "testuser".to_string(),
            groups: Vec::new(),
            device_trust: DeviceTrust::Managed,
            network_location: NetworkLocation::Corporate,
        },
        resource: Resource {
            path: "C:\\test.txt".to_string(),
            classification,
        },
        environment: Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: AccessContext::Local,
        },
        action: Action::WRITE,
        ..Default::default()
    }
}
```

**AppState Builder:**
```rust
fn app_state_with_flag(flag: bool) -> AppState {
    let pool = Arc::new(crate::db::new_pool(":memory:").expect("in-memory pool"));
    let crypto = Arc::new(crate::crypto::SecretCrypto::from_kek([0u8; 32], 1));
    AppState {
        pool: Arc::clone(&pool),
        crypto: Arc::clone(&crypto),
        policy_store: Arc::new(crate::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("store")),
        // ... other fields ...
    }
}
```

**Location:**
- Inline in test modules and integration test files.
- Shared harness helpers in `dlp-e2e/src/lib.rs`.

## Coverage

**Requirements:** No explicit coverage target enforced; SonarQube Quality Gate treats low coverage as blocking.

**View Coverage:**
```bash
cargo llvm-cov --workspace          # Requires cargo-llvm-cov
cargo tarpaulin --workspace         # Alternative
```

## Test Types

**Unit Tests:**
- Scope: Single function, method, or type.
- Location: `#[cfg(test)]` modules at end of source files.
- Characteristics: Fast (<10ms), no I/O.

**Integration Tests:**
- Scope: Multiple components working together.
- Location: `tests/*.rs`.
- Characteristics: Slower (100ms–2s), may use I/O and mock servers.

**E2E Tests:**
- Framework: `dlp-e2e` crate with cross-crate helpers.
- Scope: Full system boundary.
- Characteristics: Slowest; test real component interactions and headless TUI.

## Common Patterns

**Async Testing:**
```rust
#[tokio::test]
async fn test_async_operation() {
    let response = client.evaluate(&request).await.unwrap();
    assert!(response.decision.is_denied());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concurrent_cache_access() { ... }
```

**Error Testing:**
```rust
#[tokio::test]
async fn test_engine_500_retry_exhausted() {
    let (addr, _h) = start_error_engine(500).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();
    let request = make_request(Classification::T3);
    let result = client.evaluate(&request).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        EngineClientError::HttpError { status, .. } => assert_eq!(status, 500),
        other => panic!("expected HttpError(500), got {other:?}"),
    }
}
```

**Global State Serialization:**
- Use `parking_lot::Mutex<()>` as a test serialization lock when mutating process-wide `OnceLock` state.
- Example: `dlp-agent/src/lib.rs` `test_helpers::DISK_TEST_LOCK`.

---

*Testing analysis: 2026-07-03*
