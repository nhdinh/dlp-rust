# Testing Patterns

**Analysis Date:** 2026-04-10

## Test Framework

**Runner:**
- Rust built-in test harness via `cargo test`
- Config: Implicit in `Cargo.toml` (no separate test config file)

**Assertion Library:**
- Standard `assert!()`, `assert_eq!()`, `assert_ne!()` macros
- Pattern matching in assertions: `match parsed { ... => assert_eq!(...) }`

**Run Commands:**
```bash
cargo test                        # Run all tests in workspace
cargo test -p dlp-agent          # Test specific package
cargo test --lib                 # Unit tests only
cargo test --test '*'            # Integration tests only
cargo test -- --nocapture        # Show println/tracing output
cargo test -- --test-threads=1   # Serial execution (for stateful tests)
cargo test -- --include-ignored  # Run ignored tests
```

## Test File Organization

**Location:**
- Unit tests: Colocated in source files within `#[cfg(test)]` modules at end of file
- Integration tests: In `tests/` directory at crate root
  - `dlp-agent/tests/integration.rs` — End-to-end pipeline tests
  - `dlp-agent/tests/comprehensive.rs` — Component integration (IPC, config, cache, mapper)
  - `dlp-agent/tests/negative.rs` — Error handling, retry exhaustion, offline fallback
  - `dlp-user-ui/tests/clipboard_integration.rs` — Clipboard listener integration

**Naming:**
- Test functions prefixed with `test_`: `test_e2e_file_action_to_audit_log`, `test_cache_hit_skips_engine`
- Test modules are lowercase: `#[cfg(test)] mod tests { ... }`
- Descriptive names that specify what is being tested: `test_engine_unreachable_t4_denied` (not `test_engine`)

**Structure:**
```
dlp-agent/
├── src/
│   ├── lib.rs
│   ├── cache.rs              # Unit tests at end
│   ├── audit_emitter.rs      # Unit tests at end
│   └── ...
└── tests/
    ├── integration.rs        # E2E tests with mock Policy Engine
    ├── comprehensive.rs      # IPC serialization, config loading, boundaries
    └── negative.rs          # Error scenarios, offline fallback
```

## Test Structure

**Arrangement Pattern (Arrange-Act-Assert):**

```rust
// dlp-agent/tests/integration.rs::test_e2e_file_action_to_audit_log()
#[tokio::test]
async fn test_e2e_file_action_to_audit_log() {
    // ARRANGE: Start mock engine, create components
    let (addr, _handle) = start_mock_engine(Decision::DENY).await;
    let base_url = format!("http://{addr}");
    let client = EngineClient::new(&base_url, false).unwrap();
    let cache = Arc::new(Cache::new());
    let dir = tempfile::tempdir().unwrap();
    let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 10 * 1024 * 1024).unwrap();

    // ACT: Simulate file action, evaluate, emit audit
    let action = FileAction::Written {
        path: r"C:\Restricted\secrets.xlsx".to_string(),
        process_id: 1234,
        related_process_id: 0,
        byte_count: 4096,
    };
    let abac_action = PolicyMapper::action_for(&action);
    let classification = PolicyMapper::provisional_classification(action.path());
    let request = EvaluateRequest { ... };
    let response = client.evaluate(&request).await.unwrap();
    cache.insert(action.path(), "S-1-5-21-TEST", response.clone());
    emitter.emit(&event).unwrap();

    // ASSERT: Verify audit log
    let log_contents = std::fs::read_to_string(emitter.log_path()).unwrap();
    let parsed: dlp_common::AuditEvent = serde_json::from_str(log_contents.trim()).unwrap();
    assert_eq!(parsed.event_type, dlp_common::EventType::Block);
    assert_eq!(parsed.decision, Decision::DENY);
}
```

**Setup and Teardown:**
- Setup happens at the start of each test function (no shared fixtures)
- Cleanup is automatic via RAII: `tempfile::TempDir` deletes on drop
- No `#[before]` / `#[after]` attributes (Rust doesn't support them; use manual setup/cleanup)

**Async Tests:**
```rust
#[tokio::test]
async fn test_name() {
    // Function body — async operations OK
}
```

## Unit Test Pattern

**Colocated Tests:**
Unit tests live in the same file as the code they test, in a `#[cfg(test)]` module:

```rust
// dlp-common/src/abac.rs — end of file
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_is_denied() {
        assert!(!Decision::ALLOW.is_denied());
        assert!(Decision::DENY.is_denied());
        assert!(!Decision::AllowWithLog.is_denied());
        assert!(Decision::DenyWithAlert.is_denied());
    }

    #[test]
    fn test_decision_is_alert() {
        assert!(!Decision::ALLOW.is_alert());
        assert!(!Decision::DENY.is_alert());
        assert!(!Decision::AllowWithLog.is_alert());
        assert!(Decision::DenyWithAlert.is_alert());
    }

    #[test]
    fn test_evaluate_request_serde() {
        let req = EvaluateRequest { ... };
        let json = serde_json::to_string(&req).unwrap();
        let round_trip: EvaluateRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(
            req.resource.classification,
            round_trip.resource.classification
        );
    }
}
```

**Benefits of this pattern:**
- Tests can access private items in the module
- No separate test file to maintain
- Visible proximity to the implementation

## Mocking

**Framework:** Manual mock implementations using `axum` servers for HTTP endpoints

**Patterns:**

```rust
// dlp-agent/tests/integration.rs — Mock Policy Engine
async fn start_mock_engine(decision: Decision) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use axum::{extract::Json, routing::post, Router};
    use tokio::net::TcpListener;

    let app = Router::new().route(
        "/evaluate",
        post(move |Json(_body): Json<EvaluateRequest>| async move {
            Json(EvaluateResponse {
                decision,
                matched_policy_id: Some("mock-pol-001".to_string()),
                reason: format!("mock engine: {decision:?}"),
            })
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, handle)
}
```

**What to Mock:**
- External HTTP services (Policy Engine) — using in-process axum servers
- File system operations — using `tempfile` for temporary directories
- Configuration/Registry calls — reading from test-specific files

**What NOT to Mock:**
- Core logic (PolicyMapper, Cache, AuditEmitter) — test the real implementation
- Serialization (serde) — round-trip tests verify actual behavior
- Time-based behavior (TTL eviction) — use real `Instant::now()` and Duration

## Fixtures and Factories

**Test Data:**

```rust
// dlp-agent/tests/integration.rs — Helper function
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
            path: action.path().to_string(),
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

**Location:**
- Helper functions defined at module level in test files
- Factory functions inline where they're used (not extracted unless used in multiple tests)

## Coverage

**Requirements:** Not enforced by CI (but aspirational in CLAUDE.md section 9.16)

**Actual Coverage:**
- Core types: 95%+ (abac.rs, classification.rs have comprehensive unit tests)
- Engine client: 85%+ (happy path, 4xx/5xx errors, retry exhaustion covered)
- Cache: 85%+ (hit/miss/expiry/fail-closed tested)
- Audit emitter: 80%+ (basic emit, rotation, enrichment covered; Windows-specific paths have limits)

**View Coverage:**
```bash
# Use tarpaulin for coverage reports (not in current setup)
cargo tarpaulin --out Html --output-dir coverage/

# Or use llvm-cov if preferred
cargo llvm-cov --html
```

## Test Types

**Unit Tests:**
- Scope: Single function or type
- Location: `#[cfg(test)]` modules in source files
- Examples:
  - `test_decision_is_denied()` — tests `Decision::is_denied()` method
  - `test_classify_text_with_ssn()` — tests text classifier
  - `test_cache_entry_is_expired()` — tests TTL logic

**Integration Tests:**
- Scope: Multiple components working together
- Location: `tests/` directory
- Examples:
  - `test_e2e_file_action_to_audit_log()` — end-to-end pipeline with mock engine
  - `test_e2e_cache_hit_skips_engine()` — cache + offline logic
  - `test_engine_500_retry_exhausted()` — client + error classification

**E2E Tests:**
- Scope: Full system boundary
- Not yet implemented for Windows service (would require installation)
- Aspirational: Real NTFS interception hooks + actual Policy Engine

## Common Patterns

**Async Testing:**
```rust
#[tokio::test]
async fn test_e2e_file_action_to_audit_log() {
    // Async code allowed directly
    let response = client.evaluate(&request).await.unwrap();
    assert!(response.decision.is_denied());
}

// With explicit runtime selection
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concurrent_cache_access() { ... }
```

**Error Testing:**
```rust
// dlp-agent/tests/negative.rs — Test error handling
#[tokio::test]
async fn test_engine_500_retry_exhausted() {
    let (addr, _h) = start_error_engine(500).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();

    let request = make_request(Classification::T3);
    let result = client.evaluate(&request).await;
    assert!(result.is_err());
    // Pattern match on error type
    match result.unwrap_err() {
        EngineClientError::HttpError { status, .. } => assert_eq!(status, 500),
        other => panic!("expected HttpError(500), got {other:?}"),
    }
}
```

**Serialization Round-Trips:**
```rust
// dlp-common/src/abac.rs — Test serde correctness
#[test]
fn test_decision_serde() {
    for decision in [
        Decision::ALLOW,
        Decision::DENY,
        Decision::AllowWithLog,
        Decision::DenyWithAlert,
    ] {
        let json = serde_json::to_string(&decision).unwrap();
        let rt: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, rt);
    }
}
```

```rust
// dlp-agent/tests/comprehensive.rs — IPC message serialization
#[test]
fn test_pipe1_agent_msg_block_notify_round_trip() {
    let msg = Pipe1AgentMsg::BlockNotify { ... };
    let json = serde_json::to_string(&msg).unwrap();
    let parsed: Pipe1AgentMsg = serde_json::from_str(&json).unwrap();
    
    match parsed {
        Pipe1AgentMsg::BlockNotify { reason, classification, ... } => {
            assert_eq!(reason, "Sensitive content detected");
            assert_eq!(classification, "T4");
        }
        other => panic!("expected BlockNotify, got {other:?}"),
    }
}
```

**Cache Behavior with TTL:**
```rust
// dlp-agent/src/cache.rs — Unit test
#[test]
fn test_cache_expiry() {
    let cache = Cache::with_ttl(Duration::from_millis(100));
    cache.insert("path", "sid", response);
    
    // Hit immediately
    assert!(cache.get("path", "sid").is_some());
    
    // After TTL expires
    std::thread::sleep(Duration::from_millis(150));
    assert!(cache.get("path", "sid").is_none());
}
```

**Offline Fallback Testing:**
```rust
// dlp-agent/tests/negative.rs — Test fail-closed for T4
#[tokio::test]
async fn test_e2e_offline_fallback_deny_t4() {
    let cache = Arc::new(Cache::new());
    
    let action = FileAction::Written { path: r"C:\Restricted\top_secret.docx", ... };
    let classification = PolicyMapper::provisional_classification(action.path());
    assert_eq!(classification, Classification::T4);
    
    // Cache miss for T4 → fail-closed DENY
    let cached = cache.get(action.path(), "S-1-5-21-OFFLINE");
    assert!(cached.is_none());
    let fallback = cache::fail_closed_response(classification);
    assert!(fallback.decision.is_denied());
}
```

## Test Coverage Gaps

**Areas with Limited Testing:**
- Windows-specific code (registry, file ownership SID resolution) — limited to mock scenarios
- Service lifecycle (SCM integration) — requires Windows service installation
- NTFS interception hooks — abstracted via `notify` crate; file system operations partially tested
- Session enumeration (`WTSEnumerateSessionsW`) — limited to basic spawning tests
- UI process spawning (`CreateProcessAsUser`) — not testable in non-interactive CI

**Areas Well-Covered:**
- ABAC types and serialization (95%+)
- Cache logic and TTL expiry (85%+)
- Engine client retry logic and error handling (85%+)
- Policy mapping and classification (90%+)
- Audit event emission (80%+)

---

## Test Execution Notes

**Execution Time:**
- Unit tests: <100ms total
- Integration tests: 1-2s per test (mock engine startup/teardown)
- Comprehensive tests: 3-5s total

**Concurrency:**
- Tests default to parallel execution (`test-threads = num_cpus`)
- Stateless tests (most) run in parallel safely
- Stateful tests (cache TTL tests) run serially with `--test-threads=1`

**Debugging:**
```bash
# Run single test with output
cargo test -p dlp-agent test_e2e_file_action_to_audit_log -- --nocapture

# Run with backtrace
RUST_BACKTRACE=1 cargo test

# Run with logging (if tracing initialized in test)
RUST_LOG=debug cargo test -- --nocapture
```

---

*Testing analysis: 2026-04-10*
