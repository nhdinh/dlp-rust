# Testing Approach

**Analysis Date:** 2026-06-05
**Workspace:** Enterprise DLP System (NTFS + Active Directory + ABAC)
**Test Count:** ~1,591 `#[test]` attributes, ~283 `#[tokio::test]` async tests
**Files with Tests:** 86+ source files containing `#[cfg(test)]` modules

---

## 1. Test Framework and Tools

### 1.1 Test Runner
- **Primary:** Rust built-in test harness via `cargo test`
- **Async runtime:** `tokio` with `#[tokio::test]` for async tests (283+ instances)
- **No external test frameworks** — standard `assert!`, `assert_eq!`, `assert_ne!` macros only

### 1.2 Common Commands
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

### 1.3 Quality Gates (Required Before Commit)
- `cargo test` — all tests pass
- `cargo build --all` — no compiler warnings
- `cargo clippy -- -D warnings` — clippy passes
- `cargo fmt --check` — code is formatted
- `sonar-scanner` — static analysis passes Quality Gate

---

## 2. Test Organization and Structure

### 2.1 Unit Tests
- **Location:** Colocated in source files within `#[cfg(test)]` modules at end of file
- **Naming:** `mod tests { ... }` (lowercase)
- **Access:** Can test private items via `use super::*;`
- **Coverage:** Found in 86+ source files across all crates

**Example from `dlp-common/src/abac.rs`:**
```rust
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
    fn test_evaluate_request_serde() {
        let req = EvaluateRequest { ... };
        let json = serde_json::to_string(&req).unwrap();
        let round_trip: EvaluateRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.resource.classification, round_trip.resource.classification);
    }
}
```

### 2.2 Integration Tests
- **Location:** `tests/` directory at crate root
- **Naming:** Descriptive suffixes indicating scope

| File | Crate | Purpose |
|------|-------|---------|
| `integration.rs` | dlp-agent | End-to-end pipeline with mock Policy Engine |
| `comprehensive.rs` | dlp-agent | IPC serialization, config loading, boundaries |
| `negative.rs` | dlp-agent | Error handling, retry exhaustion, offline fallback |
| `chrome_pipe.rs` | dlp-agent | Chrome Enterprise Connector IPC |
| `encryption_integration.rs` | dlp-agent | DPAPI and encryption round-trips |
| `device_registry_cache.rs` | dlp-agent | Device registry caching behavior |
| `universal_injection.rs` | dlp-agent | DLL injection mechanics |
| `admin_audit_integration.rs` | dlp-server | Admin API audit event emission |
| `bypass_alerts_integration.rs` | dlp-server | Bypass alert ingestion and routing |
| `device_registry_integration.rs` | dlp-server | Device registry CRUD |
| `enforcement_mode_integration.rs` | dlp-server | Global/per-policy mode override |
| `ldap_config_api.rs` | dlp-server | LDAP configuration API |
| `managed_origins_integration.rs` | dlp-server | Managed origins whitelist |
| `mode_end_to_end.rs` | dlp-server | Full enforcement mode pipeline |
| `secrets_encryption_integration.rs` | dlp-server | KEK lifecycle and envelope encryption |
| `secrets_log_scan_integration.rs` | dlp-server | Secret leakage detection in logs |
| `secrets_migration_integration.rs` | dlp-server | Secret column migration |
| `secrets_rotation_integration.rs` | dlp-server | KEK rotation and re-encryption |
| `phase50_requirements.rs` | dlp-e2e | Phase 50 requirement traceability |
| `cache_benchmark.rs` | dlp-e2e | Performance benchmarks for cache |
| `bincode_compat.rs` | dlp-e2e | Binary serialization compatibility |
| `hot_reload_config.rs` | dlp-e2e | Configuration hot-reload behavior |
| `tui_conditions_builder.rs` | dlp-e2e | TUI conditions builder interaction |
| `tui_device_registry.rs` | dlp-e2e | TUI device registry screens |
| `tui_managed_origins.rs` | dlp-e2e | TUI managed origins screens |
| `agent_toml_writeback.rs` | dlp-e2e | Agent config TOML persistence |
| `agent_ui_lifecycle.rs` | dlp-e2e | Agent-to-UI lifecycle coordination |
| `ntdll_chaos_test.rs` | dlp-hook-dll | Ntdll patching stress tests |
| `clipboard_integration.rs` | dlp-user-ui | Clipboard monitor integration |
| `endpoint_cross_crate_compat.rs` | dlp-common | Cross-crate type compatibility |

### 2.3 Test Function Naming
- Prefix with `test_`: `test_e2e_file_action_to_audit_log`
- Descriptive names specifying what is tested:
  - `test_engine_unreachable_t4_denied` (not `test_engine`)
  - `test_cache_hit_skips_engine`
  - `test_abac_context_round_trip_with_volume_class`
- Requirement traceability in comments:
  ```rust
  /// **CACHE-01**: Shared-memory `Global\DlpClassificationCache` exists.
  #[test]
  fn shared_memory_created() { ... }
  ```

---

## 3. Test Coverage Patterns

### 3.1 Well-Covered Areas
| Area | Coverage | Test Strategy |
|------|----------|---------------|
| ABAC types and serialization | 95%+ | Extensive serde round-trip tests, variant discrimination |
| Classification enum | 95%+ | Ordering, sensitivity, labels, serde |
| Cache logic and TTL | 85%+ | Hit/miss/expiry, fail-closed, concurrent access |
| Engine client retry logic | 85%+ | Mock HTTP servers, error classification, backoff |
| Policy mapping | 90%+ | Action mapping, classification hints, path normalization |
| Audit event emission | 80%+ | Builder pattern, JSONL output, rotation, enrichment |
| Crypto (envelope encryption) | 85%+ | DPAPI round-trip, KEK derivation, AAD binding |
| Decision predicates | 95%+ | `is_denied()`, `is_alert()`, `requires_audit()` |
| Volume class resolution | 90%+ | Path parsing, UNC, drive letter, volume GUID |
| Enforcement mode | 90%+ | Global override, per-policy, effective mode computation |

### 3.2 Coverage Gaps
| Area | Gap | Reason |
|------|-----|--------|
| Windows-specific APIs | Limited | Requires Windows runtime (registry, SCM, `CreateProcessAsUser`) |
| NTFS interception hooks | Partial | Abstracted via `notify` crate; FS ops partially tested |
| Service lifecycle (SCM) | Minimal | Requires actual Windows service installation |
| Session enumeration | Limited | `WTSEnumerateSessionsW` needs interactive session |
| UI process spawning | Minimal | Non-interactive CI cannot spawn GUI processes |
| ETW Kernel-File consumer | Partial | Windows-only; mocked in non-Windows builds |
| Hook DLL injection | Partial | Requires target process; chaos tests cover some paths |
| WFP (Windows Filtering Platform) | Minimal | Kernel-level; integration tests use mocks |

---

## 4. Integration vs Unit Test Split

### 4.1 Unit Tests (`#[cfg(test)]` in source files)
- **Scope:** Single function, method, or type
- **Characteristics:** Fast (<10ms each), no I/O, no external dependencies
- **Examples:**
  - `test_decision_is_denied()` — tests `Decision::is_denied()` method
  - `test_classification_order()` — tests `PartialOrd` implementation
  - `test_cache_entry_is_expired()` — tests TTL logic
  - `test_volume_class_serde_roundtrip()` — tests serde correctness
  - `test_enforcement_mode_is_blocking()` — tests predicate methods

### 4.2 Integration Tests (`tests/*.rs`)
- **Scope:** Multiple components working together
- **Characteristics:** Slower (100ms–2s), may use I/O, mock external services
- **Examples:**
  - `test_e2e_file_action_to_audit_log()` — PolicyMapper + EngineClient + Cache + AuditEmitter
  - `test_admin_audit_integration.rs` — HTTP API + DB + audit store
  - `test_secrets_encryption_integration.rs` — Crypto + DB + KEK lifecycle

### 4.3 E2E Tests (`dlp-e2e/tests/`)
- **Scope:** Full system boundary across crates
- **Characteristics:** Slowest, test real component interactions
- **Examples:**
  - `phase50_requirements.rs` — Maps requirements to observable tests
  - `cache_benchmark.rs` — Performance regression detection
  - `agent_ui_lifecycle.rs` — Agent-to-UI IPC lifecycle

---

## 5. Mocking Strategy

### 5.1 HTTP Service Mocking
- **Tool:** In-process `axum` servers bound to `127.0.0.1:0`
- **Pattern:**
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

### 5.2 Database Mocking
- **Tool:** SQLite `:memory:` databases via `db::new_pool(":memory:")`
- **Pattern:** Each test creates a fresh in-memory pool, runs migrations, seeds data
- **Example from `admin_audit_integration.rs`:**
  ```rust
  fn test_app() -> (axum::Router, Arc<db::Pool>) {
      set_jwt_secret(TEST_JWT_SECRET.to_string());
      let tmp = NamedTempFile::new().expect("create temp db");
      let pool = Arc::new(db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
      // ... build AppState with real repositories ...
  }
  ```

### 5.3 File System Mocking
- **Tool:** `tempfile::TempDir` for temporary directories (auto-deleted on drop)
- **Tool:** `tempfile::NamedTempFile` for temporary files
- **Pattern:**
  ```rust
  let dir = tempfile::tempdir().unwrap();
  let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 10 * 1024 * 1024).unwrap();
  // ... test ...
  let log_contents = std::fs::read_to_string(emitter.log_path()).unwrap();
  ```

### 5.4 Windows API Stubbing
- **Pattern:** `#[cfg(not(windows))]` stubs return placeholder values
- **Pattern:** `#[cfg(windows)]` code tested where possible; non-Windows CI uses stubs
- **Example:**
  ```rust
  /// Non-Windows stub: always returns `false` (no mismatch).
  #[cfg(not(windows))]
  pub fn check_divergence(...) -> Result<bool, Error> {
      Ok(false)
  }
  ```

### 5.5 Global State Serialization
- **Tool:** `parking_lot::Mutex<()>` as a test serialization lock
- **Pattern:**
  ```rust
  #[cfg(test)]
  pub mod test_helpers {
      use parking_lot::Mutex;
      pub static DISK_TEST_LOCK: Mutex<()> = Mutex::new(());
  }
  ```
- Used when tests mutate global `OnceLock` state that cannot be reset per-test

### 5.6 What NOT to Mock
- Core logic (PolicyMapper, Cache, AuditEmitter) — test real implementation
- Serialization (serde) — round-trip tests verify actual behavior
- Time-based behavior (TTL eviction) — use real `Instant::now()` and `Duration`
- Repository SQL — tests use real SQLite in-memory databases

---

## 6. Test Structure Patterns

### 6.1 Arrange-Act-Assert
```rust
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
    let action = FileAction::Written { path: r"C:\Restricted\secrets.xlsx".to_string(), ... };
    let abac_action = PolicyMapper::action_for(&action);
    let request = EvaluateRequest { ... };
    let response = client.evaluate(&request).await.unwrap();
    emitter.emit(&event).unwrap();

    // ASSERT: Verify audit log
    let log_contents = std::fs::read_to_string(emitter.log_path()).unwrap();
    let parsed: AuditEvent = serde_json::from_str(log_contents.trim()).unwrap();
    assert_eq!(parsed.event_type, EventType::Block);
    assert_eq!(parsed.decision, Decision::DENY);
}
```

### 6.2 Serialization Round-Trip Tests
```rust
#[test]
fn test_decision_serde() {
    for decision in [Decision::ALLOW, Decision::DENY, Decision::AllowWithLog, Decision::DenyWithAlert] {
        let json = serde_json::to_string(&decision).unwrap();
        let rt: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, rt);
    }
}
```

### 6.3 Backward Compatibility Tests
```rust
#[test]
fn test_audit_event_backward_compat_missing_new_fields() {
    let legacy = r#"{ "timestamp": "2025-01-01T00:00:00Z", "event_type": "BLOCK", ... }"#;
    let event: AuditEvent = serde_json::from_str(legacy).unwrap();
    assert!(event.source_application.is_none());
    assert!(event.destination_application.is_none());
}
```

### 6.4 Error Path Tests
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

### 6.5 Async Test Patterns
```rust
// Standard async test
#[tokio::test]
async fn test_async_operation() {
    let response = client.evaluate(&request).await.unwrap();
    assert!(response.decision.is_denied());
}

// Multi-threaded async test
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concurrent_cache_access() { ... }
```

### 6.6 Phase-Specific Test Modules
Tests are sometimes grouped into phase-specific submodules:
```rust
#[cfg(test)]
mod phase37_action_tests {
    use super::Action;

    #[test]
    fn test_disk_registry_add_serializes_as_variant_name() { ... }
}
```

---

## 7. Fixtures and Factories

### 7.1 Inline Factory Functions
Defined at module level in test files when reused:
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
        resource: Resource { path: "C:\\test.txt".to_string(), classification },
        environment: Environment { timestamp: chrono::Utc::now(), session_id: 1, access_context: AccessContext::Local },
        action: Action::WRITE,
        ..Default::default()
    }
}
```

### 7.2 AppState Builder for Integration Tests
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

### 7.3 RAII Cleanup
- `tempfile::TempDir` — auto-deleted on drop
- `NamedTempFile` — auto-deleted on drop
- Mock server `JoinHandle` — aborted on test completion via drop

---

## 8. Test Execution

### 8.1 Concurrency
- **Default:** Parallel execution (`test-threads = num_cpus`)
- **Stateful tests:** Use `parking_lot::Mutex<()>` for cross-test serialization
- **Global OnceLock tests:** Require `--test-threads=1` or explicit locking

### 8.2 Execution Time
- Unit tests: <100ms total per crate
- Integration tests: 100ms–2s per test (mock server startup/teardown)
- E2E tests: 1–5s per test

### 8.3 Debugging
```bash
# Run single test with output
cargo test -p dlp-agent test_e2e_file_action_to_audit_log -- --nocapture

# Run with backtrace
RUST_BACKTRACE=1 cargo test

# Run with logging
RUST_LOG=debug cargo test -- --nocapture

# Run specific integration test file
cargo test --test admin_audit_integration
```

---

## 9. Security Testing Patterns

### 9.1 Adversarial Tests
- Corrupt shared-memory rejection
- Rapid version flips
- Partial write simulation
- Malformed header rejection
- Path bypass attempts (8.3, symlink, junction, volume GUID, ADS, trailing dots)
- Cache-hint non-authoritative invariant
- Fail-mode ABAC invariant

### 9.2 Fail-Closed Verification
```rust
#[test]
fn test_resolve_volume_guid_fails_closed() {
    let result = resolve_volume_class_from_path(
        "\\\\?\\Volume{12345678-1234-1234-1234-123456789012}\\file.txt",
        |_letter| Some(VolumeClass::LocalNTFS),
    );
    assert_eq!(result, None, "volume GUID path must fail-closed with None");
}
```

### 9.3 Threat Model Tests
Crypto module tests verify threat mitigations:
- Offline file-system theft resistance (DPAPI machine-binding)
- Cross-column ciphertext replay (AAD binding per `(table, column)`)
- Tampering detection (AES-GCM auth tag)
- Forward compatibility (envelope version byte)

---

## 10. Cross-Platform Testing

### 10.1 Windows-Only Code
- Guarded with `#[cfg(windows)]`
- Tested on Windows CI runners
- Non-Windows builds use stubs

### 10.2 Non-Windows Stubs
- Guarded with `#[cfg(not(windows))]`
- Return safe defaults (`false`, `None`, empty Vec)
- Allow compilation and basic unit testing on Linux/macOS

### 10.3 Platform-Specific Test Files
- `dlp-agent/tests/` contains Windows-specific integration tests
- `dlp-e2e/tests/` contains cross-platform behavioral tests
- `dlp-common/tests/` contains pure-Rust logic tests (platform-agnostic)
