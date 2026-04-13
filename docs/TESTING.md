<!-- generated-by: gsd-doc-writer -->

# Testing — DLP-RUST

## Test Framework

Tests use Rust's built-in test harness with `#[test]` and `#[tokio::test]` for async tests. No external framework required — `cargo test` handles everything.

| Crate | Test location | Framework |
|-------|-------------|-----------|
| `dlp-common` | `#[cfg(test)]` modules inline in source | `#[test]` |
| `dlp-server` | `#[cfg(test)]` modules inline in source + `tests/` | `#[tokio::test]` |
| `dlp-agent` | `tests/comprehensive.rs`, `tests/integration.rs`, `tests/negative.rs` | `#[tokio::test]` |
| `dlp-user-ui` | `#[cfg(test)]` modules inline in source | `#[test]` |
| `dlp-admin-cli` | `#[cfg(test)]` modules inline in source | `#[tokio::test]` |

## Running Tests

### Full workspace test suite

```powershell
cargo test --workspace
```

Runs all tests across all 5 crates. This is the authoritative check before any commit.

### By crate

```powershell
cargo test -p dlp-server
cargo test -p dlp-agent
cargo test -p dlp-admin-cli
cargo test -p dlp-user-ui
cargo test -p dlp-common
```

### By test file

```powershell
cargo test -p dlp-agent --test comprehensive
cargo test -p dlp-agent --test integration
```

> **Note:** Running `cargo test -p dlp-agent --lib` finds 0 unit tests — the agent's library tests live in `tests/` files, not `#[cfg(test)]` modules in `lib.rs`. Use `--test` or omit the flag filter to run all test targets.

### Single test by name

```powershell
cargo test test_tc_01
cargo test test_hot_reload
```

### Thread-limited (for Windows Service interference)

```powershell
cargo test -p dlp-agent -- --test-threads=1
```

Some tests run the agent service and may conflict if run in parallel. Use `--test-threads=1` to serialize.

### With output capture disabled (see `println!`)

```powershell
cargo test -p dlp-server -- --nocapture
```

## Test Files

### `dlp-agent/tests/comprehensive.rs`

The primary TC (Test Case) coverage suite. 170 test functions organized in 6 modules:

| Module | Test cases | Coverage |
|--------|-----------|----------|
| `file_ops_tc` | TC-01/02/03/10/11/12/13/14/60/61/62/70/71/72 | File interception, USB, network shares, classification |
| `email_alert_tc` | TC-20/21/22/23/24 | Email body pattern detection |
| `cloud_tc` | TC-30/31/32/33 | Cloud interception stubs (Phase 9) |
| `clipboard_tier_tc` | TC-40/41/42 | Cross-tier clipboard paste detection |
| `print_tc` | TC-50/51/52 | Print spooler stubs (Phase 9) |
| `detective_tc` | TC-80/81/82 | Audit event generation |

### `dlp-agent/tests/integration.rs`

End-to-end pipeline tests. 52 test functions exercising the full intercept → classify → engine → audit → JSONL path using a mock axum engine.

### `dlp-agent/tests/negative.rs`

Negative tests (expected failures, error paths).

### `dlp-server/src/admin_api.rs`

15+ inline `#[tokio::test]` functions covering:
- Policy CRUD (create, read, update, delete)
- JWT authentication middleware
- Audit event ingestion
- SIEM and alert config endpoints

## Writing New Tests

### Naming convention

Follow the existing pattern: `test_<category>_<number>` for TC tests, descriptive names for unit/integration tests.

```rust
#[tokio::test]
async fn test_policy_create_requires_jwt() {
    // Arrange
    let app = spawn_admin_app().await;
    // Act & Assert
    let resp = app
        .post("/admin/policies")
        .send()
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
```

### Inline test modules

For unit tests that don't need async runtime:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classification_t4_is_highest() {
        assert!(Classification::Restricted.is_higher_than(Classification::Confidential));
    }
}
```

### Key test helpers (dlp-server)

```rust
// Spawn a test app with in-memory DB
async fn spawn_admin_app() -> TestApp { ... }

// Extract JWT for authenticated requests
fn get_admin_token(app: &TestApp) -> String { ... }
```

## CI Integration

Tests run in GitHub Actions on every push to `master` and every pull request.

**Workflow:** `.github/workflows/build.yml`

```
Trigger: push to master, pull_request (opened/synchronize/reopened)
Job: SonarQube scan — runs `cargo build --release` then `sonar-scanner`
```

<!-- VERIFY: Full test suite runs in CI before merge — confirm .github/workflows/build.yml contains cargo test step -->

SonarQube quality gate must pass before merge. Low test coverage is treated as a blocking issue.

## Coverage Requirements

No coverage threshold is currently configured in CI. Coverage is monitored via SonarQube. Target: maintain or improve existing coverage as new features are added.
