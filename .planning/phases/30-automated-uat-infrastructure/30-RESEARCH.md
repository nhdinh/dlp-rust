# Phase 30: Automated UAT Infrastructure - Research

**Researched:** 2026-04-28
**Domain:** Rust integration testing, headless TUI testing, Windows USB kernel-level verification, CI/CD for Windows Rust projects
**Confidence:** HIGH

## Summary

Phase 30 replaces deferred human UAT checkpoints with automated verification across Phases 4, 6, 24, and 28. The research confirms that all required testing infrastructure already exists in the codebase or is well-supported by the Rust ecosystem. No new external dependencies are needed beyond what is already in the workspace.

The approach is a **two-tier test architecture**: (1) Rust integration tests in a new `dlp-e2e` crate for API-layer and TUI verification, and (2) PowerShell scripts for Windows-native tests requiring physical hardware or elevated privileges. CI runs the Rust tests on every PR; PowerShell scripts are local-only manual tests.

**Primary recommendation:** Create a `dlp-e2e` workspace member crate that depends on `dlp-admin-cli`, `dlp-agent`, `dlp-server`, and `dlp-common`. Use `ratatui::backend::TestBackend` for headless TUI tests, `tokio::net::TcpListener` on port 0 for mock axum servers, and `std::process::Command` (not `tokio::process::Command`) for spawning dlp-server/dlp-agent binaries from tests. Add `cargo test --workspace` to the existing GitHub Actions workflow.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| TUI headless testing | Test crate (dlp-e2e) | dlp-admin-cli (source) | TestBackend injects events into App::handle_event() without real terminal |
| API integration tests | Test crate (dlp-e2e) | dlp-server (source) | Mock axum server + tower::ServiceExt::oneshot pattern already proven |
| Agent TOML write-back | Test crate (dlp-e2e) | dlp-agent (source) | Spawns real binary, asserts file system state |
| USB write-protection | PowerShell script (local) | dlp-agent unit tests | Kernel-level IOCTL requires real hardware; unit tests mock the logic |
| CI orchestration | GitHub Actions | — | windows-latest runner required for Win32 APIs |
| Release-mode smoke | Nightly CI | — | Separate target dir avoids debug/release lock conflict |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| ratatui | 0.29.0 (workspace) | TUI framework | Already used by dlp-admin-cli; TestBackend provides headless testing [VERIFIED: cargo info] |
| crossterm | 0.28.1 (workspace) | Terminal events | KeyEvent injection for TUI tests [VERIFIED: cargo info] |
| axum | 0.8.9 (workspace) | Mock HTTP server | Existing pattern in dlp-agent/tests/comprehensive.rs [VERIFIED: codebase] |
| tokio | 1.50.0 (workspace) | Async runtime | Mock server spawning, test async [VERIFIED: cargo info] |
| tower | 0.4.13 (workspace) | Service testing | ServiceExt::oneshot for in-process router tests [VERIFIED: codebase] |
| tempfile | 3.27.0 (workspace) | Temp directories | Auto-cleanup, used in existing tests [VERIFIED: cargo info] |
| serde_json | 1.0.149 (workspace) | JSON assertions | API response parsing in tests [VERIFIED: cargo info] |
| jsonwebtoken | 9.3.1 (workspace) | JWT minting | Test auth tokens for admin API [VERIFIED: cargo info] |
| reqwest | 0.12.28 (workspace) | HTTP client | Agent->server communication in tests [VERIFIED: cargo info] |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| chrono | 0.4 (workspace) | JWT exp claim | Minting test JWTs |
| parking_lot | 0.12 (workspace) | RwLock/Mutex | Same as production code |
| tracing | 0.1 (workspace) | Structured logging | Test diagnostics |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| TestBackend | ratatui-testlib (PTY-based) | PTY adds complexity; TestBackend is sufficient for state+render assertions |
| std::process::Command | tokio::process::Command | tokio::process is for async contexts; tests that spawn binaries and block are simpler with std |
| PowerShell | Python + pywin32 | PowerShell is native on Windows, no extra install; already have script templates |

**Installation:** No new crates needed — all dependencies are already workspace members or workspace dependencies.

**Version verification:**
- ratatui 0.29.0 (latest 0.30.0; workspace uses 0.29) [VERIFIED: cargo info]
- crossterm 0.28.1 (latest 0.29.0; workspace uses 0.28) [VERIFIED: cargo info]
- tokio 1.50.0 (latest 1.52.1; workspace uses 1.x) [VERIFIED: cargo info]
- axum 0.8.9 (latest; workspace uses 0.8.x) [VERIFIED: cargo info]

## Architecture Patterns

### System Architecture Diagram

```
+--------------------------------------------------+
|                  dlp-e2e crate                    |
|  (integration tests: cargo test -p dlp-e2e)      |
+--------------------------------------------------+
|                                                   |
|  +----------------+  +------------------------+  |
|  | TUI Tests      |  | API/Stack Tests        |  |
|  | TestBackend    |  | Mock axum server       |  |
|  | KeyEvent inject|  | tower::ServiceExt      |  |
|  | state + render |  | DB seed + assert       |  |
|  | assertions     |  |                        |  |
|  +----------------+  +------------------------+  |
|                                                   |
|  +----------------+  +------------------------+  |
|  | Agent TOML Test|  | Hot-Reload Test        |  |
|  | spawn dlp-agent|  | seed DB -> poll ->     |  |
|  | + dlp-server   |  | assert behavior change |  |
|  | assert file    |  |                        |  |
|  +----------------+  +------------------------+  |
+--------------------------------------------------+
           |                    |
           v                    v
    +-------------+      +-------------+
    | dlp-admin-cli|      | dlp-server  |
    | (lib + bin)  |      | (lib + bin) |
    +-------------+      +-------------+
           |                    |
           v                    v
    +-------------+      +-------------+
    | dlp-agent    |      | dlp-common  |
    | (lib + bin)  |      | (lib only)  |
    +-------------+      +-------------+

+--------------------------------------------------+
|           scripts/Uat-UsbBlock.ps1               |
|  (local-only, manual, requires physical USB)     |
|  - WMI drive detection                           |
|  - Admin API registration                        |
|  - IOCTL_DISK_SET_DISK_ATTRIBUTES verification   |
|  - Cleanup after test                            |
+--------------------------------------------------+
```

### Recommended Project Structure

```
dlp-e2e/
├── Cargo.toml              # workspace member, depends on dlp-admin-cli, dlp-agent, dlp-server, dlp-common
├── tests/
│   ├── tui_device_registry.rs      # TUI: DeviceList -> register -> delete
│   ├── tui_managed_origins.rs      # TUI: ManagedOriginList -> add -> remove
│   ├── tui_conditions_builder.rs   # TUI: ConditionsBuilder SourceApplication/DestinationApplication
│   ├── agent_toml_writeback.rs     # Full stack: server -> agent -> TOML file
│   ├── hot_reload_config.rs        # DB seed -> hot-reload -> behavior change
│   └── release_smoke.rs            # #[ignore] release-mode smoke tests
└── src/
    └── lib.rs                # Shared test helpers (mock server builder, JWT minting, DB setup)

scripts/
├── Uat-UsbBlock.ps1        # Real-hardware USB write-protection verification
└── Uat-ReadMe.md           # Instructions for manual UAT execution

.github/workflows/
├── build.yml               # ADD: cargo test --workspace job
└── nightly.yml             # NEW: release-mode build + smoke tests
```

### Pattern 1: Headless TUI Test with TestBackend

**What:** Inject `KeyEvent` sequences into `App::handle_event()` and assert on both internal state (`app.screen`) and rendered output (`TestBackend::buffer()`).

**When to use:** All TUI screen flow tests (Device Registry, Managed Origins, Conditions Builder).

**Example:**
```rust
// Source: [CITED: docs.rs/ratatui/latest/ratatui/backend/struct.TestBackend.html]
// Source: [CITED: docs.rs/crossterm/latest/crossterm/event/struct.KeyEvent.html]
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use dlp_admin_cli::app::{App, Screen};
use dlp_admin_cli::screens::dispatch::handle_event;
use dlp_admin_cli::event::AppEvent;

#[test]
fn test_device_list_navigation() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = build_test_app(); // helper: mock client + runtime

    // Initial screen: MainMenu
    assert!(matches!(app.screen, Screen::MainMenu { .. }));

    // Navigate to Devices & Origins (index 3)
    let down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
    for _ in 0..3 { handle_event(&mut app, AppEvent::Key(down)); }

    // Press Enter
    let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
    handle_event(&mut app, AppEvent::Key(enter));

    // Assert state transition
    assert!(matches!(app.screen, Screen::DevicesMenu { .. }));

    // Render and assert buffer contains expected text
    terminal.draw(|frame| dlp_admin_cli::screens::draw(&app, frame)).unwrap();
    let buffer = terminal.backend().buffer();
    let contents: String = buffer.content.iter().map(|c| c.symbol()).collect();
    assert!(contents.contains("Device Registry"));
    assert!(contents.contains("Managed Origins"));
}
```

### Pattern 2: Mock Axum Server for API Tests

**What:** Spawn an axum router on `TcpListener::bind("127.0.0.1:0")` for zero-conflict port allocation.

**When to use:** Any test that needs a running HTTP server (agent TOML write-back, hot-reload).

**Example:**
```rust
// Source: [VERIFIED: dlp-agent/tests/comprehensive.rs lines 538-556]
use axum::{extract::Json, routing::post, Router};
use tokio::net::TcpListener;
use dlp_common::{EvaluateRequest, EvaluateResponse};

async fn start_mock_server(
    response: EvaluateResponse,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/evaluate",
        post(move |Json(_): Json<EvaluateRequest>| async move { Json(response.clone()) }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle)
}
```

### Pattern 3: In-Process Router Test with Tower

**What:** Build the admin router directly and use `tower::ServiceExt::oneshot` to send requests without starting a TCP listener.

**When to use:** Fast API tests that don't need a real TCP socket (device registry CRUD, managed origins CRUD).

**Example:**
```rust
// Source: [VERIFIED: dlp-server/tests/device_registry_integration.rs lines 47-62]
fn build_test_app() -> (axum::Router, Arc<db::Pool>) {
    let _ = set_jwt_secret(TEST_JWT_SECRET.to_string());
    let tmp = NamedTempFile::new().expect("create temp db");
    let pool = Arc::new(db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
    let state = Arc::new(AppState {
        pool: Arc::clone(&pool),
        policy_store: Arc::new(policy_store::PolicyStore::new(Arc::clone(&pool)).unwrap()),
        siem: siem_connector::SiemConnector::new(Arc::clone(&pool)),
        alert: alert_router::AlertRouter::new(Arc::clone(&pool)),
        ad: None,
    });
    (admin_router(state), pool)
}

// Usage:
let (app, _pool) = build_test_app();
let resp = app.oneshot(req).await.expect("oneshot");
```

### Pattern 4: Spawning Real Binaries from Tests

**What:** Use `std::process::Command` to spawn dlp-server and dlp-agent as child processes, then poll for expected behavior.

**When to use:** Agent TOML write-back test (full stack verification).

**Example:**
```rust
// Source: [CITED: docs.rs/tempfile/latest/tempfile/]
use std::process::{Command, Stdio};
use tempfile::tempdir;

#[test]
fn test_agent_toml_writeback() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("agent-config.toml");

    // Spawn dlp-server
    let mut server = Command::new("cargo")
        .args(["run", "--bin", "dlp-server", "--"])
        .env("DLP_DB_PATH", temp_dir.path().join("test.db"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // Wait for server ready (poll health endpoint)
    // ... poll loop ...

    // Spawn dlp-agent pointing at temp config
    let mut agent = Command::new("cargo")
        .args(["run", "--bin", "dlp-agent", "--"])
        .env("DLP_CONFIG_PATH", &config_path)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();

    // Seed DB with config via admin API
    // ...

    // Poll for TOML file update
    // ...

    // Cleanup
    let _ = agent.kill();
    let _ = server.kill();
}
```

### Anti-Patterns to Avoid

- **Using tokio::process::Command for simple spawn-and-wait:** `std::process::Command` is simpler when the test is synchronous. Use `tokio::process` only when the test is already async and needs concurrent process management.
- **Hardcoding port numbers:** Always use `TcpListener::bind("127.0.0.1:0")` and read `local_addr()` to avoid conflicts with parallel tests.
- **Moving TempDir into Command:** `Command::current_dir(tempdir())` drops the TempDir before the command runs. Pass by reference: `Command::current_dir(&temp_dir)`.
- **Using real terminal for TUI tests:** Never call `tui::setup()` in tests — it enters raw mode and alternate screen. Always use `TestBackend`.
- **Running USB hardware tests in CI:** Physical USB devices are not available in GitHub Actions runners. Mark these `#[ignore]` or use PowerShell scripts.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Mock HTTP server | Custom TCP listener + thread | axum + tokio::net::TcpListener | axum handles routing, JSON extraction, error responses |
| JWT minting for tests | Manual base64 + HMAC | jsonwebtoken crate | Already in workspace; handles exp, iss, sub correctly |
| Temp file cleanup | Manual fs::remove_dir_all | tempfile::tempdir() | Auto-cleanup on drop; handles edge cases |
| TUI buffer inspection | Manual cell iteration | TestBackend::assert_buffer_lines() | Ratatui provides built-in assertions |
| Process port discovery | Hardcoded ports | TcpListener::bind("127.0.0.1:0") | OS allocates free port; zero conflicts |
| DB setup per test | Manual CREATE TABLE | db::new_pool() + init_tables() | Already implemented; consistent schema |
| Test report formatting | Custom XML/JSON | Plain text PASS/FAIL | User chose plain text for USB script (30-CONTEXT.md D-05) |

**Key insight:** The project already has working mock server patterns, JWT minting, DB initialization, and TestBackend infrastructure. The dlp-e2e crate should compose these existing pieces, not reinvent them.

## Runtime State Inventory

This phase is an infrastructure/test phase — no runtime state changes or renames. All deferred UAT items are verification-only.

| Category | Items Found | Action Required |
|----------|-------------|-----------------|
| Stored data | None — tests use temp DBs | N/A |
| Live service config | None — tests use temp configs | N/A |
| OS-registered state | None — tests do not register services | N/A |
| Secrets/env vars | None — tests use dev JWT secret (already public) | N/A |
| Build artifacts | `target/` and `target-test/` dirs (local dev only) | N/A |

**Nothing found in category:** All categories verified — this phase creates tests, not production state.

## Common Pitfalls

### Pitfall 1: OnceLock JWT Secret Race
**What goes wrong:** `set_jwt_secret()` uses `std::sync::OnceLock`. If two test binaries run in the same process with different secrets, the first call wins and the second's tokens fail validation.
**Why it happens:** `cargo test` compiles each `tests/*.rs` file as a separate binary. Parallel execution means non-deterministic call order.
**How to avoid:** Use the SAME `TEST_JWT_SECRET` constant across ALL test files. The existing dlp-server tests already do this (`"dlp-server-dev-secret-change-me"`). The dlp-e2e crate must use the same literal.
**Warning signs:** Intermittent 401 responses in tests that "should work."

### Pitfall 2: Elevated Process Locks Target Binary
**What goes wrong:** Running dlp-server.exe or dlp-agent.exe elevated (as admin) locks the binary file. Subsequent `cargo build` or `cargo test` fails with "Access denied" or "The process cannot access the file."
**Why it happens:** Windows file locking — an executing binary cannot be overwritten.
**How to avoid:** Use `CARGO_TARGET_DIR=target-test` when spawning binaries from tests (STATE.md decision 2026-04-21). In CI, use the default target dir (no elevated processes in CI).
**Warning signs:** `cargo test` fails with OS error 5 (Access Denied) on binary files.

### Pitfall 3: TestBackend vs CrosstermBackend Mismatch
**What goes wrong:** Tests that accidentally call `tui::setup()` (which uses `CrosstermBackend`) will enter raw mode and alternate screen, breaking the terminal.
**Why it happens:** Copy-paste from main.rs into test code.
**How to avoid:** Never import `tui::setup` or `tui::restore` in test code. Always construct `Terminal::new(TestBackend::new(w, h))`.
**Warning signs:** Terminal becomes unresponsive after running tests; cursor disappears.

### Pitfall 4: Agent Poll Timing Flakiness
**What goes wrong:** The agent TOML write-back test flakes because the agent polls on its own interval (default 30s), and the test times out waiting.
**Why it happens:** Tests must wait for the agent's config poll loop to fire.
**How to avoid:** Seed DB with `heartbeat_interval_secs = 1` so the agent polls within 1-2 seconds. Use `tokio::time::timeout` or `std::thread::sleep` with a generous margin (e.g., assert within 5 seconds).
**Warning signs:** Test passes locally but fails in CI; test duration is inconsistent.

### Pitfall 5: Windows-Only Tests Compile on Non-Windows
**What goes wrong:** Tests that use Win32 APIs (`UsbDetector`, `CreateFileW`, etc.) fail to compile on Linux/macOS CI runners.
**Why it happens:** GitHub Actions `windows-latest` is the only runner with Win32 APIs, but `cargo check` on other platforms will fail.
**How to avoid:** Gate Windows-only tests with `#[cfg(windows)]` and `#[cfg_attr(not(windows), ignore)]`. The existing codebase already does this (e.g., `dlp-agent/tests/comprehensive.rs` line 1892).
**Warning signs:** CI fails on `cargo check` or `cargo clippy` with "unresolved import" for `windows::Win32::*`.

## Code Examples

### Verified patterns from official sources:

#### TestBackend Buffer Assertion
```rust
// Source: [CITED: docs.rs/ratatui/latest/ratatui/backend/struct.TestBackend.html]
let mut backend = TestBackend::new(10, 2);
backend.clear().unwrap();
backend.assert_buffer_lines(["          "; 2]);
```

#### KeyEvent Construction for Test Injection
```rust
// Source: [CITED: docs.rs/crossterm/latest/crossterm/event/struct.KeyEvent.html]
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, KeyEventKind};

let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
let esc = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
let down = KeyEvent::new_with_kind(KeyCode::Down, KeyModifiers::NONE, KeyEventKind::Press);
let char_a = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
```

#### TempDir with Command (Correct Drop Order)
```rust
// Source: [CITED: docs.rs/tempfile/latest/tempfile/]
use tempfile::tempdir;
use std::process::Command;

let temp_dir = tempdir()?;
let status = Command::new("touch")
    .arg("tmp")
    .current_dir(&temp_dir)  // borrow, do NOT move
    .status()?;
```

#### Mock Server with JSON Response
```rust
// Source: [VERIFIED: dlp-agent/tests/comprehensive.rs]
async fn start_engine_with_json_response(
    response: EvaluateResponse,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use axum::{extract::Json, routing::post, Router};
    use tokio::net::TcpListener;

    let app = Router::new().route(
        "/evaluate",
        post(move |Json(_): Json<EvaluateRequest>| async move { Json(response.clone()) }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle)
}
```

#### JWT Minting for Admin API Tests
```rust
// Source: [VERIFIED: dlp-server/tests/device_registry_integration.rs lines 65-77]
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
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Manual human UAT | Automated integration tests | Phase 30 (now) | Faster feedback, reproducible, CI-gated |
| PTY-based TUI testing (ratatui-testlib) | TestBackend + direct event injection | Phase 30 | Simpler, no external PTY deps, faster |
| Single test binary per crate | Dedicated dlp-e2e crate | Phase 30 | Clean separation; cross-crate tests don't pollute lib crates |
| `actions-rs/toolchain` | `dtolnay/rust-action` | 2024 | actions-rs is unmaintained; dtolnay is actively maintained |
| `cargo test` only | `cargo test --workspace` + `cargo clippy -- -D warnings` | Phase 30 | Zero-warning build enforcement per CLAUDE.md |

**Deprecated/outdated:**
- `actions-rs/cargo`: Unmaintained as of 2024. Use `run:` steps with cargo directly.
- `tempdir` crate: Deprecated in favor of `tempfile::tempdir()`.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | GitHub Actions `windows-latest` runner supports Win32 APIs needed for dlp-agent tests | Environment Availability | CI would fail; tests would need `#[cfg(windows)]` gating |
| A2 | `ratatui::backend::TestBackend` is sufficient for all TUI screen assertions (no PTY needed) | Standard Stack | If render assertions are insufficient, may need ratatui-testlib |
| A3 | `std::process::Command` is adequate for spawning dlp-server/dlp-agent from tests | Architecture Patterns | If async process management needed, switch to `tokio::process::Command` |
| A4 | Physical USB device is available for local manual testing | Runtime State Inventory | If no USB device, PowerShell script cannot run; unit tests still cover logic |

## Open Questions (RESOLVED)

1. **Does the TUI `App::new()` constructor require a real `EngineClient` with a running server?** — RESOLVED
   - What we know: `App::new` takes `EngineClient` and `tokio::runtime::Runtime`. `EngineClient` makes HTTP calls.
   - Resolution: Use a mock `EngineClient` pointing at an in-process mock axum server (same pattern as existing integration tests). The `EngineClient` in dlp-admin-cli uses `reqwest::blocking::Client` internally, so it needs a real HTTP endpoint. Captured in Plan 30-01 (shared helpers) and Plans 30-02 through 30-04 (TUI tests).

2. **Can the agent TOML write-back test use the agent's library directly instead of spawning the binary?** — RESOLVED
   - What we know: `config_poll_loop` is async and internal to `service.rs`. `AgentConfig::save()` exists.
   - Resolution: Spawn the binary for true end-to-end verification. For faster unit tests, test `AgentConfig::save()` and `AgentConfig::load()` directly (already covered in comprehensive.rs). Captured in Plan 30-05.

3. **Should the nightly workflow use `sccache` for faster release builds?** — RESOLVED
   - What we know: Release builds are slow. Nightly schedule means caching helps across days.
   - Resolution: Start without sccache. Add it later if build times are problematic (deferred per 30-CONTEXT.md). Captured in Plan 30-10.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust toolchain | All | Yes | 1.94.1 | — |
| Cargo | Build + test | Yes | 1.94.1 | — |
| Windows SDK / Win32 APIs | dlp-agent tests | Yes (win32) | Windows 11 | CI uses windows-latest |
| SQLite | dlp-server tests | Yes (bundled via rusqlite) | — | — |
| GitHub Actions | CI | Yes (project has build.yml) | — | — |
| Physical USB device | USB real-hardware test | No (this machine has none) | — | PowerShell script is local-only; run on machine with USB |
| Elevated console | USB IOCTL test | Yes (can run as admin) | — | — |

**Missing dependencies with no fallback:**
- Physical USB removable drive for real-hardware testing. This is expected — the PowerShell script is documented as local-only manual test.

**Missing dependencies with fallback:**
- None.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Built-in `#[test]` + `tokio::test` (async) |
| Config file | None — tests are self-contained |
| Quick run command | `cargo test -p dlp-e2e` |
| Full suite command | `cargo test --workspace` |
| Clippy check | `cargo clippy --workspace -- -D warnings` |

### Phase Requirements to Test Map

| Deferred UAT Item | Source Phase | Test Type | Automated Command | File (planned) |
|-------------------|-------------|-----------|-------------------|----------------|
| Agent TOML write-back | Phase 6 | Integration (spawn binary) | `cargo test -p dlp-e2e --test agent_toml_writeback` | `dlp-e2e/tests/agent_toml_writeback.rs` |
| Zero-warning build | Phase 6 | CI lint | `cargo clippy --workspace -- -D warnings` | `.github/workflows/build.yml` |
| Hot-reload verification | Phase 4 | Integration (in-process) | `cargo test -p dlp-e2e --test hot_reload_config` | `dlp-e2e/tests/hot_reload_config.rs` |
| Release-mode smoke | Phase 24 | Integration (release binary) | `cargo test -p dlp-e2e --test release_smoke -- --ignored` | `dlp-e2e/tests/release_smoke.rs` |
| TUI Device Registry | Phase 28 | Headless TUI | `cargo test -p dlp-e2e --test tui_device_registry` | `dlp-e2e/tests/tui_device_registry.rs` |
| TUI Managed Origins | Phase 28 | Headless TUI | `cargo test -p dlp-e2e --test tui_managed_origins` | `dlp-e2e/tests/tui_managed_origins.rs` |
| TUI Conditions Builder | Phase 28 | Headless TUI | `cargo test -p dlp-e2e --test tui_conditions_builder` | `dlp-e2e/tests/tui_conditions_builder.rs` |
| USB write-protection | Phase 28 | PowerShell (manual) | `powershell -File scripts/Uat-UsbBlock.ps1` | `scripts/Uat-UsbBlock.ps1` |

### Sampling Rate
- **Per task commit:** `cargo test -p dlp-e2e --test <relevant_test>`
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full workspace test green + clippy zero warnings + SonarQube quality gate

### Wave 0 Gaps
- [ ] `dlp-e2e/Cargo.toml` — new workspace member crate
- [ ] `dlp-e2e/src/lib.rs` — shared test helpers (mock server builder, JWT minting)
- [ ] `dlp-e2e/tests/tui_device_registry.rs` — TUI headless test
- [ ] `dlp-e2e/tests/tui_managed_origins.rs` — TUI headless test
- [ ] `dlp-e2e/tests/tui_conditions_builder.rs` — TUI headless test
- [ ] `dlp-e2e/tests/agent_toml_writeback.rs` — full stack test
- [ ] `dlp-e2e/tests/hot_reload_config.rs` — hot-reload test
- [ ] `dlp-e2e/tests/release_smoke.rs` — release-mode smoke test
- [ ] `scripts/Uat-UsbBlock.ps1` — USB hardware verification script
- [ ] `.github/workflows/nightly.yml` — nightly release-mode CI workflow
- [ ] Root `Cargo.toml` — add `dlp-e2e` to workspace members

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | Yes | JWT Bearer tokens in tests use same secret as dev mode (`TEST_JWT_SECRET`) |
| V3 Session Management | No | Tests are stateless per-test |
| V4 Access Control | Yes | Admin API tests verify 401/403 paths |
| V5 Input Validation | Yes | Test payloads use serde_json::json! with controlled data |
| V6 Cryptography | No | No crypto in test code beyond JWT HMAC |

### Known Threat Patterns for Test Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Hardcoded JWT secret in tests | Information Disclosure | Use same dev secret already public; never use production secrets |
| Test binary spawning real services | Elevation of Privilege | Tests run in temp dirs, no system-wide changes |
| Temp files left behind | Denial of Service | tempfile::tempdir() auto-cleans on drop |

## Sources

### Primary (HIGH confidence)
- `dlp-agent/tests/comprehensive.rs` — Mock axum server pattern, `start_engine_with_json_response()` helper [VERIFIED: codebase]
- `dlp-server/tests/device_registry_integration.rs` — `build_test_app()` + `mint_jwt()` + `tower::ServiceExt::oneshot` pattern [VERIFIED: codebase]
- `dlp-server/tests/managed_origins_integration.rs` — Same pattern, duplicate origin 409 test [VERIFIED: codebase]
- `dlp-agent/tests/device_registry_cache.rs` — `seed_for_test()` pattern for cache seeding [VERIFIED: codebase]
- `dlp-admin-cli/src/main.rs` — TUI event loop: `run_tui()` calls `screens::draw()` then `screens::handle_event()` [VERIFIED: codebase]
- `dlp-admin-cli/src/app.rs` — `App::new()`, `Screen` enum, `AppEvent::Key(KeyEvent)` [VERIFIED: codebase]
- `dlp-admin-cli/src/event.rs` — `AppEvent` enum definition [VERIFIED: codebase]
- `dlp-admin-cli/src/tui.rs` — `CrosstermBackend` setup (avoid in tests) [VERIFIED: codebase]
- `dlp-agent/src/config.rs` — `AgentConfig::load()`, `AgentConfig::save()` [VERIFIED: codebase]
- `dlp-agent/src/service.rs` — `config_poll_loop()` async function [VERIFIED: codebase]
- `dlp-agent/src/usb_enforcer.rs` — `UsbEnforcer::check()` with `#[cfg(test)]` module [VERIFIED: codebase]
- `dlp-agent/src/detection/usb.rs` — `UsbDetector` with `blocked_drives` and `device_identities` public fields for test seeding [VERIFIED: codebase]
- `.github/workflows/build.yml` — Existing CI workflow (SonarQube only) [VERIFIED: codebase]

### Secondary (MEDIUM confidence)
- [docs.rs/ratatui/latest/ratatui/backend/struct.TestBackend.html](https://docs.rs/ratatui/latest/ratatui/backend/struct.TestBackend.html) — TestBackend API: `new()`, `buffer()`, `assert_buffer_lines()` [CITED: official docs]
- [docs.rs/crossterm/latest/crossterm/event/struct.KeyEvent.html](https://docs.rs/crossterm/latest/crossterm/event/struct.KeyEvent.html) — KeyEvent constructors for test injection [CITED: official docs]
- [docs.rs/tokio/latest/tokio/process/struct.Command.html](https://docs.rs/tokio/latest/tokio/process/struct.Command.html) — tokio::process patterns [CITED: official docs]
- [docs.rs/tempfile/latest/tempfile/](https://docs.rs/tempfile/latest/tempfile/) — tempdir() drop behavior [CITED: official docs]
- [Rust Cargo Book — Continuous Integration](https://doc.rust-lang.org/cargo/guide/continuous-integration.html) — Official CI guidance [CITED: official docs]
- [reintech.io — Rust CI/CD with GitHub Actions](https://reintech.io/blog/rust-cicd-github-actions-testing-building-deploying) — Modern workflow patterns [CITED: web search]

### Tertiary (LOW confidence)
- [ratatui.rs/concepts/backends/](https://ratatui.rs/concepts/backends/) — Backend overview (minimal TestBackend detail) [CITED: official docs]
- [docs.rs/ratatui-testlib](https://docs.rs/ratatui-testlib) — PTY-based testing framework (not needed for this phase) [CITED: official docs]

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all crates are already in the workspace; versions verified against registry
- Architecture: HIGH — existing test patterns in codebase are proven and directly reusable
- Pitfalls: HIGH — all pitfalls are derived from actual codebase decisions and Windows-specific behavior
- TUI testing: MEDIUM-HIGH — TestBackend API verified via docs.rs; exact assertion patterns will be refined during implementation
- CI workflow: MEDIUM — based on standard patterns; exact YAML will be validated during implementation

**Research date:** 2026-04-28
**Valid until:** 2026-05-28 (stable stack, 30 days)
