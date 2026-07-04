# Technology Stack

**Analysis Date:** 2026-07-03

## Languages

**Primary:**
- **Rust** (Edition 2021, MSRV ~1.75) — Implementation language for all crates (`dlp-common`, `dlp-server`, `dlp-agent`, `dlp-admin-cli`, `dlp-user-ui`, `dlp-hook-dll`, `dlp-e2e`).

**Secondary:**
- **Protocol Buffers** (proto2) — Chrome Enterprise Content Analysis SDK interop (`dlp-agent/proto/`, `dlp-agent/build.rs`).
- **PowerShell** — CI/CD signing scripts, smoke tests (`scripts/*.ps1`, `.github/workflows/release.yml`).
- **Python 3.x** — Maintenance scripts (`scripts/fix_admin_api.py`, `scripts/update_plan.py`, `scripts/write_db_rs.py`).
- **TOML** — Agent configuration (`dlp-agent/src/config.rs`).

## Runtime

**Environment:**
- **tokio** 1.x (full features) — Async runtime for `dlp-server`, `dlp-agent`, and async tests.
- **Windows Service Control Manager (SCM)** — `dlp-agent` runs as a Windows Service under `LocalSystem` (`dlp-agent/src/service.rs`, `dlp-agent/src/main.rs`).

**Package Manager:**
- **cargo** — Rust package manager, build system, test runner.
- **Lockfile:** `Cargo.lock` present and committed.

## Frameworks

**Core:**
- **axum** 0.8 — HTTP server / admin API framework in `dlp-server` (`dlp-server/src/admin_api.rs`, `dlp-server/src/main.rs`).
- **axum-core** 0.1 — Core axum types.
- **tower** 0.4 / **tower-http** 0.5 — Middleware composition (timeouts, tracing, CORS, compression).
- **tower_governor** 0.8 — Rate limiting middleware (`dlp-server/src/rate_limiter.rs`).
- **reqwest** 0.12 — HTTP client for agent-to-server, SIEM relay, and admin CLI.

**UI:**
- **iced** 0.13 (`tiny-skia` renderer) — Per-session user GUI (`dlp-user-ui/src/app.rs`).
- **ratatui** 0.29 + **crossterm** 0.28 — Administrator TUI (`dlp-admin-cli/src/app.rs`, `dlp-admin-cli/src/tui.rs`).
- **tray-icon** 0.19 / **muda** 0.15 — System tray and menus (`dlp-user-ui/src/tray.rs`).
- **winrt-notification** 0.5 — Windows toast notifications (`dlp-user-ui/src/notifications.rs`).

**Testing:**
- Rust built-in test harness (`#[test]`, `#[tokio::test]`).
- **wiremock** 0.6 — HTTP mock server for admin CLI tests.
- **serial_test** 3 — Sequential execution for global-state tests.

**Build/Dev:**
- **cargo** + **rustfmt** + **clippy** — Build, format, lint.
- **protoc** — Protocol Buffers compiler (installed in CI via `arduino/setup-protoc@v3`).
- **winres** 0.1 — Windows resource compilation (icons, manifests) in `dlp-user-ui/build.rs`.
- **ast-grep** (`sg`) — Semantic code search (`sgconfig.yml`, `.ast-grep/`).
- **sonar-scanner** — Static analysis / security scanning (`sonar-project.properties`).

## Key Dependencies

**Critical:**
- **serde** / **serde_json** — JSON serialization across all wire formats.
- **bincode** 1.3 — Binary serialization for named-pipe IPC and hook DLL messages.
- **thiserror** / **anyhow** — Typed errors and boundary error propagation.
- **tracing** / **tracing-subscriber** / **tracing-appender** — Structured logging.
- **parking_lot** 0.12 — Fast synchronization primitives.
- **once_cell** 1.x — Lazy static initialization.
- **uuid** 1.x — UUID generation.

**Infrastructure:**
- **rusqlite** 0.39 (bundled, chrono support) + **r2d2** 0.8 + **r2d2_sqlite** 0.33 — SQLite data store and connection pooling in `dlp-server`.
- **jsonwebtoken** 9 — JWT auth and session tokens.
- **bcrypt** 0.16 — Admin password hashing.
- **aes-gcm** 0.10.3 / **pbkdf2** 0.12.2 / **hmac** 0.12.1 / **sha2** 0.10.8 / **ed25519-dalek** 2 — Cryptography for secrets at rest, approval tokens, hashing.
- **secrecy** 0.8 — Redacted secret wrapper types.
- **ldap3** 0.11 — Active Directory / LDAP client.
- **tokio-rustls** 0.26 + **rustls-native-certs** 0.8 — TLS for syslog and HTTPS.
- **notify** 8 — File system event watching for interception.
- **prost** 0.14 — Protobuf code generation for Chrome Content Analysis.
- **lettre** 0.11 — SMTP alert routing.
- **windows** 0.58/0.62 + **windows-service** 0.8 — Windows API bindings and service lifecycle.
- **wmi** 0.18 — BitLocker / encryption status queries.
- **ferrisetw** 1.2.0 — ETW process watching.
- **retour** 0.4.0-alpha.4 — Function hooking / trampolines in `dlp-hook-dll`.
- **rayon** 1.11 — Data parallelism (content hashing in hook DLL).
- **crossbeam-channel** 0.5 / **crossbeam-queue** 0.3 — Message passing and queues.
- **dashmap** 6 — Concurrent hash maps.
- **ipnetwork** 0.20 — IP network types.
- **walkdir** 2.5 / **zip** 2 / **quick-xml** 0.36 — Directory traversal, XPS print parsing.
- **tempfile** 3 — Temporary files in tests.

## Configuration

**Environment:**
- Environment variables loaded from `.env` (gitignored) or process environment.
- `dlp-server` uses `DLP_SERVER_URL`, `DLP_DATABASE_PATH`, `JWT_SECRET`, plus encrypted SQLite rows for secrets.
- `dlp-agent` uses TOML config file (`config.toml`) and registry values for server URL discovery.

**Build:**
- `Cargo.toml` (workspace root) defines 7 members and shared dependencies.
- `Cargo.toml` per crate defines crate-specific dependencies, features, and build scripts.
- `.github/workflows/build.yml` enforces `RUSTFLAGS: "-D warnings"`.
- `.github/workflows/release.yml` builds release artifacts and applies Authenticode signing.

## Platform Requirements

**Development:**
- Rust stable toolchain (MSRV ~1.75).
- `protoc` for protobuf generation.
- Windows strongly recommended for full test execution (agent, hook DLL, WFP, ETW).
- Non-Windows builds compile via `#[cfg(not(windows))]` stubs but cannot run Windows-specific enforcement.

**Production:**
- Windows 10/11 or Windows Server endpoints.
- `dlp-agent.exe` installed as `LocalSystem` Windows Service.
- `dlp-user-ui.exe` spawned per interactive session.
- `dlp-server.exe` deployed centrally (Windows/Linux/macOS capable; production typically Windows/Linux).
- Authenticode-signed binaries (`signtool verify /pa`) required for production deployment.

---

*Stack analysis: 2026-07-03*
