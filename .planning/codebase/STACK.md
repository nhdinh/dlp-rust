# Technology Stack Inventory

## Project: Enterprise DLP System (NTFS + Active Directory + ABAC)

---

## 1. Languages and Versions

| Language | Version | Usage |
|----------|---------|-------|
| Rust | Edition 2021 (MSRV ~1.75) | Primary implementation language for all crates |
| Protocol Buffers | proto2 | Chrome Enterprise Content Analysis SDK interop |
| PowerShell | N/A | CI/CD signing scripts, smoke tests |
| Python | 3.x | Maintenance scripts (`fix_admin_api.py`, `update_plan.py`, `write_db_rs.py`) |

### Rust Toolchain
- **Edition**: 2021
- **MSRV floor**: 1.75 (enforced by dependency compatibility, e.g. `aes-gcm` pinned to MSRV <= 1.60)
- **CI targets**: `x86_64-pc-windows-msvc`, `i686-pc-windows-msvc`
- **Compiler flags**: `RUSTFLAGS="-D warnings"` (zero-warning policy)

---

## 2. Key Frameworks and Libraries

### 2.1 Async Runtime & HTTP

| Crate | Version | Purpose |
|-------|---------|---------|
| `tokio` | 1.x (workspace) | Async runtime (full features) |
| `axum` | 0.8 | Web server / HTTP API framework (dlp-server) |
| `axum-core` | 0.1 | Core axum types |
| `tower` | 0.4 | Middleware composition (timeouts, tracing) |
| `tower-http` | 0.5 | HTTP middleware (CORS, trace) |
| `tower_governor` | 0.8 | Rate limiting middleware |
| `http` | 1.x | HTTP types |
| `reqwest` | 0.12 | HTTP client (agent-to-server, SIEM relay, admin CLI) |

### 2.2 Serialization

| Crate | Version | Purpose |
|-------|---------|---------|
| `serde` | 1.x (workspace) | Serialization framework |
| `serde_json` | 1.x (workspace) | JSON serialization |
| `bincode` | 1.3 | Binary serialization (IPC, hook DLL) |
| `toml` | 0.8 | TOML config parsing (agent) |
| `serde_ignored` | 0.1 | Unknown field detection (agent config) |
| `prost` | 0.14 | Protobuf code generation (Chrome Content Analysis) |
| `bytes` | 1.x | Byte buffer handling (protobuf) |

### 2.3 Terminal / TUI / GUI

| Crate | Version | Purpose |
|-------|---------|---------|
| `ratatui` | 0.29 | Terminal UI framework (admin CLI) |
| `crossterm` | 0.28 | Cross-platform terminal control |
| `iced` | 0.13 | GUI framework (user UI) — uses `tiny-skia` software renderer |
| `tray-icon` | 0.19 | System tray icon (user UI) |
| `muda` | 0.15 | Menu bar / context menus (user UI) |
| `winrt-notification` | 0.5 | Windows toast notifications |

### 2.4 Database & Storage

| Crate | Version | Purpose |
|-------|---------|---------|
| `rusqlite` | 0.39 (workspace) | SQLite bindings (bundled, chrono support) |
| `r2d2` | 0.8 | Connection pooling |
| `r2d2_sqlite` | 0.33 | SQLite connection pool adapter |

### 2.5 Cryptography & Security

| Crate | Version | Purpose |
|-------|---------|---------|
| `jsonwebtoken` | 9 | JWT encoding/decoding (auth, approval tokens) |
| `bcrypt` | 0.16 (workspace) | Password hashing |
| `aes-gcm` | 0.10.3 | AES-GCM encryption (secrets at rest) |
| `pbkdf2` | 0.12.2 | Key derivation |
| `hmac` | 0.12.1 | HMAC |
| `sha2` | 0.10.8 | SHA-256 hashing |
| `zeroize` | 1.8.2 | Secure memory clearing |
| `ed25519-dalek` | 2 | Ed25519 signing (approval workflow tokens) |
| `rand` | 0.8 | Cryptographic randomness |
| `hex` | 0.4 | Hex encoding |
| `secrecy` | 0.8 (workspace) | Secret wrapper types (redacted Debug) |
| `retour` | 0.4.0-alpha.4 | Function hooking / trampolines (hook DLL) |

### 2.6 Windows Platform

| Crate | Version | Purpose |
|-------|---------|---------|
| `windows` | 0.58 / 0.62 | Windows API bindings (extensive feature sets per crate) |
| `windows-service` | 0.8 | Windows Service Control Manager integration |
| `wmi` | 0.18 | WMI queries (BitLocker, device info) |
| `winres` | 0.1 | Windows resource compilation (user UI build) |

### 2.7 Concurrency & Parallelism

| Crate | Version | Purpose |
|-------|---------|---------|
| `parking_lot` | 0.12 (workspace) | Fast synchronization primitives |
| `dashmap` | 6 | Concurrent hash map |
| `rayon` | 1.11 | Data parallelism |
| `crossbeam-channel` | 0.5 | Multi-producer multi-consumer channels |
| `async-trait` | 0.1 | Async trait methods |
| `once_cell` | 1 (workspace) | Lazy static initialization |

### 2.8 Networking & Identity

| Crate | Version | Purpose |
|-------|---------|---------|
| `ldap3` | 0.11 (workspace) | LDAP client (Active Directory integration) |
| `tokio-rustls` | 0.26 | TLS for syslog forwarder |
| `rustls-native-certs` | 0.8 | Native TLS certificate store |
| `rustls-pki-types` | 1.14 | rustls PKI types |
| `webpki-roots` | 1.0 | Web PKI root certificates |
| `url` | 2 | URL parsing (SSRF validation) |
| `ipnetwork` | 0.20 (workspace) | IP network types |
| `hostname` | 0.4 | Machine hostname resolution |

### 2.9 File System & I/O

| Crate | Version | Purpose |
|-------|---------|---------|
| `notify` | 8 (workspace) | File system event watching (hot-reload) |
| `walkdir` | 2.5 | Recursive directory traversal |
| `glob` | 0.3 | Glob pattern matching |
| `zip` | 2 | ZIP archive handling (XPS print parsing) |
| `quick-xml` | 0.36 | XML parsing (XPS print documents) |
| `tempfile` | 3 | Temporary files (tests) |
| `rfd` | 0.14 | Native file dialogs (admin CLI) |

### 2.10 Email

| Crate | Version | Purpose |
|-------|---------|---------|
| `lettre` | 0.11 | SMTP email transport (alert router) |

### 2.11 Time & Scheduling

| Crate | Version | Purpose |
|-------|---------|---------|
| `chrono` | 0.4 | Date/time handling (serde support) |
| `uuid` | 1.x (workspace) | UUID generation (v4, serde) |

### 2.12 Rate Limiting

| Crate | Version | Purpose |
|-------|---------|---------|
| `governor` | 0.10 | Rate limiting |

### 2.13 Logging & Observability

| Crate | Version | Purpose |
|-------|---------|---------|
| `tracing` | 0.1 (workspace) | Structured logging with spans |
| `tracing-subscriber` | 0.3 | Log subscriber (env-filter, JSON) |
| `tracing-appender` | 0.2 | File log appender |

### 2.14 Error Handling

| Crate | Version | Purpose |
|-------|---------|---------|
| `thiserror` | 1 (workspace) | Custom error type derivation |
| `anyhow` | 1 (workspace) | Error propagation / context |

### 2.15 Testing

| Crate | Version | Purpose |
|-------|---------|---------|
| `wiremock` | 0.6 | HTTP mock server (admin CLI tests) |
| `serial_test` | 3 | Sequential test execution |

---

## 3. Build Tools and Package Managers

| Tool | Version | Purpose |
|------|---------|---------|
| `cargo` | Latest stable | Rust package manager, build system, test runner |
| `rustfmt` | Latest stable | Code formatting (enforced in CI) |
| `clippy` | Latest stable | Linting (enforced in CI with `-D warnings`) |
| `protoc` | Via `arduino/setup-protoc@v3` | Protocol Buffer compiler (CI) |
| `sonar-scanner` | Via SonarCloud GitHub Action | Static analysis / security scanning |
| `winres` | 0.1 | Windows resource compilation (icons, manifests) |

### Build Profiles
- **Debug**: Standard development builds
- **Release**: Optimized release builds with Authenticode signing
- **Cross-compilation**: `i686-pc-windows-msvc` target for 32-bit hook DLL

---

## 4. Infrastructure and Deployment Tech

### 4.1 CI/CD (GitHub Actions)

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `build.yml` | Push to master, PRs | Build, clippy, fmt check, tests, SonarQube scan |
| `nightly.yml` | Scheduled (02:00 UTC), manual | Release build, smoke tests, health checks |
| `release.yml` | Tag push (`v*`) | Release build, Authenticode signing, artifact upload |

### 4.2 Code Quality

| Tool | Integration | Purpose |
|------|-------------|---------|
| SonarQube / SonarCloud | GitHub Actions | Static analysis, security scanning, quality gate |
| `cargo clippy` | CI | Linting |
| `cargo fmt --check` | CI | Format verification |
| `cargo test --workspace` | CI | Unit and integration tests |

### 4.3 Signing & Distribution

| Technology | Purpose |
|------------|---------|
| Authenticode (`signtool`) | Binary signing (DigiCert primary, Sectigo fallback) |
| GitHub Releases | Artifact distribution (via `actions/upload-artifact@v4`) |

### 4.4 Issue Tracking

| Tool | Purpose |
|------|---------|
| `beads` (`bd`) | Custom issue tracker for phase-based development |

### 4.5 Code Search & Refactoring

| Tool | Purpose |
|------|---------|
| `ast-grep` (`sg`) | Semantic code search and refactoring |

---

## 5. Development Tools

| Tool | Purpose |
|------|---------|
| `cargo` | Build, test, doc generation, dependency management |
| `rustfmt` | Automatic code formatting |
| `clippy` | Linting and code quality suggestions |
| `cargo doc` | Documentation generation |
| `sonar-scanner` | Static analysis and security scanning |
| `ast-grep` | Structure-aware code search |
| `rtk` (Rust Token Killer) | Token-optimized CLI proxy for dev operations |
| `beads` (`bd`) | Issue tracking and work management |
| GitHub Actions | Continuous integration and release automation |

---

## 6. Workspace Structure

| Crate | Type | Description |
|-------|------|-------------|
| `dlp-common` | Library | Shared types, ABAC engine, audit structures, crypto primitives |
| `dlp-server` | Binary + Library | Central management server, policy engine, admin API, SIEM relay |
| `dlp-agent` | Binary + Library | Endpoint agent (Windows Service), enforcement, detection |
| `dlp-admin-cli` | Binary + Library | Interactive TUI for system administration |
| `dlp-user-ui` | Binary + Library | Endpoint user interface (GUI, tray, notifications) |
| `dlp-e2e` | Library + Tests | End-to-end integration test harness |
| `dlp-hook-dll` | CDylib + Library | API hook DLL for cloud sync client interception |
