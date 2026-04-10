# DLP-RUST Tech Stack & Dependencies

## Rust Toolchain

| Component | Version | Notes |
|-----------|---------|-------|
| **Edition** | 2021 | Workspace-wide |
| **Resolver** | 2 | Workspace-wide |
| **MSRV** | Not specified | Target: Windows 11 Pro (10.0.26200+) |

## Workspace Dependencies

All versions managed via `[workspace.dependencies]` in `Cargo.toml`.

| Crate | Version | Purpose |
|-------|---------|---------|
| `tokio` | 1 (full features) | Async runtime for all components |
| `serde` | 1 (derive) | Serialization/deserialization framework |
| `serde_json` | 1 | JSON codec |
| `thiserror` | 1 | Error type derive macros |
| `tracing` | 0.1 | Structured logging |
| `anyhow` | 1 | Error handling / context |
| `parking_lot` | 0.12 | High-performance mutex/RwLock |
| `once_cell` | 1 | Lazy static initialization |
| `uuid` | 1 (v4, serde) | Unique identifiers |
| `bcrypt` | 0.16 | Password hashing (dlp-admin, agent auth) |
| `notify` | 7 | File system events (agent only) |
| `ldap3` | 0.11 | Active Directory integration (reserved for future) |

## Crate-Specific Dependencies

### dlp-common
Pure types library; minimal external dependencies.
- `chrono` 0.4 (serde) — timestamp handling
- `uuid` 1 (v4, serde) — identifiers
- **No runtime deps** — depends only on std

### dlp-agent
Windows Service endpoint agent.

**HTTP & Clients:**
- `reqwest` 0.12 (json, rustls-tls, no-default-features) — Policy Engine + server HTTPS client
- `hostname` 0.4 — machine identity

**Logging:**
- `tracing-subscriber` 0.3 (env-filter, json) — structured logging + JSON output
- `tracing-appender` 0.2 — log file rotation

**Windows API:**
- `windows` 0.58 — extensive Win32 bindings (see Cargo.toml for complete feature list)
  - `Win32_Foundation` — base types
  - `Win32_Security`, `Win32_Security_Authorization` — SID/identity operations
  - `Win32_System_Services` — Windows Service Control Manager
  - `Win32_System_Threading` — thread/process operations
  - `Win32_Storage_FileSystem` — NTFS metadata
  - `Win32_System_Pipes` — named pipe IPC
  - `Win32_System_Diagnostics_Etw` — Event Tracing for Windows
  - `Win32_Security_Cryptography` — DPAPI
  - `Win32_UI_WindowsAndMessaging` — clipboard hooks, message windows
  - `Win32_NetworkManagement_WNet` — network share enumeration
  - `Win32_System_Registry` — Windows registry (credential cache)
- `windows-service` 0.8 — Windows Service dispatcher & lifecycle

**Configuration & Data:**
- `toml` 0.8 — config file parsing
- `chrono` 0.4 (serde) — timestamps

**Data Structures:**
- `parking_lot` 0.12 — fast Mutex/RwLock
- `once_cell` 1 — lazy statics (AUTH_HASH, USB_DETECTOR)

### dlp-server
Central HTTP server (axum + SQLite).

**Web Framework:**
- `axum` 0.7 (macros) — HTTP server & routing
- `tower` 0.4 (util) — middleware toolkit
- `tower-http` 0.5 (trace, cors) — logging & CORS middleware

**Database:**
- `rusqlite` 0.31 (bundled) — SQLite 3 (embedded)
  - `bundled` feature: compiles SQLite from source (no external binary required)

**Authentication:**
- `jsonwebtoken` 9 — JWT signing & verification
- `bcrypt` 0.16 — admin password hashing

**HTTP Clients:**
- `reqwest` 0.12 (json, rustls-tls, no-default-features) — SIEM relay, policy sync

**Email:**
- `lettre` 0.11 (tokio1-rustls-tls, smtp-transport, builder) — SMTP alerts (reserved for future)

**Utilities:**
- `rpassword` 5 — interactive password prompt (first-run admin setup)
- `chrono` 0.4 (serde) — timestamps
- `uuid` 1 — identifiers

### dlp-user-ui
Endpoint GUI (iced + Win32 integration).

**GUI Framework:**
- `iced` 0.13 (tiny-skia, tokio) — Elm-inspired UI library
  - `tiny-skia` — software renderer (avoids GPU issues in SYSTEM service context)
  - `tokio` — async integration

**System Tray & Notifications:**
- `tray-icon` 0.19 — system tray icon
- `muda` 0.15 — menu construction
- `winrt-notification` 0.5 — Windows toast notifications

**Windows API:**
- `windows` 0.58 — Win32 bindings (subset)
  - `Win32_Foundation`, `Win32_System_Pipes`, `Win32_System_Threading`
  - `Win32_UI_WindowsAndMessaging` — clipboard access
  - `Win32_Security_Cryptography` — DPAPI for password dialogs
  - `Win32_Storage_FileSystem`, `Win32_System_IO` — file operations

**Build Tools:**
- `winres` 0.1 — Windows resource compilation (app icon, version info)

### dlp-admin-cli
CLI admin tool (ratatui TUI).

**TUI Framework:**
- `ratatui` 0.29 — terminal user interface
- `crossterm` 0.28 — terminal event handling & styling

**HTTP & Auth:**
- `reqwest` 0.12 (json, blocking, rustls-tls, no-default-features) — blocking sync client
- `tokio` 1 (rt-multi-thread, macros) — async runtime for non-blocking operations

**Windows API (Registry):**
- `windows` 0.58 — Win32 bindings
  - `Win32_System_Registry` — reading DLP agent config
  - `Win32_Security`, `Win32_Foundation` — process identity

**Utilities:**
- `bcrypt` 0.16 — password verification
- `anyhow` 1 — error handling

## Build & Test Toolchain

| Tool | Command | Purpose |
|------|---------|---------|
| `cargo build` | Build debug binaries | Development |
| `cargo build --release` | Build optimized binaries | Production |
| `cargo test` | Run all unit tests | Verify functionality |
| `cargo check` | Fast syntax/type check | Development feedback |
| `cargo clippy` | Linting | Code quality |
| `cargo fmt` | Format checking | Code style |
| `cargo doc` | Generate documentation | API docs |

## External Services & Dependencies

### SQLite
- **Type:** Embedded (via `rusqlite` bundled feature)
- **Version:** 3.x (compiled from source)
- **Location:** Configurable (default: `./dlp-server.db`)
- **Mode:** WAL (Write-Ahead Logging) for concurrent reads
- **Tables:** agents, audit_events, policies, exceptions, admin_users, agent_credentials, siem_config

### SIEM Integration (Optional)
Both are read-config-on-call (hot-reload from siem_config table).

**Splunk HEC:**
- HTTP Event Collector at `https://<host>:8088`
- Authentication via bearer token
- Batched JSON events

**Elasticsearch/ELK:**
- REST API at `https://<host>:9200`
- Index-based document storage
- Optional API key auth

### SMTP Alerting (Optional)
- **Crate:** lettre 0.11
- **Protocol:** SMTP with TLS/SSL
- **Status:** Code integrated, API endpoints defined, not yet wired to audit events

### Active Directory / LDAP
- **Crate:** ldap3 0.11
- **Status:** Reserved for future use (imported but not active)
- **Purpose:** Machine/user identity validation (future enhancement)

## Runtime Targets

**Windows Only:**
- Windows 11 Pro 10.0.26200 (development machine)
- Target: Windows 10+ (Server 2019+)
- Architecture: x86_64
- Build target: `x86_64-pc-windows-gnu` or `x86_64-pc-windows-msvc`

**Platform-Specific Code:**
```
[target.'cfg(windows)'.dependencies]
  windows-service 0.8
  notify 7
  windows 0.58
```

Non-Windows builds are rejected at compile time (dlp-agent) or runtime (dlp-admin-cli/dlp-user-ui).

## Versioning Strategy

- **Workspace Version:** 0.1.0 (all crates inherit)
- **Edition:** 2021 (all crates)
- **Dependency Strategy:** Workspace-wide pinning (no semver ranges) for consistency

## Development Notes

1. **Async/Await**: Tokio runtime with `tokio::spawn` for background tasks
2. **Logging**: `tracing` + JSON-formatted output (dlp-agent, dlp-server)
3. **Error Handling**: `thiserror` for error types, `anyhow` for context
4. **Concurrency**: `parking_lot` mutexes preferred over `std::sync::Mutex` (lower contention)
5. **Named Pipes (IPC)**: Raw Win32 calls via `spawn_blocking` (dlp-agent <-> dlp-user-ui)
6. **File Monitoring**: `notify` crate (debounced file system events)
7. **Testing**: No integration tests in dlp-user-ui (manual testing only); unit tests in dlp-common, dlp-agent, dlp-server

