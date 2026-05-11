# STACK

## Languages, runtimes, and versions

- **Language:** Rust (workspace-wide)
- **Rust edition:** `2021` (workspace package setting)
- **Primary runtime:** `tokio` 1.x (async runtime across server, agent, and CLI workflows)
- **Platform focus:** Windows endpoint/service runtime (agent + UI + hook DLL), with Rust cross-platform tooling for build/test

## Package manager and workspace

- **Package manager/build tool:** Cargo
- **Workspace:** single Rust workspace (`resolver = "2"`) with members:
  - `dlp-common`
  - `dlp-agent`
  - `dlp-user-ui`
  - `dlp-admin-cli`
  - `dlp-server`
  - `dlp-e2e`
  - `dlp-hook-dll`

## Key frameworks and libraries

### Server (`dlp-server`)
- **HTTP framework:** `axum` 0.8 (`axum-core` 0.1)
- **Middleware/network:** `tower` 0.4, `tower-http` 0.5 (trace/cors)
- **Database:** `rusqlite` 0.39 (`bundled` SQLite), `r2d2`, `r2d2_sqlite`
- **Auth/security:** `jsonwebtoken` 9, `bcrypt` 0.16, `secrecy` 0.8
- **Directory integration:** `ldap3` 0.11
- **Outbound HTTP:** `reqwest` 0.12 (rustls, JSON)
- **Email:** `lettre` 0.11 (SMTP over rustls)
- **Rate limiting:** `governor` 0.10, `tower_governor` 0.8
- **Logging:** `tracing`, `tracing-subscriber` 0.3 (JSON/env-filter)

### Endpoint agent (`dlp-agent`)
- **Service/runtime:** `tokio` 1.x + `windows-service` 0.8 (Windows SCM integration)
- **OS API bindings:** `windows` 0.62 (broad Win32 surface)
- **HTTP client:** `reqwest` 0.12
- **Serialization/config:** `serde`, `serde_json`, `bincode`, `toml`
- **WMI:** `wmi` 0.18
- **Proto/IPC support:** `prost` 0.14, `bytes`
- **XPS/print parsing:** `zip` 2, `quick-xml` 0.36

### Shared crate (`dlp-common`)
- Shared domain models and ABAC-related structures
- `serde`, `chrono`, `uuid`, `ldap3`, `ipnetwork`, `tracing`
- Windows APIs via `windows` 0.62 under `cfg(windows)`

### Admin CLI (`dlp-admin-cli`)
- **Terminal UI:** `ratatui` 0.29 + `crossterm` 0.28
- **HTTP client:** `reqwest` 0.12 (JSON + blocking + rustls)
- **Auth/hash:** `bcrypt` 0.16
- **Async runtime:** `tokio` 1.x

### User UI (`dlp-user-ui`)
- **GUI framework:** `iced` 0.13 (`tiny-skia` renderer, `tokio` feature)
- **Windows UX integrations:** `tray-icon`, `muda`, `winrt-notification`
- **OS API bindings:** `windows` 0.58

### Hook DLL (`dlp-hook-dll`)
- **Artifact type:** Rust `cdylib`
- **Windows API bindings:** `windows` 0.62
- **Binary serialization:** `bincode` 1.3

### End-to-end harness (`dlp-e2e`)
- Pulls in core crates (`dlp-agent`, `dlp-server`, `dlp-admin-cli`, `dlp-common`)
- Uses `tokio`, `axum`, `reqwest`, `ratatui`, `crossterm` for integrated scenario tests

## Build tools and codegen

- **Primary build tool:** `cargo build` / `cargo test`
- **Build scripts present:**
  - `dlp-agent/build.rs`
  - `dlp-user-ui/build.rs`
  - `dlp-hook-dll/build.rs`
- **Protobuf codegen:** `prost-build` (agent build dependency)
- **Windows installer tooling:** WiX source present (`installer/DLPAgent.wxs`) + PowerShell build script (`installer/build.ps1`)

## Notes visible from repository metadata

- README states **Rust 1.75+** requirement for build/deployment.
- Dependency selection is heavily **Windows + enterprise endpoint** oriented (Win32 APIs, service model, AD/LDAP, SIEM/email connectors).
