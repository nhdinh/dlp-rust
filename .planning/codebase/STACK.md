# Technology Stack

**Analysis Date:** 2026-05-06

## Languages

**Primary:**
- Rust (Edition 2021) - Entire codebase, 6 workspace crates

**Secondary:**
- Protocol Buffers (`.proto`) - Chrome Enterprise Content Analysis API messages
- SQL (SQLite DDL) - Schema definitions in `dlp-server/src/db/mod.rs`
- PowerShell / Batch - Windows service installation scripts (in `scripts/`)

## Runtime

**Environment:**
- Tokio async runtime (multi-threaded) - All async crates
- Standard Rust runtime for sync utilities

**Package Manager:**
- Cargo (workspace resolver = "2")
- Lockfile: `Cargo.lock` present

## Frameworks

**Core:**
- Axum 0.7 - HTTP server / REST API (`dlp-server`)
- Tokio 1.x - Async runtime (all crates)
- Iced 0.13 - GUI framework (`dlp-user-ui`)
- Ratatui 0.29 + Crossterm 0.28 - TUI framework (`dlp-admin-cli`)
- Windows Service 0.8 - Windows SCM integration (`dlp-agent`)

**Testing:**
- Built-in `#[test]` + `cargo test`
- `reqwest` for HTTP integration tests
- Custom e2e harness in `dlp-e2e/`

**Build/Dev:**
- `cargo` for building, testing, dependency management
- `rustfmt` for formatting
- `clippy` for linting
- `sonar-scanner` for static analysis
- Prost / prost-build for protobuf code generation

## Key Dependencies

**Critical:**
- `rusqlite` 0.32 + `r2d2` 0.8 - SQLite database with connection pooling
- `ldap3` 0.11 - Active Directory LDAP integration
- `jsonwebtoken` 9.x - JWT Bearer authentication
- `wmi` 0.14 - Windows Management Instrumentation (BitLocker, disk info)
- `windows` 0.58 - Win32 API bindings (extensive feature set)
- `notify` 6.x - File system event monitoring
- `prost` 0.13 - Protobuf serialization (Chrome API)
- `lettre` 0.11 - SMTP email alerts
- `reqwest` 0.12 - HTTP client (SIEM relay, admin CLI)
- `tower` + `tower-governor` 0.4 - Rate limiting middleware
- `tracing` + `tracing-subscriber` - Structured logging
- `chrono` 0.4 - Date/time handling
- `serde` + `serde_json` - JSON serialization
- `parking_lot` 0.12 - Fast synchronization primitives
- `ratatui` 0.29 + `crossterm` 0.28 - Terminal UI
- `iced` 0.13 + `tray-icon` 0.19 + `muda` 0.15 - System tray GUI
- `winrt-notification` 1.0 - Windows toast notifications
- `ipnetwork` 0.20 - IP subnet calculations
- `secrecy` 0.10 - Secret wrapping types
- `thiserror` 2.x + `anyhow` 1.x - Error handling

**Infrastructure:**
- `tokio::sync::mpsc` / `broadcast` - Inter-task communication
- `crossbeam` - Lock-free data structures
- `rayon` - Data parallelism (where used)

## Configuration

**Environment:**
- `.env` file for local development (must be gitignored per security policy)
- Environment variables for all secrets (JWT secret, SMTP creds, LDAP bind creds)
- `dotenvy` for loading `.env` in development

**Build:**
- Workspace `Cargo.toml` at root defines 6 members
- Per-crate `Cargo.toml` with feature flags (notably `windows` crate features in `dlp-agent`)
- `sonar-project.properties` for SonarCloud scanning

## Platform Requirements

**Development:**
- Windows 10/11 (Win32 APIs used extensively)
- Rust toolchain (stable)
- SQLite development libraries (if building from source)
- Active Directory access for LDAP testing

**Production:**
- Windows endpoints for agent deployment
- Server can run on any platform supporting SQLite (though AD features require Windows or LDAP connectivity)
- Chrome Enterprise for Content Analysis API integration

---

*Stack analysis: 2026-05-06*
