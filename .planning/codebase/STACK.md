# Technology Stack

**Analysis Date:** 2026-04-10

## Languages

**Primary:**
- Rust 2021 edition - All crates (dlp-agent, dlp-server, dlp-admin-cli, dlp-user-ui, dlp-common)

**Secondary:**
- PowerShell - Installer build scripts (`installer/build.ps1`)
- WiX XML - Windows MSI installer definition (`installer/DLPAgent.wxs`)

## Runtime

**Environment:**
- Windows (minimum Windows 10/Server 2016 for Win32 API support)
- Native Windows service via `windows-service` crate (dlp-agent)
- Desktop/TUI application for dlp-admin-cli

**Package Manager:**
- Cargo
- Lockfile: `Cargo.lock` present (committed)

## Frameworks

**Core:**
- Tokio 1.50.0 - Async runtime for all async operations (dlp-agent, dlp-server, dlp-admin-cli)
- Axum 0.7.9 - Web server framework for dlp-server HTTP REST API
- Tower 0.4 - HTTP middleware layer (timeouts, compression, CORS)
- Tower-HTTP 0.5 - HTTP utilities for tracing and CORS

**UI:**
- Iced 0.13 - GUI framework for dlp-user-ui (endpoint notifications, dialogs, clipboard tray)
  - Renderer: tiny-skia (software rasterizer, avoids GPU issues when spawned by SYSTEM service)
- Ratatui 0.29 - Terminal UI framework for dlp-admin-cli (interactive terminal interface)
- Crossterm 0.28 - Terminal I/O abstraction for dlp-admin-cli

**Testing:**
- Built-in `#[cfg(test)]` modules (see dlp-agent, dlp-server, dlp-common)
- Tokio test utilities (test-util feature)

**Build/Dev:**
- `windows-service` 0.8 - Windows Service control API
- `winres` 0.1 - Build dependency for embedding Windows resources in dlp-user-ui

## Key Dependencies

**Critical:**
- serde 1.0.228 + serde_json 1.0.149 - Serialization (JSON protocol between agent/server)
- reqwest 0.12.28 - HTTP client (agent-to-server HTTPS, admin-cli REST API)
  - Features: json, rustls-tls for TLS cert verification
- rusqlite 0.31.0 - SQLite database for dlp-server (bundled SQLite)
  - Used for: audit store, agent registry, SIEM config, exception store

**Security/Auth:**
- jsonwebtoken 9.3.1 - JWT token generation/validation (dlp-server admin auth)
- bcrypt 0.16.0 - Password hashing (dlp-admin user passwords, stop-service password verification)
- uuid 1.x - Unique event/audit IDs

**Infrastructure:**
- Windows 0.58.x - Win32 API bindings (system integration)
  - Features: Security (SID/ACLs), Services, Registry, Pipes, UI messaging, ETW
- ldap3 0.11 - LDAP client for directory queries (dependency available but not actively used in visible code)
- lettre 0.11.21 - Email (SMTP) for alert delivery via AlertRouter

**Observability:**
- tracing 0.1 - Structured logging framework
- tracing-subscriber 0.3 - Tracing output formatting (JSON logs in dlp-agent/server)
- tracing-appender 0.2 - File-based log rotation

**Utilities:**
- chrono 0.4.44 - DateTime handling with serde support
- notify 7.0.0 - File system watcher (used by dlp-agent for file monitor)
- parking_lot 0.12.5 - Lock primitives (Mutex, RwLock) for synchronization
- once_cell 1.x - Lazy static initialization
- anyhow 1.0.102 - Error context propagation
- thiserror 1.0.69 - Custom error type derivation

**Windows-Specific UI:**
- tray-icon 0.19 - System tray icon management (dlp-user-ui)
- muda 0.15 - Menu/context menu support (dlp-user-ui)
- winrt-notification 0.5 - Windows Runtime toast notifications (dlp-user-ui)

## Configuration

**Environment Variables:**
- `DLP_SERVER_URL` - Agent overrides for policy engine endpoint (default: http://127.0.0.1:9090)
- `JWT_SECRET` - Server JWT signing secret (required for admin authentication)
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TO` - Email alerts (optional)
- `ALERT_WEBHOOK_URL`, `ALERT_WEBHOOK_SECRET` - Webhook alerts (optional)
- `DLP_SERVER_REPLICAS` - Multi-server replication list (policy sync)
- `DLP_ENGINE_CERT_PATH`, `DLP_ENGINE_KEY_PATH` - mTLS client certificate for agent-to-server
- `DLP_ENGINE_TLS_VERIFY` - Set to `false` for self-signed dev certificates

**File-Based Configuration:**
- Agent config TOML: `C:\ProgramData\DLP\agent-config.toml`
  - Specifies: server_url override, monitored_paths, excluded_paths
- Server SQLite database: `./dlp-server.db` (default, configurable via `--db` flag)

**Build:**
- `Cargo.toml` - Workspace root with shared dependencies
- `sonar-project.properties` - SonarCloud code quality scanning

## Platform Requirements

**Development:**
- Windows 10/Server 2016+ (required for Win32 API)
- Rust toolchain (stable)
- Cargo
- PowerShell (for installer build)
- WiX v4+ (for MSI generation) - installed via `dotnet tool install global wix`

**Production:**
- **Agent Deployment:** Windows endpoints (10/Server 2016+) running as SYSTEM service
- **Server Deployment:** Windows Server or Linux with libssl/libcrypto (rusqlite, reqwest native TLS)
- **Internet Connectivity:** HTTPS for agent-to-server and server-to-SIEM communication

---

*Stack analysis: 2026-04-10*
