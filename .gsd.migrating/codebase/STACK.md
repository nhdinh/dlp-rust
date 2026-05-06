# Technology Stack

## Language & Runtime

| Property | Value |
|----------|-------|
| Language | Rust |
| Edition | 2021 |
| Minimum toolchain | stable (1.75+) |
| Async runtime | Tokio 1.x (full features) |
| Target platform | Windows (x86_64-pc-windows-msvc) |

## Workspace Structure

Multi-crate Cargo workspace (resolver v2) with 6 members:

| Crate | Role |
|-------|------|
| `dlp-common` | Shared types, ABAC model, classification, AD client |
| `dlp-server` | Central management server, policy engine, REST API |
| `dlp-agent` | Windows Service endpoint agent (enforcement) |
| `dlp-admin-cli` | TUI-based administration console |
| `dlp-user-ui` | Iced GUI for end-user notifications/dialogs |
| `dlp-e2e` | End-to-end integration test harness |

## Key Frameworks & Libraries

### Core (Workspace-level)

| Library | Version | Purpose |
|---------|---------|---------|
| tokio | 1.x | Async runtime (full features) |
| serde / serde_json | 1.x | Serialization |
| thiserror | 1.x | Custom error types |
| anyhow | 1.x | Error context at app boundaries |
| tracing / tracing-subscriber | 0.1.x | Structured logging |
| parking_lot | 0.12 | Fast synchronization primitives |
| uuid | 1.x (v4) | Identifier generation |
| bcrypt | 0.16 | Password hashing |
| secrecy | 0.8 | Secret data masking |
| ldap3 | 0.11 | LDAP/Active Directory client |
| notify | 8.x | File system watching |
| ipnetwork | 0.20 | IP/CIDR parsing |
| once_cell | 1.x | Lazy statics |

### Web (dlp-server)

| Library | Version | Purpose |
|---------|---------|---------|
| axum | 0.8 | HTTP framework |
| tower / tower-http | 0.4 / 0.5 | Middleware (CORS, compression) |
| reqwest | 0.12 | HTTP client (rustls-tls) |
| jsonwebtoken | 9.x | JWT authentication |
| governor / tower_governor | 0.10 / 0.8 | Rate limiting |
| lettre | 0.11 | SMTP email (tokio1-rustls-tls) |
| dashmap | 6.x | Concurrent HashMap |

### Database (dlp-server)

| Library | Version | Purpose |
|---------|---------|---------|
| rusqlite | 0.39 | SQLite (bundled) |
| r2d2 / r2d2_sqlite | — | Connection pooling |

### TUI (dlp-admin-cli)

| Library | Version | Purpose |
|---------|---------|---------|
| ratatui | 0.29 | Terminal UI rendering |
| crossterm | 0.28 | Cross-platform terminal control |
| rfd | 0.14 | Native file dialogs |

### GUI (dlp-user-ui)

| Library | Version | Purpose |
|---------|---------|---------|
| iced | 0.13 | GUI framework (tiny-skia renderer) |
| tray-icon | 0.19 | System tray integration |
| muda | 0.15 | Menu system |
| winrt-notification | 0.5 | Windows toast notifications |

### Windows & System (dlp-agent)

| Library | Version | Purpose |
|---------|---------|---------|
| windows | 0.58–0.62 | Win32 API bindings |
| windows-service | 0.8 | Windows Service lifecycle |
| wmi | 0.14 | WMI queries (BitLocker) |
| prost / prost-build | 0.14 | Protobuf (Chrome Content Analysis) |
| hostname | 0.4 | Machine hostname |
| chrono | 0.4 | Date/time handling |
| serial_test | — | Sequential test execution |

## Build Tools

| Tool | Purpose |
|------|---------|
| Cargo | Build, test, dependency management |
| prost-build | Protobuf compilation (dlp-agent/build.rs) |
| winres | Windows resource embedding (dlp-user-ui/build.rs) |
| rustfmt | Code formatting |
| clippy | Linting |
| SonarQube | Static analysis & quality gate |

## Package Manager

- **Cargo** with `Cargo.lock` committed (deterministic builds)
- Workspace-level dependency deduplication via `[workspace.dependencies]`

## CI/CD

| Platform | Workflows |
|----------|-----------|
| GitHub Actions | `build.yml` (PR/push), `nightly.yml` (daily release build + smoke tests) |
| Runner | `windows-latest` |
| Caching | `~/.cargo/registry`, `~/.cargo/git`, `target/` |
