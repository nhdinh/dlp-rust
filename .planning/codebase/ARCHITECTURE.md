# Architecture

**Analysis Date:** 2026-05-06

## System Overview

```text
+-------------------------------------------------------------+
|                    Admin Layer                               |
|  dlp-admin-cli (TUI)    dlp-user-ui (GUI)                  |
|  `dlp-admin-cli/src/`   `dlp-user-ui/src/`                 |
+----------+----------------+-------------------------------+
           |                |
           | HTTP/REST      | Named Pipes
           | (reqwest)      | (Pipe 1/2/3)
           |                |
           v                v
+-------------------------------------------------------------+
|                    Control Layer                             |
|  dlp-server (Axum)        dlp-agent (Windows Service)       |
|  `dlp-server/src/`        `dlp-agent/src/`                  |
|                                                             |
|  - Admin API               - File Monitor                   |
|  - Policy Engine           - USB Enforcer                   |
|  - Audit Store             - Disk Enforcer                  |
|  - SIEM Relay              - Identity Resolver              |
|  - Alert Router            - Chrome Connector               |
+----------+----------------+-------------------------------+
           |                |
           | SQLite         | Win32 APIs / WMI
           | (rusqlite)     | (windows crate)
           |                |
           v                v
+-------------------------------------------------------------+
|  Data & Identity Layer                                       |
|  - SQLite (policies, audit, registry)                       |
|  - Active Directory (LDAP)                                  |
|  - NTFS ACLs (coarse-grained)                               |
|  - Windows Event Log / JSONL                                |
+-------------------------------------------------------------+
```

## Component Responsibilities

| Component | Responsibility | File |
|-----------|----------------|------|
| Admin API | HTTP handlers for all admin operations | `dlp-server/src/admin_api.rs` |
| Policy Store | In-memory policy cache with background refresh | `dlp-server/src/policy_store.rs` |
| DB Layer | SQLite pool, schema, migrations | `dlp-server/src/db/mod.rs` |
| ABAC Engine | Policy evaluation (subject/resource/action/env) | `dlp-common/src/abac.rs` |
| Audit Emitter | JSONL audit event logging | `dlp-agent/src/audit_emitter.rs` |
| File Monitor | Filesystem event capture via `notify` | `dlp-agent/src/interception/file_monitor.rs` |
| USB Enforcer | PnP device control, volume DACL | `dlp-agent/src/usb_enforcer.rs` |
| Disk Enforcer | Fixed disk registry, BitLocker check | `dlp-agent/src/disk_enforcer.rs` |
| Identity Resolver | Windows SID -> username, AD group lookup | `dlp-agent/src/identity.rs` |
| Session Identity | Per-session user mapping | `dlp-agent/src/session_identity.rs` |
| IPC Pipes | Named pipe communication (3 pipes) | `dlp-agent/src/ipc/mod.rs` |
| Chrome Connector | Protobuf-based browser integration | `dlp-agent/src/chrome/` |
| SIEM Relay | Forward audit events to Splunk/ELK | `dlp-server/src/siem_relay.rs` |
| Alert Router | SMTP + webhook alerting | `dlp-server/src/alert_router.rs` |

## Pattern Overview

**Overall:** Layered architecture with event-driven interception

**Key Characteristics:**
- NTFS as coarse-grained baseline, ABAC as fine-grained dynamic control
- Offline-first with fail-closed fallback for T3/T4 classifications
- Event loop pattern for file interception (`tokio::mpsc` channel)
- Shared state via `Arc<T>` and `tokio::sync` primitives
- Windows-centric: heavy use of Win32 APIs and Windows services

## Layers

**Presentation Layer:**
- Purpose: Human interfaces for admin and end-user
- Location: `dlp-admin-cli/src/`, `dlp-user-ui/src/`
- Contains: TUI screens, GUI views, tray icon, toast notifications
- Depends on: dlp-server HTTP API, dlp-agent named pipes
- Used by: Admin users, end users

**Control Layer (Server):**
- Purpose: Policy management, audit storage, external integrations
- Location: `dlp-server/src/`
- Contains: Axum routers, handlers, DB operations, background tasks
- Depends on: SQLite, AD LDAP, SMTP, HTTP clients
- Used by: Admin CLI, agent (via HTTP in future)

**Control Layer (Agent):**
- Purpose: Endpoint enforcement, real-time interception
- Location: `dlp-agent/src/`
- Contains: Service lifecycle, file monitor, enforcers, IPC
- Depends on: Win32 APIs, WMI, `notify`, tokio
- Used by: Windows Service Control Manager

**Common Layer:**
- Purpose: Shared types, ABAC models, AD client
- Location: `dlp-common/src/`
- Contains: `Action`, `Decision`, `Subject`, `Resource`, `AuditEvent`, `AdClient`
- Depends on: `ldap3`, `ipnetwork`, `serde`, `chrono`
- Used by: All other crates

**Data Layer:**
- Purpose: Persistence and identity truth
- Location: SQLite files, Active Directory
- Contains: Policies, audit events, device/disk registries, user/group data
- Depends on: Filesystem, LDAP
- Used by: Server, Agent

## Data Flow

### Primary Request Path (File Access Evaluation)

1. File operation occurs on endpoint (`notify` watcher)
2. `FileAction` sent via `tokio::mpsc` to `run_event_loop` (`dlp-agent/src/interception/mod.rs:62`)
3. Identity resolved from PID/path via `SessionIdentityMap` (`dlp-agent/src/interception/mod.rs:86`)
4. USB enforcement short-circuit (if applicable) (`dlp-agent/src/interception/mod.rs:92`)
5. Disk enforcement short-circuit (if applicable) (`dlp-agent/src/interception/mod.rs:174`)
6. ABAC evaluation request built (`dlp-agent/src/interception/mod.rs:264`)
7. `OfflineManager::evaluate()` called (`dlp-agent/src/interception/mod.rs:284`)
8. Audit event emitted (`dlp-agent/src/audit_emitter.rs`)
9. UI notification sent via Pipe 1 if blocked (`dlp-agent/src/interception/mod.rs:318`)

### Policy Management Path

1. Admin CLI sends HTTP request to `dlp-server`
2. JWT validated in Axum middleware
3. Handler spawns blocking DB task (`tokio::task::spawn_blocking`)
4. `UnitOfWork` manages SQLite transaction
5. Policy store cache invalidated/updated
6. Response returned to CLI

### Audit Event Path

1. Agent emits JSONL event locally
2. (Future) Agent sends to server via HTTP
3. Server stores in SQLite `audit_events` table
4. SIEM relay forwards to Splunk/ELK
5. Alert router triggers SMTP/webhook on violations

**State Management:**
- Server: `AppState` struct with `Arc<r2d2::Pool<SqliteConnectionManager>>`, policy store, SIEM/alert configs
- Agent: `Arc<OfflineManager>`, `Arc<SessionIdentityMap>`, `Arc<AdClient>`
- No global mutable state; all shared via `Arc`

## Key Abstractions

**ABAC Model:**
- Purpose: Attribute-based policy evaluation
- Examples: `dlp-common/src/abac.rs`
- Pattern: Request (Subject + Resource + Environment + Action) -> Response (Decision + Reason + Policy ID)

**Audit Event:**
- Purpose: Immutable record of access decisions
- Examples: `dlp-common/src/audit.rs`
- Pattern: Builder pattern with `.with_*()` methods

**Enforcer Pattern:**
- Purpose: Pre-ABAC short-circuit checks (USB, Disk)
- Examples: `dlp-agent/src/usb_enforcer.rs`, `dlp-agent/src/disk_enforcer.rs`
- Pattern: `check(path, action) -> Option<Result>` where `Some` means short-circuit

**Named Pipe IPC:**
- Purpose: Agent-UI communication without HTTP
- Examples: `dlp-agent/src/ipc/mod.rs`
- Pattern: 3 pipes - Command (bidirectional), Agent->UI events, UI->Agent events

## Entry Points

**dlp-server:**
- Location: `dlp-server/src/main.rs`
- Triggers: Command-line execution
- Responsibilities: Parse CLI, init tracing, SQLite pool, JWT secret, admin provisioning, AD client, policy store, background tasks, axum serve

**dlp-agent:**
- Location: `dlp-agent/src/main.rs`
- Triggers: Windows Service Control Manager
- Responsibilities: `define_windows_service!`, service dispatcher, delegate to `service.rs`

**dlp-agent service lifecycle:**
- Location: `dlp-agent/src/service.rs`
- Triggers: SCM start command
- Responsibilities: Process DACL hardening, Chrome registry registration, IPC pipe servers, session monitor, main tokio runtime loop

**dlp-admin-cli:**
- Location: `dlp-admin-cli/src/main.rs`
- Triggers: Command-line execution
- Responsibilities: TUI initialization, screen loop, API client setup

**dlp-user-ui:**
- Location: `dlp-user-ui/src/main.rs`
- Triggers: Command-line or auto-start
- Responsibilities: Iced application, system tray, toast notifications

## Architectural Constraints

- **Threading:** Single-threaded async event loop per file monitor; blocking DB ops offloaded via `spawn_blocking`
- **Global state:** `crate::ipc::pipe2::BROADCASTER` static for UI broadcasts; otherwise no module-level singletons
- **Circular imports:** None detected
- **Platform lock:** Windows-only due to Win32 API dependencies
- **Offline dependency:** Agent requires periodic server connectivity for policy refresh; fails closed on T3/T4

## Anti-Patterns

### Monolithic API Router

**What happens:** All HTTP handlers live in a single 217KB file (`dlp-server/src/admin_api.rs`)
**Why it's wrong:** Impossible to navigate, review, or test incrementally; violates single responsibility
**Do this instead:** Split into module files per domain (policy, audit, agent, device, disk, config)

### Deep Nesting in Event Loop

**What happens:** `run_event_loop` has 300+ lines with deeply nested `if let` blocks for USB, disk, ABAC
**Why it's wrong:** Hard to test individual branches; violates single responsibility
**Do this instead:** Extract each enforcement stage into its own async function returning `Option<ControlFlow>`

### Placeholder AD Client

**What happens:** `Arc<Option<AdClient>>` passed through call chain; fallback creates placeholder `Subject`
**Why it's wrong:** Optional at wrong layer; identity should always be resolvable or fail-closed
**Do this instead:** Use a trait object or enum for `AdClient | Placeholder` at the boundary

## Error Handling

**Strategy:** `thiserror` for library errors, `anyhow` for application boundaries

**Patterns:**
- `AppError` enum in `dlp-server/src/lib.rs` with `IntoResponse` for Axum
- `Result<T, DiskError>` for disk operations (`dlp-common/src/disk.rs`)
- `.context()` from `anyhow` at task boundaries
- `warn!` + continue for non-fatal IPC errors

## Cross-Cutting Concerns

**Logging:** `tracing` spans with structured fields; `info!` for lifecycle, `debug!` for diagnostics, `warn!` for recoverable errors
**Validation:** Input validation at Axum extractor layer; no separate validation crate detected
**Authentication:** JWT Bearer for admin API; Windows SID for agent identity

---

*Architecture analysis: 2026-05-06*
