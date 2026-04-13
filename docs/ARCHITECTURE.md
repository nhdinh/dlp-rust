<!-- generated-by: gsd-doc-writer -->
# System Architecture

**Document Version:** 1.1
**Date:** 2026-04-13
**Status:** Current

---

## 1. System Overview

The Enterprise DLP System is a multi-component Rust application that enforces data-loss-prevention policies on Windows endpoints by combining **NTFS as the baseline access-control layer**, **Active Directory for identity**, and **Attribute-Based Access Control (ABAC) for fine-grained, context-aware policy enforcement**.

The system consists of five independent crates in a single Cargo workspace:

| Crate | Role |
|---|---|
| `dlp-common` | Shared ABAC types, audit event schemas, classification model, text classifier |
| `dlp-server` | Central HTTP management server (axum) — admin API, audit store, SIEM relay, agent registry |
| `dlp-agent` | Windows Service running as SYSTEM — file interception, ABAC evaluation client, audit emission, clipboard monitoring |
| `dlp-user-ui` | Per-session iced GUI subprocess — system tray, block dialogs, clipboard monitor, stop-password dialog |
| `dlp-admin-cli` | Interactive ratatui TUI for DLP administrators — policy CRUD, password management, SIEM/alert configuration |

---

## 2. Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                   Active Directory                          │
│           (identity, group membership, LDAP)                │
└──────────────────────────┬──────────────────────────────────┘
                            │ HTTPS / REST
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    dlp-server (axum)                       │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────────────┐  │
│  │ Admin API    │ │ Agent Reg.   │ │ Audit Store        │  │
│  │ (JWT auth)   │ │ + Heartbeat  │ │ (SQLite JSONL)     │  │
│  └──────────────┘ └──────────────┘ └────────────────────┘  │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────────────┐  │
│  │ Policy Sync  │ │ SIEM Relay   │ │ Alert Router      │  │
│  │ (replicas)   │ │ (Splunk/ELK) │ │ (SMTP + Webhook)  │  │
│  └──────────────┘ └──────────────┘ └────────────────────┘  │
│                         │                                   │
│                    SQLite DB                               │
│  ┌─────────────────────────────────────────────────────┐  │
│  │ agents | policies | exceptions | audit_events       │  │
│  │ admin_users | agent_credentials | siem_config         │  │
│  │ alert_router_config | global_agent_config            │  │
│  │ agent_config_overrides                               │  │
│  └─────────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTPS REST
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│ dlp-agent #1  │  │ dlp-agent #2  │  │ dlp-agent #N  │
│ (WS01)        │  │ (WS02)        │  │ (WS03)        │
│ Windows Svc    │  │ Windows Svc   │  │ Windows Svc   │
└───────┬───────┘  └───────┬───────┘  └───────┬───────┘
        │                  │                  │
        │ Pipe 1/2/3 IPC   │                  │
        ▼                  ▼                  ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│ dlp-user-ui #1│  │ dlp-user-ui #2│  │ dlp-user-ui #N│
│ (iced, sess 1) │  │ (iced, sess 2)│  │ (iced, sess N)│
└───────────────┘  └───────────────┘  └───────────────┘
```

---

## 3. Data Flow

### 3.1 File Interception Flow (endpoint)

```
1. notify crate → FileAction (Created/Written/Deleted/Moved/Read)
         │
2. interception::run_event_loop (tokio task)
         │
3. session_identity::SessionIdentityMap → (user_sid, user_name)
         │
4. interception::policy_mapper → provisional classification
         │  (path prefix heuristic + content scan)
         │
5. offline.evaluate() → EvaluateRequest → HTTPS → dlp-server /policies/evaluate
         │                                         │
         │  (Online)                               (Offline fallback)
         ▼                                         ▼
   EvaluateResponse                        Cache lookup → default-deny
         │                                         (T3/T4 → fail-closed)
         ▼
   Decision { ALLOW | DENY | DenyWithAlert }
         │
6. emit_audit() → local append-only JSONL audit log
         │
7. if DENY → Pipe1AgentMsg::BlockNotify → dlp-user-ui → block dialog
```

### 3.2 Audit Event Flow (server ingestion)

```
dlp-agent  ──HTTPS POST /audit/events──►  dlp-server
                                           │
                               ┌────────────┴────────────┐
                               ▼                         ▼
                       SQLite audit_events         SIEM relay
                       (append-only JSONL)          (batched, async)
                               │
                               ▼
                     dlp-admin-cli / admin API
                     (query, export, alerts)
```

### 3.3 Agent Lifecycle

```
Agent starts
      │
      ▼
POST /agents/register ──► dlp-server records agent
      │
      ▼
Periodic POST /agents/{id}/heartbeat ──► dlp-server updates last_heartbeat
      │
      ▼
Background sweeper (30s interval) ──► mark offline if > 90s silence
```

### 3.4 Policy Sync (multi-server)

```
Admin creates/updates policy via admin API
           │
           ▼
dlp-server writes to SQLite policies table
           │
           ▼
PolicySyncer → PUT /policies/{id} ──► replica dlp-servers
```

---

## 4. Key Abstractions

### 4.1 ABAC Model (`dlp-common::abac`)

```
EvaluateRequest = Subject + Resource + Environment + Action + AgentInfo
                       │
                       ▼
                  Policy (priority-sorted, first-match)
                       │
                       ▼
               EvaluateResponse = Decision + matched_policy_id + reason

Decision ∈ { ALLOW, DENY, ALLOW_WITH_LOG, DENY_WITH_ALERT }

PolicyCondition ∈ { Classification, MemberOf, DeviceTrust,
                    NetworkLocation, AccessContext }
```

**Critical rule:** NTFS ALLOW + ABAC DENY → **final result = DENY**.

### 4.2 Classification (`dlp-common::classification`)

```
T1 (Public) < T2 (Internal) < T3 (Confidential) < T4 (Restricted)
```

`T3.is_sensitive()` and `T4.is_sensitive()` both return `true`; used for fail-closed offline behavior.

### 4.3 Audit Event (`dlp-common::audit`)

Every intercepted file operation emits an `AuditEvent` with:

- User identity (SID + display name)
- Resource path and classification
- Action attempted and ABAC decision
- Access context (`local` vs. `smb`)
- Process metadata (path + SHA-256 hash via `GetModuleFileNameExW` / `CryptHashData`)
- File owner SID (via `GetNamedSecurityInfoW`)

File **content is never included** — only metadata.

### 4.4 Database Schema (`dlp-server::db`)

Single SQLite database (WAL mode) with one mutex-guarded `Connection`. Key tables:

- `policies` — ABAC rules (priority, conditions JSON, action, version)
- `exceptions` — time-limited user overrides with justification + approver
- `agents` — endpoint registry (heartbeat, status)
- `audit_events` — appended event log (correlation_id for SIEM deduplication)
- `admin_users` — dlp-admin bcrypt hashes
- `agent_credentials` — shared agent auth hash (bcrypt, synced to all agents)
- `siem_config` — Splunk HEC and ELK endpoint configuration
- `alert_router_config` — SMTP and Webhook alert configuration
- `global_agent_config` — default per-agent settings (monitored paths, heartbeat interval)
- `agent_config_overrides` — per-agent config overrides

### 4.5 Offline Mode (`dlp-agent::offline`)

When the Policy Engine is unreachable, `OfflineManager` falls back to:

1. Policy decision cache with TTL (cache hit → cached decision)
2. Provisional classification (path prefix + 8 KB content scan)
3. Fail-closed: T3/T4 resources default to `DENY` on cache miss; T1/T2 default to `ALLOW`

### 4.6 IPC Protocol (three named pipes)

| Pipe | Direction | Purpose |
|---|---|---|
| Pipe 1 | Agent → UI | `Pipe1AgentMsg::BlockNotify`, `PolicySyncComplete`, `AgentStatus` |
| Pipe 2 | Agent → UI | Agent-to-UI async events |
| Pipe 3 | UI → Agent | UI-to-Agent commands (acknowledgements, overrides) |

`dlp-user-ui` also uses a file-based stop-password path to avoid deadlocking synchronous `ReadFile`/`WriteFile` on Pipe 1.

### 4.7 User UI Screens (`dlp-admin-cli::screens`)

The TUI uses a state-machine `Screen` enum. Key screens:

- `MainMenu` — top-level navigation
- `PolicyList` / `PolicyDetail` — policy browsing
- `TextInput` — policy ID or JSON file input
- `PasswordInput` — agent password flow, admin password change
- `AgentList` — live endpoint status
- `SiemConfig` / `AlertConfig` — operator configuration forms

---

## 5. Directory Structure Rationale

```
dlp-rust/
├── dlp-common/src/          # Zero-dependency pure type library.
│   ├── abac.rs              # Core ABAC types (Subject, Resource, Policy,
│   │                        #   EvaluateRequest/Response, Decision, etc.)
│   ├── audit.rs             # AuditEvent schema and EventType enum.
│   ├── classification.rs    # Four-tier Classification enum.
│   ├── classifier.rs        # Content-based text classifier (SSN/CC/keyword).
│   └── lib.rs               # Public re-exports.
│
├── dlp-server/src/          # Central HTTP server.
│   ├── main.rs              # CLI flag parsing, server bootstrap,
│   │                        #   graceful shutdown, admin user provisioning.
│   ├── lib.rs               # AppState (db + SIEM + AlertRouter) and AppError.
│   ├── admin_api.rs         # Full axum Router: policy CRUD, agent mgmt,
│   │                        #   exception mgmt, SIEM/alert config, JWT auth.
│   ├── admin_auth.rs        # JWT secret resolution, admin user creation,
│   │                        #   password verification (bcrypt).
│   ├── agent_registry.rs    # Agent registration, heartbeat, offline sweeper.
│   ├── audit_store.rs       # Audit event ingestion endpoint.
│   ├── db.rs                # SQLite schema initialization, WAL mode,
│   │                        #   thread-safe Connection wrapper.
│   ├── exception_store.rs   # Time-limited policy override CRUD.
│   ├── policy_sync.rs       # Async push of policy changes to replica servers.
│   ├── siem_connector.rs    # Batched Splunk HEC and ELK HTTP Ingest relay.
│   └── alert_router.rs      # Synchronous SMTP email and webhook alerting.
│
├── dlp-agent/src/           # Windows Service (SYSTEM account).
│   ├── main.rs              # Entry point; console mode vs. SCM dispatcher.
│   ├── lib.rs               # Conditional Windows module declarations.
│   ├── config.rs            # Agent configuration from TOML.
│   ├── interception/        # File system monitoring via `notify` crate.
│   │   ├── mod.rs           # run_event_loop — audit pipeline integration.
│   │   ├── file_monitor.rs  # notify-based file watcher, FileAction events.
│   │   └── policy_mapper.rs # FileAction → ABAC Action, provisional
│   │                        #   classification (path + content scan).
│   ├── identity.rs          # SMB impersonation token user resolution.
│   ├── session_identity.rs  # Per-session identity map with path heuristic.
│   ├── engine_client.rs     # HTTPS client to dlp-server /policies/evaluate.
│   ├── cache.rs             # Policy decision LRU cache with TTL.
│   ├── offline.rs          # OfflineManager: cache + provisional
│   │                        #   classification + fail-closed fallback.
│   ├── audit_emitter.rs     # Append-only JSONL local audit log + rotation.
│   ├── clipboard/           # Clipboard hooks + ContentClassifier integration.
│   │   ├── mod.rs
│   │   ├── listener.rs
│   │   └── classifier.rs
│   ├── detection/            # Endpoint exfiltration channel detection.
│   │   ├── mod.rs
│   │   ├── usb.rs           # USB mass storage detection via GetDriveTypeW.
│   │   └── network_share.rs # SMB destination whitelisting.
│   ├── ipc/                 # Three named-pipe IPC servers.
│   ├── service.rs           # Windows Service lifecycle (SCM, states).
│   ├── ui_spawner.rs        # WTSEnumerateSessionsW + CreateProcessAsUser.
│   ├── health_monitor.rs    # Mutual agent↔UI health ping-pong.
│   ├── session_monitor.rs   # Session logon/logoff handler.
│   ├── protection.rs       # Process DACL hardening.
│   ├── password_stop.rs     # Service stop password gate (3-attempt lockout).
│   └── server_client.rs     # General HTTPS client to dlp-server.
│
├── dlp-user-ui/src/         # Per-session iced GUI subprocess.
│   ├── main.rs              # iced entry point; stop-password mode path.
│   ├── lib.rs               # run() + run_stop_password() public API.
│   ├── app.rs               # iced Application state machine.
│   ├── tray.rs               # System tray icon and menu.
│   ├── clipboard_monitor.rs # Reads clipboard, invokes ContentClassifier.
│   ├── notifications.rs      # Windows toast notifications.
│   ├── dialogs/             # Modal dialogs (block, override, stop-password).
│   └── ipc/                 # Named-pipe IPC client for all three pipes.
│
├── dlp-admin-cli/src/       # ratatui TUI for DLP administrators.
│   ├── main.rs              # CLI flag parsing, raw-mode TUI bootstrap.
│   ├── app.rs               # App state machine and Screen enum.
│   ├── tui.rs               # Terminal setup, raw mode, panic hook.
│   ├── event.rs             # crossterm key event polling.
│   ├── client.rs            # Authenticated reqwest HTTP client (JWT).
│   ├── engine.rs            # DLP_SERVER_URL auto-detection (env / registry /
│   │                        #   port probe).
│   ├── login.rs             # Line-based pre-TUI health check and login.
│   ├── registry.rs          # HKLM registry read for server address.
│   ├── screens/             # ratatui frame renderers.
│   │   ├── mod.rs           # draw() dispatcher + handle_event().
│   │   ├── dispatch.rs      # Keyboard event routing per screen.
│   │   └── render.rs        # ratatui widget layout per screen.
│   └── main.rs
│
└── docs/
    ├── ARCHITECTURE.md       # This document — system topology and design.
    ├── SRS.md                # Software Requirements Specification.
    ├── SECURITY_ARCHITECTURE.md
    ├── THREAT_MODEL.md
    ├── ABAC_POLICIES.md
    ├── AUDIT_LOGGING.md
    └── OPERATIONAL.md
```

**Design rationale for crate boundaries:**

- `dlp-common` intentionally has zero runtime dependencies so it can be compiled into every crate without pulling in async runtimes or platform-specific code.
- `dlp-server` and `dlp-agent` are intentionally separate crates because the server is a cross-platform HTTP binary while the agent is Windows-only and runs as a Windows Service.
- `dlp-user-ui` is a separate crate from `dlp-agent` because Windows session isolation requires a subprocess spawned via `CreateProcessAsUser` in the interactive user's session, not a thread within the SYSTEM service.
- `dlp-admin-cli` is CLI-only (no agent dependency) so operators can administer the system from any machine with network access to `dlp-server`.

---

## 6. Concurrency Model

| Component | Concurrency primitive |
|---|---|
| `dlp-server` SQLite access | `parking_lot::Mutex` around single `rusqlite::Connection`; all DB calls wrapped in `tokio::task::spawn_blocking` to avoid blocking the async reactor |
| `dlp-server` request handling | `axum` async handlers; long-running DB operations offloaded to blocking thread pool |
| `dlp-agent` file monitor | `notify` crate blocking watcher on Tokio blocking thread pool |
| `dlp-agent` event loop | Tokio `mpsc::Receiver<FileAction>` consumed in `async fn run_event_loop` |
| `dlp-agent` engine client | Single `reqwest::Client` shared across async tasks via `Arc` |
| `dlp-admin-cli` UI | Single-threaded `tokio::runtime::Builder::new_current_thread()` because ratatui requires a single OS thread |
