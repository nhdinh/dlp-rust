# Architecture

**Analysis Date:** 2026-04-10

## Pattern Overview

**Overall:** Layered architecture with four enforcement layers (Identity → Access → Policy → Enforcement), implementing Least Privilege + Default Deny across endpoints, with a central management server.

**Key Characteristics:**
- **Identity Layer** (Active Directory): User SID/group resolution via Windows impersonation tokens
- **Access Layer** (NTFS ACLs): NTFS as baseline coarse-grained enforcement
- **Policy Layer** (ABAC Engine): Fine-grained Attribute-Based Access Control via REST API
- **Enforcement Layer** (dlp-agent): Windows Service endpoints intercepting file operations, clipboard, USB, network shares
- **Central Management** (dlp-server): HTTP/REST API for policy CRUD, agent registry, audit ingestion, SIEM relay, alert routing
- **Hybrid RBAC + ABAC**: Policies combine user groups, device trust, network location, access context

## Layers

**Identity Layer:**
- Purpose: Resolve user identity from Windows tokens (SID, username, AD groups)
- Location: `dlp-agent/src/identity.rs`, `dlp-agent/src/session_identity.rs`
- Contains: SID-to-username mapping, Windows token impersonation (ImpersonateSelf/RevertToSelf)
- Depends on: Windows APIs (QueryTokenInformation, ConvertSidToStringSidW)
- Used by: Interception engine to attach user identity to file operations
- **Details**: Identity resolver caches SID→username lookups. Uses `ImpersonateSelf` when called from hooked operations; fallback to `OpenProcessToken` when outside impersonation context. Returns `WindowsIdentity` struct with sid, username, primary_group.

**Access Layer:**
- Purpose: NTFS ACL baseline enforcement (enforced by Windows kernel before DLP agent sees file)
- Location: Windows kernel (not explicitly represented in code; dlp-agent works above this layer)
- Contains: File permissions, DACL evaluation
- Depends on: Windows NTFS implementation
- Used by: Kernel blocks operations that fail NTFS checks before reaching dlp-agent
- **Details**: Critical principle: If NTFS ALLOW and ABAC DENY → FINAL RESULT = DENY. dlp-agent operates as a policy enforcement _layer above_ NTFS.

**Policy Layer (ABAC Engine):**
- Purpose: Dynamic, context-aware policy evaluation using Attribute-Based Access Control
- Location: `dlp-server/src/` (evaluation endpoints), `dlp-common/src/abac.rs` (shared types)
- Contains: Policy CRUD API (`admin_api.rs`), policy evaluation (`admin_api.rs`), policy storage (SQLite in `db.rs`)
- Depends on: `dlp-common::Policy`, `dlp-common::EvaluateRequest/Response`, SQLite database
- Used by: dlp-agent via HTTPS client (`engine_client.rs`) to evaluate file operations
- **Details**: 
  - Evaluates against five condition types: `Classification`, `MemberOf` (groups), `DeviceTrust`, `NetworkLocation`, `AccessContext`
  - Returns `Decision`: ALLOW, DENY, ALLOW_WITH_LOG, DENY_WITH_ALERT
  - Policy structure: id, name, description, priority (lower = evaluated first), conditions[], action, enabled, version
  - First-match-wins evaluation; default-deny if no policy matches sensitive resources

**Enforcement Layer (dlp-agent):**
- Purpose: Intercept and enforce DLP decisions at the endpoint
- Location: `dlp-agent/src/service.rs` (Windows Service lifecycle), `dlp-agent/src/interception/` (file monitoring)
- Contains: 
  - Service lifecycle management (`service.rs`)
  - File interception engine (`interception/file_monitor.rs`) using `notify` crate
  - Clipboard monitoring (`clipboard/listener.rs`) with Windows hooks
  - USB/network share detection (`detection/usb.rs`, `detection/network_share.rs`)
  - IPC servers (Pipe 1/2/3) for UI communication (`ipc/`)
  - Offline mode with fail-closed cache (`offline.rs`)
  - Audit emission (`audit_emitter.rs`)
- Depends on: Policy Engine client (`engine_client.rs`), cache (`cache.rs`), session identity, NTFS interception
- Used by: Windows Service Control Manager (SCM); dlp-user-ui via named pipes
- **Details**: 
  - Runs as SYSTEM-level Windows Service named "dlp-agent"
  - Monitors all file operations via `notify` crate (CreateFile, WriteFile, DeleteFile, Rename)
  - Resolves user identity from process token
  - Sends `EvaluateRequest` to Policy Engine
  - Blocks operations on DENY, allows on ALLOW
  - Emits JSONL audit log locally, posts to dlp-server
  - Falls back to cache (fail-closed for T3/T4) when engine unreachable

**Central Management (dlp-server):**
- Purpose: REST API for admin operations, agent registration, audit/alert relay
- Location: `dlp-server/src/main.rs` (entry point)
- Contains:
  - HTTP server: axum-based REST API (`admin_api.rs`)
  - Admin authentication: JWT token generation/validation (`admin_auth.rs`)
  - Agent registry: tracks online/offline agent heartbeats (`agent_registry.rs`)
  - Audit store: append-only event log (`audit_store.rs`)
  - Exception store: policy exceptions/overrides (`exception_store.rs`)
  - SIEM connector: relays events to Splunk HEC / ELK (`siem_connector.rs`)
  - Alert router: sends DENY_WITH_ALERT emails and webhooks (`alert_router.rs`)
  - Policy sync: pushes policies to dlp-server replicas (`policy_sync.rs`)
  - Config push: sends agent configuration to endpoints (`config_push.rs`)
- Depends on: SQLite database, reqwest HTTP client, lettre SMTP
- Used by: dlp-admin-cli (TUI), agents (heartbeat/audit POST), SIEM systems, email/webhooks
- **Details**:
  - Single SQLite database for policies, audit events, agent registry, exception rules
  - TLS/JWT required in production; dev mode allows insecure JWT secret
  - First run prompts for `dlp-admin` password (can be scripted with `--init-admin`)
  - Binds default 127.0.0.1:9090; configurable via `--bind`
  - Graceful shutdown on CTRL+C

**Admin CLI (dlp-admin-cli):**
- Purpose: Interactive TUI for system administration
- Location: `dlp-admin-cli/src/main.rs`
- Contains: 
  - Screen rendering and event handling (`screens/`)
  - TUI setup/teardown (`tui.rs`)
  - Client API wrapper (`client.rs`)
  - Admin authentication flow (`login.rs`)
  - Agent registry view (`registry.rs`)
- Depends on: dlp-server REST API, ratatui for TUI, crossterm for terminal
- Used by: System administrators for policy/password/status management
- **Details**:
  - Uses ratatui for terminal UI
  - Pre-TUI login phase (line-based I/O) for credentials
  - Auto-detects server URL: DLP_SERVER_URL env var → registry → local port probing → default 127.0.0.1:9090
  - Navigates via arrow keys, Enter to select, Esc to go back, Q to quit

**User UI (dlp-user-ui):**
- Purpose: Per-session UI for blocking notifications, override requests, password dialogs
- Location: `dlp-user-ui/src/main.rs`
- Contains: Dialog windows (block notification, override request, password), IPC message handling
- Depends on: iced framework, Pipe 1 IPC
- Used by: End users (spawned by dlp-agent per session via CreateProcessAsUser)
- **Details**:
  - Lightweight mode: `--stop-password` launches just the password dialog for service stop authentication
  - Spawned by dlp-agent once per session using `WTSEnumerateSessionsW` + `CreateProcessAsUser`
  - Communicates over named pipes (Pipe 1/2/3)
  - Test mode: `--test-password-dialog` for visual testing

## Data Flow

**File Operation Interception → ABAC Evaluation → Decision → Audit:**

1. User initiates file operation (read, write, copy, delete, move) on endpoint
2. `dlp-agent` (running as SYSTEM service) intercepts via `notify` crate file watcher
3. Interception layer (`interception/file_monitor.rs`) captures `FileAction` event
4. Event loop (`interception/mod.rs::run_event_loop`) receives event via Tokio channel
5. Identity resolver (`identity.rs`) queries process token to get user SID
6. Audit context enriched with process path/owner via `audit_emitter.rs`
7. `EvaluateRequest` constructed:
   - `Subject`: user_sid, username, groups, device_trust, network_location
   - `Resource`: file path, classification (detected via classifier)
   - `Environment`: timestamp, session_id, access_context (local vs. SMB)
   - `Action`: READ|WRITE|COPY|DELETE|MOVE|PASTE
   - `AgentInfo`: machine hostname, current user
8. Engine client (`engine_client.rs`) sends HTTPS POST to `dlp-server /api/evaluate`
   - Retry logic: exponential backoff (200ms initial, 4s max) up to 3 attempts
   - Timeout: 10 seconds
9. Policy Engine evaluates via ABAC against active policies:
   - Match conditions: classification op, group membership, device trust, network location, access context
   - First-match-wins; default-deny for sensitive resources
   - Returns `EvaluateResponse`: decision (ALLOW|DENY|ALLOW_WITH_LOG|DENY_WITH_ALERT), matched_policy_id, reason
10. Agent applies decision:
    - **ALLOW**: Operation proceeds, audit logged if ALLOW_WITH_LOG decision
    - **DENY**: Operation blocked, user notified via UI toast, audit logged
    - **DENY_WITH_ALERT**: Operation blocked, UI notification sent, alert email/webhook triggered via `alert_router.rs`
11. Audit event (`AuditEvent` from `dlp_common`) emitted:
    - JSON serialized to local JSONL log via `audit_emitter.rs`
    - Rotated at size threshold (configurable, default 9 generations)
    - Batched and POSTed to `dlp-server /api/audit/events` via `server_client.rs`
12. Server processes audit:
    - Appends to audit store (`audit_store.rs`)
    - Batches and relays to SIEM (`siem_connector.rs`) — Splunk HEC or ELK HTTP Ingest API
    - If `DENY_WITH_ALERT`: triggers email/webhook via `alert_router.rs`

**Offline Fallback Flow:**

1. `engine_client.rs::evaluate()` returns `EngineClientError::Unreachable` after 3 retries
2. Agent transitions offline (sets `OfflineManager::online` flag to false)
3. `offline.rs::offline_decision()` consulted:
   - **T3/T4 resources** (sensitive): DENY (fail-closed)
   - **T1/T2 resources** (non-sensitive): ALLOW (default-allow)
4. Decision cached in `cache.rs` for future similar requests
5. Background heartbeat task (`OfflineManager::spawn_heartbeat`) probes engine every 30 seconds
6. When engine responds: transitions back online, clears offline flag

**Agent Registration & Heartbeat:**

1. dlp-agent starts, resolves hostname once
2. On each file operation evaluation or periodic heartbeat:
   - `server_client.rs` POSTs to `dlp-server /api/agents/{hostname}/heartbeat`
   - Includes: agent_id, hostname, last_seen timestamp, status (online/offline)
3. Server (`agent_registry.rs`) records agent as online, updates last_seen
4. Background sweeper task (`spawn_offline_sweeper`) runs every 90 seconds:
   - Marks agents with last_seen > 90s ago as offline
   - Used for admin visibility into endpoint connectivity

**IPC Communication (Named Pipes):**

| Pipe | Name | Direction | Purpose | Messages |
|------|------|-----------|---------|----------|
| P1 | `\\.\pipe\DLPCommand` | Bidirectional | Command/control, password dialogs | `BlockNotify`, `OverrideRequest`, `PasswordDialog`, `PasswordSubmit`, `PasswordCancel` |
| P2 | `\\.\pipe\DLPEventAgent2UI` | Agent → UI | Status/toast notifications | `Toast`, `StatusUpdate`, `HealthPing`, `UiRespawn`, `UiClosingSequence` |
| P3 | `\\.\pipe\DLPEventUI2Agent` | UI → Agent | Health/readiness signals | `HealthPong`, `UiReady`, `UiClosing` |

All pipes use JSON-encoded messages over synchronous byte stream (sent via `tokio::task::spawn_blocking` to avoid blocking async runtime).

**State Management:**

- **Agent service state**: Managed by SCM (Running, Paused, Stopped)
- **Policy cache**: LRU cache in memory (`cache.rs`) with configurable TTL
- **Offline state**: Atomic bool in `OfflineManager` shared across evaluation tasks
- **Session identity map**: Per-session identity cache (`session_identity.rs`) for SID → username lookups
- **Audit log**: Local JSONL file, batched to server via HTTP
- **Agent registry**: SQLite table on server (agent_id, hostname, last_seen, status)

## Key Abstractions

**EvaluateRequest / EvaluateResponse:**
- Purpose: Represent ABAC evaluation context and result
- Examples: `dlp-common/src/abac.rs` (lines 159-181)
- Pattern: Serializable to JSON for REST transmission; used by both agent and server

**Policy:**
- Purpose: Represent a single ABAC rule with conditions and enforcement action
- Examples: `dlp-common/src/abac.rs` (lines 241-260)
- Pattern: Stored in SQLite, versioned, enabled/disabled flag, priority-ordered evaluation

**Decision:**
- Purpose: Represent the enforcement action (ALLOW, DENY, ALLOW_WITH_LOG, DENY_WITH_ALERT)
- Examples: `dlp-common/src/abac.rs` (lines 40-54)
- Pattern: Enum with helper methods: `is_denied()`, `is_alert()`, `requires_audit()`

**AuditEvent:**
- Purpose: Represent a single security-relevant occurrence (access, block, alert, config change)
- Examples: `dlp-common/src/audit.rs` (lines 92+)
- Pattern: Serialized to JSON, appended to JSONL, batched to server, relayed to SIEM

**FileAction:**
- Purpose: Represent an intercepted file system operation
- Examples: `dlp-agent/src/interception/file_monitor.rs`
- Pattern: Emitted by file monitor, consumed by event loop, enriched with identity/audit metadata

**OfflineManager:**
- Purpose: Manage online/offline state transitions for Policy Engine connection
- Examples: `dlp-agent/src/offline.rs` (lines 29-48)
- Pattern: Wraps engine client + cache; provides `evaluate()` with fallback + heartbeat logic

**SessionIdentityMap:**
- Purpose: Cache session-to-user mappings for SID resolution
- Examples: `dlp-agent/src/session_identity.rs`
- Pattern: Per-session cache to avoid redundant AD lookups

## Entry Points

**dlp-agent Service:**
- Location: `dlp-agent/src/main.rs`
- Triggers: Windows Service Control Manager (SCM) via `service_dispatcher::start()` or `--console` flag
- Responsibilities: 
  - Register Windows Service control handler
  - Initialize logging, hostname, machine name
  - Start service event loop (file monitor, IPC servers, health checks)
  - Monitor for Stop/Pause/Resume commands
  - Graceful shutdown on service stop

**dlp-server HTTP Server:**
- Location: `dlp-server/src/main.rs`
- Triggers: Manual execution; binds TCP port (default 127.0.0.1:9090)
- Responsibilities:
  - Parse CLI flags (--bind, --db, --log-level, --init-admin)
  - Initialize structured logging
  - Resolve JWT secret (required in production)
  - Open/create SQLite database
  - Ensure admin user exists (prompt or via --init-admin)
  - Start SIEM connector (loaded per request from db)
  - Build axum HTTP router
  - Listen and serve HTTP; graceful shutdown on CTRL+C

**dlp-admin-cli TUI:**
- Location: `dlp-admin-cli/src/main.rs`
- Triggers: Manual execution
- Responsibilities:
  - Parse --connect flag (or auto-detect server URL)
  - Health check and login (line-based I/O)
  - Setup terminal and enter ratatui TUI
  - Poll events (keyboard, etc.) and dispatch to screen handlers
  - Render current screen
  - Restore terminal on exit

**dlp-user-ui Dialog:**
- Location: `dlp-user-ui/src/main.rs`
- Triggers: Spawned by dlp-agent via CreateProcessAsUser per session
- Responsibilities:
  - Show block notification toast, override request dialog, or password dialog
  - Capture user input (password, override decision)
  - Serialize response and send over Pipe 1
  - Exit cleanly, restoring UI state

## Error Handling

**Strategy:** Layered error propagation with fail-safe defaults; critical security operations fail-closed (deny) on error.

**Patterns:**

**Engine Client Errors:**
- `EngineClientError` enum: Unreachable, HttpError, TlsError, Timeout, Serialisation
- Retries: Exponential backoff (200ms → 4s, max 3 attempts)
- Fallback: If unreachable after retries, transition to offline mode → consult cache
- Example: `dlp-agent/src/engine_client.rs` (lines 28-44)

**Offline Fallback:**
- T3/T4 resources: DENY on cache miss (fail-closed)
- T1/T2 resources: ALLOW on cache miss (default-allow)
- Heartbeat probes every 30s to restore online mode
- Example: `dlp-agent/src/offline.rs` (lines 9-13)

**Service Control Errors:**
- Service failure logged but does not crash; SCM restarts service
- Control handler errors logged and ignored (status updates may fail but don't block shutdown)
- Example: `dlp-agent/src/service.rs` (lines 59-63)

**IPC Errors:**
- Pipe creation/connection errors logged; named pipe servers continue running
- Message deserialization errors logged; invalid messages ignored, connection remains open
- Example: `dlp-agent/src/ipc/server.rs` (error handling in pipe connection/read loops)

**Audit Emission Errors:**
- Audit write failures are logged but never block DLP enforcement
- If local JSONL write fails, event is still counted as processed
- Example: `dlp-agent/src/audit_emitter.rs` (emit context ensures error is never propagated to caller)

**HTTP Handler Errors:**
- All handlers return `Result<Response, AppError>`
- `AppError::IntoResponse` converts to appropriate HTTP status (500, 404, 400, 401)
- Errors logged via tracing before conversion to response
- Example: `dlp-server/src/lib.rs` (lines 73-95)

**Database Errors:**
- SQLite errors captured as `AppError::Database`, logged, converted to 500 response
- Transaction rollback on error ensures atomicity
- Example: Most `admin_api.rs` handlers wrap db calls in error handling

## Cross-Cutting Concerns

**Logging:**
- Framework: `tracing` + `tracing-subscriber` (structured logging)
- Configuration: Log level controlled by `--log-level` flag or RUST_LOG env var
- JSON formatting in production; human-readable in development
- Spans: Used to track execution context (request ID, user, policy ID)
- Rules: Never log sensitive data (passwords, tokens, PII)
- Example: `dlp-server/src/main.rs` (lines 120-122)

**Validation:**
- Input validation happens at REST API boundaries (deserialization)
- serde ensures type safety on JSON ingestion
- Policy conditions validated for semantic correctness (e.g., group_sid format, classification values)
- File paths case-normalized on Windows (case-insensitive FS)
- Example: `dlp-server/src/admin_api.rs` policy endpoints

**Authentication:**
- Admin API: JWT Bearer token required (except /health, /ready, /auth/login)
- Token generation: `admin_auth.rs::create_jwt()` uses HMAC-SHA256
- Token validation: Middleware checks signature and expiry
- Secret storage: Environment variable (REQUIRED in production, optional dev fallback)
- Password hashing: bcrypt for admin password and agent stop password
- Example: `dlp-server/src/admin_auth.rs`, middleware in `admin_api.rs`

**Authorization:**
- ABAC policies enforced via `admin_api.rs` policy evaluation endpoints
- Agent credential hash set/verified for agent authentication
- Admin user credentials required for policy/password management
- No role-based authorization in current design (single dlp-admin user)
- Example: Policy CRUD endpoints in `admin_api.rs` (POST /api/policies, PUT /api/policies/{id}, DELETE /api/policies/{id})

**Concurrency:**
- async/await: tokio runtime for I/O operations (HTTP, file reads, named pipes)
- Channels: mpsc (file events → event loop), broadcast (agent heartbeats)
- Locks: parking_lot::Mutex for state (e.g., session map, offline flag)
- RwLock: Used for policy cache reads (many readers, few writers)
- Thread-safety: Arc wrapping for shared ownership across tasks
- Example: `dlp-agent/src/service.rs` tokio::spawn for concurrent tasks

**Configuration Management:**
- Agent: TOML file at `C:\ProgramData\DLP\agent-config.toml` (monitored_paths, excluded_paths)
- Server: CLI flags (--bind, --db, --log-level) + env vars (DLP_SERVER_URL, SMTP_*, ALERT_WEBHOOK_*)
- Policy: Stored in SQLite; pushed to replicas via `policy_sync.rs`
- Hot-reload: SIEM config loaded on every relay call (no restart needed)
- Example: `dlp-agent/src/config.rs`, `dlp-server/src/main.rs` CLI parsing

---

*Architecture analysis: 2026-04-10*
