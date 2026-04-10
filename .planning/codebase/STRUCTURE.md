# Codebase Structure

**Analysis Date:** 2026-04-10

## Directory Layout

```
dlp-rust/
├── Cargo.toml                          # Workspace root; members: dlp-common, dlp-agent, dlp-server, dlp-admin-cli, dlp-user-ui
├── dlp-common/                         # Shared types (no runtime dependencies)
│   ├── src/
│   │   ├── lib.rs                      # Module tree
│   │   ├── abac.rs                     # ABAC types: Subject, Resource, Policy, Decision, EvaluateRequest/Response
│   │   ├── audit.rs                    # AuditEvent, EventType, AuditAccessContext
│   │   ├── classification.rs           # Classification enum (T1-T4)
│   │   └── classifier.rs               # Text classification for data sensitivity detection
│   └── Cargo.toml
├── dlp-agent/                          # Windows Service DLP enforcement endpoint
│   ├── src/
│   │   ├── main.rs                     # Entry point: service dispatcher or console mode
│   │   ├── lib.rs                      # Module tree and crate documentation
│   │   ├── service.rs                  # Windows Service lifecycle (Start/Stop/Pause/Resume)
│   │   ├── config.rs                   # Runtime configuration (TOML loading)
│   │   ├── interception/               # File operation interception
│   │   │   ├── mod.rs                  # Event loop integration
│   │   │   ├── file_monitor.rs         # File watcher using notify crate
│   │   │   └── policy_mapper.rs        # Maps file operations to ABAC actions
│   │   ├── identity.rs                 # Windows token → SID/username resolution
│   │   ├── session_identity.rs         # Per-session identity cache
│   │   ├── engine_client.rs            # HTTPS client to Policy Engine (with retry logic)
│   │   ├── cache.rs                    # LRU decision cache with TTL
│   │   ├── offline.rs                  # Offline mode with fail-closed fallback
│   │   ├── detection/                  # USB and network share detection
│   │   │   ├── mod.rs                  # Detection module
│   │   │   ├── usb.rs                  # USB mass storage detection
│   │   │   └── network_share.rs        # SMB share destination whitelisting
│   │   ├── clipboard/                  # Clipboard monitoring
│   │   │   ├── mod.rs                  # Clipboard module
│   │   │   ├── listener.rs             # Windows clipboard hooks
│   │   │   └── classifier.rs           # Clipboard content classification
│   │   ├── ipc/                        # Named-pipe IPC (Pipe 1/2/3)
│   │   │   ├── mod.rs                  # IPC module tree
│   │   │   ├── server.rs               # All three pipe servers startup
│   │   │   ├── pipe1.rs                # Pipe 1 (command/control)
│   │   │   ├── pipe2.rs                # Pipe 2 (agent→UI)
│   │   │   ├── pipe3.rs                # Pipe 3 (UI→agent)
│   │   │   ├── messages.rs             # IPC message types
│   │   │   ├── frame.rs                # Message framing/encoding
│   │   │   └── pipe_security.rs        # Named pipe security (DACL)
│   │   ├── ui_spawner.rs               # Per-session UI spawning (WTS + CreateProcessAsUser)
│   │   ├── session_monitor.rs          # Session logon/logoff handler
│   │   ├── health_monitor.rs           # Mutual health ping-pong (agent ↔ UI)
│   │   ├── protection.rs               # Process DACL hardening
│   │   ├── password_stop.rs            # Service stop password verification
│   │   ├── audit_emitter.rs            # Append-only JSONL audit log with rotation
│   │   ├── server_client.rs            # HTTPS client to dlp-server (heartbeat/audit POST)
│   ├── tests/                          # Integration tests
│   │   └── *.rs
│   ├── src-tauri/                      # Tauri integration (for future use)
│   └── Cargo.toml
├── dlp-server/                         # Central management HTTP server
│   ├── src/
│   │   ├── main.rs                     # Entry point: CLI parsing, startup, graceful shutdown
│   │   ├── lib.rs                      # Module tree, AppState, AppError types
│   │   ├── admin_api.rs                # REST API router: policies, agents, audit, exceptions
│   │   ├── admin_auth.rs               # JWT token generation/validation, admin user management
│   │   ├── agent_registry.rs           # Agent registration, heartbeat tracking, offline detection
│   │   ├── audit_store.rs              # Append-only audit event store (SQLite)
│   │   ├── exception_store.rs          # Policy exception/override management
│   │   ├── alert_router.rs             # Email (SMTP) and webhook alert delivery
│   │   ├── policy_sync.rs              # Push policies to dlp-server replicas
│   │   ├── config_push.rs              # Push agent configuration to endpoints
│   │   ├── siem_connector.rs           # Relay audit events to SIEM (Splunk HEC / ELK)
│   │   ├── db.rs                       # SQLite database schema and operations
│   ├── tests/                          # Integration tests
│   │   └── *.rs
│   └── Cargo.toml
├── dlp-admin-cli/                      # Interactive TUI administration
│   ├── src/
│   │   ├── main.rs                     # Entry point: TUI setup/event loop
│   │   ├── app.rs                      # Application state (current screen, selections)
│   │   ├── client.rs                   # REST API client wrapper (HTTP requests)
│   │   ├── login.rs                    # Authentication flow (line-based I/O pre-TUI)
│   │   ├── engine.rs                   # Server URL resolution (env var → registry → probing)
│   │   ├── event.rs                    # Terminal event handling (keyboard, mouse)
│   │   ├── tui.rs                      # ratatui setup/teardown, panic hook
│   │   ├── registry.rs                 # Windows registry utilities (server URL lookup)
│   │   ├── screens/                    # Screen rendering and event handling
│   │   │   ├── mod.rs                  # Screen module
│   │   │   ├── dispatch.rs             # Event dispatcher (route events to screen handlers)
│   │   │   └── render.rs               # Screen-specific rendering (ratatui widgets)
│   └── Cargo.toml
├── dlp-user-ui/                        # Per-session dialog and notification UI
│   ├── src/
│   │   ├── main.rs                     # Entry point: modes (normal, --stop-password, --test-password-dialog)
│   │   ├── dialogs/                    # Dialog windows
│   │   │   ├── mod.rs                  # Dialog module
│   │   │   └── stop_password.rs        # Password dialog for service stop
│   │   ├── ipc/                        # IPC message handling (Pipe 1)
│   │   │   ├── mod.rs                  # IPC module
│   │   │   └── messages.rs             # Pipe 1 message types (PasswordSubmit, PasswordCancel)
│   │   └── lib.rs                      # Public API for main.rs
│   ├── tests/                          # Integration tests
│   │   └── *.rs
│   └── Cargo.toml
├── docs/                               # Architecture and design documentation
├── scripts/                            # Build, deployment, testing scripts
├── installer/                          # Windows installer (NSIS)
├── .planning/                          # Phase planning and analysis
│   ├── codebase/                       # Codebase documentation (this location)
│   ├── phases/                         # Detailed phase implementation plans
│   └── seeds/                          # Architecture decision records
└── .github/workflows/                  # CI/CD pipelines
```

## Directory Purposes

**dlp-common:**
- Purpose: Shared types for all crates; zero runtime dependencies
- Contains: ABAC types (Policy, EvaluateRequest/Response, Decision), Audit types (AuditEvent, EventType), Classification (T1-T4)
- Key files: `abac.rs`, `audit.rs`, `classification.rs`

**dlp-agent:**
- Purpose: Windows Service DLP enforcement at endpoints
- Contains: File monitoring, identity resolution, policy evaluation, clipboard monitoring, USB/network detection, IPC servers, audit emission
- Key modules: `service.rs` (lifecycle), `interception/` (file monitoring), `ipc/` (named pipes), `engine_client.rs` (policy evaluation), `offline.rs` (fail-safe fallback), `audit_emitter.rs` (audit logging)

**dlp-server:**
- Purpose: Central management HTTP server for administration, agent coordination, audit storage, SIEM relay
- Contains: REST API (admin_api.rs), authentication (admin_auth.rs), agent registry, audit store, alert routing, SIEM relay
- Key modules: `admin_api.rs` (HTTP routes), `agent_registry.rs` (agent tracking), `alert_router.rs` (email/webhook), `siem_connector.rs` (SIEM relay), `db.rs` (SQLite)

**dlp-admin-cli:**
- Purpose: Interactive TUI for policy management, agent password management, system status
- Contains: TUI framework, REST client, login flow, screen rendering and event handling
- Key modules: `main.rs` (entry point), `app.rs` (state), `screens/` (rendering), `client.rs` (HTTP client), `login.rs` (auth)

**dlp-user-ui:**
- Purpose: Per-session dialog UI for blocking notifications, override requests, password dialogs
- Contains: Dialog windows, IPC message handling
- Key modules: `dialogs/` (dialog windows), `ipc/` (Pipe 1 communication)

## Key File Locations

**Entry Points:**
- `dlp-agent/src/main.rs`: Windows Service main entry point (service dispatcher or console mode)
- `dlp-server/src/main.rs`: Central server entry point (CLI parsing, HTTP listen, graceful shutdown)
- `dlp-admin-cli/src/main.rs`: Admin TUI entry point (server detection, login, TUI event loop)
- `dlp-user-ui/src/main.rs`: User dialog entry point (notification/dialog modes)

**Configuration:**
- `dlp-agent/src/config.rs`: Runtime configuration loading (TOML parsing)
- `dlp-server/src/main.rs` (lines 44-74): CLI flag parsing
- Workspace `Cargo.toml`: Workspace members and shared dependencies

**Core Logic:**
- `dlp-agent/src/interception/mod.rs`: File interception event loop (intercept → evaluate → audit)
- `dlp-agent/src/engine_client.rs`: HTTPS client to Policy Engine (with retry/exponential backoff)
- `dlp-agent/src/offline.rs`: Offline fallback logic (fail-closed for T3/T4)
- `dlp-server/src/admin_api.rs`: REST API router (policy CRUD, agent registry, audit endpoints)
- `dlp-server/src/alert_router.rs`: Email and webhook alert delivery
- `dlp-server/src/siem_connector.rs`: SIEM relay (Splunk HEC / ELK)
- `dlp-common/src/abac.rs`: ABAC types and policy evaluation interface

**Testing:**
- `dlp-agent/tests/`: Integration tests (service lifecycle, IPC communication)
- `dlp-server/tests/`: Integration tests (API endpoints, database operations)
- `dlp-user-ui/tests/`: Dialog/UI tests
- Unit tests: Inline in source files via `#[cfg(test)]` modules

**IPC Communication:**
- `dlp-agent/src/ipc/mod.rs`: Named pipe servers (Pipe 1/2/3) startup
- `dlp-agent/src/ipc/pipe1.rs`: Pipe 1 (bidirectional command/control)
- `dlp-agent/src/ipc/pipe2.rs`: Pipe 2 (agent → UI status/notifications)
- `dlp-agent/src/ipc/pipe3.rs`: Pipe 3 (UI → agent health/readiness)
- `dlp-agent/src/ipc/messages.rs`: Message types (BlockNotify, HealthPing, etc.)

## Naming Conventions

**Files:**
- Entry points: `main.rs`
- Module collections: `mod.rs`
- Public API: `lib.rs`
- Windows-specific code: `#[cfg(windows)]` guards (not separate files)
- Test files: Inline via `#[cfg(test)]` modules (not separate test files in most cases)
- Integration tests: `tests/` directory at crate root

**Directories:**
- Module grouping (subdomains): lowercase plural or singular (e.g., `ipc/`, `interception/`, `detection/`, `clipboard/`, `dialogs/`, `screens/`)
- Workspace members: lowercase hyphenated crate names (e.g., `dlp-agent`, `dlp-server`, `dlp-admin-cli`)

**Functions:**
- Event handlers: `handle_*` (e.g., `handle_event`, `handle_message`)
- Spawned tasks: `spawn_*` (e.g., `spawn_offline_sweeper`, `spawn_heartbeat`)
- Initialization: `new()` (constructor), `init_*` (setup functions)
- Boolean predicates: `is_*` (e.g., `is_denied()`, `is_sensitive()`)
- Queries: `get_*` (e.g., `get_flag`, `get_application_metadata`)

**Variables:**
- User/subject identity: `subject`, `user_sid`, `username`, `user_name`
- File resource: `resource`, `path`
- Decisions: `decision`, `result`
- Configurations: `config`, `cfg`
- Caches/storage: `cache`, `db`, `store`
- Channels/streams: `tx` (sender), `rx` (receiver)
- Temporary/loop variables: single letters (e.g., `i`, `x`) only in simple loops

**Types:**
- PascalCase: `EvaluateRequest`, `EvaluateResponse`, `Subject`, `Resource`, `Policy`, `Decision`, `AuditEvent`, `Classification`, `DeviceTrust`
- Error types: `{Operation}Error` (e.g., `EngineClientError`, `IdentityError`, `AlertError`)
- Config types: `{Component}Config` (e.g., `AgentConfig`, `SmtpConfig`, `WebhookConfig`)
- Module-level: `pub mod {lowercase}` (e.g., `pub mod abac`, `pub mod audit`, `pub mod ipc`)

## Where to Add New Code

**New Feature (e.g., new DLP detection method):**
- **Primary code:** 
  - If agent-side detection: `dlp-agent/src/detection/{new_module}.rs`
  - If policy-related: `dlp-server/src/{new_endpoint}.rs` and add route to `admin_api.rs`
  - If shared types: `dlp-common/src/{new_domain}.rs` and export in `lib.rs`
- **Tests:** Inline `#[cfg(test)]` module in same file or `{crate}/tests/{feature}_tests.rs`
- **Example:** To add fingerprint detection:
  - Create `dlp-agent/src/detection/fingerprint.rs`
  - Implement detection logic, emit `FileAction` events
  - Integrate into `dlp-agent/src/service.rs` main loop (spawn task)
  - Add unit tests in `#[cfg(test)]` module in `fingerprint.rs`

**New Component/Module (e.g., new IPC pipe):**
- **Implementation:** Create `dlp-agent/src/ipc/pipe_n.rs` for new pipe or `dlp-agent/src/{new_component}/mod.rs` for new subsystem
- **Module export:** Add `pub mod {new_component}` to `dlp-agent/src/lib.rs`
- **Integration:** Import in `dlp-agent/src/service.rs` and spawn/initialize in `run_service()` function
- **Example:** To add a new audit transport (e.g., Kafka):
  - Create `dlp-agent/src/audit_transports/kafka.rs`
  - Implement `AuditTransport` trait (if abstracted)
  - Integrate in `audit_emitter.rs` as alternative to local JSONL
  - Add to `dlp-agent/src/lib.rs` exports

**Utilities/Helpers (e.g., time formatting, SID parsing):**
- **Shared across crates:** `dlp-common/src/utils.rs` (or domain-specific module)
- **Single crate:** `{crate}/src/utils.rs` or domain-specific module (e.g., `dlp-agent/src/identity_utils.rs`)
- **Integration:** Import via `use {crate}::utils::*` or `use {crate}::utils::{specific_function}`
- **Example:** To add SID validation utility:
  - Create `dlp-agent/src/identity_utils.rs` with `fn validate_sid(sid: &str) -> Result<()>`
  - Import in `identity.rs`: `use crate::identity_utils::validate_sid`
  - Or move to `dlp-common/src/` if needed by server/CLI

**REST API Endpoint (e.g., new admin endpoint):**
- **Route definition:** Add to `dlp-server/src/admin_api.rs` in `admin_router()` function
  - Use `Router::new().route("/api/{path}", {get|post|put|delete}(handler))`
  - Handler signature: `async fn handler(State(state): State<Arc<AppState>>, ...) -> Result<Response, AppError>`
- **Database operations:** Call functions from `db.rs` or add new queries there
- **Request/response types:** Define in `admin_api.rs` or separate `models.rs` if reusable
- **Authentication:** Wrap in `admin_auth::jwt_middleware` or check manually in handler
- **Example:** To add endpoint for policy exception CRUD:
  - Define `ExceptionPayload` request type in `admin_api.rs`
  - Implement `POST /api/exceptions`, `GET /api/exceptions/{id}`, etc. handlers
  - Call `db.create_exception()`, `db.get_exception()` methods (add to `db.rs` if not present)
  - Wrap routes in JWT middleware
  - Add integration test in `dlp-server/tests/`

**UI Dialog/Screen (e.g., new notification dialog):**
- **Dialog:** Create `dlp-user-ui/src/dialogs/{dialog_name}.rs` with `pub fn show_{dialog_name}() -> Result<Pipe1UiMsg>`
- **Screen (TUI):** Create screen struct in `dlp-admin-cli/src/screens/{screen_name}.rs` with `render()` and `handle_event()` methods
- **Integration:** Import in `screens/mod.rs` and dispatch in `screens/dispatch.rs`
- **Example:** To add a policy edit screen:
  - Create `dlp-admin-cli/src/screens/policy_edit.rs`
  - Implement `PolicyEditScreen` struct, `render()` method (ratatui widgets), `handle_event()` (keyboard input)
  - Register in `screens/mod.rs` as `pub mod policy_edit`
  - Add variant to screen enum in `app.rs`

**Configuration/Constants:**
- **Agent runtime config:** Edit `dlp-agent/src/config.rs` (TOML schema) and `AgentConfig` struct
- **Server CLI flags:** Edit `dlp-server/src/main.rs` `Config` struct and `parse_config()` function
- **Workspace-level:** Edit `Cargo.toml` `[workspace.dependencies]` or `[workspace.package]`
- **Feature flags:** Use `Cargo.toml` `[features]` section (not yet utilized)

## Special Directories

**target/:**
- Purpose: Cargo build artifacts (compiled binaries, dependencies)
- Generated: Yes (by `cargo build`)
- Committed: No (ignored in `.gitignore`)

**.planning/codebase/:**
- Purpose: Codebase analysis documents (ARCHITECTURE.md, STRUCTURE.md, CONVENTIONS.md, TESTING.md, CONCERNS.md)
- Generated: No (hand-authored by Claude mapper agents)
- Committed: Yes (part of repo)

**.planning/phases/:**
- Purpose: Detailed implementation plans for each phase
- Generated: Partially (populated by planning agents)
- Committed: Yes (part of repo)

**.planning/seeds/:**
- Purpose: Architecture decision records and foundational design docs
- Generated: No (hand-authored)
- Committed: Yes (part of repo)

**.claude/agent-memory/:**
- Purpose: Per-agent persistent memory (context from previous runs)
- Generated: Yes (by agent framework)
- Committed: No (ignored in `.gitignore`)

**.github/workflows/:**
- Purpose: CI/CD pipeline definitions (GitHub Actions)
- Generated: No (hand-authored)
- Committed: Yes (part of repo)

**docs/:**
- Purpose: Architecture, design, and reference documentation
- Generated: No (hand-authored)
- Committed: Yes (part of repo)

**installer/:**
- Purpose: Windows installer (NSIS, MSI generation)
- Generated: Partially (binaries built by CI)
- Committed: Yes (installer scripts)

**scripts/:**
- Purpose: Build, deployment, testing automation
- Generated: No (hand-authored)
- Committed: Yes (part of repo)

---

*Structure analysis: 2026-04-10*
