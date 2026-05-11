# Codebase Structure

**Analysis Date:** 2026-05-06

## Directory Layout

```
dlp-rust/
├── Cargo.toml              # Workspace manifest (6 members)
├── Cargo.lock              # Dependency lockfile
├── sonar-project.properties # SonarCloud config
├── CLAUDE.md               # Project instructions
├── scripts/                # Windows service install scripts
│
├── dlp-common/             # Shared types and ABAC models
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── abac.rs         # Core ABAC types
│       ├── audit.rs        # AuditEvent, EventType
│       ├── ad_client.rs    # LDAP/AD integration
│       ├── endpoint.rs     # AppIdentity, UsbTrustTier, DeviceIdentity
│       ├── disk.rs         # DiskIdentity, EncryptionStatus
│       └── ...
│
├── dlp-server/             # Axum HTTP server + policy engine
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs         # Entry point
│       ├── lib.rs          # AppState, AppError
│       ├── admin_api.rs    # Monolithic API router (217KB)
│       ├── policy_store.rs # In-memory policy cache
│       ├── db/mod.rs       # SQLite pool and schema
│       ├── auth.rs         # JWT validation
│       ├── siem_relay.rs   # Splunk/ELK forwarding
│       ├── alert_router.rs # SMTP + webhook alerts
│       └── ...
│
├── dlp-agent/              # Windows service endpoint agent
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs         # Service entry point
│       ├── service.rs      # SCM lifecycle, runtime loop
│       ├── interception/   # File monitoring + policy evaluation
│       │   ├── mod.rs      # run_event_loop
│       │   ├── file_monitor.rs
│       │   └── policy_mapper.rs
│       ├── detection/      # USB, network, disk, encryption watchers
│       │   ├── mod.rs
│       │   ├── usb.rs
│       │   ├── disk.rs
│       │   └── ...
│       ├── ipc/            # Named pipe communication
│       │   ├── mod.rs      # Pipe definitions
│       │   ├── pipe1.rs    # Bidirectional command pipe
│       │   └── pipe2.rs    # Agent->UI broadcast pipe
│       ├── usb_enforcer.rs # USB trust-tier enforcement
│       ├── disk_enforcer.rs # Fixed disk registry enforcement
│       ├── identity.rs     # Windows SID resolution
│       ├── session_identity.rs # Per-session user mapping
│       ├── audit_emitter.rs # JSONL audit logging
│       └── chrome/         # Chrome Enterprise connector
│           └── ...
│
├── dlp-admin-cli/          # TUI admin client
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs         # Entry point
│       ├── app.rs          # TUI app state + event loop
│       ├── screens/        # Screen modules
│       │   ├── render.rs   # Drawing functions
│       │   ├── dispatch.rs # Input handling
│       │   └── ...
│       └── api.rs          # HTTP client for server API
│
├── dlp-user-ui/            # GUI user client
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs         # Entry point
│       └── ...             # Iced application, tray icon
│
└── dlp-e2e/                # Integration / e2e test harness
    ├── Cargo.toml
    └── src/
        └── ...
```

## Directory Purposes

**`dlp-common/src/`:**
- Purpose: Shared domain types used by all crates
- Contains: ABAC models, audit events, AD client, disk types, endpoint identity
- Key files: `abac.rs`, `audit.rs`, `ad_client.rs`, `endpoint.rs`, `disk.rs`

**`dlp-server/src/`:**
- Purpose: HTTP API server, policy storage, external integrations
- Contains: Axum handlers, DB layer, auth, SIEM, alerts
- Key files: `admin_api.rs`, `policy_store.rs`, `db/mod.rs`, `auth.rs`

**`dlp-agent/src/`:**
- Purpose: Windows endpoint enforcement service
- Contains: Service lifecycle, file interception, USB/disk enforcers, IPC, Chrome connector
- Key files: `service.rs`, `interception/mod.rs`, `usb_enforcer.rs`, `disk_enforcer.rs`, `ipc/mod.rs`

**`dlp-agent/src/interception/`:**
- Purpose: File system monitoring and policy evaluation pipeline
- Contains: Event loop, file monitor, policy mapper
- Key files: `mod.rs` (run_event_loop), `file_monitor.rs`, `policy_mapper.rs`

**`dlp-agent/src/detection/`:**
- Purpose: Hardware and environment detection
- Contains: USB device watcher, disk discovery, encryption status, network share detection
- Key files: `usb.rs`, `disk.rs`

**`dlp-agent/src/ipc/`:**
- Purpose: Named pipe communication between agent and UI
- Contains: Pipe 1 (commands), Pipe 2 (events), broadcaster
- Key files: `mod.rs`, `pipe1.rs`, `pipe2.rs`

**`dlp-admin-cli/src/screens/`:**
- Purpose: TUI screen implementations
- Contains: Render functions, input dispatchers, screen state
- Key files: `render.rs`, `dispatch.rs`

**`dlp-e2e/src/`:**
- Purpose: End-to-end and integration tests
- Contains: Test harness, fixtures, scenarios

## Key File Locations

**Entry Points:**
- `dlp-server/src/main.rs`: Server binary entry
- `dlp-agent/src/main.rs`: Windows service entry
- `dlp-admin-cli/src/main.rs`: TUI entry
- `dlp-user-ui/src/main.rs`: GUI entry

**Configuration:**
- `Cargo.toml`: Workspace manifest
- `sonar-project.properties`: SonarCloud settings
- `.env`: Local environment (gitignored, do not commit)

**Core Logic:**
- `dlp-common/src/abac.rs`: ABAC domain model
- `dlp-server/src/policy_store.rs`: Policy caching and evaluation
- `dlp-agent/src/interception/mod.rs`: File interception event loop
- `dlp-agent/src/service.rs`: Windows service orchestration

**Testing:**
- `dlp-e2e/`: Integration tests
- Unit tests co-located in `#[cfg(test)]` modules within source files

## Naming Conventions

**Files:**
- Module files: `snake_case.rs` (e.g., `policy_store.rs`, `usb_enforcer.rs`)
- Directory modules: `mod.rs` inside directory (e.g., `interception/mod.rs`)

**Directories:**
- Crate names: `dlp-{purpose}` (e.g., `dlp-server`, `dlp-agent`)
- Feature modules: plural nouns (e.g., `interception/`, `detection/`, `screens/`)

## Where to Add New Code

**New Feature (server-side):**
- Primary code: `dlp-server/src/` (create new module file)
- API handlers: Add to `admin_api.rs` (or split into sub-module first)
- DB schema: `dlp-server/src/db/mod.rs`
- Tests: Co-located `#[cfg(test)]` module

**New Feature (agent-side):**
- Primary code: `dlp-agent/src/` (create new module file)
- Detection logic: `dlp-agent/src/detection/`
- Enforcement logic: `dlp-agent/src/` root or new `enforcers/` directory
- IPC messages: `dlp-agent/src/ipc/messages.rs`

**New Component/Module:**
- Shared types: `dlp-common/src/`
- Server handler: `dlp-server/src/{module}.rs`
- Agent module: `dlp-agent/src/{module}.rs` or `dlp-agent/src/{module}/mod.rs`

**Utilities:**
- Shared helpers: `dlp-common/src/lib.rs` or new `dlp-common/src/{util}.rs`
- Server-only helpers: `dlp-server/src/lib.rs`
- Agent-only helpers: `dlp-agent/src/lib.rs`

## Special Directories

**`scripts/`:**
- Purpose: Windows service installation and management scripts
- Generated: No
- Committed: Yes

**`dlp-agent/src/chrome/`:**
- Purpose: Chrome Enterprise Content Analysis API protobuf integration
- Generated: Partial (protobuf code generated at build time via `prost`)
- Committed: Generated code may be in `target/` only

---

*Structure analysis: 2026-05-06*
