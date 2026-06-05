# Directory and File Structure

**Project:** Enterprise DLP System (NTFS + Active Directory + ABAC)
**Workspace Root:** `C:/Users/nhdinh/dev/dlp-rust`
**Last Updated:** 2026-06-05

---

## 1. Top-Level Directory Layout

```
dlp-rust/
├── Cargo.toml              # Workspace manifest (7 members, shared deps, metadata)
├── Cargo.lock              # Dependency lockfile
├── README.md               # Project overview, quick start, component table
├── CLAUDE.md               # AI assistant instructions (coding standards, security rules)
├── AGENTS.md               # Agent role definitions for AI workflows
├── IDEA-DOC.md             # Design ideas and research notes
├── sonar-project.properties # SonarQube scanner configuration
├── sgconfig.yml            # ast-grep configuration
├── .gitignore
│
├── dlp-common/             # Shared types library (zero runtime deps)
├── dlp-server/             # Central management HTTP server (axum + SQLite)
├── dlp-agent/              # Windows Service enforcement agent
├── dlp-user-ui/            # Per-session iced GUI subprocess
├── dlp-admin-cli/          # ratatui TUI for administrators
├── dlp-e2e/                # End-to-end integration test harness
├── dlp-hook-dll/           # API hook DLL (cdylib + rlib)
│
├── docs/                   # Project documentation
├── installer/              # MSI installer (WiX + PowerShell)
├── scripts/                # PowerShell management and UAT scripts
├── planning/               # Legacy planning directory (phases)
├── .planning/              # Active planning artifacts
│   └── codebase/           # Codebase mapping documents (this dir)
├── .cargo/                 # Cargo configuration
├── .claude/                # Claude Code configuration, hooks, skills, agent memory
├── .codex/                 # Codex/GSD skills and workflows
├── .beads/                 # Beads issue tracker (embedded Dolt DB)
├── .ast-grep/              # ast-grep rules and tests
├── .github/                # GitHub workflows and templates
├── .gitnexus/              # GitNexus configuration
├── .rtk/                   # RTK (Rust Token Killer) configuration
├── target/                 # Build artifacts (debug/release)
└── target-test/            # Test-specific build artifacts
```

---

## 2. Crate Structure

### 2.1 dlp-common

```
dlp-common/
├── Cargo.toml
└── src/
    ├── lib.rs              # Public re-exports of all modules
    ├── abac.rs             # ABAC core types (Subject, Resource, Policy, Decision, etc.)
    ├── ad_client.rs        # LDAP client, Kerberos bind, group cache, device trust, network location
    ├── approval.rs         # Approval workflow types
    ├── audit.rs            # AuditEvent schema and EventType enum
    ├── classification.rs   # Four-tier Classification enum (T1-T4)
    ├── classifier.rs       # Content-based text classifier
    ├── disk.rs             # Disk enumeration, encryption status, bus type
    ├── endpoint.rs         # AppIdentity, AppTrustTier, DeviceIdentity, SignatureState, UsbTrustTier
    ├── hash.rs             # FNV-1a 64-bit hash
    ├── hook_ipc.rs         # HookRequest, HookResponse, HandleHookRequest wire types
    ├── label.rs            # Label, LabelState, ObjectType, Tier
    ├── path_hash.rs        # Path normalization, NT-to-DOS conversion, path hashing
    ├── usb.rs              # USB device enumeration and policy constants
    └── crypto/
        └── mod.rs          # DPAPI wrappers
```

**Entry points:** Library crate only (no binary). Consumed by all other crates.

### 2.2 dlp-server

```
dlp-server/
├── Cargo.toml
└── src/
    ├── main.rs             # Server bootstrap: CLI, DB, crypto, background tasks, graceful shutdown
    ├── lib.rs              # AppState, AppError, module declarations
    ├── admin_api.rs        # Full axum router with all management endpoints
    ├── admin_auth.rs       # JWT secret resolution, bcrypt admin auth
    ├── agent_registry.rs   # Agent registration, heartbeat, offline sweeper
    ├── alert_router.rs     # SMTP + webhook alerting
    ├── approval_api.rs     # Approval workflow REST endpoints
    ├── approval_token.rs   # Ed25519 JWT signing/verification
    ├── audit_store.rs      # Audit event ingestion
    ├── exception_store.rs  # Time-limited policy override CRUD
    ├── label_service.rs    # Label resolution with TTL caching
    ├── observability.rs    # Metrics recording helpers
    ├── policy_engine_error.rs # Policy engine error types
    ├── policy_store.rs     # In-memory policy cache + ABAC evaluation
    ├── policy_sync.rs      # Async policy push to replicas
    ├── rate_limiter.rs     # IP and agent-ID rate limiting
    ├── secrets_migration.rs # Cleartext-to-encrypted migration
    ├── siem_connector.rs   # Splunk HEC + ELK relay
    ├── syslog_connector.rs # RFC 5424 syslog forwarder over TLS
    ├── crypto/
    │   ├── mod.rs          # SecretCrypto, envelope encryption
    │   ├── dpapi.rs        # DPAPI integration
    │   ├── envelope.rs     # Encrypted envelope format
    │   ├── error.rs        # Crypto error types
    │   ├── kdf.rs          # Key derivation (PBKDF2)
    │   └── tests.rs        # Crypto unit tests
    └── db/
        ├── mod.rs          # Pool, schema init, WAL config
        ├── unit_of_work.rs # Transaction wrapper
        └── repositories/
            ├── mod.rs              # Repository re-exports
            ├── admin_users.rs
            ├── agent_config.rs
            ├── agents.rs
            ├── alert_router_config.rs
            ├── allowlist.rs
            ├── approvals.rs
            ├── audit_events.rs
            ├── bypass_alerts.rs
            ├── credentials.rs
            ├── device_registry.rs
            ├── disk_registry.rs
            ├── exceptions.rs
            ├── jwt_secret.rs
            ├── labels.rs
            ├── ldap_config.rs
            ├── managed_origins.rs
            ├── policies.rs
            ├── protected_paths.rs
            ├── secret_kek.rs
            ├── siem_config.rs
            ├── syslog_config.rs
            ├── syslog_queue.rs
            └── system_kv.rs
```

**Entry point:** `src/main.rs` (binary: `dlp-server.exe`)
**Library:** `src/lib.rs` (re-exported for `dlp-e2e` testing)

### 2.3 dlp-agent

```
dlp-agent/
├── Cargo.toml
├── build.rs              # prost protobuf code generation
├── proto/                # Chrome Enterprise Content Analysis .proto files
└── src/
    ├── main.rs             # Windows Service dispatcher entry point
    ├── lib.rs              # Conditional Windows module declarations, test helpers
    ├── config.rs           # Agent TOML configuration
    ├── service.rs          # SCM lifecycle, password-protected stop
    ├── ui_spawner.rs       # Multi-session UI spawning
    ├── health_monitor.rs   # Agent<->UI health ping-pong
    ├── session_monitor.rs  # Session logon/logoff handler
    ├── session_identity.rs # Per-session identity map
    ├── protection.rs       # Process DACL hardening
    ├── password_stop.rs    # Service stop password gate
    ├── identity.rs         # SMB impersonation, AD subject resolution
    ├── engine_client.rs    # HTTPS client to dlp-server /evaluate
    ├── server_client.rs    # General HTTPS client to dlp-server
    ├── cache.rs            # Policy decision LRU cache with TTL
    ├── offline.rs          # Offline mode with fail-closed fallback
    ├── audit_emitter.rs    # Append-only JSONL local audit log
    ├── offline_audit_queue.rs # DPAPI-encrypted SQLite audit queue
    ├── bypass_correlator.rs # Bypass attempt correlation
    ├── allowlist.rs        # Agent-side allowlist
    ├── approval_cache.rs   # Approval decision cache
    ├── classification_cache.rs # Classification result cache
    ├── cache_pusher.rs     # Cache warm-up pusher
    ├── process_registry.rs # Process lifecycle tracking
    ├── process_watcher.rs  # ETW-based process watcher
    ├── device_registry.rs  # Endpoint device registration
    ├── device_controller.rs # Device control operations
    ├── disk_enforcer.rs    # Disk policy enforcement
    ├── usb_enforcer.rs     # USB policy enforcement
    ├── cloud_enforcer.rs   # Cloud upload enforcement
    ├── share_link_enforcer.rs # Share-link clipboard enforcement
    ├── print_enforcer.rs   # Print job enforcement
    ├── print_watcher.rs    # Print spooler change notification
    ├── print_job_info.rs   # RAII wrappers for print APIs
    ├── print_xps_parser.rs # XPS spool text extraction
    ├── wfp_ffi.rs          # Windows Filtering Platform FFI
    ├── wfp_manager.rs      # WFP sublayer and filter management
    ├── hook_injector.rs    # IAT hook DLL injection
    ├── hook_ipc.rs         # Hook IPC server
    ├── universal_injector.rs # Universal injection framework
    ├── appinit.rs          # AppInit_DLLs integration
    ├── dacl_tripwire.rs    # DACL integrity monitoring
    ├── dacl_repair_watcher.rs # DACL repair watcher
    ├── dacl_staging.rs     # DACL staging area
    ├── etw_kernel_file.rs  # ETW kernel file event tracing
    ├── chrome/
    │   ├── mod.rs
    │   ├── cache.rs
    │   ├── frame.rs
    │   ├── handler.rs
    │   ├── proto.rs        # Generated protobuf types
    │   └── registry.rs
    ├── clipboard/
    │   ├── mod.rs
    │   ├── listener.rs     # Clipboard hook (SetWindowsHookExW)
    │   └── classifier.rs   # Clipboard content classification
    ├── detection/
    │   ├── mod.rs
    │   ├── app_identity.rs # Application identity resolution
    │   ├── device_watcher.rs # Device arrival/removal notifications
    │   ├── disk.rs         # Fixed disk enumeration
    │   ├── encryption.rs   # BitLocker encryption status
    │   ├── network_share.rs # SMB share detection
    │   └── usb.rs          # USB mass storage detection
    ├── interception/
    │   ├── mod.rs          # File event loop orchestration
    │   ├── file_monitor.rs # notify-based file watcher
    │   ├── drag_drop.rs    # Drag-and-drop interception
    │   └── policy_mapper.rs # FileAction -> ABAC Action mapping
    └── ipc/
        ├── mod.rs
        ├── frame.rs         # IPC framing protocol
        ├── messages.rs      # IPC message types
        ├── pipe_security.rs # Pipe security descriptors
        ├── pipe1.rs         # Pipe 1 server (agent -> UI commands)
        ├── pipe2.rs         # Pipe 2 server (agent -> UI events)
        ├── pipe3.rs         # Pipe 3 server (UI -> agent)
        └── server.rs        # IPC server coordinator
```

**Entry point:** `src/main.rs` (binary: `dlp-agent.exe`, Windows Service)
**Library:** `src/lib.rs` (re-exported for `dlp-hook-dll` tests)

### 2.4 dlp-user-ui

```
dlp-user-ui/
├── Cargo.toml
├── build.rs              # winres icon embedding
├── icons/                # Application icons
└── src/
    ├── main.rs             # iced entry point; stop-password file mode
    ├── lib.rs              # Public API: run(), run_stop_password()
    ├── app.rs              # iced Application state machine
    ├── tray.rs             # System tray icon and menu
    ├── notifications.rs    # Windows toast notifications
    ├── clipboard_monitor.rs # Clipboard reading and classification
    ├── detection/
    │   ├── mod.rs
    │   └── app_identity.rs # App identity resolution (duplicated from agent)
    ├── dialogs/
    │   ├── mod.rs
    │   ├── clipboard.rs     # Clipboard block dialog
    │   ├── override_request.rs # Override request dialog
    │   └── stop_password.rs # Stop-password dialog
    └── ipc/
        ├── mod.rs
        ├── frame.rs
        ├── messages.rs
        ├── pipe1.rs         # Pipe 1 client
        ├── pipe2.rs         # Pipe 2 client
        └── pipe3.rs         # Pipe 3 client
```

**Entry point:** `src/main.rs` (binary: `dlp-user-ui.exe`)
**Library:** `src/lib.rs`

### 2.5 dlp-admin-cli

```
dlp-admin-cli/
├── Cargo.toml
└── src/
    ├── main.rs             # CLI parsing, TUI bootstrap
    ├── lib.rs              # Public module re-exports for e2e testing
    ├── app.rs              # App state machine and Screen enum
    ├── tui.rs              # Terminal setup, raw mode, panic hook
    ├── event.rs            # crossterm key event polling
    ├── client.rs           # Authenticated HTTP client (JWT)
    ├── engine.rs           # Server URL auto-detection
    ├── login.rs            # Pre-TUI health check and login
    ├── registry.rs         # HKLM registry reader
    └── screens/
        ├── mod.rs          # draw() dispatcher + handle_event()
        ├── dispatch.rs     # Keyboard event routing per screen
        ├── render.rs       # ratatui widget layout
        ├── allowlist.rs    # Allowlist management screen
        ├── approvals.rs    # Approval workflow screen
        ├── bypass_alerts.rs # Bypass alert management
        ├── cloud_config.rs  # Cloud enforcement config
        ├── labels.rs        # Label management screen
        ├── print_config.rs  # Print enforcement config
        ├── protected_paths.rs # Protected paths screen
        ├── syslog_config.rs # Syslog forwarder config
        └── usb_enforcement.rs # USB enforcement config
```

**Entry point:** `src/main.rs` (binary: `dlp-admin-cli.exe`)
**Library:** `src/lib.rs` (enables `dlp-e2e` headless TUI testing)

### 2.6 dlp-e2e

```
dlp-e2e/
├── Cargo.toml
├── src/
│   └── lib.rs            # Test helper re-exports: server, mock_engine, tui
├── tests/
│   ├── agent_toml_writeback.rs
│   ├── agent_ui_lifecycle.rs
│   ├── bincode_compat.rs
│   ├── cache_benchmark.rs
│   ├── hot_reload_config.rs
│   ├── phase50_requirements.rs
│   ├── tui_conditions_builder.rs
│   ├── tui_device_registry.rs
│   └── tui_managed_origins.rs
└── examples/
    └── debug_tui.rs      # Standalone TUI debugging example
```

**Entry point:** None (test-only crate). Run with `cargo test -p dlp-e2e`.

### 2.7 dlp-hook-dll

```
dlp-hook-dll/
├── Cargo.toml
└── src/
    ├── lib.rs              # DLL entry point, IAT patching, HOOKS table
    ├── trampolines.rs      # Hook trampolines for 12 Win32/NT functions
    ├── ntdll_patcher.rs    # Ntdll syscall stub patching (retour)
    ├── pipe_client.rs      # Named-pipe client to agent
    ├── classification_cache.rs # In-DLL classification cache
    ├── allowlist.rs        # Self-allowlist check
    ├── fail_closed.rs      # Deny return value definitions
    ├── fail_mode.rs        # Failure mode handling
    ├── crash_guard.rs      # Reentrancy and SEH guards
    ├── thread_suspender.rs # Thread suspension for safe patching
    ├── edr_detector.rs     # EDR/AV compatibility detection
    ├── perf_telemetry.rs   # Hook performance telemetry
    ├── hook_journal.rs     # Hook operation journaling
    ├── pe_utils.rs         # PE IAT parsing utilities
    ├── background_thread.rs # Background verification thread
    └── debug_test.rs       # Debug test utilities
```

**Entry point:** `DllMain` (DLL, not executable). Built as `cdylib` + `rlib`.

---

## 3. Configuration File Locations

| File | Purpose |
|------|---------|
| `Cargo.toml` (workspace root) | Workspace members, shared dependencies, package metadata |
| `Cargo.toml` (per crate) | Crate-specific dependencies, features, build scripts |
| `dlp-agent/proto/*.proto` | Chrome Enterprise Content Analysis protobuf definitions |
| `sgconfig.yml` | ast-grep rule configuration |
| `sonar-project.properties` | SonarQube project key and scanner settings |
| `.cargo/config.toml` | Cargo build configuration (if present) |
| `installer/DLPAgent.wxs` | WiX MSI installer source |
| `installer/build.ps1` | Installer build script |
| `docs/*.md` | Architecture, security, threat model, ABAC policies, audit logging, deployment, operational guides |
| `scripts/*.ps1` | PowerShell management scripts (service control, UAT benchmarks) |

---

## 4. Key Files and Their Roles

| File | Role |
|------|------|
| `dlp-common/src/abac.rs` | The ABAC type system -- central to the entire system's policy model |
| `dlp-common/src/ad_client.rs` | Active Directory integration -- identity layer for all enforcement |
| `dlp-server/src/lib.rs` | `AppState` -- the canonical shared state definition for all server handlers |
| `dlp-server/src/admin_api.rs` | The complete REST API surface -- all management operations |
| `dlp-server/src/policy_store.rs` | ABAC evaluation engine -- where policies become decisions |
| `dlp-agent/src/service.rs` | Windows Service lifecycle -- the agent's runtime backbone |
| `dlp-agent/src/interception/mod.rs` | File interception event loop -- primary enforcement pipeline |
| `dlp-agent/src/engine_client.rs` | Policy engine client -- bridges agent to server decisions |
| `dlp-hook-dll/src/lib.rs` | Hook DLL core -- IAT patching and classification dispatch |
| `dlp-user-ui/src/app.rs` | iced app state machine -- user-facing interaction layer |
| `dlp-admin-cli/src/app.rs` | ratatui app state machine -- admin interaction layer |
| `dlp-e2e/src/lib.rs` | Test harness -- enables in-process server and headless TUI testing |

---

## 5. Module/Package Organization Principles

1. **Crate per deployment unit**: Each crate maps to a distinct binary or library deployed independently (server, service, UI, CLI, DLL, test harness).

2. **dlp-common as the type contract**: All cross-crate communication types live in `dlp-common`. No crate depends on another's internal types.

3. **Platform gating**: All Windows-specific agent code is behind `#[cfg(windows)]`. The server and common crates are cross-platform.

4. **Conditional compilation for tests**: Integration-test-only features (e.g., `integration-tests` in dlp-agent) are default-off to keep CI green on non-Windows runners.

5. **Repository pattern in server**: Every database table has a corresponding repository module in `dlp-server/src/db/repositories/`. Shared query logic uses the unit-of-work pattern.

6. **IPC symmetry**: Both `dlp-agent/src/ipc/` and `dlp-user-ui/src/ipc/` share the same framing protocol and message types, defined in `dlp-common::hook_ipc` for agent<->DLL communication.

7. **Crypto abstraction**: `dlp-server::crypto::SecretCrypto` is the single abstraction for all secrets-at-rest operations. It is passed as `Arc<SecretCrypto>` to every component that needs encryption/decryption.
