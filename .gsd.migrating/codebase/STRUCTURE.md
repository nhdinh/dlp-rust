# Directory & Code Organization

## Top-Level Layout

```
dlp-rust/
├── Cargo.toml              # Workspace manifest (6 members)
├── Cargo.lock              # Pinned dependency graph
├── README.md               # Project overview
├── sonar-project.properties # SonarQube configuration
├── .github/workflows/      # CI/CD (build.yml, nightly.yml)
├── .gsd/                   # GSD project management data
├── .planning/              # Planning artifacts
├── .claude/                # Claude Code configuration & skills
├── docs/                   # Documentation
├── scripts/                # PowerShell management scripts
├── dlp-common/             # Shared types library
├── dlp-server/             # Central management server
├── dlp-agent/              # Windows Service endpoint agent
├── dlp-admin-cli/          # TUI admin console
├── dlp-user-ui/            # Iced GUI (user notifications)
└── dlp-e2e/                # End-to-end integration tests
```

## Source Code Organization

### dlp-common/src/

```
dlp-common/src/
├── lib.rs                  # Module exports
├── abac.rs                 # ABAC model (Policy, Decision, Condition, Action enums)
├── ad_client.rs            # Active Directory LDAP client
├── audit.rs                # AuditEvent, EventType definitions
├── classification.rs       # Data classification tiers (T1–T4)
├── classifier.rs           # Pattern-based content classifier
├── disk.rs                 # DiskIdentity, BusType, EncryptionStatus
├── endpoint.rs             # AppIdentity, DeviceIdentity, trust tiers
└── usb.rs                  # USB device types
```

### dlp-server/src/

```
dlp-server/src/
├── main.rs                 # Server entry point (tokio async)
├── lib.rs                  # Public API surface
├── admin_api.rs            # REST API routes (axum Router)
├── admin_auth.rs           # JWT auth, password hashing
├── agent_registry.rs       # Agent heartbeat tracking
├── alert_router.rs         # SMTP + webhook alerting
├── audit_store.rs          # Append-only audit storage
├── exception_store.rs      # Policy exception tracking
├── policy_store.rs         # ABAC policy cache + evaluation engine
├── policy_sync.rs          # Policy synchronization
├── rate_limiter.rs         # Request rate limiting
├── siem_connector.rs       # Splunk HEC / ELK bulk relay
└── db/
    ├── mod.rs              # Schema, pool init, migrations
    ├── unit_of_work.rs     # Transaction management
    └── repositories/
        ├── mod.rs
        ├── admin_users.rs
        ├── agents.rs
        ├── agent_credentials.rs
        ├── alert_router_config.rs
        ├── audit_events.rs
        ├── device_registry.rs
        ├── disk_registry.rs
        ├── exceptions.rs
        ├── ldap_config.rs
        ├── managed_origins.rs
        ├── policies.rs
        └── siem_config.rs
```

### dlp-agent/src/

```
dlp-agent/src/
├── main.rs                 # Windows Service entry (FFI dispatcher)
├── lib.rs                  # Module declarations (25+ submodules)
├── service.rs              # Service lifecycle state machine
├── config.rs               # TOML configuration loader
├── identity.rs             # SMB client identity resolution
├── session_identity.rs     # SID → AD groups mapping
├── session_monitor.rs      # Session logon/logoff handler
├── engine_client.rs        # HTTPS client to /evaluate
├── server_client.rs        # HTTPS client (registration, config fetch)
├── cache.rs                # Local policy decision cache
├── offline.rs              # Fail-closed offline mode
├── health_monitor.rs       # Health ping-pong with UI
├── audit_emitter.rs        # JSONL audit log with rotation
├── protection.rs           # Process DACL hardening
├── password_stop.rs        # Password-protected service stop
├── device_controller.rs    # Device state management
├── device_registry.rs      # Endpoint device fingerprinting
├── disk_enforcer.rs        # Disk access enforcement
├── usb_enforcer.rs         # USB access enforcement
├── ui_spawner.rs           # Per-session UI process spawning
├── interception/
│   ├── mod.rs
│   ├── file_monitor.rs     # NTFS minifilter communication
│   └── policy_mapper.rs    # File ops → ABAC evaluation
├── clipboard/
│   ├── mod.rs
│   ├── listener.rs         # Win32 clipboard hooks
│   └── classifier.rs       # Content classification
├── detection/
│   ├── mod.rs
│   ├── device_watcher.rs   # Device hotplug monitoring
│   ├── usb.rs              # USB detection (SetupDi API)
│   ├── disk.rs             # Fixed disk enumeration
│   ├── encryption.rs       # BitLocker status (WMI)
│   └── network_share.rs    # SMB destination whitelisting
├── ipc/
│   ├── mod.rs
│   ├── server.rs           # Named pipe server
│   ├── frame.rs            # Length-prefixed framing
│   ├── messages.rs         # Typed IPC messages
│   ├── pipe1.rs            # Pipe implementation (v1)
│   ├── pipe2.rs            # Pipe implementation (v2)
│   ├── pipe3.rs            # Pipe implementation (v3)
│   └── pipe_security.rs    # DACL for pipe access
└── chrome/
    ├── mod.rs
    ├── handler.rs          # Content analysis handler
    ├── cache.rs            # Response cache
    ├── frame.rs            # Protobuf framing
    ├── proto.rs            # Generated protobuf types
    └── registry.rs         # Chrome registry integration
```

### dlp-admin-cli/src/

```
dlp-admin-cli/src/
├── main.rs                 # CLI entry point
├── lib.rs                  # Library target
├── app.rs                  # Application state
├── client.rs               # Server HTTP client
├── login.rs                # Authentication flow
├── engine.rs               # ABAC/policy evaluation engine
├── event.rs                # Event handling
├── registry.rs             # Windows registry operations
├── tui.rs                  # Terminal setup
└── screens/
    ├── mod.rs              # Screen definitions
    ├── dispatch.rs         # Input routing
    └── render.rs           # UI rendering
```

### dlp-user-ui/src/

```
dlp-user-ui/src/
├── main.rs                 # UI entry point
├── lib.rs                  # Library target
├── app.rs                  # Iced application state
├── tray.rs                 # System tray integration
├── clipboard_monitor.rs    # Clipboard monitoring
├── notifications.rs        # Toast notification display
├── dialogs/
│   ├── mod.rs
│   ├── clipboard.rs        # Clipboard block dialog
│   ├── override_request.rs # Policy override request
│   └── stop_password.rs    # Service stop password prompt
├── detection/
│   ├── mod.rs
│   └── app_identity.rs     # Application identity
└── ipc/
    ├── mod.rs
    ├── frame.rs            # Length-prefixed framing
    ├── messages.rs         # Typed IPC messages
    ├── pipe1.rs            # Pipe client (v1)
    ├── pipe2.rs            # Pipe client (v2)
    └── pipe3.rs            # Pipe client (v3)
```

## Test Organization

### Unit Tests

- Inline `#[cfg(test)]` modules within source files (Rust convention)
- `serial_test` crate for tests requiring sequential execution (global state)

### Integration Tests

| Location | Scope |
|----------|-------|
| `dlp-server/tests/ldap_config_api.rs` | LDAP configuration API |
| `dlp-server/tests/admin_audit_integration.rs` | Admin audit integration |
| `dlp-server/tests/mode_end_to_end.rs` | Server mode E2E |
| `dlp-agent/tests/negative.rs` | Negative test cases |
| `dlp-e2e/src/lib.rs` | Full-system integration |

### Test Dependencies

- `wiremock` 0.6 — HTTP mocking (dlp-admin-cli)
- `tempfile` — Temporary file/directory creation
- `serial_test` — Sequential test execution
- `tokio` test-util — Async test utilities

## Configuration Files

| File | Purpose |
|------|---------|
| `Cargo.toml` (root) | Workspace manifest + shared dependencies |
| `Cargo.toml` (per crate) | Crate-specific deps, features, targets |
| `Cargo.lock` | Pinned dependency versions |
| `sonar-project.properties` | SonarQube project configuration |
| `.github/workflows/build.yml` | CI pipeline (PR + push) |
| `.github/workflows/nightly.yml` | Nightly release build + smoke tests |
| `dlp-agent/build.rs` | Protobuf compilation |
| `dlp-user-ui/build.rs` | Windows resource embedding |

### Runtime Configuration (Agent)

- Path: `C:\ProgramData\DLP\agent-config.toml`
- Format: TOML
- Contents: server_url, monitored_paths, log level, encryption check interval

## Scripts

```
scripts/
├── Manage-DlpComponents.ps1     # Start/stop/check server + agent
├── Manage-DlpAgentService.ps1   # Windows Service management
├── Uat-UsbBlock.ps1             # USB blocking UAT
└── Uat-ReadMe.md                # UAT documentation
```

## Build Artifacts

- Debug: `target/debug/` (dlp-server.exe, dlp-agent.exe, dlp-admin-cli.exe, dlp-user-ui.exe)
- Release: `target-release/` (nightly CI) or `target/release/` (local)
- Proto output: `dlp-agent/src/chrome/proto.rs` (generated by prost-build)
