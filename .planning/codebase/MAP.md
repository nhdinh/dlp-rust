# DLP-RUST Codebase Map

## Workspace Structure

5 crates in a Cargo workspace + docs + scripts.

```
dlp-common/    -- shared types (no runtime deps)
dlp-server/    -- central HTTP server (axum + SQLite)
dlp-agent/     -- Windows Service endpoint agent
dlp-user-ui/   -- iced GUI subprocess
dlp-admin-cli/ -- ratatui admin TUI
scripts/       -- PowerShell service management
docs/          -- SRS, architecture, security, operations
```

## Cross-Crate Dependencies

```
dlp-common (no internal deps)
  ^-- dlp-server
  ^-- dlp-agent
  ^-- dlp-user-ui
  ^-- dlp-admin-cli
```

## dlp-common

| Module | Key Exports |
|--------|-------------|
| `classification.rs` | `Classification` enum (T1-T4), `is_sensitive()`, `label()` |
| `abac.rs` | `Decision`, `Action`, `AccessContext`, `Subject`, `Resource`, `Policy`, `EvaluateRequest/Response` |
| `audit.rs` | `AuditEvent`, `EventType`, `AuditAccessContext` |
| `classifier.rs` | `classify_text()` — SSN/CC/keyword pattern detection |

## dlp-server

| Module | Role | Wired? |
|--------|------|--------|
| `main.rs` | CLI, bootstrap, admin provisioning | Yes |
| `db.rs` | SQLite schema (6 tables) | Yes |
| `admin_api.rs` | Router + policy CRUD + credential endpoints | Yes |
| `admin_auth.rs` | JWT + bcrypt + password change | Yes |
| `agent_registry.rs` | Registration, heartbeat, offline sweeper | Yes |
| `audit_store.rs` | Event ingestion + query + count | Yes |
| `exception_store.rs` | Policy exception CRUD | Yes |
| `siem_connector.rs` | Splunk HEC + ELK relay | **Not wired** |
| `alert_router.rs` | SMTP + webhook alerts | **Not wired** |
| `policy_sync.rs` | Multi-replica sync | **Not wired** |
| `config_push.rs` | Agent config distribution | **Not wired** |

### DB Tables
agents, audit_events, policies, exceptions, admin_users, agent_credentials

### REST API (20+ endpoints)
Public: health, ready, auth/login, agents/register, heartbeat, audit/events (POST), agent-credentials/auth-hash (GET)
Protected (JWT): agents (GET), audit/events (GET), policies CRUD, exceptions CRUD, auth/password (PUT), agent-credentials/auth-hash (PUT)

## dlp-agent

| Module | Role |
|--------|------|
| `service.rs` | Windows Service lifecycle (SCM, state machine) |
| `config.rs` | TOML config (server_url, monitored_paths, excluded_paths) |
| `interception/file_monitor.rs` | `notify` crate file system watcher |
| `interception/policy_mapper.rs` | FileAction -> ABAC EvaluateRequest |
| `interception/mod.rs` | Event loop: intercept -> evaluate -> audit -> notify |
| `engine_client.rs` | HTTPS client to Policy Engine |
| `cache.rs` | TTL-based decision cache (FNV-1a hash) |
| `offline.rs` | Fail-closed offline mode (T3/T4 DENY) |
| `identity.rs` | SID/username resolution via impersonation |
| `session_identity.rs` | Per-session user identity map |
| `audit_emitter.rs` | JSONL audit log + size rotation (9 gens) |
| `server_client.rs` | dlp-server heartbeat + audit relay + hash fetch |
| `password_stop.rs` | bcrypt verification for `sc stop` |
| `protection.rs` | Process DACL hardening |
| `ui_spawner.rs` | CreateProcessAsUserW per session |
| `clipboard/listener.rs` | WH_GETMESSAGE hook (runs in user session) |
| `clipboard/classifier.rs` | Content classification (uses dlp-common) |
| `detection/usb.rs` | USB mass storage detection |
| `detection/network_share.rs` | SMB share monitoring + whitelist |
| `health_monitor.rs` | Ping-pong with UI |
| `session_monitor.rs` | Session logon/logoff polling |
| `ipc/` | 3-pipe named pipe architecture |

## dlp-user-ui

| Module | Role |
|--------|------|
| `app.rs` | iced application, tray, IPC task spawn |
| `tray.rs` | System tray icon + context menu |
| `notifications.rs` | winrt-notification toast wrapper |
| `clipboard_monitor.rs` | AddClipboardFormatListener + classify + alert |
| `dialogs/clipboard.rs` | Win32 clipboard read (CF_UNICODETEXT) |
| `dialogs/stop_password.rs` | Win32 password dialog (plaintext + DPAPI variants) |
| `dialogs/override_request.rs` | Custom modal with justification field |
| `ipc/pipe1.rs` | Bidirectional command pipe client |
| `ipc/pipe2.rs` | Agent->UI event listener |
| `ipc/pipe3.rs` | UI->Agent sender (UiReady, ClipboardAlert) |

## dlp-admin-cli

| Module | Role |
|--------|------|
| `main.rs` | Entry point, --connect parsing, TUI lifecycle |
| `app.rs` | Screen enum state machine |
| `tui.rs` | Terminal setup/teardown, panic hook |
| `event.rs` | Crossterm event polling |
| `login.rs` | Pre-TUI health check + JWT auth |
| `client.rs` | EngineClient with JWT, login(), check_health() |
| `engine.rs` | Server URL auto-detection |
| `registry.rs` | Windows registry read |
| `screens/render.rs` | All screen rendering (menus, tables, inputs) |
| `screens/dispatch.rs` | Event handling + server actions |

## Test Coverage

| Area | Status |
|------|--------|
| dlp-common types + classifier | Full |
| dlp-agent config/cache/offline/IPC | Full |
| dlp-agent file interception/policy mapper | Full |
| dlp-server DB/auth/serde | Partial |
| dlp-admin-cli engine URL | Partial |
| dlp-user-ui | None (manual only) |
| Integration (agent<->server) | Broken (references removed modules) |
