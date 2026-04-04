# Implementation Guide (Rust)

## Architecture

- Policy Engine: Rust
- Agent: Rust (Windows API bindings)
- Logging: JSON → SIEM

## Crate Structure

The project is a Cargo workspace with the following crates:

| Crate                  | Role                                                                    | Phase        |
| ---------------------- | ----------------------------------------------------------------------- | ------------ |
| `dlp-common/`          | Shared types: Subject, Resource, ABAC enums, AuditEvent, Classification | 1            |
| `policy-engine/`       | ABAC evaluator, HTTPS/REST server, AD LDAP client, policy cache         | 1            |
| `dlp-agent/`           | Windows Service: file interception, policy enforcement                  | 1            |
| `dlp-user-ui/`         | iced endpoint UI: toasts, dialogs, clipboard, tray                      | 1            |
| `dlp-admin-portal/`    | iced admin UI: policy CRUD, dashboard, audit viewer, TOTP               | **Deferred** |
| `dlp-server/`          | Central HTTP server: audit store, SIEM relay, admin auth, policy sync   | **Phase 5**  |

> **Note:** `dlp-admin-portal/` is deferred to a later phase. During Phase 1–4, audit logs are read directly from the local append-only JSON file.

## Key Libraries

Full toolchain per project coding standards (see `CLAUDE.md`):

- **Serialization:** `serde`, `serde_json`
- **Async runtime:** `tokio`
- **Web server:** `axum`, `tower`, `reqwest` (client)
- **Windows API:** `windows-rs`
- **Terminal UI:** `ratatui`, `crossterm`
- **CLI progress:** `indicatif`
- **Logging:** `tracing` + `tracing-subscriber` (structured logging with spans); `log` crate as a compat shim for libraries expecting the `log` facade
- **Error handling:** `thiserror` for all error types; `anyhow` only at application boundaries (e.g., `main.rs` entry point) for context-wrapping
- **Data processing:** `polars`, `rayon`
- **Secrets:** `secrecy`, `dotenvy`
- **UI framework:** iced (pure Rust native GUI)

## Deployment Phases

See SRS.md §8 (Implementation Plan) for the full 5-phase task breakdown.

### Phase 1 — Foundation

- Workspace scaffold (`Cargo.toml`)
- `dlp-common/`: Subject, Resource, ABAC enums, AuditEvent, Classification
- `policy-engine/`: HTTPS/REST server, ABAC evaluator, AD integration, hot-reload
- `dlp-agent/`: Windows Service, file interception hooks, IPC pipe servers, UI spawner
- `dlp-user-ui/`: Endpoint UI (toasts, override dialogs, clipboard, tray)

### Phase 2 — Process Protection + IPC Hardening

- Process DACL hardening (deny PROCESS_TERMINATE to non-`dlp-admin`)
- Named pipe security hardening

### Phase 3 — SMB Share Detection + Integration Tests

- SMB share detection: poll `WNetOpenEnumW`/`WNetEnumResourceW` (MPR) every 30s; differential scan emits `Connected`/`Disconnected` events; whitelist enforcement for T3/T4 destinations (F-AGT-14)
- Integration test suite

### Phase 4 — Production Hardening

- Security audit (`docs/SECURITY_AUDIT.md`)
- MSI installer packaging (`dlp-agent/installer/DLPAgent.wxs`)
- `docs/OPERATIONAL.md` runbook

### Phase 5 — dlp-server

- `dlp-server/`: audit store, SIEM relay, admin auth (TOTP+JWT), policy sync
- `dlp-admin-portal/`: admin UI (policy CRUD, audit viewer, TOTP)
