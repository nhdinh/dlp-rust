---
gsd_state_version: 1.0
milestone: v0.2.0
milestone_name: "### Phase 0.1: Fix clipboard monitoring runtime pipeline [COMPLETED]"
status: Ready to plan
last_updated: "2026-04-10T12:26:17.853Z"
progress:
  total_phases: 12
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
---

# STATE.md — Project Memory

## Decisions

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-04-09 | Server-managed auth hash | CLI shouldn't need HKLM write access; server is single source of truth |
| 2026-04-09 | Remove POST /auth/admin | Unauthenticated admin creation is a security hole; prompt on first run instead |
| 2026-04-09 | Interactive-only TUI for dlp-admin-cli | ratatui + crossterm; login required before entering menus |
| 2026-04-09 | Plaintext base64 for file-based stop password | DPAPI fails cross-context (user vs SYSTEM); file is admin-only |
| 2026-04-10 | File-based agent logging | tracing to C:\ProgramData\DLP\logs\ for service diagnostics |
| 2026-04-10 | Skip USB thread join on shutdown | GetMessageW blocks forever; OS reclaims on process exit |
| 2026-04-10 | Clipboard monitoring in UI process | SYSTEM session 0 cannot access user clipboard |
| 2026-04-10 | classify_text in dlp-common | Shared classifier avoids duplication between agent and UI |

## Known Issues

- `dlp-agent/tests/integration.rs` references removed `dlp_server` modules (pre-existing, needs update)
- `policy_sync`, `config_push`, `alert_router`, `siem_connector` modules are implemented but not wired into server startup
- No rate limiting on server endpoints
- JWT secret has hardcoded dev fallback
- Single SQLite Mutex (not connection-pooled)

## Patterns

- Agent config: TOML at C:\ProgramData\DLP\agent-config.toml
- Debug logging: password_stop::debug_log() writes to C:\ProgramData\DLP\logs\stop-debug.log
- IPC: 3-pipe architecture (Pipe1 bidirectional, Pipe2 agent->UI, Pipe3 UI->agent)
- Audit: JSONL append-only with size-based rotation
