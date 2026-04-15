---
gsd_state_version: 1.0
milestone: v0.3.0
milestone_name: Operational Hardening
status: Ready to plan
last_updated: "2026-04-15T07:50:27.263Z"
progress:
  total_phases: 5
  completed_phases: 0
  total_plans: 2
  completed_plans: 1
  percent: 50
---

# STATE.md — Project Memory

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-13)

**Core value:** Real-time file/clipboard/USB interception with ABAC-based policy enforcement, centralized admin control, and SIEM/alert integration.
**Current focus:** Phase 10 — sqlite-connection-pool

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
| 2026-04-10 | Operator config in SQLite (not env vars) | Hot-reload + TUI-manageable + persistent |
| 2026-04-11 | Axum .route() merges methods per-call only | Consolidate all verbs into one .route() call per path |
| 2026-04-11 | Fire-and-forget for SIEM/alert relay | No HTTP-ingest latency impact |
| 2026-04-12 | Agent config polling (not server push) | Agents are fire-and-forget; polling is more resilient |
| 2026-04-13 | DB-backed config as the standard pattern | Established on Phase 3.1; Phases 4 and 6 followed automatically |

## Known Issues (v0.2.0 — to address in v0.3.0)

- R-05: AD LDAP not integrated — ABAC uses placeholder values for user groups
- R-07: No rate limiting on server endpoints
- R-09: Admin CRUD operations not persisted as audit events
- R-10: Single SQLite Mutex<Connection> serializes concurrent requests
- R-03: Policy Engine Separation deferred — architectural refactor needed
- Phase 6 human UAT: live agent TOML write-back test not run
- Phase 6 human UAT: zero-warning workspace build not verified
- Phase 4 human UAT: live SMTP email delivery not tested
- Phase 4 human UAT: live webhook POST not tested
- Phase 4 human UAT: hot-reload verification through HTTP + TUI not run

## Patterns

- Agent config: TOML at C:\ProgramData\DLP\agent-config.toml
- Debug logging: password_stop::debug_log() writes to C:\ProgramData\DLP\logs\stop-debug.log
- IPC: 3-pipe architecture (Pipe1 bidirectional, Pipe2 agent->UI, Pipe3 UI->agent)
- Audit: JSONL append-only with size-based rotation
- Operator config: SQLite single-row tables with CHECK constraints, hot-reload on every operation
- Agent-server comms: JWT heartbeat, unauthenticated config poll endpoint
