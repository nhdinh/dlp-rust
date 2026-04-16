---
gsd_state_version: 1.0
milestone: v0.3.0
milestone_name: Operational Hardening
status: Ready to plan
last_updated: "2026-04-16T00:48:26.981Z"
progress:
  total_phases: 6
  completed_phases: 1
  total_plans: 5
  completed_plans: 8
  percent: 100
---

# STATE.md — Project Memory

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-13)

**Core value:** Real-time file/clipboard/USB interception with ABAC-based policy enforcement, centralized admin control, and SIEM/alert integration.
**Current focus:** Phase 07 — AD LDAP integration (Plans 01, 02 complete; Plans 03–05 already done)

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
| 2026-04-16 | PolicyStore uses parking_lot::RwLock | Faster uncontended read path vs std::sync::RwLock |
| 2026-04-16 | Classification from dlp_common root | dlp_common::abac does not re-export Classification; must use root path |
| 2026-04-16 | Test helpers inside #[cfg(test)] module | Keeps public lib API clean, avoids dead_code in lib binary |
| 2026-04-16 | POLICY_REFRESH_INTERVAL_SECS #[allow(dead_code)] | Wave 2 wires background refresh task; suppress until then |
| 2026-04-16 | Wave 3: evaluate_handler in public_routes | POST /evaluate is unauthenticated; agent identity from AgentInfo body per 11-CONTEXT.md § Q1 |
| 2026-04-16 | Wave 4: Task 4.1 already complete | wave 3 propagated AppState change to all test helpers; no additional code needed |
| 2026-04-16 | Wave 4: EvaluateRequest requires Environment.timestamp | DateTime<Utc> field has no default; test fixtures must include full environment object |
| 2026-04-16 | Wave 3: invalidate() outside spawn_blocking | In-memory Vec swap is microseconds; no async context needed |
| 2026-04-15 | Background cache refresh: tokio interval loop | POLICY_REFRESH_INTERVAL_SECS exported as pub; avoids hardcoding magic number in main.rs |
| 2026-04-15 | Startup failure on policy cache load error | Server does not start silently with empty cache; explicit map_err |
| 2026-04-15 | Arc<PolicyStore> in AppState | pool and policy_store are both Arc<_> so AppState remains Clone for axum |
| 2026-04-16 | AD client channel-based async | AdClient spawns background Tokio task owning LDAP connection; mpsc + oneshot serializes LDAP ops cleanly |
| 2026-04-16 | AD fail-open: empty groups on error | Never block operations due to AD unavailability; warn-level log + empty vector |
| 2026-04-16 | Machine account Kerberos TGT bind | CN={COMPUTERNAME}$,CN=Computers,{base_dn} with empty password — no stored credentials |
| 2026-04-16 | Group cache keyed by caller_sid | SID is universally available; username used for sAMAccountName LDAP filter (no DN needed) |
| 2026-04-16 | NetGetJoinInformation for device_trust | NETSETUP_JOIN_STATUS(3) == NetSetupDomainName check; more reliable than NetIsPartOfDomain |
| 2026-04-16 | Manual binary SID parse per MS-DTYP §2.4.2 | Zero unsafe blocks; revision byte + subauthority count + authority + subauthorities |
| 2026-04-16 | Duplicate windows deps key fix | Merged two [target.'cfg(windows)'.dependencies] keys into one in dlp-common/Cargo.toml |

## Known Issues (v0.2.0 — to address in v0.3.0)

- [Resolved] R-05: AD LDAP not integrated — AdClient implemented in dlp-common; Phase 7 Plan 1 complete
- R-07: No rate limiting on server endpoints
- R-09: Admin CRUD operations not persisted as audit events
- R-10: Single SQLite Mutex<Connection> serializes concurrent requests
- R-03: Policy Engine Separation in progress — PolicyStore + PolicyEngineError created (wave 1/5 complete)
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

## Accumulated Context

### Roadmap Evolution

- Phase 99 added: Refactor DB layer to Repository + Unit of Work
