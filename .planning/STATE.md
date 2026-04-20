---
gsd_state_version: 1.0
milestone: v0.3.0
milestone_name: — Operational Hardening
status: executing
last_updated: "2026-04-20T00:00:00.000Z"
last_activity: 2026-04-20 -- Phase 16 complete
progress:
  total_phases: 4
  completed_phases: 4
  total_plans: 9
  completed_plans: 9
  percent: 100
---

# STATE.md — Project Memory

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-16)

**Core value:** Real-time file/clipboard/USB interception with ABAC-based policy enforcement, centralized admin control, and SIEM/alert integration.
**Current focus:** Phase 17 — policy import/export (planned)

## Current Position

Phase: 17
Plan: Not started
Status: Ready to plan
Last activity: 2026-04-20 -- Phase 16 complete

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
| 2026-04-16 | Wave 3: evaluate_handler in public_routes | POST /evaluate is unauthenticated; agent identity from AgentInfo body per 11-CONTEXT.md § Q1 |
| 2026-04-16 | AD client channel-based async | AdClient spawns background Tokio task owning LDAP connection; mpsc + oneshot serializes LDAP ops cleanly |
| 2026-04-16 | AD fail-open: empty groups on error | Never block operations due to AD unavailability; warn-level log + empty vector |
| 2026-04-16 | Machine account Kerberos TGT bind | CN={COMPUTERNAME}$,CN=Computers,{base_dn} with empty password — no stored credentials |
| 2026-04-16 | Group cache keyed by caller_sid | SID is universally available; username used for sAMAccountName LDAP filter (no DN needed) |
| 2026-04-16 | TOML export blocked | toml crate incompatible with #[serde(tag = "attribute")] PolicyCondition; JSON only for v0.4.0 |
| 2026-04-16 | Conditions builder: PolicyFormState struct | Eliminates borrow-split issues when returning Vec<PolicyCondition> to caller form |
| 2026-04-16 | Import: GET existing IDs before POST/PUT | Detects conflicts without overwriting untracked policies |
| 2026-04-20 | DeviceTrust/NetworkLocation not Copy | Use .cloned() on Option<&T> rather than .copied() when indexing into simulate form arrays |
| 2026-04-20 | chrono = "0.4" explicit dep | dlp-admin-cli uses it for EvaluateRequest timestamp; not a transitive dep of dlp-common |

## Known Issues (carry-forward from v0.3.0)

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
- Policy conditions: JSON array of typed PolicyCondition variants (Classification, MemberOf, DeviceTrust, NetworkLocation, AccessContext)
- TUI screens: ratatui + crossterm; generic get::<serde_json::Value> HTTP client pattern (not typed client methods)
- Policy forms: PolicyFormState struct holds all form fields + conditions list to avoid borrow-split at submit time

## Accumulated Context

### Roadmap Evolution

- Phase 99 added: Refactor DB layer to Repository + Unit of Work
- v0.4.0: Policy Authoring — admin API already complete; milestone is 100% dlp-admin-cli TUI work + thin server-side import/export endpoint

### v0.4.0 Phase Summary

| Phase | Name | Depends |
|-------|------|---------|
| 13 | Conditions Builder | None (foundational) |
| 14 | Policy Create | Phase 13 |
| 15 | Policy Edit + Delete | Phase 14 |
| 16 | Policy List + Simulate | Phase 13 (parallel-capable with 14/15) |
| 17 | Import + Export | Phase 14 + Phase 15 |
