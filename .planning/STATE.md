---
gsd_state_version: 1.0
milestone: v0.5.0
milestone_name: â Boolean Logic
status: executing
last_updated: "2026-04-22T11:42:35.485Z"
last_activity: 2026-04-22
progress:
  total_phases: 13
  completed_phases: 11
  total_plans: 28
  completed_plans: 27
  percent: 96
---

# STATE.md — Project Memory

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-21)

**Core value:** Real-time file/clipboard/USB interception with ABAC-based policy enforcement, centralized admin control, and SIEM/alert integration.
**Current focus:** Phase 25 — app-identity-capture-in-dlp-user-ui

## Current Position

Phase: 25 (app-identity-capture-in-dlp-user-ui) — READY TO EXECUTE
Plan: 1 of 3 (planning complete)
Status: Ready to execute
Resume: `/gsd-execute-phase 25`
Last activity: 2026-04-22

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
| 2026-04-20 | GET admin routes asymmetry | Only /policies (no /admin/policies) serves GET; /admin/policies is POST/PUT/DELETE only (Phase 9 legacy) |
| 2026-04-20 | Import/export typed via PolicyResponse/PolicyPayload | From<PolicyResponse> for PolicyPayload drops version/updated_at for wire POST/PUT; unit-tested roundtrip |
| 2026-04-20 | Skip-nav in ImportConfirm | Informational rows (header + diff counts) are non-selectable; Up/Down cycles only Confirm/Cancel |
| 2026-04-20 | v0.5.0 phase split: engine before TUI | Phase 18 ships server-side mode + backward-compat default (POLICY-12) so the TUI work in Phase 19 lands against an already-mode-aware server (POLICY-09 user-facing completion) |
| 2026-04-20 | Boolean mode is flat top-level only | No nested expression trees in v0.5.0; rule-builder UX and wire-format simplicity. Users needing AND-of-ORs author two policies and use priority ordering |
| 2026-04-21 | PolicyMode::ALL arm in footer advisory is exhaustive-but-unreachable | Outer guard `form.mode != PolicyMode::ALL` makes the ALL arm dead code; Rust requires exhaustive match on three-variant enum; empty string renders nothing |
| 2026-04-21 | Integration test conditions JSON uses snake_case attribute tags | `PolicyCondition` has `#[serde(tag = "attribute", rename_all = "snake_case")]`; AccessContext variant serializes as "access_context" not "accesscontext" |
| 2026-04-21 | CARGO_TARGET_DIR=target-test workaround for locked dlp-server.exe | Elevated dlp-server process holds target/debug/dlp-server.exe; alternate target dir lets cargo compile test binary without touching locked file |
| 2026-04-22 | ON CONFLICT DO UPDATE preserves UUID PK | INSERT OR REPLACE deletes-then-reinserts changing the PK; ON CONFLICT DO UPDATE updates in place keeping the original id |
| 2026-04-22 | In-memory pool test: release write conn before read | r2d2 in-memory SQLite pool — write PooledConnection must be dropped (returned to pool) before list_all acquires a second connection |
| 2026-04-22 | seed_for_test always-compiled, not feature-gated | Integration tests in tests/ compile lib crate without cfg(test); #[doc(hidden)] pub fn is the only pattern that works without --features flags |

## Known Issues (carry-forward)

- Phase 6 human UAT: live agent TOML write-back test not run
- Phase 6 human UAT: zero-warning workspace build not verified
- Phase 4 human UAT: live SMTP email delivery not tested
- Phase 4 human UAT: live webhook POST not tested
- Phase 4 human UAT: hot-reload verification through HTTP + TUI not run
- Phase 24 human UAT: approved for debug build only — release-mode UAT (cargo build --release + curl smoke test) not verified; defer to Phase 25 or hardening pass

## Deferred Items (from v0.5.0 close — 2026-04-21)

Items acknowledged and deferred at milestone close on 2026-04-21. Known deferred items at close: 6

| Category | Item | Status |
|----------|------|--------|
| seed | SEED-001: Application-aware DLP | active — promoted to v0.6.0 as APP-01..06 |
| seed | SEED-002: Protected Clipboard browser boundary | active — promoted to v0.6.0 as BRW-01..03 |
| seed | SEED-003: USB Device-Identity-Aware Whitelist | active — promoted to v0.6.0 as USB-01..04 |
| server | POLICY-F4: TOML export format | deferred — toml crate incompatible with #[serde(tag)] PolicyCondition |
| server | POLICY-F5: Batch import endpoint | deferred — reduces cache invalidations on bulk import |
| server | POLICY-F6: Typed Decision action field | deferred — eliminates silent `_ => DENY` fallback |

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
- Import/export: typed Vec<PolicyResponse> for file shape; From<PolicyResponse> for PolicyPayload for wire format
- Skip-nav lists: informational rows in ratatui List render but are excluded from Up/Down navigation (e.g., ImportConfirm rows 0-2)
- DB schema migrations: column adds via ALTER TABLE in dlp-server::db::open with NOT NULL DEFAULT for backward compat (no formal migration framework)
- PolicyStore evaluate() stays sync on hot path; cache invalidation fires on every policy mutation

## Accumulated Context

### Milestones Shipped

- v0.2.0 Feature Completion (2026-04-13) — phases 0.1–12
- v0.3.0 Operational Hardening (2026-04-16) — phases 7–11 + 99
- v0.4.0 Policy Authoring (2026-04-20) — phases 13–17; POLICY-01..08 all delivered

### Shipped Milestones (complete)

- v0.5.0 Boolean Logic — phases 18–21; POLICY-09..12 (4 requirements, all delivered 2026-04-21)

### Active Milestone

- v0.6.0 Endpoint Hardening — phases 22–29; APP-01..06, BRW-01..03, USB-01..04 (13 requirements)
  - Phase 22: dlp-common Foundation (unblocks all tracks)
  - Phase 23: USB Enumeration in dlp-agent (USB-01)
  - Phase 24: Device Registry DB + Admin API (USB-02)
  - Phase 25: App Identity Capture in dlp-user-ui (APP-01, APP-02, APP-05, APP-06)
  - Phase 26: ABAC Enforcement Convergence (APP-03, USB-03)
  - Phase 27: USB Toast Notification (USB-04)
  - Phase 28: Admin TUI Screens (APP-04, BRW-02)
  - Phase 29: Chrome Enterprise Connector (BRW-01, BRW-03)
