---
phase: 03-wire-siem-connector-into-server-startup
plan: PLAN
subsystem: infra
tags: [axum, appstate, siem, audit, background-task, dlp-server]
superseded_by: 03.1-siem-config-in-db

# Dependency graph
requires:
  - phase: 2
    provides: "JWT_SECRET required at startup — admin-authenticated endpoints can safely be added"
provides:
  - "AppState { db, siem } shared axum state"
  - "Handler refactor from State<Arc<Database>> to State<Arc<AppState>>"
  - "Best-effort background SIEM relay after audit event ingest"
affects: [03.1-siem-config-in-db, 04-wire-alert-router-into-server, 05-wire-policy-sync, 06-wire-config-push, 09-admin-operation-audit-logging]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Fire-and-forget background relay via tokio::spawn — HTTP response is never blocked by external SIEM latency"
    - "Shared AppState as the canonical axum state type (vs per-handler Arc<Database>)"

key-files:
  created: []
  modified:
    - dlp-server/src/lib.rs
    - dlp-server/src/main.rs
    - dlp-server/src/admin_api.rs
    - dlp-server/src/admin_auth.rs
    - dlp-server/src/agent_registry.rs
    - dlp-server/src/audit_store.rs
    - dlp-server/src/exception_store.rs

key-decisions:
  - "Share AppState across all admin/agent/audit/exception handlers instead of extending per-module state"
  - "SIEM relay is best-effort fire-and-forget — failures log but never block the ingest HTTP response"
  - "Config-loading mechanism superseded by Phase 3.1 same day — env-var approach dropped in favor of DB-backed hot-reload"

patterns-established:
  - "All server handlers use State<Arc<AppState>> — adding a new shared resource (SIEM, alerts, metrics) now just extends AppState instead of threading yet another Arc<T>"
  - "Background relay pattern: tokio::spawn after DB commit, tracing::warn! on error, no caller impact"

requirements-completed: [R-01]

# Metrics
duration: ~40 min (plan → feature commit)
completed: 2026-04-10
---

# Phase 3: Wire SIEM Connector into Server Startup Summary

**`AppState { db, siem }` is now the canonical axum state across all dlp-server handlers, and audit events spawn a best-effort SIEM relay in the background after DB commit. Config-loading half was superseded by Phase 3.1 the same day — see addendum in PLAN.md.**

## Performance

- **Duration:** ~40 min (plan `e2fd3b2` → feature `30ccaaf`)
- **Started:** 2026-04-10 10:23 +0700 (plan)
- **Completed:** 2026-04-10T11:03:31+07:00 (feature commit)
- **Tasks:** 1 feature commit
- **Files modified:** 5 source files + 2 added (lib.rs `AppState`, audit relay wiring)

## Accomplishments

- Defined `AppState { db: Arc<Database>, siem: SiemConnector }` in `dlp-server/src/lib.rs` as the shared axum state type.
- Refactored every admin/agent/audit/exception handler from `State<Arc<Database>>` to `State<Arc<AppState>>` — a single shared state replaces the per-module `Arc<Database>` threading.
- Wired `SiemConnector` construction into `main.rs` before the router is built, so the relay handle is available to every handler via `AppState.siem.clone()`.
- Added best-effort background SIEM relay in `audit_store::ingest_events`: after the batched transaction commits, `tokio::spawn` fires `siem.relay_events(&events).await` and logs failures at `warn!` level without affecting the HTTP response.

## Task Commits

1. **Feature** — `30ccaaf` (feat: wire SIEM connector into server startup (Phase 3, R-01))
   - `dlp-server/src/admin_api.rs` +19 / -11
   - `dlp-server/src/admin_auth.rs` +6 / -4
   - `dlp-server/src/agent_registry.rs` +11 / -7
   - `dlp-server/src/audit_store.rs` +19 / -4 (background relay task)
   - `dlp-server/src/exception_store.rs` +7 / -4
   - `dlp-server/src/lib.rs` / `main.rs` — AppState definition + wiring

**Plan metadata:** `e2fd3b2` (plan: phase 3 — wire SIEM connector into server startup)

## Files Created/Modified

- `dlp-server/src/lib.rs` — `pub struct AppState { pub db: Arc<Database>, pub siem: SiemConnector }`
- `dlp-server/src/main.rs` — constructs `SiemConnector` + `AppState`, passes to router
- `dlp-server/src/admin_api.rs` — all handlers now take `State(state): State<Arc<AppState>>` and read `state.db`
- `dlp-server/src/admin_auth.rs` — login, change_password, require_auth — same refactor
- `dlp-server/src/agent_registry.rs` — register, heartbeat, list-agents — same refactor
- `dlp-server/src/audit_store.rs` — `ingest_events`: after commit, `tokio::spawn` runs `state.siem.relay_events(&relay_events)` and logs failures
- `dlp-server/src/exception_store.rs` — create/list/resolve exceptions — same refactor

## Decisions Made

- **Single AppState instead of per-subsystem state structs.** The plan proposed a single AppState and this was implemented as-is. Future subsystems (alert router, rate limit backend, metrics) extend AppState instead of adding new extractors — keeps handler signatures stable.
- **Best-effort relay, never blocking.** The ingest HTTP response returns immediately after the DB commit; SIEM relay runs in a spawned task. Rationale: external SIEM latency should never degrade audit ingest throughput, and a SIEM outage should not cause agents to think the server is down.
- **Config-loading mechanism deferred to Phase 3.1.** The original plan loaded SIEM config via `SiemConnector::from_env()`. Same-day user feedback during Phase 3.1 discuss: operator config must live in DB + admin API + TUI. Phase 3's `from_env()` was replaced by Phase 3.1's `SiemConnector::new(db)` — see addendum in PLAN.md for the supersession rationale.

## Deviations from Plan

**1. Config loading mechanism — superseded by Phase 3.1 same day**
- **Found during:** Phase 3.1 discuss session
- **Issue:** Plan Step 2 prescribed `SiemConnector::from_env()` reading `SPLUNK_HEC_*` / `ELK_*` env vars. User's locked decision (see `.planning/phases/03.1-siem-config-in-db/CONTEXT.md`): SIEM/alert/config-push settings must live in the SQLite database, not env vars, so admins can manage them via dlp-admin-cli TUI without restarting the server.
- **Fix:** Phase 3 shipped with `from_env()` as a transitional state; Phase 3.1 (commit `8911669`) then replaced it with `SiemConnector::new(db: Arc<Database>)` + new `siem_config` table + `GET/PUT /admin/siem-config` + TUI screen.
- **Files modified:** See Phase 3.1 SUMMARY.md
- **Verification:** Current `dlp-server/src/siem_connector.rs` has zero `SPLUNK_HEC_*`/`ELK_*`/`from_env` references (grep returns zero hits).
- **Committed in:** `8911669` (Phase 3.1 feature)

---

**Total deviations:** 1 (config mechanism superseded — not a bug, an intentional refinement)
**Impact on plan:** Neutral — Phase 3's **foundation work** (AppState + handler refactor + background relay plumbing) is fully intact and depended on by Phase 3.1 and later phases. Only the config-loading half was replaced.

## Issues Encountered

- None during Phase 3 execution itself. The supersession was a forward-looking decision in Phase 3.1's discuss step, not a defect in Phase 3's implementation.

## Next Phase Readiness

- `AppState` is now the canonical state type — Phase 4 (alert router), Phase 5 (policy sync), Phase 6 (config push), Phase 9 (admin audit logging) can all extend it rather than adding new extractors.
- Background relay pattern is proven in `audit_store::ingest_events` — alert router (Phase 4) should use the same `tokio::spawn` fire-and-forget shape.
- **Warning for Phase 4 and Phase 6 executors:** those phases currently have PLAN.md files prescribing env-var loading. Per the Phase 3.1 decision, they must migrate to DB-backed config. See `.planning/phases/03.1-siem-config-in-db/CONTEXT.md` for the scope guidance.

---
*Phase: 03-wire-siem-connector-into-server-startup*
*Superseded-by: 03.1-siem-config-in-db (config loading only)*
*Completed: 2026-04-10*
