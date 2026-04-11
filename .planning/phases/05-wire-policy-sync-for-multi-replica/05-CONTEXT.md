# Phase 5: Wire Policy Sync for Multi-Replica — Context

**Gathered:** 2026-04-11
**Status:** Ready for planning
**Source:** Discussion with user — single decision on replica config source.

<domain>
## Phase Boundary

Wire `PolicySyncer` into `dlp-server` startup and policy CRUD handlers so that
creating, updating, or deleting a policy via the admin API pushes the change to all
configured peer server replicas via HTTP PUT/DELETE on `PUT /policies/{id}` and
`DELETE /policies/{id}`.

In scope:
- New `policy_sync_config` DB table (mirror Phase 3.1 / Phase 4 pattern: single-row, CHECK id=1)
- Rewrite `PolicySyncer` to hold `Arc<Database>` and load replica URLs from DB on every sync call (hot-reload, same pattern as `SiemConnector` / `AlertRouter`)
- Add `AppState.syncer: PolicySyncer` field (or equivalent — planner decides whether to store in AppState or construct inline)
- `PUT /policies/{id}` handler calls `syncer.sync_policy(policy)` — fire-and-forget or awaited, planner decides (see gray areas below)
- `DELETE /policies/{id}` handler calls `syncer.delete_policy(id)` — same question
- `POST /policies` handler calls `syncer.sync_policy(policy)` after DB insert
- Configurable via `GET/PUT /admin/policy-sync-config` (JWT protected) — mirror Phase 4 TUI pattern if time permits; Phase 5 can ship server-side only with a future dlp-admin-cli screen

Out of scope:
- Full dlp-admin-cli TUI screen for policy sync config (defer to Phase 5.x or Phase 6 companion)
- Encryption of replica URLs stored in DB (same deferred key-management phase as other secrets)
- Agent-side policy fetch / polling (Phase 6 handles agent config distribution)

</domain>

<decisions>
## Implementation Decisions

### Replica config source — DB-backed, not env vars
- **D-01:** `PolicySyncer` reads replica URLs from a `policy_sync_config` SQLite table (single-row, CHECK id=1), not the `DLP_SERVER_REPLICAS` env var. Hot-reloads on every sync call — same pattern as Phase 3.1 (`siem_config`) and Phase 4 (`alert_router_config`).
- **D-02:** The `policy_sync_config` table has two columns: `id INTEGER PRIMARY KEY CHECK (id = 1)` and `replica_urls TEXT NOT NULL DEFAULT ''` (comma-separated, same format `PolicySyncer::from_env()` already parses). Seed row via `INSERT OR IGNORE INTO policy_sync_config (id) VALUES (1)`.
- **D-03:** Rewrite `PolicySyncer` from `from_env()` to `new(Arc<Database>)` + private `load_replicas()` helper. Delete `from_env()` and the existing unit tests that reference it.
- **D-04:** Update ROADMAP.md Phase 5 description: replace "Initialize PolicySyncer from env vars" with "Initialize PolicySyncer from policy_sync_config DB table".

### Partial failure handling — BEST-EFFORT, fire-and-forget spawn
- **D-05:** Sync to replicas is fire-and-forget (`tokio::spawn`, NOT awaited). Policy CRUD handlers return success immediately after DB write. Replica failures are logged at `warn` level. The local DB write is authoritative — admin API responses are never blocked by replica availability.
- **D-06:** The `sync_policy` / `delete_policy` futures are spawned in a background task inside each handler. Failures do not affect the HTTP response status.

### Manual sync trigger — skip for Phase 5
- **D-07:** No `POST /admin/policy-sync` endpoint in Phase 5. A future phase can add it if needed.

### Folded Todos
None — no matching todos from cross_reference_todos.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Reference implementations — mirror these patterns
- `.planning/phases/03.1-siem-config-in-db/PLAN.md` — structural template for DB-backed operator config with hot-reload
- `.planning/phases/04-wire-alert-router-into-server/04-01-PLAN.md` — most recent server-side wiring plan (AlertRouter into AppState + ingest path)
- `.planning/phases/04-wire-alert-router-into-server/04-CONTEXT.md` — DB schema pattern, hot-reload pattern, threat model decisions

### Current code to modify
- `dlp-server/src/policy_sync.rs` — rewrite `PolicySyncer` struct: add `db: Arc<Database>`, delete `from_env()`, add `load_replicas()`, update existing methods
- `dlp-server/src/db.rs` — add `policy_sync_config` table schema + seed + table-creation test
- `dlp-server/src/admin_api.rs` — add `sync_policy` background spawn in `create_policy` / `update_policy` / `delete_policy` handlers
- `dlp-server/src/lib.rs` — add `PolicySyncer` construction to `AppState` OR construct inline in admin_api (planner decides wiring approach)
- `dlp-server/src/main.rs` — construct `PolicySyncer::new(Arc::clone(&db))` and include in state if AppState field is added
- `ROADMAP.md` — update Phase 5 description from "env vars" to "policy_sync_config DB table"

### Project conventions
- `CLAUDE.md` §9 — Rust Coding Standards. No `.unwrap()` in production paths, `thiserror` for errors, `tracing` for logs, 100-char lines, 4-space indent.
- `.planning/REQUIREMENTS.md` — R-03 is the requirement this phase satisfies ("Policy changes propagate to peer servers listed in DLP_REPLICA_URLS").
- `.planning/STATE.md` — "operator config in DB, not env vars" is an established project decision (Phases 3.1, 4).

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `policy_sync.rs` already has `PolicySyncer` with `sync_policy(&Policy)` and `delete_policy(&str)` — implementation is complete, only wiring is missing
- `SiemConnector::new(Arc<Database>)` + `load_config()` private helper — the exact pattern to mirror for `PolicySyncer`
- `AlertRouter::new(Arc<Database>)` — most recent example of the DB-backed hot-reload pattern

### Established Patterns
- Hot-reload on every call (not cached) — consistent with Phases 3.1 and 4
- Fire-and-forget via `tokio::spawn` for async side-effects that must not block HTTP responses
- Single-row DB table with `CHECK (id = 1)` + `INSERT OR IGNORE` seed row
- `Arc<Database>` in struct, private loader method, `pub fn new(db: Arc<Database>)` constructor
- `SyncError` enum already defined in `policy_sync.rs` with `Http` and `ReplicaError` variants — still usable after rewrite

### Integration Points
- `create_policy` handler (line ~452 in `admin_api.rs`) — spawn sync after DB insert
- `update_policy` handler (line ~505 in `admin_api.rs`) — spawn sync after DB update
- `delete_policy` handler (line ~568 in `admin_api.rs`) — spawn sync after DB delete
- `main.rs` line ~154 — `AppState` construction; `PolicySyncer` needs to be added here or constructed in admin_api

</code_context>

<specifics>
## Specific Ideas

- "Update ROADMAP to remove env vars. Use DB instead." — user's explicit directive from discuss phase
- Fire-and-forget pattern matches existing Phase 4 alert routing and Phase 3 SIEM relay patterns
- Planner should check whether to add `PolicySyncer` to `AppState` or construct it inline in the handlers — both are valid; recommend checking how `SiemConnector` / `AlertRouter` were wired and mirror that approach

</specifics>

<deferred>
## Deferred Ideas

### PolicySyncConfig TUI screen
- A dlp-admin-cli screen for managing replica URLs (mirrors Phase 4 "Alert Config" screen). Low priority for Phase 5 server-side work. Can be added as Phase 5.x or combined with Phase 6.

### Manual sync trigger endpoint
- `POST /admin/policy-sync` to force a full re-sync of all policies to all replicas. Useful for recovering from network partitions. Skip for Phase 5 — DB config change propagation is implicit on next CRUD operation.

### Encryption of replica_urls at rest
- Same deferred key-management phase as other secret columns. Do NOT add encryption in Phase 5.

### Reviewed Todos (not folded)
None — no todos matched Phase 5 scope.

</deferred>

---

*Phase: 05-wire-policy-sync-for-multi-replica*
*Context gathered: 2026-04-11*
