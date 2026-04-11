# Phase 5: Policy Engine Separation — Context

**Gathered:** 2026-04-11
**Status:** Ready for planning
**Source:** Discussion — significant architectural pivot from symmetric peer model to separated policy engine.

<domain>
## Phase Boundary

Split `dlp-server` into two separate binaries to resolve consistency problems with the
symmetric peer model (concurrent writes → divergent state, ordering conflicts).

**`dlp-policy-engine`** — New binary. The single source of truth for all policies and
admin operations.

**`dlp-server`** — Refactored to be an evaluation replica only. No admin API.
Serves agent register/heartbeat and audit ingestion, evaluates against a local policy
cache, and does NOT own policy storage.

Architecture:

```
dlp-policy-engine          dlp-server (replica)
┌──────────────────┐       ┌─────────────────────┐
│ policies DB      │       │ agent_registry DB   │
│ siem_config DB   │       │ audit_store DB      │
│ alert_config DB  │       │ policies cache (eval)│
│ config_push DB   │       │                     │
└────────┬─────────┘       └──────────┬──────────┘
         │                             │
         │  push (PUT/DELETE /policies)│
         └──────────┐                 │
                    │                 │
                    ▼                 ▼
            [replicas receive policy updates]
```

In scope:
- **`dlp-policy-engine` binary** — new `dlp-policy-engine/` crate in the Cargo workspace
  - `src/main.rs` — server startup, CLI args (`--bind`, `--db`, `--log-level`)
  - `src/lib.rs` — `AppState { db, siem, alert, policy_syncer }`
  - Holds the policies DB + admin config DBs (SIEM, alerts, config_push)
  - Admin API: policy CRUD (`GET/POST/PUT/DELETE /policies`), SIEM config, alert config, config push, agent auth hash
  - On policy create/update/delete: push change to all known replicas via `PolicySyncer`
  - No agent comms (register, heartbeat, audit ingest) — replicas handle that

- **`dlp-server` refactor** — evaluation replica mode
  - Remove admin API routes entirely (policy CRUD, SIEM config, alert config, config push)
  - Add local `policies` table (writable, receives pushes from engine)
  - Policy evaluation uses local `policies` table (same `POST /audit/events` handler unchanged)
  - `GET /policies/{id}` returns from local cache (needed for eval consistency)
  - On startup, fetch full policy list from engine via `GET /policies` and populate local cache
  - `policy_cache_config` table: stores `engine_url` for the policy engine

- **`PolicySyncer` rewrite** — moved to policy engine side only
  - Owned by `dlp-policy-engine`
  - Reads replica URLs from `replica_urls` DB table (single-row, hot-reload on every push)
  - Pushes policy changes to all replicas after local DB write commits
  - Fire-and-forget (`tokio::spawn`), warn on failure

- **`policy_cache_config` table** — in dlp-server replica DB
  - `id INTEGER PRIMARY KEY CHECK (id = 1)`, `engine_url TEXT NOT NULL DEFAULT ''`
  - Set via new `PUT /admin/policy-engine-url` endpoint on the replica (JWT protected)
  - `GET /admin/policy-engine-url` to read it back
  - Replicas read this at startup to know where to sync from

- **Startup sync** — replicas fetch full policy list from engine on startup
  - `POST /audit/events` continues to evaluate locally (no engine dependency at eval time)
  - Engine outage does not block evaluation; replicas use cached policies

Out of scope:
- Active-active / leader election (single policy engine is assumed; HA election is a future phase)
- Replica-to-replica sync (engine is the only source of truth)
- dlp-admin-cli changes (Phase 5 server-side only; TUI changes for new engine vs replica distinction deferred)

</domain>

<decisions>
## Implementation Decisions

### Architecture — separated policy engine binary
- **D-01:** `dlp-policy-engine` is a separate Cargo workspace crate (`dlp-policy-engine/`). Not a feature flag or runtime mode of `dlp-server` — a separate binary with its own `main.rs` and `Cargo.toml`.
- **D-02:** `dlp-server` becomes an evaluation replica only. It does NOT serve the admin API (no policy CRUD, no SIEM config, no alert config, no config push). All admin operations are exclusively on `dlp-policy-engine`.
- **D-03:** `dlp-policy-engine` and `dlp-server` replicas do NOT share the same SQLite database file. Each has its own.

### dlp-policy-engine — scope
- **D-04:** `dlp-policy-engine` holds: policies DB + all admin config (SIEM, alerts, config_push). It owns the SIEM relay and alert routing (same as current `dlp-server`). It does NOT handle agent register/heartbeat/audit-ingest — replicas do.
- **D-05:** `dlp-policy-engine` has admin API routes: all policy CRUD, SIEM config, alert config, config push, agent auth hash, replica URL management (`GET/PUT /admin/replica-urls`). Mirrors what current `dlp-server` serves minus agent comms.
- **D-06:** `PolicySyncer` lives in `dlp-policy-engine` only. Replicas do NOT have it. On policy create/update/delete, `dlp-policy-engine` pushes to all replicas via `PolicySyncer::sync_policy()` / `PolicySyncer::delete_policy()`.

### dlp-server replica — refactor
- **D-07:** Remove from `dlp-server`: SIEM config routes (`GET/PUT /admin/siem-config`), alert config routes (`GET/PUT /admin/alert-config`, `POST /admin/alert-config/test`), config push routes, agent auth hash routes. These all move to `dlp-policy-engine`.
- **D-08:** `dlp-server` keeps: health/ready probes, agent register/heartbeat, audit ingest, `GET /policies`, `GET /policies/{id}` (local cache), `GET /audit/events` (query from local audit store).
- **D-09:** `dlp-server` adds a local `policies` table (same schema as engine's `policies` table). This is the evaluation cache. `POST /audit/events` evaluates against this local table.
- **D-10:** `dlp-server` evaluates policy locally. No forwarding to engine on each event — replicas must have a current policy cache. Engine outage does NOT block evaluation.

### Replica → engine sync (startup bootstrap)
- **D-11:** On `dlp-server` replica startup: fetch all policies from `GET /policies` on the configured engine URL. Clear and repopulate the local `policies` table. This is a blocking startup step — replica does not begin serving requests until cache is populated or engine fetch fails gracefully.
- **D-12:** Replicas read `engine_url` from their local `policy_cache_config` DB table (single-row, `CHECK (id = 1)`). DB-backed, not env var.

### Push protocol
- **D-13:** Engine pushes full policy JSON to replicas via `PUT /policies/{id}` (replica) and `DELETE /policies/{id}` (replica). Replicas accept these as writes to their local `policies` table. This is the same HTTP endpoint that currently exists in `admin_api.rs` — just restricted to replica-receiving role on `dlp-server`.

### PolicySyncer — DB-backed config
- **D-14:** `PolicySyncer` reads replica URLs from `replica_urls` DB table in `dlp-policy-engine`'s DB (single-row, CHECK id=1, `replica_urls TEXT NOT NULL DEFAULT ''`). Hot-reload on every push. Mirror Phase 3.1/4 pattern.
- **D-15:** `PolicySyncer::from_env()` is deleted. Replaced by `PolicySyncer::new(Arc<Database>)` + private `load_replicas()`.

### Admin API — replica URL management
- **D-16:** `dlp-policy-engine` serves `GET/PUT /admin/replica-urls` (JWT protected). `replica_urls` DB table stores comma-separated replica base URLs. Mirrors Phase 3.1/4 config pattern.

### Failure handling
- **D-17:** Replica sync (fire-and-forget `tokio::spawn`). Policy engine admin API responses are NEVER blocked by replica availability. Failures logged at `warn`. Local DB write on engine is authoritative.

### Folded Todos
None.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Architecture decisions
- `.planning/phases/05-wire-policy-sync-for-multi-replica/05-CONTEXT.md` (this file) — all Phase 5 decisions
- `.planning/REQUIREMENTS.md` — R-03 is the requirement this phase addresses

### Reference implementations to mirror
- `.planning/phases/03.1-siem-config-in-db/PLAN.md` — DB-backed operator config pattern
- `.planning/phases/04-wire-alert-router-into-server/04-01-PLAN.md` — most recent server-side wiring plan
- `dlp-server/src/policy_sync.rs` — existing `PolicySyncer` implementation (to be moved to `dlp-policy-engine`)
- `dlp-server/src/admin_api.rs` — current admin API surface (split between engine and replica)
- `dlp-server/src/lib.rs` — current `AppState` (engine adds `PolicySyncer`; replica drops admin routes)

### Current code to modify / create
- New `dlp-policy-engine/src/main.rs` — engine binary entry point
- New `dlp-policy-engine/src/lib.rs` — engine library with `AppState { db, siem, alert, policy_syncer }`
- New `dlp-policy-engine/Cargo.toml` — new workspace member
- `dlp-server/src/lib.rs` — remove admin routes, add `policies` table, `policy_cache_config` table
- `dlp-server/src/db.rs` — add `policies` table schema (if not exists), `policy_cache_config` schema
- `dlp-server/src/admin_api.rs` — strip admin API routes, keep agent comms + local policy read
- `dlp-server/src/main.rs` — add startup bootstrap: fetch policies from engine, populate local cache
- `dlp-policy-engine/src/policy_sync.rs` — rewrite from `from_env()` to `new(Arc<Database>)`
- `dlp-policy-engine/src/db.rs` — add `replica_urls` table schema + seed

### Project conventions
- `CLAUDE.md` §9 — Rust Coding Standards
- `.planning/STATE.md` — "operator config in DB, not env vars" confirmed again

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `policy_sync.rs` existing implementation — moved to `dlp-policy-engine`, rewritten to DB-backed config
- `SiemConnector::new(Arc<Database>)` / `AlertRouter::new(Arc<Database>)` — pattern to mirror in `dlp-policy-engine`
- `POST /audit/events` handler in `dlp-server` — stays on replica, evaluates against local `policies` table unchanged

### What needs significant change
- `dlp-server/src/main.rs` — currently builds admin router; needs refactor to evaluation-replica startup
- `dlp-server/src/admin_api.rs` — most routes removed; a significant portion of the file is deleted
- `dlp-server/src/lib.rs` — `AppState` shrinks; admin fields removed
- New binary scaffolding for `dlp-policy-engine` — Cargo workspace entry, main.rs, lib.rs

### Integration Points
- `dlp-policy-engine`: replica push on policy CRUD → `PUT /policies/{id}` on replica
- `dlp-server` replica: `GET /policies/{id}` accepts engine push writes to local cache
- `dlp-server` startup: `GET /policies` on engine → populate local `policies` table

</code_context>

<specifics>
## Specific Ideas

- "In case there many replicas of dlp-server, I think we need to separate the policy-engine again. So the policy-engine will be single-source-of-truth that manage all the policies."
- All three recommended options confirmed by user: separate binary, evaluation replicas only, push from engine, separate DB files, policies only (not all admin config), writable policies table on replicas, DB-backed engine URL on replicas
- Planner should handle the significant refactor of `dlp-server` — removing admin API routes is non-trivial; suggest a wave-based plan that deletes routes first, then adds replica-specific logic

</specifics>

<deferred>
## Deferred Ideas

### HA / leader election for policy engine
- Single policy engine is a single point of failure in Phase 5. A future phase adds leader election (Raft or similar) or hot standby. Do NOT add in Phase 5.

### Replica-to-replica failover
- If one replica goes down and comes back online, it fetches from engine on startup (D-11). If the engine goes down, replicas continue evaluating with stale cache. Future phase: staleness detection + forced re-fetch.

### dlp-admin-cli changes
- TUI needs to know whether it's connecting to a policy engine or a replica. Phase 5 server-side only; TUI changes deferred to Phase 5.x or combined with Phase 6.

### Config push on replicas
- `config_push` DB table and API currently live in `dlp-server`. Move to `dlp-policy-engine` alongside other admin config. Deferred to Phase 6 or Phase 5.x.

### Encryption of replica_urls / engine_url at rest
- Deferred key-management phase (same as other secret columns in Phase 3.1/4).

### Reviewed Todos (not folded)
None.

</deferred>

---

*Phase: 05-wire-policy-sync-for-multi-replica*
*Context gathered: 2026-04-11 (architectural pivot from symmetric peer to separated policy engine)*
