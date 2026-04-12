---
phase: 06-wire-config-push-for-agent-config-distribution
plan: "01"
subsystem: dlp-server
tags: [agent-config, db, admin-api, rest, tdd]
dependency_graph:
  requires: []
  provides:
    - global_agent_config DB table with seed row
    - agent_config_overrides DB table with FK to agents
    - AgentConfigPayload struct (monitored_paths, heartbeat_interval_secs, offline_cache_enabled)
    - GET /agent-config/:id public endpoint (override-then-global fallback)
    - GET/PUT /admin/agent-config protected endpoints (global default)
    - GET/PUT/DELETE /admin/agent-config/:agent_id protected endpoints (per-agent override)
  affects:
    - dlp-server/src/db.rs
    - dlp-server/src/admin_api.rs
    - dlp-server/src/lib.rs
tech_stack:
  added: []
  patterns:
    - Single-row table with CHECK (id = 1) and INSERT OR IGNORE seed (same as siem_config / alert_router_config)
    - Multi-row override table with TEXT PRIMARY KEY and FK ON DELETE CASCADE
    - tokio::task::spawn_blocking for all rusqlite calls
    - i64 -> u64 conversion for heartbeat_interval_secs (rusqlite INTEGER limitation)
    - row.get::<_, i64>(n)? != 0 for bool columns
    - serde_json::to_string / from_str for monitored_paths JSON TEXT column
key_files:
  created: []
  modified:
    - dlp-server/src/db.rs
    - dlp-server/src/admin_api.rs
    - dlp-server/src/lib.rs
  deleted:
    - dlp-server/src/config_push.rs
decisions:
  - "Deleted config_push.rs: server-push model is not viable (agents have no HTTP listener); poll model adopted instead"
  - "AgentConfigPayload named with Payload suffix to avoid collision with dlp-agent AgentConfig struct"
  - "parse_agent_config_row propagates JSON parse error via InvalidParameterName rather than silently defaulting"
metrics:
  duration: "10 minutes"
  completed_date: "2026-04-12T14:23:10Z"
  tasks_completed: 2
  tasks_total: 2
  files_modified: 3
  files_deleted: 1
requirements:
  - R-04
---

# Phase 06 Plan 01: Server-Side Agent Config Distribution Summary

Server-side DB tables, admin API endpoints, and public config resolution endpoint for poll-based agent config distribution. Two new SQLite tables, six new HTTP handlers, `AgentConfigPayload` struct, and `config_push.rs` deleted.

## What Was Built

### DB Layer (dlp-server/src/db.rs)

Two new tables added inside `init_tables()` execute_batch:

- `global_agent_config`: single-row default with `CHECK (id = 1)` constraint, seeded with `INSERT OR IGNORE`. Defaults: `monitored_paths='[]'`, `heartbeat_interval_secs=30`, `offline_cache_enabled=1`.
- `agent_config_overrides`: multi-row table keyed by `agent_id` (TEXT PRIMARY KEY, FK to `agents.agent_id` ON DELETE CASCADE). No seed row — rows created by PUT handler.

### API Layer (dlp-server/src/admin_api.rs)

`AgentConfigPayload` struct added (after `AlertRouterConfigPayload`) with three fields:
- `monitored_paths: Vec<String>`
- `heartbeat_interval_secs: u64`
- `offline_cache_enabled: bool`

`parse_agent_config_row()` private helper — parses the three-column query result, propagates JSON errors rather than silently defaulting.

Six handler functions:

| Handler | Route | Auth |
|---------|-------|------|
| `get_agent_config_for_agent` | `GET /agent-config/:id` | Public |
| `get_global_agent_config_handler` | `GET /admin/agent-config` | JWT |
| `update_global_agent_config_handler` | `PUT /admin/agent-config` | JWT |
| `get_agent_config_override_handler` | `GET /admin/agent-config/:agent_id` | JWT |
| `update_agent_config_override_handler` | `PUT /admin/agent-config/:agent_id` | JWT |
| `delete_agent_config_override_handler` | `DELETE /admin/agent-config/:agent_id` | JWT |

`heartbeat_interval_secs < 10` rejected with `AppError::BadRequest` on all PUT handlers.

### Deleted

`dlp-server/src/config_push.rs` — server-push model is architecturally incompatible with the decided poll model. `pub mod config_push` removed from `lib.rs`.

## Tests Added (10 new)

### db.rs
- `test_tables_created` — extended to assert `global_agent_config` and `agent_config_overrides` exist
- `test_global_agent_config_seed_row` — verifies seed row defaults after `Database::open(":memory:")`

### admin_api.rs
- `test_agent_config_payload_serde` — AgentConfigPayload round-trips through serde_json
- `test_get_agent_config_falls_back_to_global` — GET /agent-config/{id} returns global defaults when no override
- `test_put_global_agent_config` — PUT sets global config, GET confirms updated values
- `test_put_global_config_rejects_low_interval` — heartbeat_interval_secs=5 returns 400
- `test_put_agent_config_override` — PUT /admin/agent-config/{id} upserts; GET /agent-config/{id} returns override
- `test_delete_agent_config_override` — DELETE removes override; GET falls back to global
- `test_get_agent_config_requires_no_auth` — GET /agent-config/{id} returns 200 without JWT
- `test_put_admin_agent_config_requires_jwt` — PUT /admin/agent-config returns 401 without JWT

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed unused `delete` import from axum::routing**
- **Found during:** Task 2 clippy check
- **Issue:** `delete` was imported from `axum::routing` but all route method chaining uses `.delete()` on the MethodRouter (not the standalone `delete()` function). Clippy `-D warnings` fails on unused import.
- **Fix:** Removed `delete` from the import line, leaving `get, post, put`.
- **Files modified:** `dlp-server/src/admin_api.rs`
- **Commit:** 2ddecea

**2. [Rule 3 - Formatting] Applied rustfmt before commit**
- **Found during:** Task 2 pre-commit `cargo fmt --check`
- **Issue:** Several lines exceeded 100 chars (method chains, tuple type annotation in test).
- **Fix:** `cargo fmt -p dlp-server` applied automatically.
- **Files modified:** `dlp-server/src/admin_api.rs`, `dlp-server/src/db.rs`
- **Commit:** 2ddecea

**3. [Rule 3 - Blocking] SQL comment with backslashes caused tokenizer error**
- **Found during:** Task 1 GREEN phase compile
- **Issue:** The SQL batch string contained `'["C:\\Data\\"]'` in a comment. Rust string literal tokenizer treated the backslashes as escape sequences inside the raw SQL string.
- **Fix:** Simplified comment to "monitored_paths is stored as a JSON text array" (no example with backslashes).
- **Files modified:** `dlp-server/src/db.rs`
- **Commit:** aeb2880

## Known Stubs

None — all endpoints are fully wired with real DB queries. No placeholder data.

## Threat Flags

No new threat surface beyond what is documented in the plan's threat model. All PUT/DELETE admin endpoints are correctly placed behind `require_auth` middleware in `protected_routes`. The public `GET /agent-config/:id` is intentionally unauthenticated per CONTEXT.md design decision T-06-01.

## Self-Check

### Files exist
- `dlp-server/src/admin_api.rs` — FOUND (modified)
- `dlp-server/src/db.rs` — FOUND (modified)
- `dlp-server/src/lib.rs` — FOUND (modified)
- `dlp-server/src/config_push.rs` — confirmed DELETED

### Commits exist
- `aeb2880` — Task 1: delete config_push.rs, add DB tables, AgentConfigPayload struct
- `2ddecea` — Task 2: add agent config handlers and route wiring

## Self-Check: PASSED
