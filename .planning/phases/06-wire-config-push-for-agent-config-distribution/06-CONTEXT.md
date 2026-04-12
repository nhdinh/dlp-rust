# Phase 6: Wire Config Push for Agent Config Distribution — Context

**Gathered:** 2026-04-12
**Status:** Ready for planning
**Source:** /gsd-discuss-phase

<domain>
## Phase Boundary

Deliver a DB-backed admin API for managing agent configuration (monitored paths,
heartbeat interval, offline cache enabled), with per-agent override support that
falls back to a global default. Agents poll a dedicated server endpoint on a
configurable timer and persist received config to their local TOML file.

This phase does NOT include `server_url` in the pushed config (self-referential —
a bad push would cut off the agent), UI TUI screens, or rate limiting (separate phases).

</domain>

<decisions>
## Implementation Decisions

### 1. Delivery Model — Separate Poll Endpoint (Option B)

Agent calls `GET /agent-config/{id}` on a timer (not bundled into the heartbeat
response, and not server-push). The server returns the resolved config for that
agent (per-agent override if set, otherwise global default).

**Why not heartbeat response:** Keeps heartbeat semantics clean (presence signal,
not config carrier). Easier to reason about, test, and version independently.

**Why not config_push.rs server-push:** Agents have no HTTP listener — the existing
`config_push.rs` module's push model is not viable without adding an agent HTTP server.
The `config_push.rs` module can be retained as dead code or removed; the planner should
decide whether to delete it or stub it out cleanly.

### 2. Config Storage — Per-Agent with Global Default Fallback

New DB tables:
- `global_agent_config` — single-row default applied to all agents unless overridden.
- `agent_config_overrides` — per-agent rows keyed by `agent_id`. When present,
  overrides the global default for that agent. When absent, agent gets global default.

Admin API exposes:
- `GET/PUT /admin/agent-config` — read/write the global default.
- `GET/PUT /admin/agent-config/{agent_id}` — read/write per-agent override.
- `DELETE /admin/agent-config/{agent_id}` — remove override, agent falls back to global default.

This mirrors the siem_config / alert_router_config DB pattern established in Phases 3.1 and 4.

### 3. Configurable Fields

Only these three fields are in scope:

| Field | Type | Notes |
|-------|------|-------|
| `monitored_paths` | `Vec<String>` | Directory paths the agent monitors |
| `heartbeat_interval_secs` | `u64` | How often agent sends heartbeat (min: 10s) |
| `offline_cache_enabled` | `bool` | Whether agent caches events offline when server unreachable |

`server_url` is explicitly excluded — a bad push makes the agent unreachable with
no recovery path without manual TOML edit.

### 4. Agent-Side Persistence — Write Back to agent-config.toml

When the agent receives a config update from `GET /agent-config/{id}`:
1. Compare received config against current in-memory config.
2. If different, apply in-memory immediately (hot-reload).
3. Write the updated values back to `C:\ProgramData\DLP\agent-config.toml` so
   config survives agent restarts without requiring a re-poll.
4. Log the config change at `INFO` level (fields changed, not values — don't log
   path contents that could be sensitive).

The poll timer uses `heartbeat_interval_secs` from the *previously applied* config
(not the newly received one) to avoid a race where reducing the interval causes
immediate tight loops.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase requirement
- `.planning/ROADMAP.md` — Phase 6 section (R-04 requirement, UAT criteria, file list)
- `.planning/REQUIREMENTS.md` — R-04 full text

### Existing modules (read before modifying)
- `dlp-server/src/config_push.rs` — Existing push module; planner must decide to delete or stub cleanly
- `dlp-server/src/admin_api.rs` — All existing routes and handler patterns (follow exactly)
- `dlp-server/src/db.rs` — DB init and `CREATE TABLE` patterns (add new tables here)
- `dlp-server/src/agent_registry.rs` — Agent heartbeat and registry patterns
- `dlp-agent/src/server_client.rs` — Agent HTTP client patterns (add config poll here)
- `dlp-agent/src/config.rs` — `AgentConfig` struct and TOML load/save pattern
- `dlp-agent/src/service.rs` — Heartbeat loop wiring (add config poll timer alongside)

### Prior-phase patterns to mirror
- `.planning/phases/03.1-siem-config-in-db/SUMMARY.md` — DB-backed config with GET/PUT admin API
- `.planning/phases/04-wire-alert-router-into-server/04-CONTEXT.md` — Alert config pattern (same shape)

</canonical_refs>

<specifics>
## Specific Implementation Notes

- The `global_agent_config` table should be a single-row table with a `CHECK (id = 1)`
  constraint, seeded on first DB init — same pattern as `siem_config` and
  `alert_router_config`.
- `agent_config_overrides` is a multi-row table keyed by `agent_id` (TEXT PRIMARY KEY,
  foreign-keyed to `agents.agent_id`).
- The `GET /agent-config/{id}` endpoint is **unauthenticated** (agent calls it without
  JWT — agents use `agent_id` as their identity, not admin JWT). Place it in `public_routes`
  in `admin_router()`.
- The admin management endpoints (`GET/PUT /admin/agent-config`, etc.) are
  **JWT-protected** — place in `protected_routes`.
- Config poll interval on the agent side: default to `heartbeat_interval_secs` seconds
  (same cadence as heartbeat), but run as a separate independent timer so heartbeat
  and config poll don't block each other.

</specifics>

<deferred>
## Deferred Ideas

- TUI screen in dlp-admin-cli for managing agent config — separate phase
- `server_url` as a pushable field — not in scope (self-referential risk)
- Push notification / webhooks to trigger immediate config refresh — not in scope
- Rate limiting on `/agent-config/{id}` endpoint — covered by Phase 7 (rate limiting)

</deferred>

---

*Phase: 06-wire-config-push-for-agent-config-distribution*
*Context gathered: 2026-04-12 via /gsd-discuss-phase*
