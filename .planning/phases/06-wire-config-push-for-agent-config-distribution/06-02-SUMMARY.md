---
phase: 06-wire-config-push-for-agent-config-distribution
plan: "02"
subsystem: dlp-agent
tags: [agent-config, toml, poll-loop, server-client, tdd]
dependency_graph:
  requires:
    - 06-01 (AgentConfigPayload struct, GET /agent-config/:id endpoint)
  provides:
    - AgentConfig.heartbeat_interval_secs (Option<u64>, serde(default))
    - AgentConfig.offline_cache_enabled (Option<bool>, serde(default))
    - AgentConfig::save() TOML write-back method
    - ServerClient::fetch_agent_config() GET /agent-config/{agent_id}
    - AgentConfigPayload struct in dlp-agent crate (agent-side mirror)
    - config_poll_loop async fn with diff, TOML persist, re-arm logic
    - config_poll_handle spawned in run_loop alongside heartbeat
  affects:
    - dlp-agent/src/config.rs
    - dlp-agent/src/server_client.rs
    - dlp-agent/src/service.rs
    - dlp-agent/tests/comprehensive.rs
tech_stack:
  added: []
  patterns:
    - Option<T> with serde(default) for backwards-compatible TOML fields
    - anyhow::Context for save() error propagation at application boundary
    - tokio::time::interval + select! for shutdown-aware poll timer
    - Arc<parking_lot::Mutex<AgentConfig>> for shared config across tasks
    - Previous-interval re-arm pattern (T-06-08 DoS mitigation)
    - Field-name-only logging (T-06-09 info disclosure mitigation)
key_files:
  created: []
  modified:
    - dlp-agent/src/config.rs
    - dlp-agent/src/server_client.rs
    - dlp-agent/src/service.rs
    - dlp-agent/tests/comprehensive.rs
decisions:
  - "AgentConfigPayload defined independently in agent crate — no shared crate dependency needed (HTTP/JSON boundary)"
  - "config_arc wraps agent_config before InterceptionEngine construction; engine gets clone (paths fixed at startup)"
  - "server_client cloned before move into offline_manager to give poll loop its own handle"
  - "Poll timer re-arms with current_interval captured pre-update, preventing tight-loop on interval reduction"
metrics:
  duration: "12 minutes"
  completed_date: "2026-04-12T15:00:00Z"
  tasks_completed: 3
  tasks_total: 3
  files_modified: 4
  files_deleted: 0
requirements:
  - R-04
---

# Phase 06 Plan 02: Agent-Side Config Polling Summary

Agent-side config polling: new `AgentConfig` fields, TOML persistence via `save()`, `fetch_agent_config()` on `ServerClient`, and `config_poll_loop` wired into `run_loop` alongside heartbeat.

## What Was Built

### Config Layer (dlp-agent/src/config.rs)

Two new optional fields added to `AgentConfig` after `excluded_paths`, before `machine_name`:

- `heartbeat_interval_secs: Option<u64>` with `#[serde(default)]` — `None` means use compiled default (30 s)
- `offline_cache_enabled: Option<bool>` with `#[serde(default)]` — `None` means default to `true`

`Option<T>` with `serde(default)` ensures existing TOML files without these fields still parse correctly (backwards compatibility). The poll loop treats `None` as "use compiled default."

`save()` method added using `toml::to_string` + `std::fs::write` with `anyhow::Context` for error messages. `machine_name` is `#[serde(skip)]` so it is never written. `server_url` is preserved through save/load cycles.

`use anyhow::Context` added at the top of the file.

### Server Client Layer (dlp-agent/src/server_client.rs)

`AgentConfigPayload` struct added (after `ServerClientError` definitions):
- `monitored_paths: Vec<String>`
- `heartbeat_interval_secs: u64`
- `offline_cache_enabled: bool`

This is the agent-side mirror of `dlp_server::admin_api::AgentConfigPayload`. The two types are defined independently — no shared crate dependency. They communicate over HTTP/JSON.

`fetch_agent_config()` async method added to `ServerClient`:
- Calls `GET {base_url}/agent-config/{agent_id}`
- Returns `ServerClientError::ServerError` on non-2xx responses
- Returns `ServerClientError::Http` on network failures
- Callers log errors and retain current config (best-effort)

`Serialize` added to serde imports (was `Deserialize` only).

### Service Layer (dlp-agent/src/service.rs)

`config_poll_loop` added as a module-level async fn:

| Step | Behavior |
|------|----------|
| Init | Read `heartbeat_interval_secs` from config (default 30 s), skip first immediate tick |
| Each tick | Capture `current_interval` before any update (T-06-08 re-arm safety) |
| Fetch | `fetch_agent_config()` — on error, log at DEBUG and continue |
| Diff | Compare 3 fields: `monitored_paths`, `heartbeat_interval_secs`, `offline_cache_enabled` |
| Apply | Update in-memory `Arc<Mutex<AgentConfig>>` for changed fields only |
| Persist | Call `cfg.save(DEFAULT_CONFIG_PATH)` on any change |
| Log | `info!(fields = ?changed_fields, ...)` — field names only, no values (T-06-09) |
| Re-arm | `tokio::time::interval(current_interval)` — not the new interval |
| Shutdown | `shutdown_rx.changed()` arm in `select!` returns immediately |

`run_loop` changes:
- `server_client` cloned into `server_client_for_config` before the move into `offline_manager`
- `config_arc = Arc::new(parking_lot::Mutex::new(agent_config.clone()))` created before `InterceptionEngine` construction
- `(config_shutdown_tx, config_shutdown_rx)` watch channel added
- `_config_poll_handle` spawned if `server_client_for_config.is_some()`
- Graceful shutdown: `config_shutdown_tx.send(true)` + `h.await` in shutdown path

## Tests Added (7 new)

### config.rs (5 new)
- `test_agent_config_new_fields_default` — `AgentConfig::default()` has `None` for both new fields
- `test_agent_config_new_fields_deserialize` — TOML with explicit values deserializes correctly
- `test_agent_config_save_roundtrip` — all fields survive save()/load() cycle; machine_name excluded
- `test_agent_config_save_preserves_server_url` — server_url present in written TOML
- `test_agent_config_backwards_compatible` — old TOML without new fields still parses

### server_client.rs (2 new)
- `test_agent_config_payload_serde` — `AgentConfigPayload` round-trips through serde_json
- `test_fetch_agent_config_unreachable` — error returned when server unreachable on loopback port

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing test update] comprehensive.rs struct literals updated**
- **Found during:** Task 1 GREEN compile
- **Issue:** `dlp-agent/tests/comprehensive.rs` had two `AgentConfig { ... }` struct literals without the new `heartbeat_interval_secs` and `offline_cache_enabled` fields, causing E0063 compile errors.
- **Fix:** Added `heartbeat_interval_secs: None, offline_cache_enabled: None` to both struct literals.
- **Files modified:** `dlp-agent/tests/comprehensive.rs`
- **Commit:** 7bde2cc

**2. [Rule 3 - Formatting] rustfmt applied to server_client.rs**
- **Found during:** Task 3 pre-commit `cargo fmt --check`
- **Issue:** The `resp.text().await.unwrap_or_else(...)` chain in `fetch_agent_config` exceeded 100 chars.
- **Fix:** `cargo fmt -p dlp-agent` applied automatically.
- **Files modified:** `dlp-agent/src/server_client.rs`
- **Commit:** 35565db

## Known Stubs

None — all three fields are fully wired. Config changes are persisted to TOML immediately on detection. `monitored_paths` changes take effect on next restart (InterceptionEngine paths fixed at construction; live hot-reload is a deferred follow-on per RESEARCH.md).

## Threat Flags

No new threat surface introduced beyond the plan's documented threat model. The `config_poll_loop` accesses `DEFAULT_CONFIG_PATH` for writes — this path is admin-only ACL and the agent runs as SYSTEM (T-06-07 accepted). Field-name-only logging confirmed in `info!(fields = ?changed_fields, ...)` — no path values logged (T-06-09 mitigated). Poll timer re-arms on `current_interval` not `payload.heartbeat_interval_secs` (T-06-08 mitigated).

## Self-Check

### Files exist
- `dlp-agent/src/config.rs` — FOUND (modified)
- `dlp-agent/src/server_client.rs` — FOUND (modified)
- `dlp-agent/src/service.rs` — FOUND (modified)
- `dlp-agent/tests/comprehensive.rs` — FOUND (modified)

### Commits exist
- `7bde2cc` — Task 1: add heartbeat_interval_secs, offline_cache_enabled, save()
- `1aa8328` — Task 2: add AgentConfigPayload, fetch_agent_config()
- `35565db` — Task 3: wire config_poll_loop into run_loop

## Self-Check: PASSED
