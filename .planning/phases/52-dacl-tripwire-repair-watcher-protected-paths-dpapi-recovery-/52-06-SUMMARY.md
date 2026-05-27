---
phase: 52-dacl-tripwire-repair-watcher-protected-paths-dpapi-recovery-
plan: 06
type: execute
subsystem: dlp-server + dlp-agent
completed_date: "2026-05-27"
duration_minutes: 120
tasks_completed: 2
total_tasks: 2
---

# Phase 52 Plan 06: Admin API + Agent Config for Protected Paths

## Summary

Implemented the admin API routes for protected paths, extended the agent config payload with `protected_paths`, and wired the `ProtectedPathsRepository` into `AppState`. This plan builds on the schema and repository from Plan 52-03.

## What Was Built

### Task 1: Admin API Routes for Protected Paths

- **6 CRUD handlers** in `dlp-server/src/admin_api.rs`:
  - `list_protected_paths_handler` — GET /admin/protected-paths
  - `get_protected_path_handler` — GET /admin/protected-paths/{id}
  - `create_protected_path_handler` — POST /admin/protected-paths
  - `update_protected_path_handler` — PUT /admin/protected-paths/{id}
  - `delete_protected_path_handler` — DELETE /admin/protected-paths/{id}
  - `sync_protected_paths_handler` — POST /admin/protected-paths/sync

- **Windows API path validation** using `GetFullPathNameW` (addresses HIGH review concern):
  - Rejects UNC paths (`\\server\share`)
  - Rejects extended-length paths (`\\?\...`)
  - Rejects volume GUID paths (`\\?\Volume{...}`)
  - Rejects 8.3 short names (containing `~`)
  - Requires absolute drive path (`X:\...`)

- **Route registration** in `admin_router()` with JWT protection

### Task 2: Agent Config Payload Extension + AppState Wiring

- **Server-side** `AgentConfigPayload` extended with `protected_paths: Vec<ProtectedPathConfig>`
- **Agent-side** `AgentConfigPayload` and `AgentConfig` extended with same field
- **`get_agent_config_for_agent()`** populates `protected_paths` from `ProtectedPathsRepository::list_all()`
- **`AppState`** extended with `protected_paths: Arc<ProtectedPathsRepository>`
- **`main.rs`** constructs `AppState` with the new field
- All **16 test AppState initializers** updated across `admin_api.rs`, integration tests, `lib.rs`, and `dlp-e2e`

## Files Modified

| File | Changes |
|------|---------|
| `dlp-server/src/admin_api.rs` | +808 lines: DTOs, handlers, validation, routes, tests |
| `dlp-server/src/lib.rs` | `AppState.protected_paths` field + Debug impl |
| `dlp-server/src/main.rs` | AppState construction with `protected_paths` |
| `dlp-server/Cargo.toml` | Added `Win32_Storage_FileSystem` feature |
| `dlp-agent/src/server_client.rs` | `ProtectedPathConfig` struct + `protected_paths` field |
| `dlp-agent/src/config.rs` | `AgentConfig.protected_paths` field |
| `dlp-agent/src/service.rs` | Test helper updated |
| `dlp-e2e/src/lib.rs` | AppState construction updated |
| `dlp-server/tests/*.rs` (7 files) | AppState construction updated |

## Test Results

- **dlp-server**: 520 tests passed, 3 ignored
- **dlp-agent**: All tests passed
- **5 new tests** for protected paths:
  - `test_protected_paths_crud_roundtrip`
  - `test_protected_paths_validation_rejects_invalid_paths`
  - `test_protected_paths_duplicate_returns_409`
  - `test_protected_paths_get_not_found_returns_404`
  - `test_protected_paths_agent_config_includes_protected_paths`

## Quality Gates

- [x] `cargo test -p dlp-server --lib` passes (520 tests)
- [x] `cargo test -p dlp-agent` passes
- [x] `cargo build --workspace` succeeds
- [x] `cargo clippy --workspace -- -D warnings` clean

## Deviations from Plan

None. Plan executed exactly as written.

## Commit

- `58dd9b5`: feat(52-06): admin API + agent config for protected paths
