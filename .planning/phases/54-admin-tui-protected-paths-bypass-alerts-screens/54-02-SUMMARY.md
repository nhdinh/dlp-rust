---
phase: 54-admin-tui-protected-paths-bypass-alerts-screens
plan: 02
subsystem: dlp-admin-cli
milestone: v0.10.0
completed: "2026-05-28T03:52:57Z"
duration: 299
tasks: 3
task_commits:
  - task: "Task 1-3: Add 7 EngineClient methods + unit tests"
    hash: c4daa43
    files:
      - dlp-admin-cli/src/client.rs
tags:
  - client
  - http
  - protected-paths
  - bypass-alerts
  - api-contract
key-decisions: []
---

# Phase 54 Plan 02: EngineClient HTTP Methods for Protected Paths + Bypass Alerts

**One-liner:** Added 7 typed HTTP client methods to `EngineClient` for the Protected Paths and Bypass Alerts admin TUI screens, with 9 unit tests and full doc comments.

## What Was Built

### Protected Paths API (5 methods)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `list_protected_paths` | GET /admin/protected-paths | Returns full list; TUI paginates client-side |
| `create_protected_path` | POST /admin/protected-paths | Creates manual protected path entry |
| `update_protected_path` | PUT /admin/protected-paths/{id} | Updates existing entry |
| `delete_protected_path` | DELETE /admin/protected-paths/{id} | Removes entry |
| `sync_protected_paths` | POST /admin/protected-paths/sync | Re-imports policy-derived paths from labels |

### Bypass Alerts API (2 methods)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `list_bypass_alerts` | GET /admin/bypass-alerts?limit=N&offset=N&severity=S&acknowledged=B | Paginated, filtered alert listing |
| `ack_bypass_alert` | POST /admin/bypass-alerts/{id}/ack | Acknowledges a single alert |

### Key Implementation Details

- All methods use `#[allow(dead_code)]` to suppress warnings until dispatch.rs calls them in Plans 03-05.
- `list_bypass_alerts` uses `urlencoding::encode()` for the severity parameter (follows existing `list_labels` pattern; mitigates T-54-04 query parameter injection).
- `ack_bypass_alert` uses the raw `self.inner.post()` + `self.apply_auth()` pattern (like `maintenance_enter`) because the generic `post<T, B>` helper requires a JSON response body, but ack returns empty 200.
- All methods have doc comments with endpoint, purpose, and error behavior.

## Tests

9 compilation/signature tests added in `#[cfg(test)] mod client_tests`:

- `list_protected_paths_method_exists`
- `create_protected_path_method_exists`
- `update_protected_path_method_exists`
- `delete_protected_path_method_exists`
- `sync_protected_paths_method_exists`
- `list_bypass_alerts_method_exists`
- `list_bypass_alerts_all_filters_none`
- `ack_bypass_alert_method_exists`
- `ack_bypass_alert_builds_correct_url`

All 9 tests pass. Total dlp-admin-cli tests: 148 (139 existing + 9 new).

## Quality Gates

| Gate | Result |
|------|--------|
| `cargo check -p dlp-admin-cli` | PASS (no warnings) |
| `cargo test -p dlp-admin-cli client_tests` | PASS (9/9) |
| `cargo clippy -p dlp-admin-cli -- -D warnings` | PASS |

## Deviations from Plan

None -- plan executed exactly as written.

## Auth Gates

None.

## Known Stubs

None.

## Threat Flags

None -- all security-relevant surface (query parameter encoding, auth header attachment) follows established patterns already threat-modeled in prior phases.

## Self-Check: PASSED

- [x] File `dlp-admin-cli/src/client.rs` exists and contains all 7 methods
- [x] Commit `c4daa43` exists in git log
- [x] All 9 tests pass
- [x] Clippy clean (-D warnings)
- [x] No compiler warnings
