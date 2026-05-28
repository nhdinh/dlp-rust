---
phase: 54-admin-tui-protected-paths-bypass-alerts-screens
plan: 04
subsystem: dlp-admin-cli
completed_date: 2026-05-28
duration_minutes: 35
tags: [tui, bypass-alerts, ratatui, optimistic-ui]
dependency_graph:
  requires: [54-01, 54-02, 54-03]
  provides: [UX-02]
  affects: [dlp-admin-cli]
tech_stack:
  added: []
  patterns: [two-phase-read-then-mutate, optimistic-ui, stable-id-rollback]
key_files:
  created: []
  modified:
    - dlp-admin-cli/src/screens/dispatch.rs
    - dlp-admin-cli/src/screens/render.rs
decisions:
  - "Pending ack tracking uses HashSet<i64> to prevent double-ack during in-flight server calls"
  - "Optimistic ack revert uses stable ID lookup (find by id) instead of index position to survive list mutations"
  - "Filter change and hide-ack toggle reset to page 0 and selected 0 to prevent invalid selection state"
  - "BypassAlertDetail returns to list with default filters (All, show ack'd) since filter state is not preserved across popup"
  - "Relative time uses coarse buckets (<1m, Xm, Xh, Xd) for recent alerts; falls back to raw ISO-8601 for older entries"
  - "draw_bypass_alert_list uses #[allow(clippy::too_many_arguments)] matching existing render function convention"
metrics:
  duration: 35m
  tasks_completed: 3
  tests_added: 12
  tests_passing: 184
---

# Phase 54 Plan 04: BypassAlertList Screen Summary

## One-liner

Complete BypassAlertList TUI screen with optimistic ack, severity/ack filtering, pagination, and detail popup — delivering UX-02 requirement.

## What Was Built

### Task 1: Dispatch Handler + Action Helpers

**File:** `dlp-admin-cli/src/screens/dispatch.rs`

- **`handle_bypass_alert_list`**: Full key-event handler supporting:
  - `Up/Down` — navigate list
  - `a` — optimistic ack with stable ID rollback and `pending_ack_ids` double-ack prevention
  - `f` — cycle severity filter (All -> Crit -> Warn -> Info -> All), resets to page 0
  - `h` — toggle hide-acknowledged, resets to page 0
  - `r` — refresh current page
  - `PgUp/PgDn` — pagination
  - `Enter` — open BypassAlertDetail popup
  - `Esc` — return to SystemMenu at index 11

- **`handle_bypass_alert_detail`**: Enter/Esc both return to list (reloads with defaults)

- **`action_load_bypass_alert_list`**: Server pagination via `limit`/`offset`, constructs `BypassAlertList` screen with fresh `pending_ack_ids`

- **Menu wiring**: SystemMenu index 11 now calls real action (was stub)

### Task 2: Render Function + Detail Popup

**File:** `dlp-admin-cli/src/screens/render.rs`

- **`draw_bypass_alert_list`**: Table with 5 columns (Severity, Time, Image, File, Reason)
  - Severity badges: crit=Red+BOLD, warn=Yellow, info=Blue
  - Relative time formatting via `format_relative_time` (<1m, Xm, Xh, Xd)
  - Path truncation at 25 chars with `...` suffix
  - Human-friendly correlation reason mapping (NoHookJournal, OpMismatch, HookOverwritten)
  - Acknowledged rows dimmed with DarkGray fg
  - Title shows active filter suffixes and total count
  - Page info: "Page N of M (X total)"

- **`draw_bypass_alert_detail`**: Full-screen popup showing all 12 alert fields
  - SHA-256 truncated to 16 chars with `...` suffix
  - `file_object` displayed as raw hex string
  - Severity colored badge

- **`format_relative_time`**: ISO-8601 to coarse relative time converter

### Task 3: Unit Tests

**12 new tests** (6 dispatch + 6 render):

| Test | File | What It Verifies |
|------|------|-----------------|
| `handle_bypass_alert_list_esc_returns_to_system_menu` | dispatch.rs | Esc routes to SystemMenu(11) |
| `handle_bypass_alert_list_enter_opens_detail` | dispatch.rs | Enter opens detail popup |
| `handle_bypass_alert_list_ack_prevents_double_ack` | dispatch.rs | pending_ack_ids blocks second ack |
| `handle_bypass_alert_list_ack_already_ack_shows_info` | dispatch.rs | Already-acked shows info toast |
| `handle_bypass_alert_detail_enter_attempts_reload` | dispatch.rs | Enter attempts reload (error path in test) |
| `handle_bypass_alert_detail_esc_attempts_reload` | dispatch.rs | Esc attempts reload (error path in test) |
| `draw_bypass_alert_list_empty_renders` | render.rs | Empty state with correct message |
| `draw_bypass_alert_list_renders_severity_badge` | render.rs | Crit badge + human-friendly reason |
| `draw_bypass_alert_list_acknowledged_row_dimmed` | render.rs | Acknowledged row renders |
| `draw_bypass_alert_detail_renders_fields` | render.rs | All 12 fields present in detail |
| `format_relative_time_recent` | render.rs | <1m for current timestamp |
| `format_relative_time_invalid` | render.rs | Falls back to raw string on parse failure |

**Total dlp-admin-cli tests: 184 passing, 0 failed, 0 ignored.**

## Deviations from Plan

None — plan executed exactly as written.

## Threat Model Compliance

| Threat ID | Status | Verification |
|-----------|--------|-------------|
| T-54-09 (Tampering: optimistic UI not reverted) | Mitigated | Handler explicitly reverts `acknowledged` to false by stable ID and shows `StatusKind::Error` toast on server error |
| T-54-10 (Info Disclosure: alert detail paths) | Accepted | Paths shown to DLP admin who has full system access |
| T-54-11 (DoS: rapid ack spamming) | Accepted | Single POST per ack; no bulk ack in this phase |

## Commits

| Hash | Type | Description |
|------|------|-------------|
| b95a8e3 | feat | BypassAlertList dispatch handler + action helpers |
| e1e2943 | feat | BypassAlertList render function + detail popup |
| 6984913 | test | BypassAlertList dispatch + render unit tests |

## Self-Check: PASSED

- [x] `cargo test -p dlp-admin-cli` — 184 passed
- [x] `cargo clippy -p dlp-admin-cli -- -D warnings` — clean
- [x] `cargo check -p dlp-admin-cli` — no warnings
- [x] All modified files compile
- [x] Commit hashes verified in git log
