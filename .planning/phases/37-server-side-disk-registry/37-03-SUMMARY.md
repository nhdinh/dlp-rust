---
phase: 37
plan: 03
subsystem: agent-config
tags: [disk-registry, agent, config-poll, instance-id-map, serde, tdd, abac]
dependency_graph:
  requires:
    - AgentConfigPayload.disk_allowlist field (server-side, Plan 02)
    - DiskRegistryRepository.list_by_agent (Plan 01)
    - DiskEnumerator.instance_id_map (Phase 33)
    - AgentConfig.disk_allowlist (Phase 35)
  provides:
    - AgentConfigPayload.disk_allowlist field (agent-side mirror with #[serde(default)])
    - config_poll_loop diff + apply logic for disk_allowlist (D-03)
    - merge_disk_allowlist_into_map() with Pitfall 5 preservation
    - BusType::Deserialize forward-compatible (unknown strings -> Unknown)
  affects:
    - dlp-agent/src/server_client.rs (AgentConfigPayload extended)
    - dlp-agent/src/service.rs (config_poll_loop refactored + 5 tests)
    - dlp-common/src/disk.rs (BusType manual Deserialize impl)
    - dlp-agent/src/disk_enforcer.rs (pre-existing clippy fix)
tech_stack:
  added: []
  patterns:
    - Helper fn extract from macro body for testability (apply_payload_to_config)
    - DiskMergeData type alias to avoid clippy::type_complexity
    - Lock-order invariant: config mutex released BEFORE instance_id_map.write()
    - Pitfall 5 guard: preserve live-enumerated entries not in old allowlist
    - Custom Deserialize for BusType (forward-compatible unknown -> Unknown)
key_files:
  created: []
  modified:
    - dlp-agent/src/server_client.rs (850 lines before; ~960 lines after; +110)
    - dlp-agent/src/service.rs (1176 lines before; ~1650 lines after; +474)
    - dlp-common/src/disk.rs (+32 lines: manual Deserialize impl for BusType)
    - dlp-agent/src/disk_enforcer.rs (2 lines: map_or -> is_some_and)
decisions:
  - "apply_payload_to_config() extracted from do_poll! macro; returns (changed_fields, DiskMergeData) so tests can call it directly without a tokio runtime"
  - "DiskMergeData = Option<(HashSet<String>, Vec<DiskIdentity>)> type alias satisfies clippy::type_complexity"
  - "config mutex released BEFORE map.write() in do_poll! (T-37-13 lock-order invariant)"
  - "Custom Deserialize for BusType maps unknown strings to Unknown (Rule 2: forward-compatible for rolling deploys)"
  - "Pre-existing disk_enforcer.rs map_or -> is_some_and fix (Rule 1 auto-fix: blocked clippy -D warnings gate)"
metrics:
  duration: "15 minutes"
  completed: "2026-05-04"
  tasks_completed: 2
  files_changed: 4
---

# Phase 37 Plan 03: Agent-Side disk_allowlist Apply + instance_id_map Merge Summary

Closes the D-02/D-03 loop: agent-side AgentConfigPayload now mirrors the server's disk_allowlist field; config_poll_loop diffs, applies, and merges into DiskEnumerator.instance_id_map within one poll cycle while preserving live-enumerated disks (Pitfall 5).

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Extend agent-side AgentConfigPayload with disk_allowlist field | 8b5c6e5 | dlp-agent/src/server_client.rs, dlp-common/src/disk.rs |
| 2 | Apply disk_allowlist updates in config_poll_loop with instance_id_map merge | 08e7ae5 | dlp-agent/src/service.rs, dlp-agent/src/disk_enforcer.rs |

## Test Results

| Test Suite | Pass | Fail |
|-----------|------|------|
| AgentConfigPayload serde tests (3 new) | 3 | 0 |
| config_poll_loop diff+merge tests (5 new) | 5 | 0 |
| dlp-agent full lib suite | 261 | 0 |
| **Total new** | **8** | **0** |

## Files Created / Modified

| File | Status | Lines |
|------|--------|-------|
| dlp-agent/src/server_client.rs | MODIFIED | ~960 (+110 from 850) |
| dlp-agent/src/service.rs | MODIFIED | ~1650 (+474 from 1176) |
| dlp-common/src/disk.rs | MODIFIED | +32 (custom BusType Deserialize) |
| dlp-agent/src/disk_enforcer.rs | MODIFIED | -2 (clippy fix, 2 lines changed) |

## Refactor Note: do_poll! Macro vs Helper Function

The `do_poll!` macro body was refactored to call two new private helper functions:

1. **`apply_payload_to_config(cfg, payload) -> (Vec<&'static str>, DiskMergeData)`** — contains ALL diff logic (existing 5 fields + new disk_allowlist). Returns field names changed and optional merge data for the deferred map update. Called INSIDE the config lock scope.

2. **`merge_disk_allowlist_into_map(enumerator, old_ids, new_list)`** — applies the actual `instance_id_map` merge. Called OUTSIDE the config lock scope (after lock is dropped).

The macro body is now minimal: capture interval, call `apply_payload_to_config` inside lock, call `merge_disk_allowlist_into_map` after lock releases, log/save if changed.

**Rationale:** The extracted helpers are fully testable without a `tokio` runtime or HTTP mock. Tests call them directly with synthetic `AgentConfig` and `DiskEnumerator` instances. This was the plan's recommended approach and produces cleaner, more maintainable code than a monolithic macro body.

## Lock-Order Invariant Confirmation (T-37-13)

The lock-order invariant is enforced by design:

```
do_poll! {
    // config mutex ACQUIRED
    let (changed_fields, disk_merge_data) = {
        let mut cfg = config.lock();          // <-- config lock held
        apply_payload_to_config(&mut cfg, &payload)
    };                                         // <-- config lock RELEASED here
    // config mutex RELEASED
    
    if let Some((old_ids, new_list)) = disk_merge_data {
        if let Some(enumerator) = get_disk_enumerator() {
            merge_disk_allowlist_into_map(&enumerator, &old_ids, &new_list);
            // instance_id_map.write() acquired AFTER config lock is gone
        }
    }
}
```

Phase 36 enforcement holds `instance_id_map.read()` and never acquires the config mutex. This plan's code holds the config mutex THEN acquires `instance_id_map.write()` — the only allowed order, never reversed.

## Pitfall 5 Regression Test Confirmation

Test 4 (`test_config_poll_preserves_live_enumerated_disks_not_in_allowlist`) explicitly exercises the Pitfall 5 scenario:

- `instance_id_map` starts with `live-disk-X` (not in `cfg.disk_allowlist` — added by Phase 33 live enumeration)
- `cfg.disk_allowlist` is empty
- Server payload contains `allow-disk-Y` only
- After merge: `instance_id_map` contains BOTH `live-disk-X` AND `allow-disk-Y`

The key guard is that `old_ids` in `merge_disk_allowlist_into_map` is derived from the PREVIOUS `cfg.disk_allowlist`. Entries NOT in `old_ids` are never removed from the map. `live-disk-X` was never in `cfg.disk_allowlist` so its `instance_id` is not in `old_ids` and is preserved.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical Functionality] BusType::Deserialize forward-compatibility**
- **Found during:** Task 1 (Test 3 specification review)
- **Issue:** `BusType` had `#[derive(Serialize, Deserialize)]` with `#[serde(rename_all = "snake_case")]` but no `#[serde(other)]` variant. Any unrecognized bus_type string from a future server build would fail to deserialize the entire `disk_allowlist` entry, causing the entire config payload to be rejected silently.
- **Fix:** Replaced `Deserialize` derive with a custom implementation in `dlp-common/src/disk.rs` that maps any unrecognized string to `BusType::Unknown`. This makes new bus types from future server builds safe during rolling deploys.
- **Files modified:** `dlp-common/src/disk.rs`
- **Commit:** 8b5c6e5

**2. [Rule 1 - Bug] Pre-existing disk_enforcer.rs clippy::unnecessary_map_or**
- **Found during:** Task 2 (`cargo clippy -p dlp-agent -- -D warnings` gate)
- **Issue:** Two occurrences of `letter_opt.map_or(false, |l| self.should_notify(l))` in `disk_enforcer.rs` caused `clippy::unnecessary_map_or` errors under `-D warnings`, blocking the quality gate.
- **Fix:** Replaced with `letter_opt.is_some_and(|l| self.should_notify(l))`.
- **Files modified:** `dlp-agent/src/disk_enforcer.rs`
- **Commit:** 08e7ae5

### Pre-existing Issues (Out of Scope)

- Integration test binaries for `dlp-server` fail to link ("paging file too small", OS error 1455) in the worktree environment. Pre-existing Windows virtual memory issue with parallel worktree builds. All `--lib` unit tests pass.

## Phase-Level Wrap-Up

All Phase 37 requirements are now delivered:

| Req ID | Description | Plan | Status |
|--------|-------------|------|--------|
| ADMIN-01 | disk_registry table with 7 columns + UNIQUE + CHECK | 37-01 | DELIVERED |
| ADMIN-02 | GET /admin/disk-registry (all + ?agent_id= filter) | 37-02 | DELIVERED |
| ADMIN-03 | POST 201/409/422; DELETE 204/404 | 37-02 | DELIVERED |
| AUDIT-03 | AdminAction events with disk:{instance_id}@{agent_id} | 37-02 | DELIVERED |
| D-02 | Server payload includes disk_allowlist per agent | 37-02 | DELIVERED |
| D-03 | Agent applies disk_allowlist within one poll cycle | 37-03 | DELIVERED |

Phase 37 is ready for `/gsd-verify-work`.

## Threat Surface Scan

No new network endpoints or auth paths introduced. The custom `BusType::Deserialize` implementation is strictly more restrictive than the derived version (unknown input -> Unknown rather than error), which is the security-safe behavior.

## Known Stubs

None. The `disk_allowlist` flow is fully wired: server populates from `disk_registry` table -> agent receives via poll -> cfg updated -> instance_id_map merged -> TOML persisted.

## Self-Check: PASSED

- dlp-agent/src/server_client.rs: FOUND (modified with disk_allowlist field + 3 tests)
- dlp-agent/src/service.rs: FOUND (modified with apply_payload_to_config, merge_disk_allowlist_into_map + 5 tests)
- dlp-common/src/disk.rs: FOUND (modified with custom BusType Deserialize)
- dlp-agent/src/disk_enforcer.rs: FOUND (modified with is_some_and fix)
- Commit 8b5c6e5: FOUND (Task 1)
- Commit 08e7ae5: FOUND (Task 2)
- 3/3 Task 1 serde tests pass
- 5/5 Task 2 config_poll tests pass
- 261/261 dlp-agent lib tests pass
- cargo build --workspace exits 0 with no warnings
- cargo clippy -p dlp-agent -- -D warnings exits 0
- disk_allowlist count in service.rs >= 4: YES (58)
- instance_id_map.write() in service.rs >= 1: YES (3)
- changed_fields.push("disk_allowlist") count: 1
- 5 test functions present: YES
