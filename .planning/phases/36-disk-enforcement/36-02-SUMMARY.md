---
phase: 36-disk-enforcement
plan: "02"
subsystem: dlp-agent/disk-enforcer
tags:
  - dlp-agent
  - disk
  - enforcement
  - DISK-04
dependency_graph:
  requires:
    - "Phase 33-35: DiskEnumerator (get_disk_enumerator, set_disk_enumerator, instance_id_map, drive_letter_map)"
    - "dlp-common: DiskIdentity, BusType, Decision"
    - "dlp-agent/interception: FileAction enum"
  provides:
    - "DiskEnforcer::check - DISK-04 write-path enforcement primitive"
    - "DiskBlockResult - block decision carrier for Plan 03 event loop wiring"
  affects:
    - "dlp-agent/src/lib.rs - module declaration added"
tech_stack:
  added:
    - "parking_lot::Mutex<HashMap<char, Instant>> for per-drive toast cooldown"
  patterns:
    - "fail-closed enforcement: explicit None arm on get_disk_enumerator() (not ?"
    - "compound allowlist check: instance_id presence + serial equality"
    - "physical-swap closure: serial mismatch on same instance_id"
key_files:
  created:
    - dlp-agent/src/disk_enforcer.rs
  modified:
    - dlp-agent/src/lib.rs
decisions:
  - "DiskEnforcer wraps get_disk_enumerator() internally (not injected at construction) to match Claude Discretion recommendation and avoid coupling to service.rs startup order"
  - "byte_count field in FileAction test helpers uses u32 (not u64 as in plan interface block) to match actual enum definition"
  - "Combined Task 1 (skeleton) and Task 2 (full implementation) into single commit since the full check body is a direct replacement of the placeholder"
metrics:
  duration: "~10 minutes"
  completed: "2026-05-04T03:04:32Z"
  tasks_completed: 2
  files_created: 1
  files_modified: 1
---

# Phase 36 Plan 02: DiskEnforcer Module Summary

DiskEnforcer write-path enforcement primitive (DISK-04) with compound instance_id + serial allowlist check, fail-closed startup semantics, and 10-test coverage of all plan truths.

## Public API

### `DiskEnforcer`

```rust
pub struct DiskEnforcer { /* last_toast: parking_lot::Mutex<HashMap<char, Instant>> */ }

impl DiskEnforcer {
    pub fn new() -> Self;
    pub fn check(&self, path: &str, action: &FileAction) -> Option<DiskBlockResult>;
}
```

### `DiskBlockResult`

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct DiskBlockResult {
    pub decision: Decision,   // always Decision::DENY when Some is returned
    pub disk: DiskIdentity,   // live identity from drive_letter_map (or placeholder on fail-closed)
    pub notify: bool,         // false during 30-second per-drive cooldown
}
```

### Private helper

```rust
fn drive_letter_from_path(path: &str) -> Option<char>
```

Returns uppercase drive letter; `None` for UNC paths (`\\server\share`), non-alpha leading chars, or empty string.

## Decision Tree

```
check(path, action)
  |
  +-- action not in {Created, Written, Moved}?
  |     -> None (DISK-04: read/delete pass through)
  |
  +-- get_disk_enumerator() returns None?
  |     -> Some(DENY, placeholder identity with drive_letter=Some(letter))
  |        [D-06 fail-closed: enumerator not yet installed]
  |
  +-- enumerator.is_ready() == false?
  |     -> Some(DENY, placeholder identity)
  |        [D-06 fail-closed: enumeration still in progress]
  |
  +-- drive_letter_from_path(path) returns None?
  |     -> None (UNC or non-Windows path)
  |
  +-- disk_for_drive_letter(letter) returns None?
  |     -> None (drive not a tracked fixed disk; pass to ABAC)
  |        [D-07 step 2]
  |
  +-- disk_for_instance_id(live.instance_id) returns None?
  |     -> Some(DENY, live identity)
  |        [D-07 step 3: unregistered disk]
  |
  +-- both serials Some and they differ?
  |     -> Some(DENY, live identity)
  |        [D-07 step 4 / D-11: physical-swap closure]
  |
  +-- -> None (allowlisted; fall through to ABAC)
         [D-07 step 5]
```

## Test List

| Test name | Truth verified |
|-----------|----------------|
| `test_read_action_returns_none` | DISK-04: FileAction::Read always returns None |
| `test_deleted_action_returns_none` | DISK-04: FileAction::Deleted always returns None |
| `test_write_blocked_when_not_ready_fail_closed` | D-06: blocks writes when enumeration_complete=false; disk.drive_letter populated; instance_id empty (placeholder) |
| `test_path_not_in_drive_letter_map_passes` | D-07 step 2: path on untracted drive letter returns None |
| `test_unregistered_disk_blocked_on_create_write_move` | D-07 step 3: Created, Written, Moved all blocked when instance_id not in allowlist |
| `test_serial_mismatch_blocked` | D-07 step 4 / D-11: same instance_id but different serial blocks with LIVE identity |
| `test_allowlisted_disk_passes` | D-07 step 5: matching serials returns None; both-None serials also returns None |
| `test_should_notify_cooldown` | D-02: first block notifies; second block within 30s does not; different drive letters have independent cooldowns |
| `test_unc_path_returns_none` | UNC paths (\\server\share) pass through even when enumerator ready |
| `test_drive_letter_helpers` | drive_letter_from_path: E: -> Some('E'), e: -> Some('E'), UNC -> None, /unix -> None, empty -> None |

## DISK-04 Traceability

This plan delivers the enforcement primitive only. The complete DISK-04 enforcement chain requires:

- **Plan 02 (this plan):** `DiskEnforcer::check` enforcement logic + unit tests
- **Plan 03:** Wire `DiskEnforcer` into `run_event_loop` as `disk_enforcer: Option<Arc<DiskEnforcer>>` parameter; emit `AuditEvent` with `with_blocked_disk`; broadcast toast via `Pipe2AgentMsg::Toast`

## Notes

### `--test-threads=1` requirement

Tests must run single-threaded because the global `DiskEnumerator` is stored in a `OnceLock<Arc<DiskEnumerator>>` at process level. `OnceLock::set` succeeds only once, so all tests share the same `Arc<DiskEnumerator>` singleton and reset its internal `RwLock`-protected maps between tests. A `parking_lot::Mutex<()> TEST_LOCK` serializes test execution. Always invoke with:

```
cargo test -p dlp-agent disk_enforcer -- --test-threads=1
```

### Pitfall 3 (fail-closed)

The `?` operator on `get_disk_enumerator()` is deliberately NOT used. Using `?` would silently pass through all writes when the enumerator is absent (None = no context = pass), which is the wrong default. The `match` with explicit `None => Some(DENY)` arm ensures the fail-closed invariant is preserved.

### Deviation: byte_count type correction

The plan's interface block showed `byte_count: u64` for `FileAction::Written` and `FileAction::Read`, but the actual enum in `dlp-agent/src/interception/file_monitor.rs` uses `u32`. Test helpers were written with `u32` to match the actual code. [Rule 1 - Bug Fix]

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed byte_count type in test helpers**
- **Found during:** Task 2 implementation
- **Issue:** Plan interface block documented `byte_count: u64` for `FileAction::Written` and `FileAction::Read`, but actual enum uses `u32`.
- **Fix:** Used `u32` in `write_action()` and `read_action()` test helpers (value `100u32`).
- **Files modified:** `dlp-agent/src/disk_enforcer.rs`
- **Commit:** 1ced0b3

## Threat Flags

None. The `disk_enforcer.rs` module introduces no new network endpoints, auth paths, file access patterns, or schema changes. It reads from the existing global `DiskEnumerator` state (populated by Phase 33-35) and returns a decision struct to the caller. All security-relevant threat mitigations are covered by the plan's threat model (T-36-02-01 through T-36-02-08) and verified by the 10 unit tests.

## Self-Check

**Checking created files exist:**
- `dlp-agent/src/disk_enforcer.rs`: FOUND
- `dlp-agent/src/lib.rs` (modified): FOUND

**Checking commit exists:**
- 1ced0b3: feat(36-02): implement DiskEnforcer module: FOUND

## Self-Check: PASSED
