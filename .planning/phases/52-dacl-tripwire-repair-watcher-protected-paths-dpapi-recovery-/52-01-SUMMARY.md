---
phase: 52-dacl-tripwire-repair-watcher-protected-paths-dpapi-recovery-
plan: 01
subsystem: dlp-agent / dlp-common
status: complete
tags: [dacl, tripwire, ntfs, security, windows, acl]
dependency_graph:
  requires: []
  provides: [DACL-01]
  affects: [52-02, 52-04, 52-07]
tech_stack:
  added:
    - walkdir 2.5 (recursive directory traversal with junction/symlink skip)
  patterns:
    - Raw ACL buffer construction (from protection.rs pattern)
    - SDDL snapshot storage for human-readable canonical ACL
    - Canonical DACL algorithm per MS-DTYP 2.4.5
    - Fail-closed recursive walk with pre-count
key_files:
  created:
    - dlp-agent/src/dacl_tripwire.rs
  modified:
    - dlp-agent/src/lib.rs
    - dlp-agent/Cargo.toml
    - dlp-common/src/audit.rs
decisions:
  - "Use SDDL strings for CanonicalAclSnapshot (human-readable, diffable) per D-13"
  - "Use walkdir over std::fs::read_dir for junction/symlink safety per research"
  - "60 KB guard enforced on ALL write paths: initial apply, recursive repair, snapshot restore"
  - "Fail-closed for 10K limit: count BEFORE applying any ACLs"
  - "Non-Windows stubs for cross-platform compilation"
metrics:
  duration_minutes: 45
  completed_date: "2026-05-27"
  tasks: 3
  commits: 2
  tests_added: 19
---

# Phase 52 Plan 01: DACL Tripwire Writer Summary

**One-liner:** Kernel-enforced NTFS DACL backstop that injects Deny ACEs for Authenticated Users (S-1-5-11) onto T3/T4 protected paths, with canonical ACL algorithm, SDDL snapshots, 60 KB guard, and access-control proof matrix.

## What Was Built

### dlp-agent/src/dacl_tripwire.rs (NEW)

A complete DACL tripwire writer module with:

| Function | Purpose |
|----------|---------|
| `build_deny_authusers_dacl()` | Raw ACL buffer with Authenticated Users SID via `CreateWellKnownSid` |
| `build_canonical_security_descriptor()` | Canonical DACL algorithm: SYSTEM Allow -> DLP-Admin Allow -> DLP Deny -> preserved non-DLP ACEs |
| `apply_tripwire_to_path()` | Atomically apply tripwire with path validation and 60 KB guard |
| `remove_tripwire_from_path()` | Restore pre-tripwire ACL from SDDL snapshot |
| `apply_tripwire_recursive()` | Recursive subtree application with 10K fail-closed limit and junction skip |
| `verify_access_control_matrix()` | Access-control proof matrix verifying SYSTEM/DLP-Admin full access, AuthUsers denied write |

**Structs:**
- `CanonicalAclSnapshot` — SDDL string + timestamp + path
- `AccessControlMatrix` — effective access for SYSTEM, DLP-Admin, normal user, AuthUsers
- `DaclTripwireError` — thiserror enum with 5 variants

### dlp-common/src/audit.rs (MODIFIED)

Added two `EventType` variants:
- `DaclTripwireTooLarge` — `triggers_alert=false`, `routed_to_siem=true`
- `DaclTamperDetected` — `triggers_alert=true`, `routed_to_siem=true`

Plus 5 unit tests for SIEM routing, alert triggering, and serde roundtrip.

### dlp-agent/Cargo.toml (MODIFIED)

Added `walkdir = "2.5"` dependency for recursive directory traversal.

### dlp-agent/src/lib.rs (MODIFIED)

Added `#[cfg(windows)] pub mod dacl_tripwire;` module declaration.

## Test Results

| Test Suite | Result |
|-----------|--------|
| `cargo test -p dlp-common audit` | 32 passed, 0 failed |
| `cargo test -p dlp-agent dacl_tripwire` | 14 passed, 0 failed |
| `cargo clippy -p dlp-agent -p dlp-common -- -D warnings` | Clean |
| `cargo fmt --check` | Clean |
| `cargo build -p dlp-agent -p dlp-common` | Success |

### Unit Tests Added (19 total)

**dlp-common (5 tests):**
1. `test_dacl_tripwire_too_large_routed_to_siem`
2. `test_dacl_tamper_detected_routed_to_siem`
3. `test_dacl_tamper_detected_triggers_alert`
4. `test_dacl_tripwire_too_large_does_not_trigger_alert`
5. `test_dacl_event_serde_roundtrip`

**dlp-agent (14 tests):**
1. `test_build_deny_authusers_dacl_structure` — ACL buffer layout correct
2. `test_build_deny_authusers_dacl_sid` — SID matches CreateWellKnownSid output
3. `test_acl_size_guard_rejects_oversized` — 60 KB guard verified
4. `test_apply_tripwire_invalid_path_rejection` — UNC, extended-length, volume GUID, 8.3, ADS rejected
5. `test_canonical_snapshot_sddl_roundtrip` — SDDL parses back correctly
6. `test_canonical_order_dlp_deny_first` — DLP Deny after SYSTEM Allow
7. `test_canonical_order_preserves_existing_aces` — non-DLP ACEs preserved
8. `test_canonical_order_system_allow_before_deny` — SYSTEM Allow precedes Deny
9. `test_recursive_walk_limit_fail_closed` — 5 files pass, no WalkError
10. `test_walkdir_skips_junctions` — junctions not followed
11. `test_remove_tripwire_restores_acl` — snapshot restore works
12. `test_access_control_matrix_system_full` — SYSTEM has GENERIC_ALL
13. `test_access_control_matrix_authusers_denied_write` — AuthUsers denied write/delete/permission-change
14. `test_access_control_matrix_dlpadmin_full` — DLP-Admin has GENERIC_ALL

## Deviations from Plan

None — plan executed exactly as written.

## Threat Flags

No new threat surface introduced beyond what is documented in the plan's threat model. All STRIDE mitigations are implemented as specified.

## Known Stubs

None. All functions are fully implemented with real Windows API calls on `#[cfg(windows)]` and appropriate stubs on non-Windows.

## Self-Check: PASSED

- [x] `dlp-agent/src/dacl_tripwire.rs` exists
- [x] `dlp-agent/src/lib.rs` has `pub mod dacl_tripwire`
- [x] `dlp-agent/Cargo.toml` has `walkdir`
- [x] `dlp-common/src/audit.rs` has new EventType variants
- [x] Commit `0718f24` exists (audit events)
- [x] Commit `6b9b42f` exists (dacl_tripwire module)
- [x] All tests pass
- [x] Clippy clean
- [x] Format clean

## Commits

| Hash | Message |
|------|---------|
| `0718f24` | feat(52-01): add DaclTripwireTooLarge and DaclTamperDetected audit event variants |
| `6b9b42f` | feat(52-01): create dacl_tripwire.rs with canonical DACL algorithm and access-control proof matrix |
