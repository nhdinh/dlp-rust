---
phase: 56-sd-optical-virtual-drive-enumeration-volume-class-abac-seed
plan: "04"
subsystem: dlp-server
tags: [abac, volume-class, policy-store, fail-closed]
dependency_graph:
  requires: [56-01]
  provides: [PolicyStore::evaluate volume class conditions, volume_class_matches helper]
  affects: [dlp-server, dlp-agent, dlp-hook-dll]
tech-stack:
  added: []
  patterns:
    - "Fail-closed helper pattern: None input returns false (condition cannot be confirmed)"
    - "Trust-agent-context pattern: server does NOT resolve paths locally"
    - "Match arm extension: append new PolicyCondition variants after existing arms"
key-files:
  created: []
  modified:
    - dlp-server/src/policy_store.rs
    - dlp-server/src/alert_router.rs
    - dlp-common/src/abac.rs
    - dlp-common/src/audit.rs
decisions:
  - "Server TRUSTS agent-provided volume class context exclusively — no server-side path resolution"
  - "volume_class_matches uses single-value 'in' semantics (treats as eq); multi-value via multiple conditions"
  - "AlertRouter test AuditEvent structs updated with volume_class: None field for Plan 01 compatibility"
metrics:
  duration: "~15 minutes"
  completed_date: "2026-05-29"
---

# Phase 56 Plan 04: Server-Side ABAC Volume Class Evaluation Summary

**One-liner:** Server-side ABAC evaluation match arms for `SourceVolumeClass` and `DestinationVolumeClass` conditions, with a fail-closed `volume_class_matches` helper and explicit removal of server-side path resolution — the server trusts agent-provided context exclusively.

---

## What Was Built

### Task 1: Volume class match arms and `volume_class_matches` helper

**`volume_class_matches` helper** (lines 553-578 in `policy_store.rs`):
- Takes `(op: &str, expected: &VolumeClass, actual: Option<VolumeClass>) -> bool`
- Returns `false` when `actual` is `None` (fail-closed — no volume class means condition cannot be confirmed)
- Supports `"eq"` (exact match), `"ne"` (inverse match), `"in"` (single-value semantics = eq)
- Unknown operators return `false` (fail-closed)
- Doc comment references the VolumeClass FAIL-CLOSED INVARIANT from `dlp-common/src/abac.rs`

**New match arms in `condition_matches`** (lines 411-416):
```rust
PolicyCondition::SourceVolumeClass { op, value } => {
    volume_class_matches(op, value, ctx.source_volume_class)
}
PolicyCondition::DestinationVolumeClass { op, value } => {
    volume_class_matches(op, value, ctx.destination_volume_class)
}
```

**Server-side path resolution REMOVED:**
- The original plan draft included server-side path resolution via `resolve_volume_class_from_path`
- This was DELETED per D-07: the server trusts agent-provided context exclusively
- Zero occurrences of `resolve_volume_class_from_path` in `policy_store.rs`
- Eliminates the third source of truth (agent + hook + server) and prevents audit log divergence

**`VolumeClass` import** added to the existing `dlp_common::abac` use statement (line 16).

### Task 2: Integration test for "DENY LocalNTFS T4 to Optical" policy

**`test_evaluate_deny_localntfs_t4_to_optical`**:
- 4-condition policy: Classification eq T4 + SourceVolumeClass eq LocalNTFS + DestinationVolumeClass eq Optical + AccessContext eq Local
- Asserts `Decision::DENY` with matched policy ID when all conditions match

**`test_evaluate_localntfs_destination_no_match`**:
- Same policy but destination is LocalNTFS instead of Optical
- Asserts default-deny (T4) with no matched policy ID

**`test_evaluate_none_source_volume_class_fails_closed`**:
- Same policy but `source_volume_class` is `None`
- SourceVolumeClass condition fails closed → policy does not match → default-deny (T4)

**Additional end-to-end tests:**
- `test_evaluate_volume_class_audit_mode` — Audit mode returns ALLOW + would_have_denied=true
- `test_evaluate_volume_class_ne_operator` — "ne" operator matches when actual differs
- `test_evaluate_volume_class_in_operator` — "in" operator uses single-value semantics

### Compilation fix: AlertRouter test code

Plan 01 added `volume_class: Option<VolumeClass>` to `AuditEvent`. The `alert_router.rs` test code had 6 `AuditEvent` struct initializers that needed the new field. Added `volume_class: None` to all 6 occurrences to restore compilation.

---

## Test Coverage

| Test Category | Count | Key Tests |
|---------------|-------|-----------|
| volume_class_matches helper | 6 | eq matches, eq no-match, ne matches, none fails closed, in matches, unknown op fails closed |
| DestinationVolumeClass direct | 1 | condition_matches evaluates DestinationVolumeClass eq Virtual |
| Server does not resolve paths | 1 | resource_path present but source_volume_class=None → condition fails closed |
| End-to-end DENY LocalNTFS T4 to Optical | 1 | All 4 conditions match → DENY |
| End-to-end destination mismatch | 1 | DestinationVolumeClass does not match → default-deny |
| End-to-end None source fails closed | 1 | None source_volume_class → policy does not match → default-deny |
| Audit mode | 1 | Volume-class policy in Audit mode → ALLOW + would_have_denied=true |
| ne operator | 1 | SourceVolumeClass ne LocalNTFS with USBRemovable → DENY |
| in operator | 1 | DestinationVolumeClass in NetworkShare → DENY |

**Total: 114 policy_store tests pass (96 existing + 18 new)**
**Total: 574 dlp-server lib tests pass**

---

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking Issue] AlertRouter test compilation failures**
- **Found during:** Task 1 verification (cargo test)
- **Issue:** Plan 01 added `volume_class: Option<VolumeClass>` to `AuditEvent` struct, but `dlp-server/src/alert_router.rs` test code had 6 `AuditEvent { ... }` struct initializers without the new field, causing `E0063: missing field volume_class` errors
- **Fix:** Added `volume_class: None` to all 6 `AuditEvent` initializers in `alert_router.rs` test code
- **Files modified:** `dlp-server/src/alert_router.rs`
- **Commit:** included in `6b36e0a`

**2. [Rule 1 - Bug] dlp-common formatting drift**
- **Found during:** Task 1 post-test verification
- **Issue:** `cargo fmt --check` reported formatting differences in `dlp-common/src/abac.rs` and `dlp-common/src/audit.rs` (long lines from Plan 01)
- **Fix:** Ran `cargo fmt` to auto-fix formatting
- **Files modified:** `dlp-common/src/abac.rs`, `dlp-common/src/audit.rs`
- **Commit:** included in `6b36e0a`

---

## Verification Results

- `cargo test -p dlp-server --lib`: 574 passed, 0 failed, 3 ignored
- `cargo clippy -p dlp-server -- -D warnings`: clean
- `cargo fmt --check`: clean

---

## Commits

| Hash | Message | Files |
|------|---------|-------|
| 6b36e0a | feat(56-04): add volume class match arms and volume_class_matches helper to policy_store.rs | dlp-server/src/policy_store.rs, dlp-server/src/alert_router.rs, dlp-common/src/abac.rs, dlp-common/src/audit.rs |

---

## Self-Check: PASSED

- [x] All created/modified files exist and compile
- [x] All commits exist in git history
- [x] All tests pass (574 dlp-server lib tests)
- [x] Clippy clean
- [x] Formatting clean
- [x] No modifications to shared orchestrator artifacts (STATE.md, ROADMAP.md)
- [x] `resolve_volume_class_from_path` absent from policy_store.rs (server trusts agent context)
- [x] `volume_class_matches` helper documented with fail-closed invariant
- [x] Integration test proves "DENY LocalNTFS T4 to Optical" without hardware
