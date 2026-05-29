# Plan 55-04 Summary: Global-Mode-Aware DACL Tripwire

**Phase:** 55-monitor-only-audit-only-per-policy-enforcement-mode
**Plan:** 04 (DACL Tripwire Mode Awareness)
**Status:** Complete
**Date:** 2026-05-29

---

## Objective

Make the DACL tripwire mode-aware at the global level: when `global_mode` is `Audit`, skip ALL Deny ACEs and remove existing ones. When `global_mode` is `Block` or `PerPolicy`, apply Deny ACEs to all protected paths as before.

---

## Tasks Completed

### Task 1: Add global-mode-only tripwire helper

**Commit:** `738cc67`
**Files:** `dlp-agent/src/dacl_tripwire.rs`

- Added `should_apply_tripwire_for_global_mode(global_mode: EnforcementMode) -> bool`:
  - Returns `false` when `global_mode` is `Audit`
  - Returns `true` for `Block`, `AuditAndBlock`, and `PerPolicy`
- Intentionally global-mode-only; per-policy tripwire filtering deferred until path-to-policy mapping is designed
- Added 4 unit tests covering all mode variants

### Task 2: Wire global mode into service.rs tripwire application and removal

**Commit:** `44b4a67`
**Files:** `dlp-agent/src/service.rs`, `dlp-agent/src/dacl_tripwire.rs`

- Extended `build_canonical_security_descriptor()` with `include_deny_ace: bool` parameter:
  - `true`: includes DLP Deny ACE for Authenticated Users (existing behavior)
  - `false`: omits Deny ACE (Audit mode)
- Updated all call sites across `dacl_tripwire.rs` and `service.rs`
- Added `remove_tripwire_by_rebuilding_without_deny()` helper:
  - Builds canonical descriptor without Deny ACE and applies it via `SetFileSecurityW`
  - Returns the new snapshot for watcher registration
- Modified `init_dacl_watcher()`:
  - Reads `agent_config.enforcement.global_mode` before applying tripwire
  - Audit mode: calls `remove_tripwire_by_rebuilding_without_deny` for each path, registers watcher with no-deny snapshot
  - Block/PerPolicy/AuditAndBlock: applies tripwire recursively as before
- Modified `init_dacl_watcher_without_staging()` with identical mode-aware logic
- Added 4 service tests verifying startup mode behavior

### Task 3: Update repair watcher to respect global mode

**Commit:** `6fd7b84`
**Files:** `dlp-agent/src/dacl_repair_watcher.rs`, `dlp-agent/src/dacl_tripwire.rs`

- Modified `repair_acl()` to read global mode via `with_config` before repairing:
  - Audit mode: calls `remove_tripwire_by_rebuilding_without_deny` (rebuilds without Deny ACE)
  - Block/PerPolicy/AuditAndBlock: calls `apply_tripwire_to_path` (existing behavior)
  - Fail-safe default: `Block` when config is unavailable
- Added 2 tests verifying `build_canonical_security_descriptor` with/without deny ACE:
  - `test_canonical_descriptor_with_deny_includes_authusers_deny`
  - `test_canonical_descriptor_without_deny_excludes_authusers_deny`

---

## Verification Results

| Check | Command | Result |
|-------|---------|--------|
| dacl_tripwire tests | `cargo test -p dlp-agent --lib -- dacl_tripwire` | 20 passed |
| dacl_repair_watcher tests | `cargo test -p dlp-agent --lib -- dacl_repair_watcher` | 18 passed |
| service tests | `cargo test -p dlp-agent --lib -- service` | 25 passed |
| dlp-agent full test suite | `cargo test -p dlp-agent --lib` | 714 passed, 0 failed |
| dlp-agent clippy | `cargo clippy -p dlp-agent -- -D warnings` | Clean |

---

## Key Design Decisions

1. **Global-mode-only, not per-policy:** Per-policy tripwire filtering is architecturally infeasible because `protected_paths` has no foreign key to policies; policies match via dynamic conditions at evaluation time. Global-mode-only satisfies the common monitor-only use case without scope creep.

2. **Parameterized `build_canonical_security_descriptor`:** Adding `include_deny_ace: bool` to the existing function is cleaner than creating a parallel function hierarchy. All call sites were updated.

3. **Fail-safe default:** When config is unavailable (race at startup), `repair_acl` defaults to `Block` — the safest choice.

4. **Audit mode removes AND prevents re-addition:** In Audit mode, the watcher is registered with a no-deny snapshot, so the polling backstop will not detect a "mismatch" and try to re-add the Deny ACE.

---

## Artifacts Produced

- `dlp-agent/src/dacl_tripwire.rs` — `should_apply_tripwire_for_global_mode()`, `remove_tripwire_by_rebuilding_without_deny()`, extended `build_canonical_security_descriptor()`
- `dlp-agent/src/service.rs` — Mode-aware `init_dacl_watcher()` and `init_dacl_watcher_without_staging()`
- `dlp-agent/src/dacl_repair_watcher.rs` — Mode-aware `repair_acl()`

---

## Threat Model Disposition

| Threat ID | Status | Notes |
|-----------|--------|-------|
| T-55-10 | Mitigated | Config file in ProgramData with SYSTEM-only ACL; audit log records mode changes |
| T-55-11 | Mitigated | Defensive fallback to Block for unrecognized mode strings; unit tests verify both paths |
| T-55-12 | Mitigated | Mode is read from agent config (server-signed payload), not from filesystem |
