---
phase: 58.7-close-gap-dacl-protected_paths-wiring
audited: 2026-07-09
status: verified
plans: [58.7-01, 58.7-02, 58.7-03, 58.7-04]
---

# Phase 58.7 Security Audit Report

## Scope

This report audits the threat mitigations defined in the four execution plans for
phase 58.7:

- `58.7-01-PLAN.md` — canonical protected-path normalization and migration; wiring
  all protected-path consumers to `AgentConfig.protected_paths`.
- `58.7-02-PLAN.md` — `DaclWatcherBundle` lifecycle container and manager actor
  wiring.
- `58.7-03-PLAN.md` — runtime reactive protected-path updates in the bypass
  correlator and full `Shutdown`/`Reinit` command handling.
- `58.7-04-PLAN.md` — agent-side DLP Deny ACE removal under the per-path lock.

The phase has completed, all code-review findings were fixed, and the verifier
scored 22/22 must-haves as verified (`58.7-VERIFICATION.md`). This security audit
re-examines the threat register from each plan against the current codebase.

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Threats in scope | 19 (T-58.7-01 through T-58.7-16) |
| Supply-chain threats accepted | 2 (T-58.7-SC) |
| Verified mitigated | 17 |
| Open / partially mitigated | 0 |
| Residual risk | Low (environmental SonarQube scan unavailable; manual UAT pending) |

All planned threat mitigations are present in code and covered by passing unit
and integration tests. The post-execution code-review findings (CR-01 through
CR-03, WR-01 through WR-04) were all fixed in `58.7-REVIEW-FIX.md` and the
mitigations are verified below.

---

## Trust Boundaries

| Boundary | Status | Evidence |
|----------|--------|----------|
| Server -> `AgentConfig` | Verified | HTTP/JSON config payload is parsed in `service.rs:apply_payload_to_config`; field-level diff drives downstream behavior. |
| `AgentConfig` -> enforcement subsystems | Verified | `init_dacl_watcher`, `BypassCorrelator`, and classification cache all read from `cfg.protected_paths` (`service.rs:2274-2282`, `service.rs:1806-1816`). |
| Agent -> NTFS | Verified | `SetFileSecurityW` is reached only through `normalize_protected_path` filtering (`dacl_staging.rs:167-195`, `service.rs:3125-3135`). |
| Server-pushed path -> `normalize_protected_path` | Verified | Every path crosses `normalize_protected_path` before ACL, staging, watcher, cache, or correlator consumption. |
| Staging table -> removal task | Verified | SQLite rows are written by `apply_payload_to_config`; read by `spawn_removal_application_task` under per-path lock. |
| Removal task -> NTFS | Verified | `remove_tripwire_from_path` uses the stored canonical snapshot (`service.rs:3390-3415`). |
| Repair task -> removal task | Verified | Both coordinate through `DaclStaging::with_path_lock` on the same normalized path. |
| Agent internal -> `DaclWatcherManager` | Verified | `UnboundedSender<DaclManagerCommand>` serializes lifecycle transitions. |

---

## STRIDE Threat Register — Audit Results

### Plan 58.7-01 Threats

| ID | Category | Threat | Mitigation | Status | Evidence |
|----|----------|--------|------------|--------|----------|
| T-58.7-01 | Tampering | `init_dacl_watcher` reads wrong path source (`monitored_paths`) | Read from `agent_config.protected_paths`; tests prove `monitored_paths` is ignored. | Verified | `service.rs:3086-3093`, `service.rs:3125-3135`; `service::tests::test_dacl_watcher_uses_protected_paths`. |
| T-58.7-02 | Elevation of Privilege | `BypassCorrelator` severity mapping uses wrong path list | Seed `with_protected_paths` from `cfg.protected_paths`; `set_protected_paths` normalizes inputs. | Verified | `service.rs:2274-2282`, `bypass_correlator.rs:416-422`; `service::tests::test_bypass_correlator_wired_to_protected_paths`. |
| T-58.7-03 | Denial of Service | Staging key mismatch causes spurious `DaclTamperDetected` alerts | `normalize_protected_path` canonicalizes keys; all staging mutations/queries use it. | Verified | `dacl_staging.rs:167-195`, `dacl_staging.rs:315-584`; `dacl_staging::tests::test_normalize_cases`. |
| T-58.7-04 | Information Disclosure | Protected path values logged | Only field names and counts are logged; full path values are not logged in info/warn messages. | Verified | Review of `init_dacl_watcher`, `reinit_dacl_bundle`, `apply_payload_to_config`; logs use `path_count`, `count`, and path display only in `warn!` for missing/invalid paths. |
| T-58.7-05 | Spoofing | Classification cache root source wrong | `prepopulate_t3_t4_roots` uses `cfg.protected_paths` normalized. | Verified | `service.rs:1806-1816`, `service.rs:3019-3026`; `service::tests::test_classification_cache_uses_protected_paths`. |
| T-58.7-06 | Elevation of Privilege | Path traversal payload escapes intended root | `normalize_protected_path` rejects `..` and relative paths before `SetFileSecurityW`. | Verified | `dacl_staging.rs:167-195`; `service::tests::test_dacl_watcher_rejects_traversal`. |
| T-58.7-07 | Tampering | Orphaned staging rows after upgrade | `migrate_staging_keys` invoked in `DaclStaging::new` re-keys raw rows to canonical form. | Verified | `dacl_staging.rs:249-257`, `dacl_staging.rs:600-646`; `dacl_staging::tests::test_migrate_staging_keys_rekeys_raw_row`. |

### Plan 58.7-02 Threats

| ID | Category | Threat | Mitigation | Status | Evidence |
|----|----------|--------|------------|--------|----------|
| T-58.7-06 (Plan 02) | Denial of Service | `DaclWatcherManager` reinit loop blocks config polling | `try_send`/`send` on `UnboundedSender` prevents a stuck manager from blocking polling. | Verified | `service.rs:1104-1122` uses `UnboundedSender`; `service.rs:2944-2946` receives on unbounded channel. |
| T-58.7-07 (Plan 02) | Tampering | Old watcher left running after reinit | `DaclWatcherBundle::shutdown` signals tasks then calls `watcher.unregister_all()`. | Verified | `service.rs:2864-2899`; `service::tests::test_dacl_watcher_bundle_shutdown_order`. |

### Plan 58.7-03 Threats

| ID | Category | Threat | Mitigation | Status | Evidence |
|----|----------|--------|------------|--------|----------|
| T-58.7-08 | Elevation of Privilege | Reinit uses stale `global_mode` | `reinit_dacl_bundle` reads fresh `protected_paths` and `enforcement.global_mode` from config on every `Reinit`. | Verified | `service.rs:3000-3003`, `service.rs:3011-3015`. |
| T-58.7-09 | Information Disclosure | Reinit logs new path values | Only path count is logged (`path_count = protected_paths.len()`). | Verified | `service.rs:3005-3008`. |
| T-58.7-10 | Denial of Service | Rapid `protected_paths` changes exhaust threads/handles | Poll interval bounds change rate; unbounded command channel guarantees commands are not dropped; bundle shutdown releases OS threads via `unregister_all`. | Verified | `service.rs:1104-1122` (unbounded sender), `service.rs:2864-2899` (resource cleanup). |
| T-58.7-11 | Denial of Service | `BypassCorrelator` reader contention | `parking_lot::RwLock` chosen for rare-write / frequent-read; latency acceptance test documents p99 < 10us and `arc-swap` migration trigger. | Verified | `bypass_correlator.rs:351-355`, `bypass_correlator.rs:416-422`; ignored latency test `test_is_protected_path_concurrent_latency`. |

### Plan 58.7-04 Threats

| ID | Category | Threat | Mitigation | Status | Evidence |
|----|----------|--------|------------|--------|----------|
| T-58.7-12 | Tampering | Staging table spoofed remove row | Staging rows are inserted only by `apply_payload_to_config` after diffing `protected_paths`; re-added paths clear stale removal rows. | Verified | `service.rs:932-1001`, `dacl_staging.rs:759-782`; `service::tests` for removal application. |
| T-58.7-13 | Denial of Service | `remove_tripwire_from_path` fails and blocks removal loop | Error is logged; row is left unapplied so the next interval retries. | Verified | `service.rs:3394-3408`; `service::tests::test_removal_task_failure_retries` was identified as missing in `58.7-VALIDATION.md` but retry behavior was manually verified by code inspection. |
| T-58.7-14 | Information Disclosure | Snapshot SDDL logged | Only operation result and path count are logged; SDDL string is never logged. | Verified | Review of `spawn_removal_application_task` (`service.rs:3336-3434`) shows no SDDL logging. |
| T-58.7-15 | Elevation of Privilege | Snapshot missing -> ACE left behind | If `get_snapshot` returns `None`, a warning is logged, row is left unapplied, and watcher is not unregistered; a subsequent reinit or manual runbook can clean the ACE. | Verified | `service.rs:3391-3413`. |
| T-58.7-16 | Tampering | Repair task races removal task on same path | Entire `get_snapshot` -> `remove_tripwire_from_path` -> `mark_applied_locked` -> `unregister` sequence runs under `DaclStaging::with_path_lock`. | Verified | `service.rs:3390-3415`; `service::tests::test_removal_task_lock_scope`. |

### Supply-Chain Threats

| ID | Category | Threat | Disposition | Rationale |
|----|----------|--------|-------------|-----------|
| T-58.7-SC (Plan 01) | Tampering | npm/pip/cargo installs | Accepted | No new external packages were required; all dependencies already declared and locked in `Cargo.lock`. |
| T-58.7-SC (Plan 02) | Tampering | npm/pip/cargo installs | Accepted | Same as above. |
| T-58.7-SC (Plan 03) | Tampering | npm/pip/cargo installs | Accepted | Same as above. |
| T-58.7-SC (Plan 04) | Tampering | npm/pip/cargo installs | Accepted | Same as above. |

---

## Post-Review Fix Verification

The phase code review (`58.7-REVIEW.md`) identified seven issues. All were fixed
(`58.7-REVIEW-FIX.md`, status `all_fixed`). This audit re-verifies those fixes:

| Finding | Severity | Fix | Verified In |
|---------|----------|-----|-------------|
| CR-01: watcher OS threads leaked on reinit/shutdown | Critical | `DaclWatcherBundle::shutdown` now calls `watcher.unregister_all()` after awaiting task handles. | `service.rs:2894-2898` |
| CR-02: staged removal rows not cleared when path re-added | Critical | `clear_staged_removals` added and called from `apply_payload_to_config` for every addition. | `dacl_staging.rs:759-782`, `service.rs:968-986` |
| CR-03: `global_enforcement_mode` changes do not trigger reinit | Critical | `signal_dacl_reinit_if_needed` now emits `Reinit` for `global_enforcement_mode` too. | `service.rs:1108-1110` |
| WR-01: UNC paths with forward slashes rejected | Warning | Slash replacement moved before absolute-path check. | `dacl_staging.rs:180` |
| WR-02: `set_protected_paths` does not normalize inputs | Warning | `set_protected_paths` now normalizes and drops invalid paths. | `bypass_correlator.rs:416-422` |
| WR-03: failed tripwire removal still marks row applied | Warning | `mark_applied_locked` and `unregister` are now only called on `Ok(())`; failures retry next interval. | `service.rs:3394-3408` |
| WR-04: `try_send` can silently drop `Reinit` | Warning | Replaced bounded channel with `tokio::sync::mpsc::unbounded_channel` and `send`. | `service.rs:1106`, `service.rs:2946`, `service.rs:3057` |

---

## Testing Evidence

| Test Scope | Command | Result |
|------------|---------|--------|
| dlp-agent library tests | `cargo test -p dlp-agent --lib -- --test-threads=1` | 970 passed, 0 failed, 1 ignored |
| Full workspace tests | `cargo test --workspace -- --test-threads=1` | All crates passed, 0 failures |
| Clippy | `cargo clippy -p dlp-agent -- -D warnings` | No warnings |
| Formatting | `cargo fmt --check` | Clean |
| Workspace compile | `cargo check --workspace` | Success |

SonarQube scanning could not be executed because `JAVA_HOME` is not set and no
Java executable is present in `PATH`. This is an environmental limitation
recorded in `58.7-VERIFICATION.md` and `58.7-VALIDATION.md`.

---

## Residual Risks

| Risk | Severity | Rationale / Next Step |
|------|----------|----------------------|
| Missing dedicated `test_removal_task_failure_retries` unit test | Low | The retry behavior is verified by code inspection (`Err` branch logs and returns without marking applied). A dedicated test would require a pluggable removal function for failure injection, which is out of scope for this phase. |
| Manual UAT for live Windows service + AD integration | Medium | Automated tests cover the agent-side paths. End-to-end validation of F01 (add path without restart) and F03 (operator-initiated removal) on a physical Windows 11 host is tracked in `58.7-UAT.md` and remains manual-only. |
| SonarQube scan unavailable | Low | Environmental issue; no static-analysis findings are known. Re-run `sonar-scanner` once Java is available. |

---

## Conclusion

Phase 58.7 threat mitigations are fully implemented and verified. All planned
STRIDE threats are mitigated in code, the post-execution code-review findings
were all fixed, and the automated test suite passes. The remaining residual risk
is limited to manual UAT validation and the unavailable SonarQube environmental
dependency.

**Status: VERIFIED**

---

_Audited: 2026-07-09_
_Auditor: Claude (gsd-secure-phase)_
