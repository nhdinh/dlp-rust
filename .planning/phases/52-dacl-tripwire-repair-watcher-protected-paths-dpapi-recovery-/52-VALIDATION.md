---
phase: 52-dacl-tripwire-repair-watcher-protected-paths-dpapi-recovery-
validation: true
nyquist_compliant: true
last_updated: 2026-06-28
---

# Phase 52 Validation Strategy

## Dimensions

| Dimension | Method | Coverage | Status |
|-----------|--------|----------|--------|
| Unit | `cargo test -p dlp-agent dacl_tripwire` | 20 tests, all new modules | PASS |
| Unit | `cargo test -p dlp-agent dacl_repair_watcher` | 18 tests | PASS |
| Unit | `cargo test -p dlp-agent dacl_staging` | 15 tests | PASS |
| Unit | `cargo test -p dlp-server protected_paths` | 19 repository + admin API tests | PASS |
| Unit | `cargo test -p dlp-common audit` | 62 audit routing tests | PASS |
| Integration | `cargo test -p dlp-server admin_api::tests -- --test-threads=1` | 154 admin API CRUD + payload tests | PASS |
| Static | `cargo clippy -p dlp-agent -p dlp-common -p dlp-server -- -D warnings` | Linting across modified crates | PASS |
| Documentation | `test -f docs/operations/dpapi-recovery.md` | Runbook existence | PASS |

## Test Strategy

### Per-Requirement Test Map

| Req ID | Behavior | Test Type | Automated Command | File | Status |
|--------|----------|-----------|-------------------|------|--------|
| DACL-01 | Tripwire writer applies Deny ACE to protected path | unit | `cargo test -p dlp-agent dacl_tripwire` | dlp-agent/src/dacl_tripwire.rs | COVERED |
| DACL-01 | 60 KB ACL guard rejects oversized ACLs | unit | `cargo test -p dlp-agent dacl_tripwire::test_acl_size_guard_rejects_oversized` | dlp-agent/src/dacl_tripwire.rs | COVERED |
| DACL-01 | Authenticated Users SID constructed via CreateWellKnownSid | unit | `cargo test -p dlp-agent dacl_tripwire::test_build_deny_authusers_dacl_sid` | dlp-agent/src/dacl_tripwire.rs | COVERED |
| DACL-01 | Recursive walk fail-closed at 10,000 files | unit | `cargo test -p dlp-agent dacl_tripwire::test_recursive_walk_limit_fail_closed` | dlp-agent/src/dacl_tripwire.rs | COVERED |
| DACL-01 | walkdir skips junctions/symlinks | unit | `cargo test -p dlp-agent dacl_tripwire::test_walkdir_skips_junctions` | dlp-agent/src/dacl_tripwire.rs | COVERED |
| DACL-01 | remove_tripwire_from_path restores ACL from SDDL snapshot | unit | `cargo test -p dlp-agent dacl_tripwire::test_remove_tripwire_restores_acl` | dlp-agent/src/dacl_tripwire.rs | COVERED |
| DACL-01 | Access-control proof matrix (SYSTEM/DLP-Admin full, AuthUsers denied) | unit | `cargo test -p dlp-agent dacl_tripwire::test_access_control_matrix_*` | dlp-agent/src/dacl_tripwire.rs | COVERED |
| DACL-02 | Repair watcher detects ACL tamper and restores | integration | `cargo test -p dlp-agent dacl_repair_watcher` | dlp-agent/src/dacl_repair_watcher.rs | COVERED |
| DACL-02 | 60s polling backstop catches missed events | integration | `cargo test -p dlp-agent dacl_repair_watcher::test_poll_backstop_detects_mismatch` | dlp-agent/src/dacl_repair_watcher.rs | COVERED |
| DACL-02 | Debounce batches rapid ACL changes | integration | `cargo test -p dlp-agent dacl_repair_watcher::test_debounce_batches_rapid_changes` | dlp-agent/src/dacl_repair_watcher.rs | COVERED |
| DACL-02 | DaclTamperDetected audit emitted on repair failure | integration | `cargo test -p dlp-agent dacl_repair_watcher::test_repair_acl_emits_audit` | dlp-agent/src/dacl_repair_watcher.rs | COVERED |
| DACL-03 | Admin API CRUD for protected paths | unit | `cargo test -p dlp-server admin_api::tests` | dlp-server/src/admin_api.rs | COVERED (tests exist; execution blocked by unrelated compile errors) |
| DACL-03 | Agent config sync includes protected paths | unit | `cargo test -p dlp-server admin_api::tests::test_protected_paths_agent_config_includes_protected_paths` | dlp-server/src/admin_api.rs | COVERED (tests exist; execution blocked by unrelated compile errors) |
| DACL-04 | Staging row suppresses tamper alert on removal | integration | `cargo test -p dlp-agent dacl_repair_watcher::test_staging_removal_suppresses_alert` | dlp-agent/src/dacl_repair_watcher.rs | COVERED |
| DACL-04 | GC removes expired staging rows after 5 min | integration | `cargo test -p dlp-agent dacl_staging::test_gc_removes_expired_applied_rows` | dlp-agent/src/dacl_staging.rs | COVERED |
| DACL-04 | Removal application task applies staged removals | integration | `cargo test -p dlp-agent dacl_staging::test_batch_stage_removals` + service.rs tests | dlp-agent/src/dacl_staging.rs, dlp-agent/src/service.rs | COVERED |
| DACL-04 | Per-path locking serializes concurrent operations | integration | `cargo test -p dlp-agent dacl_staging::test_per_path_lock_serializes_concurrent_ops` | dlp-agent/src/dacl_staging.rs | COVERED |
| DACL-05 | DPAPI recovery runbook exists and is readable | doc | `test -f docs/operations/dpapi-recovery.md` | docs/operations/dpapi-recovery.md | COVERED |

### Sampling Rate

- **Per task commit:** `cargo test -p dlp-agent dacl_tripwire` (quick filter)
- **Per wave merge:** `cargo test -p dlp-agent` + `cargo test -p dlp-server protected_paths` (when workspace compile errors resolved)
- **Phase gate:** Package-scoped tests green; workspace-wide gates pending resolution of unrelated issues

### Wave 0 Gaps (Closed)

- [x] `dlp-agent/src/dacl_tripwire.rs` — module creation + 20 unit tests
- [x] `dlp-agent/src/dacl_repair_watcher.rs` — module creation + 18 unit tests
- [x] `dlp-agent/src/dacl_staging.rs` — module creation + 15 unit tests
- [x] `dlp-server/src/db/repositories/protected_paths.rs` — repository + 15 CRUD tests
- [x] `dlp-server/src/admin_api.rs` — admin API CRUD + 5 protected_paths tests
- [x] `dlp-common/src/audit.rs` — add `DaclTamperDetected` and `DaclTripwireTooLarge` variants + 5 tests
- [x] `docs/operations/dpapi-recovery.md` — runbook creation

## Verification Checklist

- [x] `cargo test -p dlp-server protected_paths` passes (19/19)
- [x] `cargo test -p dlp-common audit` passes (62/62)
- [x] `cargo test -p dlp-server admin_api::tests` passes (154/154, 2 ignored)
- [x] `cargo test --workspace` passes (all crates, all tests green)
- [x] `cargo build --workspace` succeeds with zero warnings
- [x] `cargo clippy --workspace -- -D warnings` clean
- [x] No `unwrap()` in new Phase 52 library code paths
- [x] All public functions in Phase 52 modules have doc comments
- [x] `docs/operations/dpapi-recovery.md` exists with both recovery flows
- [x] ROADMAP.md Phase 52 shows all plans complete

## Manual-Only / Escalated Items

None. All Phase 52 requirements have automated test coverage.

## Validation Audit 2026-06-28 (Re-audit after blocker resolution)

| Metric | Count |
|--------|-------|
| Gaps found | 0 (Phase 52 requirements) |
| Resolved | 0 |
| Escalated | 0 |
| Workspace gate blockers | 0 (previously 3, resolved via dlp-rust-539) |

### Previously Blocked Workspace Gates — Now PASS

The three unrelated workspace gate blockers identified in the 2026-06-28 audit were resolved under beads issue `dlp-rust-539` ("Fix workspace-wide test/clippy gate blockers"):

1. **dlp-server test compile errors** — RESOLVED
   - Missing struct fields (`chain_hash`, `prev_hash`, `diagnostic_store`, `content_sha256`, `pid`) were added to test initializers across `dlp-server` and `dlp-common`.
   - Verification: `cargo test -p dlp-server protected_paths` → 19 passed.

2. **dlp-common test compile error** — RESOLVED
   - Missing `pid` field in `HookRequest` initializer was added.
   - Verification: `cargo test -p dlp-common audit` → 62 passed.

3. **dlp-agent clippy type_complexity** — RESOLVED
   - `health_aggregator.rs:77` complex `alert_router` field was extracted into `type AlertRouterSlot`.
   - Verification: `cargo clippy --workspace -- -D warnings` → clean.

### Full Workspace Verification

| Gate | Command | Result |
|------|---------|--------|
| Build | `cargo build --workspace` | PASS (zero warnings) |
| Clippy | `cargo clippy --workspace -- -D warnings` | PASS |
| Tests | `cargo test --workspace` | PASS (all crates green, 0 failures) |

### Generated Test Files

No new test files were generated. The re-audit confirmed all Phase 52 requirements retain automated coverage and no Nyquist gaps exist.

## Validation Audit 2026-06-28

| Metric | Count |
|--------|-------|
| Gaps found | 0 (Phase 52 requirements) |
| Resolved | 0 |
| Escalated | 0 |
| Workspace gate blockers | 3 |

### Workspace Gate Blockers (Unrelated to Phase 52)

1. **dlp-server test compile errors**
   - Files: `dlp-server/src/alert_router.rs`, `dlp-server/src/audit_store.rs`, `dlp-server/src/db/repositories/audit_events.rs`
   - Errors: missing fields `chain_hash`, `prev_hash`, `diagnostic_store`, `content_sha256` in struct initializers
   - Impact: `cargo test -p dlp-server protected_paths` and `cargo test -p dlp-server admin_api::tests` cannot run

2. **dlp-common test compile error**
   - File: `dlp-common/src/hook_ipc.rs:592`
   - Error: missing field `pid` in `HookRequest` initializer
   - Impact: `cargo test -p dlp-common audit` cannot run

3. **dlp-agent clippy type_complexity**
   - File: `dlp-agent/src/health_aggregator.rs:77`
   - Warning: very complex type used for `alert_router` field
   - Impact: `cargo clippy --workspace -- -D warnings` fails

These blockers prevent workspace-wide verification commands from executing but do not indicate missing Phase 52 test coverage. Resolution is tracked separately.

## Validation Audit 2026-06-28 (Re-validation run)

| Metric | Count |
|--------|-------|
| Gaps found | 0 (Phase 52 requirements) |
| Resolved | 0 |
| Escalated | 0 |
| Workspace gate blockers | 0 |

### Full Workspace Verification

| Gate | Command | Result |
|------|---------|--------|
| Build | `cargo build --workspace` | PASS (zero warnings) |
| Clippy | `cargo clippy -p dlp-agent -p dlp-common -p dlp-server -- -D warnings` | PASS |
| Tests | `cargo test -p dlp-agent dacl_tripwire` | PASS (20/20) |
| Tests | `cargo test -p dlp-agent dacl_repair_watcher` | PASS (18/18) |
| Tests | `cargo test -p dlp-agent dacl_staging` | PASS (15/15) |
| Tests | `cargo test -p dlp-server protected_paths` | PASS (19/19) |
| Tests | `cargo test -p dlp-common audit` | PASS (62/62) |
| Tests | `cargo test -p dlp-server admin_api::tests -- --test-threads=1` | PASS (154/154, 2 ignored) |
| Tests | `cargo test --workspace` | PASS (all crates green, 0 failures) |
| Documentation | `test -f docs/operations/dpapi-recovery.md` | PASS |

### Generated Test Files

No new test files were generated. The re-validation confirmed all Phase 52 requirements retain automated coverage and no Nyquist gaps exist.

## Sign-Off

- **Phase 52 Nyquist status:** COMPLIANT (all Phase 52 requirements have automated tests)
- **Workspace verification:** PASS (all workspace gates green after dlp-rust-539)
- **Recommended next step:** Phase 52 validation is complete; no further action required
