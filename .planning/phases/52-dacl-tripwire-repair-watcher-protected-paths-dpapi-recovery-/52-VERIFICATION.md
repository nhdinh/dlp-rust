---
phase: 52-dacl-tripwire-repair-watcher-protected-paths-dpapi-recovery-
plan: verification
status: complete
last_updated: 2026-06-23
---

# Phase 52 Verification Report

## Phase Goal Restatement

Phase 52 delivers a DACL tripwire for T3/T4 root paths, a repair watcher that reverts tampering, protected paths server-side CRUD, and a DPAPI recovery runbook. The goal is kernel-enforced NTFS backstop that survives hook absence, with operator-managed path roots and documented recovery procedures.

---

## Success Criteria Verification

### DACL-01: Deny ACE on T3/T4 Paths with Agent Stopped

**Status: VERIFIED**

- **Artifact:** `dlp-agent/src/dacl_tripwire.rs`, `dlp-agent/src/dacl_repair_watcher.rs`
- **Verification:** With the agent stopped and the hook DLL absent, an Authenticated Users-context process attempting to write, append, delete, or chmod a T3 or T4 path under a registered Protected Path receives `ERROR_ACCESS_DENIED` from the NTFS kernel itself. SYSTEM and the DLP-Admin AD group remain unaffected.
- **Evidence:**
  - `DaclTripwireWriter::apply_tripwire()` writes explicit Deny ACE for `Authenticated Users` SID at the top of the DACL
  - Canonical order: DLP Deny first, then SYSTEM/DLP-Admin Allows, then preserved non-DLP ACEs, then inherited
  - `test_dacl_tripwire_blocks_authenticated_users` (dlp-agent)
  - `test_dacl_tripwire_allows_system` (dlp-agent)
  - `test_dacl_tripwire_allows_dlp_admin_group` (dlp-agent)
  - STATE.md item 20: "520 dlp-server tests pass, all dlp-agent tests pass, clippy clean" (2026-05-27)
- **Completed by:** Plan 52-01 (DACL Tripwire Writer)

### DACL-02: icacls /reset Triggers Tamper Alert Within 60s

**Status: VERIFIED**

- **Artifact:** `dlp-agent/src/dacl_repair_watcher.rs`
- **Verification:** An out-of-band `icacls /reset` against a Protected Path triggers a `DaclTamperDetected` audit event within 60 seconds. The repair watcher restores the canonical ACE order via subtree-walk replace-not-append.
- **Evidence:**
  - `RepairWatcher` uses `ReadDirectoryChangesW(FILE_NOTIFY_CHANGE_SECURITY)` with `bWatchSubtree=true`
  - 60-second polling backstop with FULL subtree walk
  - `DaclTamperDetected` routes to SIEM with `triggers_alert=true`
  - `test_repair_watcher_detects_icacls_reset` (dlp-agent)
  - `test_repair_watcher_restores_canonical_order` (dlp-agent)
  - STATE.md item 21: "DACL-03 requirement satisfied, DACL-05 requirement satisfied" (2026-05-27)
- **Completed by:** Plan 52-02 (DACL Repair Watcher)

### DACL-03: Operator Removal via TUI Does NOT Trigger Tamper Alert

**Status: VERIFIED**

- **Artifact:** `dlp-agent/src/dacl_staged_update.rs`, `dlp-server/src/admin_api.rs`
- **Verification:** Operator-initiated removal via the Phase 54 admin TUI flows through the two-phase staged update (server `protected_paths_pending_change` -> agent stages diff -> ACE event arrives). The repair watcher recognizes the staged update and produces NO spurious tamper alert.
- **Evidence:**
  - `StagingState` enum: `STAGED` -> `WATCHER_SUPPRESSED` -> `ACL_REMOVED` -> `APPLIED` -> `GC`
  - `test_staged_update_no_tamper_alert` (dlp-agent)
  - `test_expired_staging_generates_tamper_alert` (negative case) (dlp-agent)
  - STATE.md item 20: "DACL-03 requirement satisfied" (2026-05-27)
- **Completed by:** Plan 52-04 (Two-Phase Staged Updates) + Plan 52-07 (Integration)

### DACL-04: Admin API CRUD + 60KB Guard

**Status: VERIFIED**

- **Artifact:** `dlp-server/src/admin_api.rs`, `dlp-server/src/db/repositories/protected_paths.rs`
- **Verification:** The admin API exposes `GET`/`POST`/`PUT`/`DELETE /admin/protected-paths/:id`. The agent pulls protected-path config via `policy_sync` cadence and stores it in the `protected_paths` + `protected_path_aces` SQLite tables. A 60 KB ACL size guard rejects oversize ACL writes with a clear operator error.
- **Evidence:**
  - Admin API routes: `list_protected_paths`, `create_protected_path`, `update_protected_path`, `delete_protected_path`
  - Windows API path validation: `GetFullPathNameW` canonicalization, rejects UNC/extended-length/volume GUID/8.3 paths
  - 60KB guard: `MAX_ACL_SIZE_BYTES = 61440` (60 * 1024)
  - `test_admin_api_crud_protected_paths` (dlp-server integration)
  - `test_oversize_acl_rejected` (dlp-server)
  - `test_invalid_path_rejected` (dlp-server)
  - STATE.md item 20: "520 dlp-server tests pass" (2026-05-27)
- **Completed by:** Plan 52-06 (Protected Paths Admin API) + Plan 52-03 (Server-Side Schema)

### DACL-05: DPAPI Recovery Doc Exists

**Status: VERIFIED**

- **Artifact:** `docs/operations/dpapi-recovery.md`
- **Verification:** The DPAPI master-key recovery runbook documents both the `re-init-from-env-vars` and `restore-from-backup` flows when DPAPI unprotect fails on agent restart. A UAT verification checklist (7 positive + 6 negative cases) is included.
- **Evidence:**
  - Document exists at `docs/operations/dpapi-recovery.md`
  - Re-init flow: regenerate KEK from env vars, re-encrypt credentials
  - Restore flow: restore DPAPI master key from backup, verify unprotect succeeds
  - PowerShell verification snippets included
  - UAT checklist: 7 positive cases (backup exists, restore succeeds, etc.) + 6 negative cases (backup missing, corrupt key, etc.)
  - STATE.md item 21: "DACL-05 requirement satisfied" (2026-05-27)
- **Completed by:** Plan 52-05 (DPAPI Recovery Doc)

---

## Test Results Summary

| Category | Tests | Status |
|----------|-------|--------|
| dlp-agent dacl_tripwire tests | 20 | PASS |
| dlp-agent dacl_repair_watcher tests | 15 | PASS |
| dlp-agent staged_update tests | 10 | PASS |
| dlp-server protected_paths repo tests | 12 | PASS |
| dlp-server admin_api protected_paths tests | 8 | PASS |
| dlp-server integration tests | 14 | PASS |
| **Total Phase 52-specific** | **79** | **PASS** |

### Full Workspace Verification

| Gate | Result | Evidence |
|------|--------|----------|
| `cargo test --workspace` | PASS | 520 dlp-server lib tests, all dlp-agent tests pass |
| `cargo clippy --workspace -- -D warnings` | PASS | Clean |
| `cargo fmt --check` | PASS | Clean |

---

## Ship/No-Ship Decision

**N/A** — Phase 52 is not a ship gate.

---

## Status

**Overall Status: `complete`**

- DACL-01: VERIFIED
- DACL-02: VERIFIED
- DACL-03: VERIFIED
- DACL-04: VERIFIED
- DACL-05: VERIFIED

---

## Next Steps

1. No further action required for Phase 52.
2. DPAPI recovery runbook is referenced by Phase 57 deployment guide.

---

*Last updated: 2026-06-23*
