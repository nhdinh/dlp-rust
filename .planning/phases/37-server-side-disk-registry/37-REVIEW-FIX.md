---
phase: 37-server-side-disk-registry
fixed_at: 2026-05-04T00:00:00Z
review_path: .planning/phases/37-server-side-disk-registry/37-REVIEW.md
iteration: 1
findings_in_scope: 7
fixed: 7
skipped: 0
status: all_fixed
---

# Phase 37: Code Review Fix Report

**Fixed at:** 2026-05-04T00:00:00Z
**Source review:** .planning/phases/37-server-side-disk-registry/37-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 7 (3 Critical, 4 Warning)
- Fixed: 7
- Skipped: 0

## Fixed Issues

### CR-01: `GET /admin/disk-registry` missing in-handler auth check

**Files modified:** `dlp-server/src/admin_api.rs`
**Commit:** 115e141
**Applied fix:** Converted `list_disk_registry_handler` from `(State, Query)` signature to
`(State, Request)` pattern. Added `AdminUsername::extract_from_headers(req.headers())?` as the
first statement, matching all other protected handlers. Updated 4 unit tests to use a new
`make_list_request()` helper that builds HTTP requests with Bearer auth headers.

Note: `AppError::from` did not cover `QueryRejection`, so the query param extraction
uses `.map_err(|e| AppError::BadRequest(e.to_string()))` instead.

---

### CR-02: Audit failure propagates as HTTP 500 after successful INSERT/DELETE

**Files modified:** `dlp-server/src/admin_api.rs`
**Commit:** 5de6ff2
**Applied fix:** Replaced the `??` double-propagation on the audit `spawn_blocking` result in
both `insert_disk_registry_handler` and `delete_disk_registry_handler` with an
`if let Err(e) = ... { tracing::warn!(...) }` pattern. Audit failures are now logged but
do not affect the 201/204 response, matching the D-10 contract stated in the doc comment.

---

### CR-03: No input length/content guards on POST body fields

**Files modified:** `dlp-server/src/admin_api.rs`
**Commit:** 52dce10
**Applied fix:** Added validation guards after the existing `encryption_status` checks:
- `agent_id` and `instance_id`: max 512 bytes
- `model`: max 256 bytes
- `bus_type`: allowlist check (`usb`, `sata`, `nvme`, `scsi`, `unknown`)

All return 422 Unprocessable Entity on violation. Updated handler doc comment to document
all validation rules.

---

### WR-01: `bus_type` JSON construction via `format!` without sanitization

**Files modified:** `dlp-server/src/admin_api.rs`
**Commit:** 412a9d4
**Applied fix:** Replaced `serde_json::from_str(&format!("\"{}\"", row.bus_type)).unwrap_or_default()`
with a direct exhaustive `match` on the string value. Maps `"usb"`, `"sata"`, `"nvme"`, `"scsi"`
to corresponding `BusType` variants; any other value falls back to `BusType::Unknown`. Eliminates
the JSON injection risk from DB values containing double-quotes or backslashes.

---

### WR-02: DB CHECK constraint mismatch with EncryptionStatus serde names

**Files modified:** `dlp-server/src/db/mod.rs`, `dlp-server/src/admin_api.rs`, `dlp-server/src/db/repositories/disk_registry.rs`
**Commits:** 943a710, f5b647c
**Applied fix:**
1. Updated `disk_registry` CHECK constraint from `('fully_encrypted', 'partially_encrypted', 'unencrypted', 'unknown')` to `('encrypted', 'suspended', 'unencrypted', 'unknown')` — the canonical `EncryptionStatus` serde names.
2. Removed the manual mapping in `disk_row_to_identity`; replaced with `serde_json::from_str` roundtrip (now works correctly since DB values match serde names).
3. Updated POST handler `VALID_STATUSES` allowlist and error message to use the new values.
4. Updated all test data, doc comments, and field documentation across three files to use the canonical names.

Note: The schema change uses `CREATE TABLE IF NOT EXISTS` so existing databases with old values need a drop+recreate of `disk_registry` before upgrading.

Note: The SQL comment initially included `"snake_case"` in double-quotes inside a non-raw Rust string literal, causing a compile error. Fixed by removing the quoted attribute name from the SQL comment.

---

### WR-03: TOCTOU race in delete handler (SELECT then DELETE)

**Files modified:** `dlp-server/src/admin_api.rs`
**Commit:** 5210a01
**Applied fix:** Replaced the two-step SELECT+DELETE (two separate pool acquisitions) with a
single atomic `DELETE FROM disk_registry WHERE id = ?1 RETURNING agent_id, instance_id`
statement executed within a `UnitOfWork` transaction. `QueryReturnedNoRows` maps to 404;
a returned row proceeds to the audit emission. Uses `uow.tx.query_row(...)` since
`UnitOfWork` exposes the transaction as `pub(crate) tx`.

---

### WR-04: Misleading comment about heartbeat interval timing

**Files modified:** `dlp-agent/src/service.rs`
**Commit:** 46a7c2d
**Applied fix:** Replaced the inaccurate one-liner ("The new interval takes effect after the
*next* tick completes") with a per-cycle breakdown explaining that the updated interval takes
effect on the third poll cycle (N+1), because `do_poll!()` reads `heartbeat_interval_secs`
from the already-updated in-memory config at the top of the next loop iteration.

---

## Skipped Issues

None — all 7 in-scope findings were fixed.

---

_Fixed: 2026-05-04T00:00:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
