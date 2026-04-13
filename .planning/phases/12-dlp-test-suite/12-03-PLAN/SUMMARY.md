# Phase 12-03 Summary — TC E2E Integration Tests

## Objective
Append 5 end-to-end pipeline integration tests to `dlp-agent/tests/integration.rs`
covering the full intercept-to-audit path for TC-11, TC-14, TC-21, TC-72, and TC-81.

---

## What Was Done

### Files Modified

| File | Change |
|------|--------|
| `dlp-agent/tests/integration.rs` | +420 lines — 5 TC E2E tests + 1 helper |
| `dlp-agent/src/detection/usb.rs` | `blocked_drives` field made `pub` with doc note (CI test seeding) |

### Files Created
| File | Purpose |
|------|---------|
| `.planning/phases/12-dlp-test-suite/12-03-PLAN/SUMMARY.md` | This document |

---

## Tests Added

### TC-11 — `test_tc_11_copy_confidential_to_internal_blocked_alert`
- Path: `C:\Data\confidential_copy.xlsx` → `PolicyMapper::provisional_classification` = **T3**
- `PolicyMapper::action_for(FileAction::Written)` = **Action::COPY**
- Mock engine returns `Decision::DenyWithAlert`
- `EventType::Alert` emitted; JSONL read-back asserts Alert / DenyWithAlert / T3

### TC-14 — `test_tc_14_copy_confidential_to_usb_blocked_log`
- `UsbDetector::blocked_drives.write().insert('F')` seeds blocked USB drive
- `should_block_write(r"F:\confidential_report.pdf", T3)` → **true**
- Mock engine returns `Decision::DENY`
- `EventType::Block` emitted; JSONL asserts Block / DENY / T3 / `resource_path` contains `F:`

### TC-21 — `test_tc_21_email_credit_card_blocked_alert`
- `ContentClassifier::classify("Card: 4111-1111-1111-1111 …")` → **T4**
- Mock engine returns `Decision::DenyWithAlert`
- `EventType::Alert` emitted; JSONL asserts Alert / DenyWithAlert / T4
- Uses `Action::WRITE` (closest available ABAC action; `Action::SEND_EMAIL` is future-phase)

### TC-72 — `test_tc_72_delete_restricted_secure_delete`
- `C:\Restricted\secret.xlsx` → `PolicyMapper::provisional_classification` = **T4**
- `FileAction::Deleted` → `PolicyMapper::action_for` = **Action::DELETE**
- Mock engine returns `Decision::DENY`
- `EventType::Alert` emitted; JSONL asserts Alert / DENY / T4 / DELETE
- Explicitly asserts `policy_name` contains `"secure_delete"`

### TC-81 — `test_tc_81_bulk_download_alert`
- Classifies 10 sensitive texts (CC numbers, SSNs, CONFIDENTIAL keywords)
- Asserts all 10 are `>= Classification::T3`
- Emits representative `EventType::Alert` with `Decision::ALLOW` (detective)
- JSONL asserts Alert / ALLOW / T3 / Action::READ

### Helper — `start_mock_engine_response(EvaluateResponse)`
- Reuses the existing `start_mock_engine(Decision)` pattern from line 23
- Starts a local axum router returning a configurable `EvaluateResponse`
- Bound to an ephemeral port; handle kept alive via `_h`

---

## Verification

| Check | Result |
|-------|--------|
| `cargo check --package dlp-agent --tests` | ✓ Compiles |
| `cargo clippy --package dlp-agent --tests -- -D warnings` | ✓ 0 warnings |
| `cargo fmt --check` | ✓ (auto-formatted) |
| `grep "fn test_tc_11" integration.rs` | 1 match |
| `grep "fn test_tc_14" integration.rs` | 1 match |
| `grep "fn test_tc_21" integration.rs` | 1 match |
| `grep "fn test_tc_72" integration.rs` | 1 match |
| `grep "fn test_tc_81" integration.rs` | 1 match |
| `grep "start_mock_engine_response" integration.rs` | present |

> **Note:** `cargo test` could not be executed in this session due to a held lock on
> `target/debug/dlp-agent.exe` from a prior test run. The lock must be released
> (close the locking process, or rename/remove the file) before tests can run.
> The code compiles and lints cleanly — see checks above.

---

## Design Notes

- **`blocked_drives` visibility**: Made `pub` (with doc comment) to allow integration
  tests to seed drives. `GetDriveTypeW` is unavailable in the test compilation
  environment; seeding bypasses that dependency.
- **`Action::WRITE` as email placeholder**: `Action::SEND_EMAIL` and `Action::DOWNLOAD`
  are not yet defined in `dlp-common/src/abac.rs`. `Action::WRITE` is used as the
  closest available variant; a future phase will add the correct enum variants.
- **`is_some_and` availability**: This is a nightly-only method on `Option` in older
  Rust; the minimum Rust version for this project includes it. Using `.as_ref()`
  and `.map()` would work on older toolchains if needed.
- **Bulk download detection**: The threshold-counting `BulkDownloadDetector` struct
  is unimplemented. TC-81 validates the classification prerequisite (10/10 texts
  T3+) and emits a representative audit event.
