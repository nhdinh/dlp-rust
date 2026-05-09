# S04: Print Spooler Interception — UAT

**Milestone:** M017
**Written:** 2026-05-09T00:14:43.485Z

# S04 UAT: Print Spooler Interception

## UAT Type
**Unit + Integration (mock-based)** — All test cases execute against mock/in-memory data without requiring a live Windows printer or elevated print spooler access. TC-50..52 verify the full classification→decision→audit-event pipeline using `ContentClassifier`, `OfflineManager`, and `AuditEvent` with realistic content fixtures.

## Not Proven By This UAT
- Live print job cancellation against a real Windows printer (requires physical/virtual printer and elevated service account)
- `FindFirstPrinterChangeNotification` notification loop under real spooler load
- XPS spool file parsing from an actual `.spl` file written by the spooler (only in-memory ZIP fixtures tested)
- Performance characteristics under high print volume (many concurrent jobs)
- Admin CLI display of `print_enabled` / `print_xps_timeout_ms` config (deferred to S05)
- Full end-to-end chain: user prints → spooler notified → job cancelled → audit event flows to SIEM (deferred to S05)

---

## Preconditions
- Build passes: `cargo build -p dlp-agent` exits 0 with zero warnings
- All lib tests pass: `cargo test --lib -p dlp-agent` exits 0
- Test fixtures in `comprehensive.rs` include T2 (internal), T3 (confidential), and T4 (restricted/PII with credit card number) content strings

---

## TC-50: T2 Internal Content — Print Allowed

**Scenario:** A document with T2 (Internal) text sensitivity is printed. The DLP engine should allow the job.

**Steps:**
1. Classify a string containing internal business text using `ContentClassifier::classify`.
2. Verify the result is `DataTier::T2` (Internal).
3. Construct an `EvaluateRequest` with `Action::PRINT` and T2 classification.
4. Evaluate via `OfflineManager::evaluate()`.
5. Verify the decision is `PolicyDecision::Allow` (or equivalent permissive decision).
6. Verify no `EventType::Block` audit event is emitted.

**Expected Outcome:** Decision = ALLOW; no cancellation; no Block audit event.

**Command:** `cargo test --test comprehensive print_tc_50_print_internal_allowed`

**Pass Criteria:** Exit 0, test passes.

---

## TC-51: T3 Confidential Content — Print Alerts and Cancels

**Scenario:** A document containing T3 (Confidential) text is printed. The DLP engine should deny with alert and cancel the job.

**Steps:**
1. Classify a string containing confidential business content using `ContentClassifier::classify`.
2. Verify the result is `DataTier::T3` (Confidential).
3. Construct an `EvaluateRequest` with `Action::PRINT` and T3 classification.
4. Evaluate via `OfflineManager::evaluate()`.
5. Verify the decision is `DenyWithAlert`.
6. Construct the resulting `AuditEvent`.
7. Verify `event_type == EventType::Alert`.
8. Verify `decision == Decision::DENY`.
9. Verify `action == Action::PRINT`.

**Expected Outcome:** Decision = DenyWithAlert; Alert audit event emitted; job cancelled.

**Command:** `cargo test --test comprehensive print_tc_51_print_confidential_require_auth`

**Pass Criteria:** Exit 0, test passes.

---

## TC-52: T4 Restricted/PII Content — Print Blocked

**Scenario:** A document containing T4 (Restricted) content including a credit card number (PII) is printed. The DLP engine should hard-block the job.

**Steps:**
1. Classify a string containing a credit card number using `ContentClassifier::classify`.
2. Verify the result is `DataTier::T4` (Restricted/PII detected).
3. Construct an `EvaluateRequest` with `Action::PRINT` and T4 classification.
4. Evaluate via `OfflineManager::evaluate()`.
5. Verify the decision is `Decision::DENY`.
6. Verify the job is in spooling state (status=0), enabling cancellation.
7. Construct the resulting `AuditEvent`.
8. Verify `event_type == EventType::Block`.
9. Verify `action == Action::PRINT`.
10. Verify `correlation_id` encodes the job ID for auditability.

**Expected Outcome:** Decision = DENY; Block audit event emitted with job ID in correlation_id; job cancelled.

**Command:** `cargo test --test comprehensive print_tc_52_print_restricted_blocked`

**Pass Criteria:** Exit 0, test passes.

---

## Edge Cases Verified by Unit Tests

| Test | Module | Scenario |
|------|--------|----------|
| `extract_text_max_pages_zero` | print_xps_parser | max_pages=0 returns empty string |
| `extract_text_no_fpage_entries` | print_xps_parser | ZIP with no .fpage returns empty |
| `extract_text_corrupted_xml_page` | print_xps_parser | Corrupted XML page skipped, others continue |
| `extract_text_case_insensitive_fpage` | print_xps_parser | Case-insensitive .fpage path matching |
| `is_job_printing_with_zero_status` | print_job_info | Status=0 → not printing (cancellable) |
| `is_job_printing_with_printing_bit` | print_job_info | JOB_STATUS_PRINTING bit set → printing |
| `stop_without_start_is_noop` | print_watcher | Stop before start does not panic |
| `print_enforcer_disabled_by_default` | print_enforcer | print_enabled=None → watcher not constructed |
| `update_enabled_false_to_true_logs_warning` | print_enforcer | Runtime enable logs warning, does not start watcher |
| `start_when_disabled_is_noop` | print_enforcer | start() when disabled is safe no-op |

---

## Run All S04 Tests

```bash
cargo test --test comprehensive print_tc
cargo test --lib print_job_info
cargo test --lib print_xps_parser
cargo test --lib print_watcher
cargo test --lib print_enforcer
```

All five commands must exit 0 for the UAT to pass.
