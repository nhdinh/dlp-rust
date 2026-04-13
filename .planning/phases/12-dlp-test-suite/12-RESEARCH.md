# Phase 12: Comprehensive DLP Test Suite — Research

**Phase:** 12
**Research:** Lightweight — test suite planning, not feature implementation
**Date:** 2026-04-13

## Test Coverage Gap Analysis

### Already Implemented (Phase 04.1 covered)

| Surface | Module | Test Status |
|---------|--------|-------------|
| File open | `dlp-common/src/classifier.rs` | Covered by Phase 04.1 (classify_text/file) |
| File copy/move | `dlp-agent/src/detection/file_monitor.rs` | Covered (usb + network share E2E) |
| Clipboard paste | `dlp-agent/src/clipboard/classifier.rs` | Covered by Phase 04.1 |
| File save/overwrite | `dlp-agent/src/detection/file_monitor.rs` | Partially covered |
| File delete | `dlp-agent/src/detection/file_monitor.rs` | Not explicitly covered |

### Partially Implemented (Phase 4 email)

The alert router (`dlp-server/src/alert_router.rs`) has `send_email` functionality wired to `DenyWithAlert` decisions. The SMTP implementation uses `lettre`. Email interception (outbound email scanning before send) is NOT implemented — that's a different architecture from alert routing.

**TC-20–24 test approach:**
- TC-20, TC-22: Preventive allow/block tests using existing classify_text logic
- TC-21, TC-23, TC-24: Block + alert tests that verify audit events are emitted with correct classification
- Email send interception itself is not in scope — tests validate the audit event emission path

### Not Implemented (Cloud, Print, Bulk Detection, Working Hours)

| TC | Feature | Status | Blocker Phase |
|----|---------|--------|-------------|
| TC-30–33 | Cloud upload/share monitoring | Not implemented | Future |
| TC-50–52 | Print spooler interception | Not implemented | Future |
| TC-80 | Confidential file access logging | Audit available | None |
| TC-81 | Bulk download detection | Not implemented | Future |
| TC-82 | Working-hours access control | Not implemented | Phase 7 (AD) |

## Architecture Notes

### Test Structure Decision

Tests follow the established Phase 04.1 pattern:
- `dlp-agent/tests/comprehensive.rs` — agent-side tests (file ops, clipboard, USB, classification, detective controls)
- `dlp-server/src/admin_api.rs` inline tests — server-side evaluation (policy enforcement, audit event flow)

Group B tests for unimplemented features use `todo!()` macros to define the acceptance contract. This is intentional — the tests document the expected behavior before the features are built.

### Naming Convention

All tests follow `fn tc_<id>_<scenario>()` pattern per D-06 in CONTEXT.md. Scenario descriptions are short (max 50 chars for function name), using snake_case.

### Key Implementation Notes

1. **Email tests (TC-20–24):** Test the audit event emission path, not the SMTP send path. The alert router handles email; TC-21/23/24 validate that DenyWithAlert is triggered at the right classification tier.

2. **TC-51 `require_auth`:** No `require_auth` interception layer exists yet. Test documents the expected behavior as a TODO with the Phase that will implement it noted.

3. **TC-81 bulk download:** "Bulk" threshold detection is not implemented. Test uses a comment noting the threshold (e.g., 10 files in 60 seconds) as the acceptance criterion.

4. **TC-82 working-hours:** Requires AD integration (Phase 7). Mark `#[ignore = "requires AD working-hours (Phase 7)"]`.

## Validation Architecture

Tests are organized by enforcement surface:

```
dlp-agent/tests/comprehensive.rs
  mod file_ops_tc (TC-01, 10, 11, 12, 13, 14, 40, 41, 42, 60, 61, 62, 70, 71, 72)
  mod email_alert_tc (TC-20, 21, 22, 23, 24)
  mod cloud_tc (TC-30, 31, 32, 33) — todo!() stubs
  mod clipboard_tc (TC-40, 41, 42 — extend existing)
  mod print_tc (TC-50, 51, 52) — todo!() stubs
  mod detective_tc (TC-80, 81, 82)

dlp-server/src/admin_api.rs (inline tests)
  mod tc_server_eval (TC-01, 02, 03, 51, 52) — server-side enforcement
```

---

*Phase: 12-dlp-test-suite*
*Research: 2026-04-13*
*Status: READY FOR PLANNING*