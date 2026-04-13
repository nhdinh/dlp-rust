# Phase 12: Comprehensive DLP Test Suite — Context

**Gathered:** 2026-04-13
**Status:** Ready for planning
**Source:** User-provided test case table — 28 TCs across all DLP enforcement surfaces

<domain>
## Phase Boundary

Comprehensive test suite for all DLP enforcement surfaces across file operations,
email/SMTP, cloud, clipboard, print, and detective controls. 28 test cases mapped
from user requirements into two groups:

**Group A — Regression coverage (already implemented, covered by Phase 04.1 plans):**
- TC-01–03: File open (allowed/blocked by classification tier)
- TC-10–14: File copy/move (intra-system, cross-tier, USB)
- TC-40–42: Clipboard copy-paste between files
- TC-60–62: Save/save_as/overwrite operations
- TC-70–72: File delete (allow, log, secure delete by tier)

Phase 04.1 already implemented comprehensive tests for these (comprehensive.rs,
admin_api.rs inline tests, integration.rs E2E tests). This phase will add
regression tests explicitly covering the TC-* scenarios at the scenario level.

**Group B — Future-feature validation (features not yet implemented):**
- TC-20–24: Email/SMTP (send, forward, attach, external/internal routing)
- TC-30–33: Cloud upload/share (upload, share_link, public link, restricted)
- TC-50–52: Print interception (allow, require_auth, block by tier)
- TC-80–82: Detective controls (Confidential log, bulk download alert, working-hours)

Tests in Group B will be structured to validate the interface contract and
expected behavior — they may fail at runtime until the underlying features are
built, but they define the acceptance criteria for those features.
</domain>

<decisions>
## Implementation Decisions

### Scope — all 28 TCs included
- **D-01:** Include all 28 TCs from user table (Group A for regression, Group B for feature validation)
- **D-02:** Test location — `dlp-agent/tests/comprehensive.rs` for agent-side tests; `dlp-server/src/admin_api.rs` inline tests for server-side evaluation
- **D-03:** Group B tests marked with `#[cfg(test)]` and descriptive names matching TC-ID — they compile and define contracts, runtime failure is expected until features land

### Classification tiers — consistent with dlp-common
- **D-04:** Classification levels: Public (T1), Internal (T2), Confidential (T3), Restricted (T4)
- **D-05:** All TC assertions must reference the correct tier and expected control type (preventive/detective/corrective)

### Test naming convention
- **D-06:** Test function names match TC-ID: `fn tc_01_access_internal_file_with_permission()` etc.
- **D-07:** Each test documents `expected_result`, `control_type`, and `expected_behavior` from the TC table in a doc comment

### Group B handling — stubs vs full tests
- **D-08:** Email/cloud/print tests that reference unimplemented modules use `todo!()` or `unimplemented!()` with a comment referencing the blocking phase (Phase 4 for email, future phase for cloud/print)
- **D-09:** TC-80, TC-81, TC-82 (detective) tests are implementable now — bulk download detection and audit log querying are available; TC-82 requires AD working-hours from Phase 7, mark as `#[ignore = "requires AD (Phase 7)"]`

### Test data
- **D-10:** Use realistic enterprise DLP test data: credit card numbers, SSN patterns, API keys, PII — consistent with existing classifier test patterns
</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

- `dlp-agent/tests/comprehensive.rs` — existing test structure, naming conventions, mod block patterns
- `dlp-agent/src/clipboard/classifier.rs` — T4/T3 classification patterns for clipboard tests
- `dlp-agent/src/detection/mod.rs` — USB and network share public API
- `dlp-common/src/classifier.rs` — `classify_text`, `classify_file`, classification tier logic
- `dlp-server/src/admin_api.rs` — existing inline test patterns (helpers, app building, JWT)
- `dlp-server/src/alert_router.rs` — SMTP email interface (Phase 4 deliverable, currently stubs)
- `dlp-agent/src/detection/usb.rs` — USB block logic
- `.planning/phases/04.1-full-detection-and-intercept-test-suite/04.1-CONTEXT.md` — Phase 04.1 decisions (D-04, D-05 naming, #[cfg(windows)] strategy)
- `.planning/STATE.md` — project decisions (no hardcoded credentials, test patterns)
</canonical_refs>

<specifics>
## Specific Test Cases

| TC-ID | Scenario | Data Level | Source | Action | Dest | Expected | Control | Expected Behavior |
|-------|----------|-----------|--------|--------|------|----------|---------|-------------------|
| TC-01 | Access Internal file with permission | Internal | shared_drive | open | user | allowed | preventive | allow |
| TC-02 | Access Confidential without permission | Confidential | shared_drive | open | unauthorized | denied | preventive | block, log |
| TC-03 | Access Restricted by non-privileged user | Restricted | secure_folder | open | user | denied | preventive | block, alert |
| TC-10 | Copy Internal file within system | Internal | folder_A | copy | folder_B | allowed | preventive | allow |
| TC-11 | Copy Confidential to Internal | Confidential | secure_folder | copy | internal_folder | blocked | preventive | block, alert |
| TC-12 | Copy Restricted to Public | Restricted | secure_folder | copy | public_folder | blocked | preventive | block, log, alert |
| TC-13 | Move Confidential within same level | Confidential | folder_A | move | folder_B | allowed | preventive | allow |
| TC-14 | Copy Confidential to USB | Confidential | local_disk | copy | usb | blocked | preventive | block, log |
| TC-20 | Send Internal email | Internal | outlook | send_email | internal_user | allowed | preventive | allow |
| TC-21 | Send Confidential to external | Confidential | outlook | send_email | external | blocked | preventive | block, log, alert |
| TC-22 | Send Restricted internally | Restricted | outlook | send_email | internal_user | blocked | preventive | block |
| TC-23 | Attach Restricted file to email | Restricted | local_disk | attach_file | email | blocked | preventive | block, alert |
| TC-24 | Forward Confidential email externally | Confidential | email | forward | external | blocked | preventive | block |
| TC-30 | Upload Public file to cloud | Public | local_disk | upload | cloud | allowed | preventive | allow |
| TC-31 | Upload Confidential to cloud | Confidential | local_disk | upload | cloud | restricted | preventive | allow, monitor |
| TC-32 | Share Confidential via public link | Confidential | cloud | share_link | public | blocked | preventive | block, alert |
| TC-33 | Share Restricted file | Restricted | cloud | share | any | blocked | preventive | block |
| TC-40 | Copy Internal content between files | Internal | file_A | copy_paste | file_B | allowed | preventive | allow |
| TC-41 | Copy Confidential into Public file | Confidential | file_A | copy_paste | public_file | blocked | preventive | block |
| TC-42 | Copy Restricted into Internal file | Restricted | file_A | copy_paste | internal_file | blocked | preventive | block |
| TC-50 | Print Internal file | Internal | file | print | printer | allowed | preventive | allow |
| TC-51 | Print Confidential file | Confidential | file | print | printer | restricted | preventive | require_auth |
| TC-52 | Print Restricted file | Restricted | file | print | printer | blocked | preventive | block |
| TC-60 | Save new version of Confidential | Confidential | file | save_as | new_file | allowed | preventive | allow |
| TC-61 | Overwrite Public with Confidential | Confidential | file | overwrite | public_file | blocked | preventive | block |
| TC-62 | Save Restricted into Public folder | Restricted | file | save | public_folder | blocked | preventive | block |
| TC-70 | Delete Public file | Public | file | delete | recycle_bin | allowed | corrective | allow |
| TC-71 | Delete Confidential file | Confidential | file | delete | system | logged | detective | log |
| TC-72 | Delete Restricted file | Restricted | file | delete | system | secure_delete | corrective | secure_delete |
| TC-80 | Access Confidential file | Confidential | file | open | user | logged | detective | log |
| TC-81 | Bulk download Confidential files | Confidential | system | download | user | alert | detective | alert |
| TC-82 | Access Restricted outside working hours | Restricted | system | access | user | alert | detective | alert |
</specifics>

<deferred>
## Deferred Ideas

- Phase 4 (email/SMTP wiring) must land before TC-20–24 execute fully
- Cloud upload/share (TC-30–33) requires cloud monitoring implementation — no phase assigned yet
- Print interception (TC-50–52) requires print spooler interception — no phase assigned yet
- TC-82 working-hours detection requires AD integration (Phase 7)
</deferred>

---

*Phase: 12-dlp-test-suite*
*Context gathered: 2026-04-13 via /gsd-plan-phase*
