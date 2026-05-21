---
status: deferred
phase: 59-label-service
source:
  - 59-01-SUMMARY.md
  - 59-02-SUMMARY.md
  - 59-03-SUMMARY.md
  - 59-04-SUMMARY.md
started: "2026-05-21T04:00:00.000Z"
updated: "2026-05-21T04:00:00.000Z"
---

## Current Test

number: 1
name: Cold Start Smoke Test
expected: |
  Start the dlp-server from scratch with a fresh database. Server boots without errors, migrations complete, and the health check endpoint returns 200 OK.
awaiting: user response

## Tests

### 1. Cold Start Smoke Test
expected: Start dlp-server from scratch with fresh DB. Server boots, migrations complete, health check returns 200 OK.
result: [pending]

### 2. Create Label via Admin API
expected: POST /admin/labels with path="C:\\Documents\\secret.doc" and tier="T3" returns 201 Created with the new label's ID. The label shows state "Pending".
result: [pending]

### 3. Folder Inheritance
expected: Label parent folder "C:\\Documents" as T3 with no explicit label on "C:\\Documents\\file.txt". GET /admin/labels/tier?path=... for the child file returns Inherited T3 with parent_path pointing to "C:\\Documents".
result: [pending]

### 4. Strictest Tier Wins
expected: Label parent folder "C:\\Projects" as T4 (Restricted) and child file "C:\\Projects\\readme.txt" as T2 (Internal). Querying the child returns T4 (Inherited) because parent is stricter.
result: [pending]

### 5. Paginated Label Listing
expected: GET /admin/labels?limit=2&offset=0 returns exactly 2 labels with total count, limit, and offset fields. Next page with offset=2 returns the remaining labels.
result: [pending]

### 6. Label Expiration
expected: POST /admin/labels/{id}/expire on an active label changes its state to "Expired". A subsequent GET shows state="Expired". Attempting to expire again returns appropriate error.
result: [pending]

### 7. Transactional Audit on Mutations
expected: After creating or expiring a label, a corresponding audit event exists in the audit log with action type LabelCreate or LabelExpire, including the label path and tier.
result: [pending]

### 8. ABAC Label-Aware Evaluation
expected: With label_aware_evaluation_enabled=true in system config, a policy evaluation for a file path that has a T4 label returns DENY regardless of other ABAC conditions. Audit event shows ClassificationOverride.
result: [pending]

### 9. Admin TUI Label List with Pagination
expected: Open admin TUI, navigate to Label List screen. Screen shows labels in a scrollable table with pagination info "Page 1 of N | K per page" in the footer.
result: [pending]

### 10. TUI Expire Action with Confirmation
expected: In Label List screen, press 'x' on a label. A confirmation dialog appears showing the label's path and tier. Confirming expires the label and refreshes the list.
result: [pending]

## Summary

total: 10
passed: 0
issues: 0
pending: 10
skipped: 0

## Gaps

[none yet]
