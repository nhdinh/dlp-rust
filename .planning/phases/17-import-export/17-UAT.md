---
status: partial
phase: 17-import-export
source: [17-01-SUMMARY.md, 17-02-SUMMARY.md]
started: 2026-04-20T08:52:11Z
updated: 2026-04-20T09:15:00Z
---

## Current Test

[testing paused — 7 items outstanding; resume after fix commit for GET /admin/policies -> /policies]

## Tests

### 1. PolicyMenu shows Import/Export entries
expected: PolicyMenu lists 9 entries with "Import Policies..." (row 7), "Export Policies..." (row 8), and "Back" (row 9).
result: pass

### 2. Export Policies opens native save dialog
expected: Select "Export Policies..." and press Enter. A native OS save dialog opens titled "Export Policies" with JSON filter and default filename `policies-export-YYYY-MM-DD.json` (today's date).
result: issue
reported: "Entered on 'Export Policies', error shown: 'Failed to fetch policies: GET http://127.0.0.1:9090/admin/policies returned 405 Method Not Allowed:'"
severity: blocker

### 3. Export writes file and shows success status
expected: In the save dialog, accept the default name and save. Control returns to PolicyMenu. The status bar shows a green message: `Exported N policies to {path}` where N matches the server's current policy count.
result: blocked
blocked_by: prior-phase
reason: "Depends on success of test 2 (Export save dialog) — currently blocked by GET /admin/policies 405."

### 4. Export cancel returns silently
expected: Select "Export Policies..." again; when the save dialog opens, press Cancel/Esc. Control returns to PolicyMenu with no status message (no error).
result: skipped

### 5. Import Policies opens native file picker
expected: Select "Import Policies..." and press Enter. A native OS file-open dialog opens titled "Import Policies" with a JSON filter.
result: pass

### 6. Import shows ImportConfirm with conflict diff
expected: In the file picker, select the file exported in test 3. Screen transitions to "Import Policies" confirmation. The screen shows (from top): bold white header "Import N policies?", dark-gray "X will overwrite existing entries", dark-gray "Y will be created as new", a [Confirm] button, a [Cancel] button. Because you just exported, X should equal N (all IDs exist) and Y should be 0.
result: issue
reported: "Failed to parse JSON file: invalid type: map, expected a sequence at line 1 column 0"
severity: major

### 7. ImportConfirm skip-nav between Confirm and Cancel
expected: On the ImportConfirm screen, press Up and Down repeatedly. The cursor cycles ONLY between [Confirm] and [Cancel] — the three informational rows at the top are not selectable. Selected button is styled (green bg for Confirm, red bg for Cancel).
result: [pending]

### 8. ImportConfirm Cancel returns to PolicyMenu
expected: On ImportConfirm, either press Esc or navigate to [Cancel] and press Enter. Screen returns to PolicyMenu. No policies were created or modified (list count unchanged).
result: [pending]

### 9. Import Confirm executes and shows Success block
expected: Open Import again, select the same exported file, navigate to [Confirm] and press Enter. The screen briefly shows a yellow "Working / Importing policies..." block, then a green "Import Complete" block with `Imported N policies (X new, Y updated).` matching the conflict diff shown earlier.
result: [pending]

### 10. Import dismisses to PolicyMenu on Enter/Esc after success
expected: On the Success terminal state, press Enter (or Esc). Screen returns to PolicyMenu.
result: [pending]

### 11. Import error on malformed JSON aborts cleanly
expected: Create a file with invalid JSON (e.g., `{broken`) or a valid JSON file that is not an array of policies. Select "Import Policies..." and pick that file. The status bar shows a red error like `Failed to parse JSON file: ...` and control stays on PolicyMenu (no transition to ImportConfirm).
result: [pending]

### 12. Hints bar updates with ImportState
expected: On ImportConfirm in Pending state, the bottom hints bar shows "Up/Down: navigate | Enter: confirm | Esc: cancel". After Confirm executes and terminal state is reached (Success or Error), the hints bar shows "Enter/Esc: dismiss".
result: [pending]

## Summary

total: 12
passed: 2
issues: 2
pending: 7
skipped: 1
blocked: 1

## Gaps

- truth: "Export Policies fetches the current policy set via the admin API before opening the save dialog"
  status: failed
  reason: "User reported: Entered on 'Export Policies', error shown: 'Failed to fetch policies: GET http://127.0.0.1:9090/admin/policies returned 405 Method Not Allowed:'"
  severity: blocker
  test: 2
  root_cause: ""
  artifacts: []
  missing: []
  debug_session: ""

- truth: "Import parses a valid policies-export JSON file (array of PolicyResponse) and transitions to ImportConfirm"
  status: failed
  reason: "User reported: Failed to parse JSON file: invalid type: map, expected a sequence at line 1 column 0. (Likely the user-picked JSON was a map/object, not a top-level array — either the export file format is wrong or the import expectation mismatches the server's GET /policies response shape.)"
  severity: major
  test: 6
  root_cause: ""
  artifacts: []
  missing: []
  debug_session: ""
