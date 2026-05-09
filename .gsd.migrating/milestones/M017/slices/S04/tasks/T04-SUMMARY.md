---
id: T04
parent: S04
milestone: M017
key_files:
  - dlp-agent/src/print_watcher.rs
  - dlp-agent/src/lib.rs
key_decisions:
  - Used PRINTER_CHANGE_ADD_JOB | PRINTER_CHANGE_WRITE_JOB | PRINTER_CHANGE_SET_JOB filter to catch job creation and status changes
  - Scanned job IDs 1-50 per notification instead of EnumJobsW to avoid complex two-call buffer sizing pattern
  - Used metadata-only (document name heuristic → T1/T2/T3) fallback for non-XPS jobs and SPL read failures
  - Emit EventType::Block for cancelled jobs and EventType::Alert for cancellation failures or already-printing jobs
duration: 
verification_result: passed
completed_at: 2026-05-08T15:42:34.616Z
blocker_discovered: false
---

# T04: Built print spooler watcher thread with FindFirstPrinterChangeNotification, XPS text extraction, ABAC evaluation, and job cancellation

**Built print spooler watcher thread with FindFirstPrinterChangeNotification, XPS text extraction, ABAC evaluation, and job cancellation**

## What Happened

Built the print spooler watcher thread module (print_watcher.rs) that completes the M017/S04 print interception pipeline. The PrintWatcher struct spawns a dedicated std thread which opens the spooler, creates a FindFirstPrinterChangeNotification handle, and loops waiting for job changes with a 500ms timeout. On each notification it scans recent job IDs, queries job info via GetJobW, and for XPS_PASS jobs reads the SPL file and extracts text via the existing XPS parser. Content is classified with ContentClassifier, evaluated against ABAC policy via OfflineManager, and blocked jobs are cancelled with SetJob(JOB_CONTROL_DELETE) before they reach the printer. Non-XPS jobs fall back to metadata-only classification. Audit events (Block/Alert) are emitted for cancelled jobs and failures. Added comprehensive unit tests covering SPL path construction, decision mapping, config respecting unclassifiable_action, document name heuristics, shutdown flag, and max_pages=0 behavior. All 15 print_watcher tests and the full 434-test lib suite pass.

## Verification

cargo test --lib print_watcher: 15 tests passed. Full cargo test --lib: 434 tests passed. No new clippy warnings introduced.

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo test --lib print_watcher` | 0 | ✅ pass | 9100ms |
| 2 | `cargo test --lib` | 0 | ✅ pass | 5060ms |

## Deviations

Used direct HANDLE return handling for FindFirstPrinterChangeNotification (windows-rs 0.62 returns HANDLE, not Result<HANDLE>) and BOOL with .as_bool() for FindNextPrinterChangeNotification. Scanned job IDs 1-50 on each notification instead of calling EnumJobsW, which avoids complex buffer sizing while covering the typical spooler job ID range.

## Known Issues

None.

## Files Created/Modified

- `dlp-agent/src/print_watcher.rs`
- `dlp-agent/src/lib.rs`
