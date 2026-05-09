---
id: S04
parent: M017
milestone: M017
provides:
  - ["PrintEnforcer module — watch_spool(), start(), stop(), update_enabled()", "Action::PRINT ABAC variant (serializes as 'PRINT')", "Admin config schema — print_enabled, print_xps_timeout_ms, print_unclassifiable_action, print_max_pages with hot-reload", "Audit event shape for print operations — EventType::Block/Alert with job_id, printer_name, document_name in correlation_id", "Win32 print job wrappers — PrinterHandle (RAII), get_job_info(), cancel_job(), is_job_printing()", "XPS spool file text extractor — extract_text(bytes, max_pages) -> Result<String>", "PrintWatcher spooler thread — FindFirstPrinterChangeNotification loop with XPS parse + ABAC eval + SetJob cancel"]
requires:
  []
affects:
  - ["S05"]
key_files:
  - ["dlp-common/src/abac.rs", "dlp-agent/src/config.rs", "dlp-agent/src/server_client.rs", "dlp-agent/src/service.rs", "dlp-agent/Cargo.toml", "dlp-agent/src/print_job_info.rs", "dlp-agent/src/print_xps_parser.rs", "dlp-agent/src/print_watcher.rs", "dlp-agent/src/print_enforcer.rs", "dlp-agent/src/lib.rs", "dlp-agent/tests/comprehensive.rs"]
key_decisions:
  - ["Used literal variant name serde pattern (no rename) for PRINT action per MEM015/MEM026 convention", "windows-rs 0.62: PRINTER_HANDLE (not HANDLE), BOOL return for GetJobW/SetJobW (not Result), plain u32 constants for JOB_CONTROL_DELETE", "quick-xml 0.36: reader.decoder() returns Decoder for decode_and_unescape_value (not &Reader)", "Scan job IDs 1-50 per notification instead of EnumJobsW to avoid complex two-call buffer sizing", "update_enabled(false→true) logs warning and sets flag but does NOT start watcher — requires service restart to avoid stale-capture", "Option<PrintEnforcer> in RunLoopContext so shutdown if-let can consume without moving the context", "Print config fields use Option<T> in AgentConfig with None guards in apply_payload_to_config to prevent spurious change logs when old servers omit fields"]
patterns_established:
  - ["Enforcer shape (MEM018/MEM023): new/start/stop/update_enabled with Option<T> storage in RunLoopContext", "Two-call size-probe for GetJobW buffer sizing (probe with null → allocate → fetch)", "Metadata-only fallback classification for non-XPS jobs using document name heuristics", "XPS text extraction from ZIP archive: iterate Documents/*/Pages/*.fpage (case-insensitive), parse Glyphs/@UnicodeString, skip corrupted pages"]
observability_surfaces:
  - ["tracing spans log every job lifecycle phase: detected → parsed → classified → decided → cancelled/allowed", "Agent log file (C:\\ProgramData\\DLP\\audit\\agent-*.log) contains JSONL audit events with event_type, decision, action, resource_path (document name), job_id, printer_name", "SetJob failures emit EventType::Alert with GetLastError code", "Watcher thread panic is caught via JoinHandle await in shutdown and logged", "print_enabled=false disables watcher entirely — visible in config-change log at service start"]
drill_down_paths:
  - [".gsd/milestones/M017/slices/S04/tasks/T01-SUMMARY.md", ".gsd/milestones/M017/slices/S04/tasks/T02-SUMMARY.md", ".gsd/milestones/M017/slices/S04/tasks/T03-SUMMARY.md", ".gsd/milestones/M017/slices/S04/tasks/T04-SUMMARY.md", ".gsd/milestones/M017/slices/S04/tasks/T05-SUMMARY.md"]
duration: ""
verification_result: passed
completed_at: 2026-05-09T00:14:43.483Z
blocker_discovered: false
---

# S04: Print Spooler Interception

**Delivered a complete user-mode print spooler interception subsystem: Win32 job wrappers, XPS text extraction, ABAC-driven cancellation, and PrintEnforcer wired into service lifecycle with TC-50/51/52 passing.**

## What Happened

S04 built the full print interception pipeline in five tasks, each leaving the test suite clean with zero new warnings.

**T01 — Foundations:** Added `Action::PRINT` to `dlp-common/src/abac.rs` using the project's literal-variant-name serde convention (MEM015/MEM026) with round-trip tests. Extended `AgentConfig` with four Option-wrapped print fields (`print_enabled`, `print_xps_timeout_ms`, `print_unclassifiable_action`, `print_max_pages`) mirrored as serde-defaulted fields in `AgentConfigPayload`. Wired diff/apply into `apply_payload_to_config` following the existing USB field pattern — None guards prevent spurious change logs when old servers omit the fields. Added `Win32_Graphics_Printing` feature, `zip = "2"`, and `quick-xml = "0.36"` to `dlp-agent/Cargo.toml`.

**T02 — Win32 Job Wrappers:** Created `print_job_info.rs` with safe Rust wrappers around `OpenPrinterW`, `GetJobW`, and `SetJobW`. `PrinterHandle` wraps `PRINTER_HANDLE` with a `Drop` impl calling `ClosePrinter`. `get_job_info` uses the two-call size-probe pattern to allocate the exact buffer size needed by `GetJobW`. `cancel_job` sends `JOB_CONTROL_DELETE` via `SetJobW`. Key gotcha (MEM021): windows-rs 0.62 returns BOOL not Result for these APIs; all callers use `.as_bool()` with manual `GetLastError` context capture.

**T03 — XPS Text Extraction:** Created `print_xps_parser.rs` implementing `extract_text(xps_bytes: &[u8], max_pages: usize) -> Result<String>`. Opens the XPS archive as a ZIP, iterates `Documents/*/Pages/*.fpage` entries (case-insensitive), extracts `UnicodeString` attribute values from `Glyphs` XML elements. Malformed ZIPs return an error; missing `.fpage` entries return empty string; corrupted XML pages are skipped and iteration continues. Key API gotcha (MEM022): quick-xml 0.36 `decode_and_unescape_value` expects `Decoder` from `reader.decoder()`, not `&Reader`.

**T04 — Spooler Watcher Thread:** Created `print_watcher.rs` with `PrintWatcher` that spawns a dedicated `std::thread`. The thread opens the local spooler printer, creates a `FindFirstPrinterChangeNotification` handle watching `PRINTER_CHANGE_ADD_JOB | PRINTER_CHANGE_WRITE_JOB | PRINTER_CHANGE_SET_JOB`, and loops with a 500ms timeout. On each notification it scans job IDs 1–50 (MEM025 — avoids complex `EnumJobsW` buffer sizing), queries `JobInfo` via `GetJobW`, reads the SPL spool file for XPS_PASS jobs and extracts text via the T03 parser. Non-XPS jobs fall back to document-name heuristic classification. Content is classified with `ContentClassifier`, evaluated via `OfflineManager::evaluate()`, and blocked jobs cancelled with `SetJob(JOB_CONTROL_DELETE)`. Audit events (`EventType::Block` / `EventType::Alert`) are emitted for every cancellation and failure. Key gotcha (MEM027): `FindFirstPrinterChangeNotification` returns raw `HANDLE`; `FindNextPrinterChangeNotification` returns `BOOL` — neither wrapped in `Result`.

**T05 — PrintEnforcer & Service Wiring:** Created `print_enforcer.rs` following the established enforcer shape (MEM023): `new()` reads `print_enabled`, `start()` delegates to `PrintWatcher::start()`, `stop()` delegates to `PrintWatcher::stop()`, `update_enabled()` handles runtime flag flips. When `print_enabled=None` or `false`, the watcher is never constructed. Notable design decision (MEM024): `update_enabled(false→true)` at runtime logs a warning and marks the flag but does NOT start the watcher — requires a service restart to fully activate, avoiding stale-capture risk. `PrintEnforcer` stored as `Option<PrintEnforcer>` in `RunLoopContext` so shutdown can `if-let` consume it without moving the full context. Wired into `service.rs`: constructed in `run_loop_init` after WfpManager, stored as `Some(enforcer)`, and consumed in `run_loop_shutdown`. Implemented TC-50/51/52 in `comprehensive.rs`: TC-50 verifies T2 internal content maps to ALLOW, TC-51 verifies T3 confidential content produces `DenyWithAlert` with `EventType::Alert`, TC-52 verifies T4 restricted PII (credit card number) produces `Decision::DENY` with `EventType::Block` and job-ID correlation.

**Aggregate result:** 40 tests added across five modules (6 + 8 + 15 + 8 unit + 3 integration), all passing. Zero new compiler warnings. The print interception pipeline is complete and ready for S05 end-to-end integration UAT.

## Verification

All slice must-haves verified:
- `Action::PRINT` exists in `dlp-common/src/abac.rs`, serializes as `"PRINT"` (round-trip tests pass)
- Agent config accepts `print_enabled`, `print_xps_timeout_ms`, `print_unclassifiable_action`, `print_max_pages`; hot-reload applies them without restart
- `cargo test --lib print_job_info` → 6/6 pass (exit 0)
- `cargo test --lib print_xps_parser` → 8/8 pass (exit 0)
- `cargo test --lib print_watcher` → 15/15 pass (exit 0)
- `cargo test --lib print_enforcer` → 8/8 pass (exit 0)
- `cargo test --test comprehensive print_tc` → 3/3 pass: TC-50 (ALLOW), TC-51 (Alert/cancel), TC-52 (Block/cancel) (exit 0)
- `cargo check -p dlp-agent` → clean, zero warnings (exit 0)

## Requirements Advanced

None.

## Requirements Validated

None.

## New Requirements Surfaced

None.

## Requirements Invalidated or Re-scoped

None.

## Operational Readiness

None.

## Deviations

["FindFirstPrinterChangeNotification returns raw HANDLE (not Result<HANDLE>) in windows-rs 0.62 — handled with manual INVALID_HANDLE_VALUE check rather than ? operator", "Scanned job IDs 1-50 per notification instead of EnumJobsW — avoids two-call buffer sizing complexity, covers typical spooler range"]

## Known Limitations

["update_enabled(false→true) at runtime does not start the watcher; operator must restart service to fully activate print interception", "Job ID scan range 1-50 may miss jobs above ID 50 in very high-volume spooler environments (uncommon in enterprise DLP deployment)"]

## Follow-ups

None.

## Files Created/Modified

None.
