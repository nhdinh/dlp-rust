# S04: Print Spooler Interception

**Goal:** Deliver a user-mode print spooler interception subsystem that detects new print jobs, extracts text content from XPS spool files, classifies sensitivity, evaluates ABAC policy, and cancels blocked jobs before they reach the printer. Admin-configurable via existing config hot-reload.
**Demo:** Print a document containing T4 content — job is cancelled via SetJob(..., JOB_CONTROL_DELETE) before the printer receives it. Admin CLI shows print policy status.

## Must-Haves

- `Action::PRINT` exists in `dlp-common/src/abac.rs` and serializes as `"PRINT"`.
- Agent config accepts `print_enabled`, `print_xps_timeout_ms`, `print_unclassifiable_action`, and `print_max_pages`; hot-reload applies them without restart.
- `cargo test --lib print_job_info` passes: Win32 wrappers compile and unit tests verify `JobInfo` extraction.
- `cargo test --lib print_xps_parser` passes: inline XPS fixture is parsed and text extracted correctly.
- `cargo test --lib print_watcher` passes: watcher module compiles, helper logic (status checks, decision mapping) is unit-tested.
- `cargo test --test comprehensive print_tc` passes: TC-50 (ALLOW), TC-51 (Alert/cancel), TC-52 (Block/cancel) all pass.
- `cargo check -p dlp-agent` is clean with zero new warnings.

## Proof Level

- This slice proves: - **This slice proves:** integration — real Windows Print APIs (`FindFirstPrinterChangeNotification`, `GetJobW`, `SetJobW`) are exercised, XPS ZIP+XML parsing works on real spool file structure, and policy evaluation flows through `OfflineManager`.
- **Real runtime required:** yes — Windows print spooler APIs require a Windows host. Unit tests for XPS parser and job-info wrappers run without spooler. Watcher integration tests may require a local printer or mock handles.
- **Human/UAT required:** yes — TC-50..52 verify end-to-end classification and cancellation logic with mock data.

## Integration Closure

- **Upstream surfaces consumed:** `OfflineManager::evaluate()` (policy engine client), `AuditEvent`/`EmitContext` (audit pipeline), `AgentConfig`/`AgentConfigPayload` (config hot-reload), `ContentClassifier::classify()` (clipboard content classifier).
- **New wiring introduced:** `PrintEnforcer` constructed in `service.rs` `run_loop_init()`, stored in `RunLoopContext`, torn down in `run_loop_shutdown()`. Dedicated std thread spawned for `FindFirstPrinterChangeNotification` loop.
- **What remains before milestone E2E:** S02 (cloud sync interception with real sync paths), S03 (cloud share link detection), S05 (full integration UAT across cloud + print + audit).

## Verification

- **Runtime signals:** `tracing` spans in print watcher log every job lifecycle phase (detected → parsed → classified → decided → cancelled/allowed). Error logs include Windows `GetLastError` code on `SetJob`/`OpenPrinter` failure.
- **Inspection surfaces:** Agent log file (`C:\ProgramData\DLP\audit\agent-*.log`) contains structured JSONL audit events with `event_type: Block` or `Alert` for print operations, including `resource_path` (document name), `job_id`, and `printer_name`.
- **Failure visibility:** If the watcher thread panics, the `JoinHandle` is awaited in shutdown and any panic message is logged. `SetJob` failures emit `EventType::Alert` audit events with the failure reason. Config `print_enabled=false` disables the watcher entirely.
- **Redaction constraints:** XPS text content is parsed in-memory and never written to disk or logs; only document name, job ID, and classification tier appear in audit events.

## Tasks

- [x] **T01: Add ABAC PRINT action, config fields, and dependencies** `est:45m`
  Add the foundational types and dependencies needed by all subsequent print tasks.
  - Files: `dlp-common/src/abac.rs`, `dlp-agent/src/config.rs`, `dlp-agent/src/server_client.rs`, `dlp-agent/src/service.rs`, `dlp-agent/Cargo.toml`
  - Verify: cargo check -p dlp-agent passes with zero new warnings

- [x] **T02: Build Win32 print job info wrappers** `est:1h`
  Create safe Rust wrappers around `OpenPrinterW`, `GetJobW`, and `SetJobW` for querying and cancelling print jobs.
  - Files: `dlp-agent/src/print_job_info.rs`, `dlp-agent/src/lib.rs`
  - Verify: cargo test --lib print_job_info passes

- [x] **T03: Build XPS text extraction parser** `est:1h`
  Create a ZIP+XML parser that extracts text content from XPS spool files for classification.
  - Files: `dlp-agent/src/print_xps_parser.rs`, `dlp-agent/src/lib.rs`
  - Verify: cargo test --lib print_xps_parser passes

- [x] **T04: Build print spooler watcher thread** `est:1.5h`
  Create the core detection and cancellation loop. Spawns a dedicated std thread that watches the print spooler for new jobs using `FindFirstPrinterChangeNotification`.
  - Files: `dlp-agent/src/print_watcher.rs`, `dlp-agent/src/lib.rs`
  - Verify: cargo test --lib print_watcher passes

- [x] **T05: Integrate print enforcer into service and implement UAT tests** `est:1.5h`
  Build the `PrintEnforcer` wrapper, wire it into the agent service lifecycle, add audit event emission, and implement the TC-50..52 print interception tests.
  - Files: `dlp-agent/src/print_enforcer.rs`, `dlp-agent/src/lib.rs`, `dlp-agent/src/service.rs`, `dlp-agent/tests/comprehensive.rs`
  - Verify: cargo test --test comprehensive print_tc passes

## Files Likely Touched

- dlp-common/src/abac.rs
- dlp-agent/src/config.rs
- dlp-agent/src/server_client.rs
- dlp-agent/src/service.rs
- dlp-agent/Cargo.toml
- dlp-agent/src/print_job_info.rs
- dlp-agent/src/lib.rs
- dlp-agent/src/print_xps_parser.rs
- dlp-agent/src/print_watcher.rs
- dlp-agent/src/print_enforcer.rs
- dlp-agent/tests/comprehensive.rs
