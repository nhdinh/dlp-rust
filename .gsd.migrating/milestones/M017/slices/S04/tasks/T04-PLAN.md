---
estimated_steps: 47
estimated_files: 2
skills_used: []
---

# T04: Build print spooler watcher thread

Create the core detection and cancellation loop. Spawns a dedicated std thread that watches the print spooler for new jobs using `FindFirstPrinterChangeNotification`.

**Steps:**
1. Create `dlp-agent/src/print_watcher.rs`.
2. Define `PrintWatcher` struct with fields:
   - `offline: Arc<crate::offline::OfflineManager>`
   - `audit_ctx: crate::audit_emitter::EmitContext`
   - `runtime_handle: tokio::runtime::Handle`
   - `shutdown: Arc<std::sync::atomic::AtomicBool>`
   - `handle: Option<std::thread::JoinHandle<()>>`
3. Implement `new(offline, audit_ctx, runtime_handle) -> Self`.
4. Implement `start(&mut self)`:
   - Spawn std thread.
   - In thread: open local printer with `open_printer` (from `print_job_info`).
   - Call `FindFirstPrinterChangeNotification` with `PRINTER_CHANGE_ADD_JOB | PRINTER_CHANGE_WRITE_JOB | PRINTER_CHANGE_SET_JOB`.
   - Loop: `WaitForSingleObject(notification_handle, 500)` and check `shutdown.load(Ordering::Relaxed)`.
   - On signaled: `FindNextPrinterChangeNotification`, then enumerate jobs with `EnumJobsW` (Level 1) or query specific job IDs from the change notification info.
   - For each new job: call `get_job_info`, check `datatype`.
   - If `datatype == "XPS_PASS"`: construct SPL path (`C:\Windows\System32\spool\PRINTERS\{job_id}.SPL`), read file, call `extract_text` with `max_pages` from config, classify with `crate::clipboard::ContentClassifier::classify()`.
   - Else: metadata-only classification (document name heuristic → T1 default).
   - Build `EvaluateRequest` with `Action::PRINT`, call `self.runtime_handle.block_on(self.offline.evaluate(&request))`.
   - On `DENY` or `DenyWithAlert`: check `is_job_printing(job.status)`; if false, call `cancel_job`; else emit Alert audit event (job already printing).
   - On `ALLOW` or `AllowWithLog`: allow job to proceed.
   - Emit `EventType::Block` audit event for cancelled jobs; `EventType::Alert` for require_auth or cancellation failures.
5. Implement `stop(&mut self)`:
   - Set `shutdown` AtomicBool to true.
   - `take()` the `JoinHandle` and `join()` it.
6. Add `#[cfg(windows)] pub mod print_watcher;` to `dlp-agent/src/lib.rs`.
7. Write unit tests for helper logic:
   - `build_spl_path(job_id)` returns correct path.
   - `decision_from_response` maps `EvaluateResponse` correctly.
   - `should_cancel_for_classification` respects `print_unclassifiable_action` config.

**Skills used:** rust-engineer, unsafe-checker, test

**Failure Modes:**
- `OpenPrinterW` fails → log error, retry on next iteration.
- `FindFirstPrinterChangeNotification` fails → log fatal error, thread exits.
- `SetJob` fails (job already printing) → emit Alert audit event, do not retry.
- `std::fs::read` on SPL file fails (file locked by spooler) → skip XPS parse, use metadata-only.
- `OfflineManager::evaluate` fails/unreachable → fall back to `cache::fail_closed_response` (offline mode), which defaults to DENY for sensitive content.

**Load Profile:**
- **Shared resources:** print spooler APIs are serialized by the spooler service itself.
- **Per-operation cost:** one `GetJobW`, one file read (SPL), one ZIP parse (first N pages), one `ContentClassifier::classify()`, one `OfflineManager::evaluate()`.
- **10x breakpoint:** `ContentClassifier` is CPU-bound text scanning; at 10x rapid print jobs, the watcher thread may backlog. Mitigation: 500ms polling loop naturally throttles.

**Negative Tests:**
- `shutdown=true` immediately after `start()` → thread exits cleanly within <1s.
- `max_pages=0` → no XPS parsing, metadata-only.
- `print_unclassifiable_action="ALLOW"` with EMF job → ALLOW even without content.
- `print_unclassifiable_action="DENY"` with EMF job → DENY.

## Inputs

- `dlp-agent/src/lib.rs`
- `dlp-agent/src/print_job_info.rs`
- `dlp-agent/src/print_xps_parser.rs`

## Expected Output

- ``dlp-agent/src/print_watcher.rs` — new spooler watcher module`
- ``dlp-agent/src/lib.rs` — mod declaration added`

## Verification

cargo test --lib print_watcher passes

## Observability Impact

- Signals added: `tracing::info!` on job detected, `tracing::debug!` on classification result, `tracing::warn!` on `SetJob` failure or SPL read failure.
- How a future agent inspects this: read agent log for `print_watcher` target; grep for "job_detected", "job_cancelled", "job_allowed".
- Failure state exposed: if watcher thread panics, `join()` in `stop()` returns `Err` which is logged. If notification handle fails, error is logged and thread exits.
