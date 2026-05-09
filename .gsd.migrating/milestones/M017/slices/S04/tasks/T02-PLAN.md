---
estimated_steps: 18
estimated_files: 2
skills_used: []
---

# T02: Build Win32 print job info wrappers

Create safe Rust wrappers around `OpenPrinterW`, `GetJobW`, and `SetJobW` for querying and cancelling print jobs.

**Steps:**
1. Create `dlp-agent/src/print_job_info.rs`.
2. Define `PrinterHandle` struct wrapping `windows::Win32::Graphics::Printing::HANDLE` with a `Drop` impl that calls `ClosePrinter`.
3. Implement `open_printer(name: &str) -> Result<PrinterHandle>` using `OpenPrinterW` with `PRINTER_ACCESS_ADMINISTER`.
4. Define `JobInfo` struct with fields: `job_id: u32`, `document_name: String`, `user_name: String`, `status: u32`, `datatype: String`, `pages: u32`.
5. Implement `get_job_info(handle: &PrinterHandle, job_id: u32) -> Result<JobInfo>` using `GetJobW` Level 2 (`JOB_INFO_2W`).
6. Implement `cancel_job(handle: &PrinterHandle, job_id: u32) -> Result<()>` using `SetJobW` with `JOB_CONTROL_DELETE`.
7. Add helper `is_job_printing(status: u32) -> bool` checking `JOB_STATUS_PRINTING` bit.
8. Add `#[cfg(windows)] pub mod print_job_info;` to `dlp-agent/src/lib.rs`.
9. Write unit tests for `JobInfo` construction and helper functions.

**Skills used:** rust-engineer, unsafe-checker

**Failure Modes:**
- `OpenPrinterW` with `PRINTER_ACCESS_ADMINISTER` requires SYSTEM/admin — agent runs as SYSTEM, but tests may fail without elevation. Tests should avoid calling real APIs; test struct construction and conversion helpers only.
- `SetJobW` with `JOB_CONTROL_DELETE` on a non-existent job returns error — unit tests should not call real spooler.

**Negative Tests:**
- Test `JobInfo` default construction and field access.
- Test `is_job_printing` with zero status (false) and `JOB_STATUS_PRINTING` (true).

## Inputs

- `dlp-agent/src/lib.rs`
- `dlp-agent/Cargo.toml`

## Expected Output

- ``dlp-agent/src/print_job_info.rs` — new Win32 wrapper module`
- ``dlp-agent/src/lib.rs` — mod declaration added`

## Verification

cargo test --lib print_job_info passes

## Observability Impact

No new runtime signals; this is a contract module.
