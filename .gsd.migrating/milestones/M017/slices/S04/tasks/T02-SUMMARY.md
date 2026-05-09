---
id: T02
parent: S04
milestone: M017
key_files:
  - dlp-agent/src/print_job_info.rs
  - dlp-agent/src/lib.rs
  - dlp-agent/Cargo.toml
key_decisions:
  - Used PRINTER_HANDLE (not HANDLE) per windows-rs 0.62 typing for all print APIs
  - GetJobW/SetJobW return BOOL in windows 0.62, not Result — manual .as_bool() checks with GetLastError context
  - JOB_CONTROL_DELETE and JOB_STATUS_PRINTING are plain u32 constants, not newtypes with .0 field
duration: 
verification_result: passed
completed_at: 2026-05-08T15:29:16.273Z
blocker_discovered: false
---

# T02: Built Win32 print job info wrappers with safe PrinterHandle, JobInfo, get/cancel helpers, and unit tests

**Built Win32 print job info wrappers with safe PrinterHandle, JobInfo, get/cancel helpers, and unit tests**

## What Happened

Created dlp-agent/src/print_job_info.rs with safe Rust wrappers around OpenPrinterW, GetJobW, and SetJobW. PrinterHandle wraps PRINTER_HANDLE with a Drop impl calling ClosePrinter. JobInfo extracts document name, user, status, datatype, and pages from JOB_INFO_2W. get_job_info uses the two-call size-probe pattern (probe with None buffer to get needed size, then allocate and fetch). cancel_job sends JOB_CONTROL_DELETE via SetJobW. is_job_printing checks the JOB_STATUS_PRINTING bit. Added Win32_Graphics_Printing to windows crate features in Cargo.toml. Added #[cfg(windows)] pub mod print_job_info declaration to lib.rs. Wrote 6 unit tests covering JobInfo construction, clone/equality, is_job_printing with zero/mixed/printing bits, and pwstr_to_string null handling. No real spooler APIs are called in tests, satisfying the failure-mode constraint about elevation.

## Verification

cargo check -p dlp-agent passes with zero warnings; cargo test -p dlp-agent --lib print_job_info passes all 6 tests; full dlp-agent lib suite passes all 411 tests with zero regressions

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo check -p dlp-agent` | 0 | ✅ pass | 4173ms |
| 2 | `cargo test -p dlp-agent --lib print_job_info` | 0 | ✅ pass | 41916ms |
| 3 | `cargo test -p dlp-agent --lib` | 0 | ✅ pass | 5565ms |

## Deviations

None

## Known Issues

None

## Files Created/Modified

- `dlp-agent/src/print_job_info.rs`
- `dlp-agent/src/lib.rs`
- `dlp-agent/Cargo.toml`
