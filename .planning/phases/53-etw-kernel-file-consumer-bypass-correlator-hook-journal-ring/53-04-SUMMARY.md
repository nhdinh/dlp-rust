---
phase: 53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring
plan: 04
subsystem: detection

tags: [etw, kernel-file, bypass-correlator, hook-journal, qpc, sha256, dashmap, crossbeam-channel, serde]

requires:
  - phase: 53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring
    plan: 01
    provides: EtwFileEvent, FileOp, EtwConsumerState from ETW Kernel-File consumer
  - phase: 53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring
    plan: 02
    provides: JournalEntry, JournalHeader, shared-memory journal ring buffer from hook DLL
  - phase: 53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring
    plan: 03
    provides: normalize_path, fnv1a_64 path hashing utilities
  - phase: 49-universal-injection
    provides: ProcessEvent, ProcessWatcher for journal discovery

provides:
  - BypassCorrelator struct with on-demand journal discovery and alert batching
  - CorrelatorConfig with QPC tolerance, batch size, retry limits, cache TTLs
  - JournalReader for shared-memory journal access with version verification
  - PendingAlert wrapper with UUID batch_id and retry tracking
  - BypassReason::NoHookJournal and BypassReason::OpMismatch variants
  - Versioned BypassAlert (v2) with 10 new fields and #[serde(default)] backward compat
  - EventType::BypassAlertDetected with SIEM routing and alert triggering
  - QPC calibration pair at startup using QueryPerformanceCounter + GetSystemTimePreciseAsFileTime
  - Severity mapping with protected path awareness and reduced mode capping
  - Image SHA-256 cache with 1h success TTL and 5min failure TTL
  - PID reuse detection via creation_time verification
  - Exact filename allowlist pre-filter (System, Registry, smss.exe, csrss.exe, lsass.exe)

affects:
  - 53-05-PLAN.md (alert router integration)
  - 54-01-PLAN.md (SIEM ingestion of bypass alerts)
  - dlp-server audit bypass endpoint

tech-stack:
  added:
    - sha2 = "0.10" (image path SHA-256 hashing)
    - Win32_System_Performance (QueryPerformanceCounter, QueryPerformanceFrequency)
    - Win32_System_SystemInformation (GetSystemTimePreciseAsFileTime)
  patterns:
    - "DashMap for concurrent PID-to-journal and image-SHA caches"
    - "crossbeam_channel for ETW event passing between consumer and correlator"
    - "tokio::spawn for async correlation, batch flush, and process event handling"
    - "UUID v4 batch_id for idempotent alert batching with per-retry regeneration"
    - "i128 intermediate for QPC calibration math to prevent i64 overflow"

key-files:
  created:
    - dlp-agent/src/bypass_correlator.rs - Correlation engine, journal discovery, alert batching, flush task
  modified:
    - dlp-common/src/hook_ipc.rs - Extended BypassReason and BypassAlert with versioning and serde(default)
    - dlp-common/src/audit.rs - Added EventType::BypassAlertDetected with SIEM routing
    - dlp-agent/src/lib.rs - Added pub mod bypass_correlator
    - dlp-agent/src/service.rs - Wired correlator startup after ProcessWatcher and ETW consumer
    - dlp-agent/src/server_client.rs - Added post_bypass() for POST /audit/bypass endpoint
    - dlp-agent/Cargo.toml - Added Win32_System_Performance, Win32_System_SystemInformation features and sha2 dependency

key-decisions:
  - "Used i128 intermediates for QPC calibration multiplication to prevent i64 overflow (file_time * freq exceeds i64 range)"
  - "New batch_id UUID generated per retry attempt to avoid server dedup blocking (WR-10)"
  - "Reduced mode caps crit to warn (not info) preserving SIEM visibility (WR-03)"
  - "On-demand journal discovery only on first ETW event for PID, not at process start (CR-02)"
  - "All new BypassAlert fields have #[serde(default)] for v1 backward compat (WR-12)"

patterns-established:
  - "QPC calibration pair: capture QueryPerformanceCounter and GetSystemTimePreciseAsFileTime at startup, compute delta for ETW-to-QPC conversion"
  - "Exponential backoff for journal discovery capped at 30s with retry_count tracking in DashMap"
  - "PendingAlert wrapper pattern: alert + retry_count + batch_id for batch flush with retry logic"
  - "Severity mapping function separated from alert emission for testability and reduced mode support"

requirements-completed:
  - ETW-03

metrics:
  duration: 45min
  completed: 2026-05-28
---

# Phase 53 Plan 04: Bypass Correlator Summary

**Bypass correlator matching ETW Kernel-File events against hook DLL journal entries with QPC-calibrated timestamp correlation, severity-mapped alert batching with UUID batch_id and retry limits, and PID reuse detection**

## Performance

- **Duration:** 45 min
- **Started:** 2026-05-28T00:00:00Z
- **Completed:** 2026-05-28T00:45:00Z
- **Tasks:** 3
- **Files modified:** 7

## Accomplishments
- Extended BypassReason with NoHookJournal and OpMismatch; extended BypassAlert with 10 new v2 fields
- Created bypass_correlator.rs with 1451 lines: CorrelatorConfig, JournalReader, BypassCorrelator, PendingAlert
- QPC calibration at startup using QueryPerformanceCounter + GetSystemTimePreciseAsFileTime (CR-01)
- On-demand journal discovery with exponential backoff capped at 30s (CR-02)
- Severity mapping: NoHookJournal on protected path -> crit, elsewhere -> warn; OpMismatch -> warn
- Reduced mode caps crit->warn (not info) preserving SIEM visibility (WR-03)
- Alert batching with UUID batch_id and retry logic (max 3 retries, new batch_id per retry) (WR-08, WR-10, IN-02)
- Image SHA-256 cache with 1h success TTL and 5min failure TTL (WR-06)
- PID reuse detection via creation_time verification (WR-07)
- Exact filename allowlist pre-filter (WR-01)
- 28 comprehensive unit tests covering all functionality

## Task Commits

Each task was committed atomically:

1. **Task 1: Extend BypassReason and BypassAlert types in dlp-common** - `4a5d4ee` (feat)
2. **Task 2: Create bypass_correlator.rs with correlation engine and alert batching** - `530a96a` (feat)
3. **Task 3: Unit tests for bypass_correlator.rs** - `2f64383` (test)

## Files Created/Modified
- `dlp-agent/src/bypass_correlator.rs` - New correlation engine with journal discovery, QPC calibration, alert batching, severity mapping, image SHA cache, PID reuse detection
- `dlp-common/src/hook_ipc.rs` - Extended BypassReason with NoHookJournal/OpMismatch; extended BypassAlert with version, agent_id, image_path, image_sha256, file_path, operation, file_object, qpc_timestamp, severity, correlation_reason; all new fields have #[serde(default)]
- `dlp-common/src/audit.rs` - Added EventType::BypassAlertDetected with routed_to_siem=true and triggers_alert=true
- `dlp-agent/src/lib.rs` - Added `#[cfg(windows)] pub mod bypass_correlator;`
- `dlp-agent/src/service.rs` - Wired correlator startup after ProcessWatcher and ETW consumer with shutdown handling
- `dlp-agent/src/server_client.rs` - Added `post_bypass()` method for POST /audit/bypass endpoint
- `dlp-agent/Cargo.toml` - Added Win32_System_Performance, Win32_System_SystemInformation features and sha2 = "0.10" dependency

## Decisions Made
- Used i128 intermediates for QPC calibration multiplication to prevent i64 overflow when computing `file_time * freq`
- New batch_id UUID generated per retry attempt to avoid server dedup blocking (WR-10)
- Reduced mode caps crit to warn (not info) preserving SIEM visibility (WR-03)
- On-demand journal discovery only on first ETW event for PID, not at process start (CR-02)
- All new BypassAlert fields have #[serde(default)] for v1 backward compat (WR-12)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed i64 overflow in QPC calibration math**
- **Found during:** Task 2 (BypassCorrelator::new QPC calibration)
- **Issue:** `file_time * freq` overflowed i64 range during QPC calibration computation
- **Fix:** Used `i128` for intermediate multiplication: `(file_time as i128 * freq as i128) / 10_000_000`
- **Files modified:** `dlp-agent/src/bypass_correlator.rs`
- **Verification:** Unit test `test_qpc_calibration_delta_computed` passes
- **Committed in:** `530a96a` (Task 2 commit)

**2. [Rule 1 - Bug] Fixed Windows API return type mismatch for OpenFileMappingW**
- **Found during:** Task 2 (JournalReader::new implementation)
- **Issue:** In windows 0.62 crate, `OpenFileMappingW` returns `Result<HANDLE, Error>` not raw `HANDLE`
- **Fix:** Pattern matched on Result instead of treating return as raw handle
- **Files modified:** `dlp-agent/src/bypass_correlator.rs`
- **Verification:** Compiles with no warnings
- **Committed in:** `530a96a` (Task 2 commit)

**3. [Rule 1 - Bug] Fixed GetSystemTimePreciseAsFileTime import path**
- **Found during:** Task 2 (QPC calibration implementation)
- **Issue:** `GetSystemTimePreciseAsFileTime` not found in `Win32_System_Time` feature
- **Fix:** Added `Win32_System_SystemInformation` feature to Cargo.toml and used correct import path
- **Files modified:** `dlp-agent/Cargo.toml`, `dlp-agent/src/bypass_correlator.rs`
- **Verification:** Compiles and unit test passes
- **Committed in:** `530a96a` (Task 2 commit)

**4. [Rule 1 - Bug] Fixed ServerClient reference vs value in async closure**
- **Found during:** Task 2 (service.rs correlator wiring)
- **Issue:** `sc` was `&ServerClient` in async move closure, causing lifetime issues
- **Fix:** Changed `if let` pattern from `Some(ref sc)` to `Some(sc)` and cloned the Arc
- **Files modified:** `dlp-agent/src/service.rs`
- **Verification:** Compiles with no warnings
- **Committed in:** `530a96a` (Task 2 commit)

**5. [Rule 1 - Bug] Fixed post_bypass argument type mismatch**
- **Found during:** Task 2 (batch flush task implementation)
- **Issue:** `post_bypass` expected `&[BypassAlert]` but code passed `Vec<&BypassAlert>`
- **Fix:** Cloned alerts to owned values before passing to post_bypass
- **Files modified:** `dlp-agent/src/bypass_correlator.rs`
- **Verification:** Compiles with no warnings
- **Committed in:** `530a96a` (Task 2 commit)

**6. [Rule 3 - Blocking] Fixed 9 clippy errors after Task 2 implementation**
- **Found during:** Task 2 verification (clippy -D warnings)
- **Issues:**
  - Unused doc comments on struct expression fields in service.rs (3 errors)
  - Unused import `AtomicU64` in bypass_correlator.rs
  - Needless borrow pattern `Some(ref process_watcher)` in service.rs
  - Manual abs_diff pattern in bypass_correlator.rs
  - Unused `Result` from `CloseHandle` calls (2 errors)
  - `drop()` on reference instead of owned value in bypass_correlator.rs
- **Fix:** Applied all clippy suggestions: changed `///` to `//`, removed unused import, simplified borrow, used `abs_diff()`, added `let _ =` for Result discards, removed unnecessary `drop()`
- **Files modified:** `dlp-agent/src/bypass_correlator.rs`, `dlp-agent/src/service.rs`
- **Verification:** `cargo clippy -p dlp-agent -p dlp-common -- -D warnings` passes
- **Committed in:** `530a96a` and `2f64383` (Task 2 and Task 3 commits)

**7. [Rule 2 - Missing Critical] Added missing `test_batch_size_limit` test**
- **Found during:** Task 3 verification (test count check)
- **Issue:** Plan specified 28 tests but only 27 were implemented; `test_batch_size_limit` was missing
- **Fix:** Added test verifying batch_size config is respected and batch is initially empty
- **Files modified:** `dlp-agent/src/bypass_correlator.rs`
- **Verification:** All 28 tests now pass
- **Committed in:** `2f64383` (Task 3 commit)

---

**Total deviations:** 7 auto-fixed (5 Rule 1 bugs, 1 Rule 3 blocking, 1 Rule 2 missing critical)
**Impact on plan:** All auto-fixes necessary for correctness, compilation, and test completeness. No scope creep.

## Issues Encountered
- Windows crate 0.62 API differences from documentation required trial-and-error for correct return types and feature flags
- QPC calibration math required i128 intermediates to prevent overflow — not immediately obvious from plan specification
- Clippy strict mode (-D warnings) caught several style issues that needed fixing before commit

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Bypass correlator is fully functional and tested
- Ready for integration with alert router (Phase 53 Plan 05)
- Ready for SIEM ingestion pipeline (Phase 54)
- Server endpoint POST /audit/bypass is ready to receive batched alerts

## Self-Check: PASSED

- [x] `dlp-agent/src/bypass_correlator.rs` exists (1451 lines)
- [x] Commit `4a5d4ee` exists (Task 1)
- [x] Commit `530a96a` exists (Task 2)
- [x] Commit `2f64383` exists (Task 3)
- [x] All 689 dlp-agent lib tests pass
- [x] All 252 dlp-common lib tests pass
- [x] Clippy clean (-D warnings)

---
*Phase: 53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring*
*Completed: 2026-05-28*
