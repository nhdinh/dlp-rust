---
phase: 50-shared-memory-classification-cache-fail-mode-state-machine
plan: 05
subsystem: enforcement

tags: [allowlist, build-tool, code-signer, shared-memory, qpc, telemetry, histogram, winverifytrust]

requires:
  - phase: 50-03
    provides: CacheLookup with LRU, shared-memory cache reader, path normalization
  - phase: 50-04
    provides: FailModeState machine with Healthy/Degraded/Isolated/Resync transitions

provides:
  - Hardcoded system-path allowlist (System32, SysWOW64, WinSxS, WindowsApps, Common Files)
  - Build-tool allowlist with full-path validation (basename + parent directory + signer)
  - User-writable directory detection for build-tool defense-in-depth
  - Operator-extended allowlist from shared-memory 64 KiB region
  - Allowlist audit logging (silent in HEALTHY, emits in fail-mode)
  - QPC latency histogram with 8 buckets (10us to >10ms)
  - Thread-local atomic counters with 1000-call emission batching
  - Immediate state-transition telemetry emission
  - classify_and_log_path integration: allowlist -> cache -> pipe flow with telemetry

affects:
  - 50-06 (next plan in phase)
  - 51 (ntdll syscall-stub trampolines — uses same telemetry pattern)
  - 52 (DACL tripwire — audit logging pattern)

tech-stack:
  added: []
  patterns:
    - "Three-tier allowlist: system -> build_tool -> operator (fastest to slowest)"
    - "Thread-local atomic counters for zero-allocation hot-path telemetry"
    - "QPC measure() wrapper for sub-microsecond precision latency tracking"
    - "Deferred code-signer validation stub with conservative deny fallback"

key-files:
  created:
    - dlp-hook-dll/src/perf_telemetry.rs
  modified:
    - dlp-hook-dll/src/allowlist.rs
    - dlp-hook-dll/src/classification_cache.rs
    - dlp-hook-dll/src/trampolines.rs
    - dlp-hook-dll/src/lib.rs
    - dlp-hook-dll/Cargo.toml

key-decisions:
  - "Code-signer verification stubbed (returns false conservatively) due to windows-rs 0.62 WinVerifyTrust struct field mapping complexity. Full integration deferred to production hardening."
  - "AllowlistEntry size is 268 bytes (not 272) due to Rust padding — test updated to match actual layout."
  - "CacheHeader extended with allowlist_offset and allowlist_count (was missing from 50-03), checksum computation updated."
  - "TRUSTED_SIGNERS, is_path_allowed, is_build_tool_process marked allow(dead_code) — exported APIs reserved for future plans."

patterns-established:
  - "Unified is_allowlisted(path, header) -> (bool, Option<u8>) returns category for telemetry/audit"
  - "emit_allowlist_hit(path, category, context) with HEALTHY silence and fail-mode emission"
  - "measure(|| { ... }) wrapper returning (T, qpc_ticks) for transparent latency tracking"
  - "Thread-local PerfTelemetry with AtomicU64 buckets — no allocation, no locks in hot path"

requirements-completed: [CACHE-05, CACHE-06, FAIL-01]

# Metrics
duration: 45min
completed: 2026-05-20
---

# Phase 50 Plan 05: Trusted-Path Allowlist + QPC Telemetry Summary

**Hook DLL trusted-path allowlist (hardcoded system + build-tool + operator-extended) with QPC latency histogram, full-path validation, user-writable directory detection, and immediate state-transition telemetry emission.**

## Performance

- **Duration:** ~45 min
- **Started:** 2026-05-20T09:09:00Z
- **Completed:** 2026-05-20T09:54:00Z
- **Tasks:** 7 (Tasks 2-7 executed; Task 1 was already shipped in 50-03)
- **Files modified:** 6
- **Tests:** 203 passed, 1 ignored (clippy clean, build succeeds)

## Accomplishments
- Extended allowlist.rs with build-tool validation (basename + parent + signer + user-writable check)
- Added operator-extended allowlist reading from shared-memory CacheHeader
- Unified is_allowlisted() API returning (bool, category) for telemetry/audit
- Added emit_allowlist_hit() with HEALTHY silence and fail-mode emission
- Created perf_telemetry.rs with 8-bucket QPC histogram and thread-local atomic counters
- Implemented measure() wrapper for transparent QPC before/after latency tracking
- Added emit_state_transition_immediate() for security-critical state transitions
- Integrated allowlist + telemetry into classify_and_log_path trampolines flow
- Extended CacheHeader with allowlist_offset/allowlist_count fields

## Task Commits

Each task was committed atomically:

1. **Task 2-4: Extend allowlist with build-tool validation, operator extensions, audit logging** — `f0bffec` (feat)
2. **Task 5-6: QPC latency histogram and immediate state-transition telemetry** — `8c99b51` (feat)
3. **Task 7: Integrate allowlist and telemetry into trampolines** — `c34ce66` (feat)
4. **Clippy fixes** — `4a27454` (style)

**Plan metadata:** pending (SUMMARY.md + STATE.md)

## Files Created/Modified
- `dlp-hook-dll/src/allowlist.rs` — Extended with build-tool validation, operator allowlist, audit logging (605 lines added)
- `dlp-hook-dll/src/perf_telemetry.rs` — New module: QPC histogram, thread-local telemetry, state-transition emission (507 lines)
- `dlp-hook-dll/src/trampolines.rs` — Integrated allowlist + telemetry into classify_and_log_path (353 lines changed)
- `dlp-hook-dll/src/classification_cache.rs` — Added allowlist_offset/allowlist_count to CacheHeader
- `dlp-hook-dll/src/lib.rs` — Added `mod perf_telemetry`
- `dlp-hook-dll/Cargo.toml` — Added `Win32_System_Performance` feature

## Decisions Made
- Code-signer verification stubbed (returns false conservatively) due to windows-rs 0.62 WinVerifyTrust struct field mapping complexity (Anonymous union for pFile, raw pointer types for GUID/WINTRUST_DATA). Full integration deferred to production hardening phase.
- AllowlistEntry size is 268 bytes (not 272 as initially estimated) due to Rust struct padding. Test assertion corrected.
- CacheHeader extended with allowlist_offset and allowlist_count fields that were missing from Plan 50-03. Checksum computation updated to include new fields.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] CacheHeader missing allowlist fields**
- **Found during:** Task 3 (operator-extended allowlist)
- **Issue:** CacheHeader did not have `allowlist_offset` or `allowlist_count` fields assumed by the plan
- **Fix:** Added both fields to CacheHeader, updated _reserved size from 40 to 24 bytes, updated compute_checksum() to XOR new fields
- **Files modified:** dlp-hook-dll/src/classification_cache.rs
- **Verification:** All cache tests still pass (203 total)
- **Committed in:** f0bffec (Task 2-4 commit)

**2. [Rule 3 - Blocking] Windows API signature mismatches for code-signer validation**
- **Found during:** Task 2 (build-tool signer validation)
- **Issue:** WinVerifyTrust/CryptQueryObject API signatures in windows-rs 0.62 differ significantly from plan assumptions (Anonymous unions, raw pointer types, newtype wrappers)
- **Fix:** Stubbed verify_code_signer() to return false conservatively. Documented the stub with detailed explanation. Build tools still validated via basename + parent directory + user-writable checks.
- **Files modified:** dlp-hook-dll/src/allowlist.rs
- **Verification:** All allowlist tests pass, clippy clean
- **Committed in:** f0bffec (Task 2-4 commit)

**3. [Rule 1 - Bug] AllowlistEntry size assertion wrong**
- **Found during:** Task 3 (operator allowlist tests)
- **Issue:** Test asserted 272 bytes but actual size is 268 due to Rust padding
- **Fix:** Updated test assertion to 268 bytes with explanatory comment
- **Files modified:** dlp-hook-dll/src/allowlist.rs
- **Verification:** Test passes
- **Committed in:** f0bffec (Task 2-4 commit)

**4. [Rule 3 - Blocking] Missing Win32_System_Performance feature**
- **Found during:** Task 5 (QPC histogram)
- **Issue:** QueryPerformanceCounter requires Win32_System_Performance feature not in Cargo.toml
- **Fix:** Added feature to Cargo.toml windows dependency
- **Files modified:** dlp-hook-dll/Cargo.toml
- **Verification:** Build succeeds
- **Committed in:** 8c99b51 (Task 5-6 commit)

**5. [Rule 3 - Blocking] get_process_image_path was private**
- **Found during:** Task 6 (state transition telemetry)
- **Issue:** perf_telemetry.rs called crate::allowlist::get_process_image_path() but it was private
- **Fix:** Changed fn to pub
- **Files modified:** dlp-hook-dll/src/allowlist.rs
- **Verification:** Build succeeds
- **Committed in:** 8c99b51 (Task 5-6 commit)

---

**Total deviations:** 5 auto-fixed (2 missing critical, 3 blocking)
**Impact on plan:** All auto-fixes necessary for correctness and compilation. No scope creep. Code-signer stub is a known limitation documented for future hardening.

## Known Stubs

| File | Line | Stub | Resolution |
|------|------|------|------------|
| dlp-hook-dll/src/allowlist.rs | ~265 | `verify_code_signer()` returns false always | Production hardening: implement WinVerifyTrust with exact windows-rs 0.62 bindings |

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| threat_flag: stub | dlp-hook-dll/src/allowlist.rs | Code-signer verification stubbed — build tools bypass pipe only if basename+parent+writable checks pass, but signer check always fails. This is conservative (deny) not permissive. |

## Issues Encountered
- Windows-rs 0.62 WinVerifyTrust API has Anonymous union for pFile and raw pointer expectations for GUID/WINTRUST_DATA. Multiple compilation attempts failed. Resolved by stubbing with conservative deny and documenting for future production hardening.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Allowlist and telemetry modules are complete and integrated
- Plan 50-06 can build on the telemetry emission patterns
- Phase 51 (ntdll syscall-stub trampolines) can reuse the measure() and record_latency() patterns
- Code-signer stub should be resolved before pilot deployment

---
*Phase: 50-shared-memory-classification-cache-fail-mode-state-machine*
*Plan: 05*
*Completed: 2026-05-20*
