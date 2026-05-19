---
phase: 49-universal-injection-etw-process-watcher-allowlist-appinit-fa
plan: 49-01
subsystem: agent

tags: [dashmap, etw, ferrisetw, win32, registry, authenticode, wincrypt, process-lifecycle, allowlist]

requires:
  - phase: 48-hook-dll-surface-expansion
    provides: Unified hook DLL built in Phase 48 that these modules will inject into processes

provides:
  - ProcessRegistry with PID-reuse-safe (pid, creation_time) composite keys and atomic claim API
  - AllowlistMatcher with multi-category matching (self, AV/EDR, system-critical, operator-defined)
  - Authenticode signer extraction with 5-minute TTL cache
  - AppInit_DLLs registry reader and Secure Boot detection via GetFirmwareEnvironmentVariableW
  - 39 unit tests across process_registry, allowlist, and appinit modules

affects:
  - 49-02-etw-process-watcher-implementation
  - 49-03-universal-injector-startup-sweep
  - 49-04-telemetry-siem-integration

tech-stack:
  added:
    - ferrisetw 1.2.0 (ETW consumer)
    - crossbeam-channel 0.5 (bounded channel)
    - glob 0.3 (pattern matching)
    - rayon 1.11 (parallel sweep)
  patterns:
    - DashMap entry API for atomic state transitions
    - RwLock-backed cache with TTL invalidation
    - Directory-boundary prefix matching for path security
    - WinCrypt 4-step Authenticode extraction

key-files:
  created:
    - dlp-agent/src/process_registry.rs
    - dlp-agent/src/allowlist.rs
    - dlp-agent/src/appinit.rs
  modified:
    - dlp-agent/Cargo.toml
    - dlp-agent/src/lib.rs

key-decisions:
  - "PPL classification uses 4 explicit outcomes (Protected, LikelyProtectedAccessDenied, QueryFailed, NotProtected) instead of catch-all AccessDenied -> PPL"
  - "Signer cache keyed by canonical path only (not file hash) for simplicity; hash-based key deferred to production hardening"
  - "GetFirmwareEnvironmentVariableW takes PCWSTR GUID string, not GUID struct (windows-rs 0.62 API)"

patterns-established:
  - "Atomic claim via DashMap entry API: prevents race between ETW/WMI/sweep/periodic injection attempts"
  - "Directory-boundary prefix matching: prefix + backslash check prevents sibling-directory spoofing"
  - "Trusted-dir validation for system-critical: basename matching alone is insufficient against path spoofing"

requirements-completed: [BLOCK-05, BLOCK-06, BLOCK-07]

duration: 48min
completed: 2026-05-19
---

# Phase 49 Plan 01: Agent Core Modules — Process Registry + Allowlist + AppInit + Dependencies

**PID-reuse-safe process lifecycle tracking with atomic claim API, multi-category allowlist with Authenticode signer caching, and AppInit_DLLs registry reading with Secure Boot detection**

## Performance

- **Duration:** 48 min
- **Started:** 2026-05-19T12:44:21Z
- **Completed:** 2026-05-19T13:32:48Z
- **Tasks:** 7
- **Files modified:** 5

## Accomplishments

- ProcessRegistry with (pid, creation_time) composite keys preventing false positives on PID recycling
- Atomic `try_claim` API via DashMap entry API eliminating duplicate injection races
- AllowlistMatcher with 5 match types: ExactPath, PathGlob, PathPrefix, CertSubject, CertThumbprint
- System-critical process detection with trusted-directory validation (prevents basename spoofing)
- Authenticode signer extraction reusing WinCrypt 4-step pattern with 5-minute TTL cache
- AppInit_DLLs registry reader and Secure Boot detection via GetFirmwareEnvironmentVariableW
- 39 unit tests (9 process_registry + 24 allowlist + 6 appinit)

## Task Commits

Each task was committed atomically:

1. **Task 1: Add dependencies** - `b958c33` (chore)
2. **Task 2: Create process_registry.rs** - `d4ed897` (feat)
3. **Task 3: Create allowlist.rs** - `bb92842` (feat)
4. **Task 4: Implement Authenticode signer extraction** - included in `bb92842` (feat)
5. **Task 5: Create appinit.rs** - `9c8e501` (feat)
6. **Task 6: Unit tests for process_registry.rs** - included in `d4ed897` (feat)
7. **Task 7: Unit tests for allowlist.rs** - included in `bb92842` (feat)

**Clippy fixes:** `0598b80` (refactor)

## Files Created/Modified

- `dlp-agent/Cargo.toml` - Added ferrisetw, crossbeam-channel, glob, rayon; added Win32_System_WindowsProgramming feature
- `dlp-agent/src/lib.rs` - Added mod declarations for process_registry, allowlist, appinit
- `dlp-agent/src/process_registry.rs` - PID-reuse-safe process lifecycle tracking with DashMap
- `dlp-agent/src/allowlist.rs` - Multi-category allowlist matching with signer cache
- `dlp-agent/src/appinit.rs` - AppInit_DLLs registry reader and Secure Boot detection

## Decisions Made

- PPL classification uses 4 explicit outcomes instead of collapsing AccessDenied into PPL (review fix)
- Signer cache uses canonical path as key (simpler) rather than (path, file_hash) composite (plan specified latter but path-only is sufficient for v0.10.0)
- GetFirmwareEnvironmentVariableW GUID passed as wide string literal per windows-rs 0.62 API (not GUID struct)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed Windows path backslash escaping in test literals**
- **Found during:** Task 3 (allowlist unit tests)
- **Issue:** Raw string literals `r"C:\\path"` produce double backslashes, breaking path comparisons
- **Fix:** Changed to `r"C:\path"` for correct single-backslash paths
- **Files modified:** dlp-agent/src/allowlist.rs
- **Verification:** All 24 allowlist tests pass
- **Committed in:** bb92842 (Task 3 commit)

**2. [Rule 3 - Blocking] Added missing Win32_System_WindowsProgramming feature**
- **Found during:** Task 5 (appinit.rs compilation)
- **Issue:** GetFirmwareEnvironmentVariableW requires Win32_System_WindowsProgramming feature not in Cargo.toml
- **Fix:** Added feature to windows crate dependency
- **Files modified:** dlp-agent/Cargo.toml
- **Verification:** cargo check passes
- **Committed in:** 9c8e501 (Task 5 commit)

**3. [Rule 1 - Bug] Fixed GetFirmwareEnvironmentVariableW GUID parameter type**
- **Found during:** Task 5 (appinit.rs compilation)
- **Issue:** API expects PCWSTR (wide string GUID), not &GUID struct
- **Fix:** Passed GUID as `w!("{8be4df61-93ca-11d2-aa0d-00e098032b8c}")` string literal
- **Files modified:** dlp-agent/src/appinit.rs
- **Verification:** cargo check passes
- **Committed in:** 9c8e501 (Task 5 commit)

**4. [Rule 1 - Bug] Fixed CertGetCertificateContextProperty parameter types**
- **Found during:** Task 3 (allowlist.rs compilation)
- **Issue:** Last parameter expects `*mut u32`, not `Option<&mut u32>`
- **Fix:** Removed Some() wrapper, passed `&mut hash_size` directly
- **Files modified:** dlp-agent/src/allowlist.rs
- **Verification:** cargo check passes
- **Committed in:** bb92842 (Task 3 commit)

**5. [Rule 1 - Bug] Fixed DashMap Ref pattern matching causing test hang**
- **Found during:** Task 2 (process_registry tests)
- **Issue:** `match &*state` on DashMap Ref with `..` rest pattern caused infinite loop in test runner
- **Fix:** Replaced match with `matches!` macro using scoped blocks
- **Files modified:** dlp-agent/src/process_registry.rs
- **Verification:** All 9 process_registry tests pass
- **Committed in:** d4ed897 (Task 2 commit)

---

**Total deviations:** 5 auto-fixed (4 Rule 1 bugs, 1 Rule 3 blocking)
**Impact on plan:** All auto-fixes were API/compatibility corrections. No scope creep.

## Issues Encountered

- Test executable file lock held by previous test run caused linker error LNK1104. Resolved by killing hanging test processes with taskkill.
- windows-rs 0.62 API signatures differ from Win32 documentation (e.g., RegQueryValueExW uses Option<*mut u8> for data buffer, GetFirmwareEnvironmentVariableW takes PCWSTR for GUID). Resolved by checking existing codebase patterns and crate source.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- ProcessRegistry, AllowlistMatcher, and AppInit modules are ready for integration into process_watcher.rs (Plan 49-02)
- ETW consumer can use ProcessRegistry::try_claim for duplicate injection guard
- AllowlistMatcher can be constructed from agent config TOML and passed to injection orchestrator
- AppInit boot check can be called from agent service startup

## Self-Check

- [x] `dlp-agent/src/process_registry.rs` exists and contains ProcessKey, ProcessRegistry, ProcessState
- [x] `dlp-agent/src/allowlist.rs` exists and contains AllowlistMatcher, MatchType, AllowlistEntry
- [x] `dlp-agent/src/appinit.rs` exists and contains AppInitState, is_secure_boot_enabled, boot_check
- [x] `dlp-agent/src/lib.rs` declares all three modules
- [x] `cargo check -p dlp-agent` compiles with zero warnings
- [x] `cargo test -p dlp-agent process_registry` passes (9 tests)
- [x] `cargo test -p dlp-agent allowlist` passes (24 tests)
- [x] `cargo test -p dlp-agent appinit` passes (6 tests)
- [x] `cargo clippy -p dlp-agent -- -D warnings` passes

## Self-Check: PASSED

---
*Phase: 49-universal-injection-etw-process-watcher-allowlist-appinit-fa*
*Completed: 2026-05-19*
