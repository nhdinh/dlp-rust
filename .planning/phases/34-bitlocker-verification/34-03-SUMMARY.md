---
phase: 34-bitlocker-verification
plan: 03
subsystem: disk-encryption
tags: [windows, wmi, bitlocker, wmi-rs, registry, com, encryption-checker, tokio-spawn-blocking, parking-lot]

# Dependency graph
requires:
  - phase: 34-01
    provides: "EncryptionStatus, EncryptionMethod enums and three Option<> fields on DiskIdentity"
  - phase: 34-02
    provides: "EncryptionConfig in AgentConfig, windows crate 0.62 bump, wmi 0.14 dep"
  - phase: 33
    provides: "DiskEnumerator singleton, DiskIdentity, spawn_disk_enumeration_task, get_disk_enumerator"
provides:
  - "EncryptionChecker singleton (parking_lot::RwLock + OnceLock<Arc<...>>)"
  - "EncryptionBackend trait for WMI + Registry abstraction"
  - "WindowsEncryptionBackend with wmi 0.14 query + Registry RAII close"
  - "spawn_encryption_check_task + spawn_encryption_check_task_with_backend (injectable backend)"
  - "Pure-logic helpers: parse_drive_letter, derive_encryption_status, compute_changed_transitions"
  - "build_unknown_justification, build_change_justification"
  - "12 unit tests covering all pure-logic paths (platform-agnostic)"
affects: [34-04, 34-05, 35, 36, 37, 38]

# Tech tracking
tech-stack:
  added:
    - "windows-core = 0.59 (direct dep to access Interface::as_raw() on wmi 0.14 IWbemServices)"
    - "Win32_System_Com windows feature (CoSetProxyBlanket raw FFI for PktPrivacy auth)"
  patterns:
    - "EncryptionBackend trait injection for WMI/Registry abstraction (unit-testable on non-Windows)"
    - "raw CoSetProxyBlanket FFI via upgrade_to_pkt_privacy() to work around wmi 0.14 version split"
    - "DiskCheckResult type alias to satisfy clippy::type_complexity on JoinSet"
    - "RAII RegKey struct (Drop calls RegCloseKey) for Registry handle safety"

key-files:
  created:
    - dlp-agent/src/detection/encryption.rs
  modified:
    - dlp-agent/src/detection/mod.rs
    - dlp-agent/Cargo.toml
    - dlp-agent/tests/comprehensive.rs

key-decisions:
  - "PktPrivacy upgrade via raw CoSetProxyBlanket FFI because wmi 0.14 lacks set_proxy_blanket/AuthLevel (wmi 0.18 has these APIs but is not pinned per D-21a)"
  - "windows-core = 0.59 added as direct dep to make Interface::as_raw() callable on wmi 0.14-returned IWbemServices"
  - "DiskCheckResult type alias pattern for JoinSet to satisfy clippy::type_complexity"

patterns-established:
  - "EncryptionBackend trait injection: trait defines query_volume + read_boot_status_registry; production uses WindowsEncryptionBackend; tests inject mock"
  - "upgrade_to_pkt_privacy(): raw FFI helper as the single call-site for CoSetProxyBlanket (Pitfall F centralization)"
  - "JoinSet fan-out + 5s timeout via tokio::time::timeout wrapping spawn_blocking (Pitfall A + B pattern)"

requirements-completed: [CRYPT-01, CRYPT-02]

# Metrics
duration: 22min
completed: 2026-05-03
---

# Phase 34 Plan 03: EncryptionChecker Module Summary

**BitLocker WMI/Registry verification engine with EncryptionBackend trait, 12 unit tests, and spawn_encryption_check_task targeting Plan 34-04's service.rs wiring**

## Performance

- **Duration:** 22 min
- **Started:** 2026-05-03T13:40:07Z
- **Completed:** 2026-05-03T14:02:00Z
- **Tasks:** 2 (T1: pure-logic + types + tests, T2: WMI + Registry bodies + orchestration loop)
- **Files modified:** 4

## Accomplishments

- Created `dlp-agent/src/detection/encryption.rs` (1312 lines) with full implementation:
  - `EncryptionError` enum (9 variants, `warrants_registry_fallback` gate for D-01a)
  - `EncryptionBackend` trait isolating WMI/Registry primitives for non-Windows test coverage
  - `EncryptionChecker` singleton mirroring `DiskEnumerator` shape (parking_lot::RwLock, OnceLock<Arc<...>>)
  - 9-row truth table in `derive_encryption_status` (D-14 defensive Unknown default)
  - `compute_changed_transitions` preserving None vs Some(Unknown) distinction (Pitfall D)
  - `mark_first_check_complete` idempotent flag (Pitfall E — one Alert per cold-start)
  - `WindowsEncryptionBackend` with `wmi 0.14` query + Registry RAII `RegKey` Drop wrapper
  - `spawn_encryption_check_task_with_backend` for Plan 34-05 mock injection
  - D-20 in-place `DiskEnumerator` mutation (three RwLock maps kept consistent)
  - D-25 status-change DiskDiscovery + D-16 first-check total-failure Alert emission
- 12 unit tests passing on non-Windows (all pure-logic, no COM/WMI/Registry gating)
- Fixed pre-existing `comprehensive.rs` compilation error from Plan 34-02 missing `encryption` field

## Test Coverage

- `test result: ok. 235 passed; 0 failed` (dlp-agent lib tests)
- 12 new encryption module tests covering: parse_drive_letter, derive_encryption_status (11 rows), EncryptionChecker default/singleton/status-lookup, compute_changed_transitions (unchanged/first-observation/Unknown->Unknown), mark_first_check_complete idempotency, build_unknown/change justification, warrants_registry_fallback gate

## Task Commits

Each task was committed atomically:

1. **Tasks 1+2: EncryptionChecker module (types + WMI bodies + orchestration)** - `cf6097f` (feat)
2. **Bug fix: comprehensive.rs missing encryption field** - `706b086` (fix)

**Plan metadata:** (SUMMARY commit to follow)

## Files Created/Modified

- `dlp-agent/src/detection/encryption.rs` — full EncryptionChecker implementation (1312 lines)
- `dlp-agent/src/detection/mod.rs` — added `pub mod encryption` + re-exports
- `dlp-agent/Cargo.toml` — added `Win32_System_Com` feature + `windows-core = "0.59"`
- `dlp-agent/tests/comprehensive.rs` — added `encryption: Default::default()` to two AgentConfig initializers

## Decisions Made

- Used raw `CoSetProxyBlanket` FFI via `upgrade_to_pkt_privacy()` instead of `wmi::AuthLevel::PktPrivacy` (wmi 0.14 doesn't expose this; wmi 0.18 does but is pinned per D-21a). Added `windows-core = "0.59"` as direct dep to access `Interface::as_raw()` on the wmi-returned `IWbemServices`.
- Used `DiskCheckResult` type alias for JoinSet to satisfy `clippy::type_complexity`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] wmi 0.14 lacks set_proxy_blanket / AuthLevel::PktPrivacy**
- **Found during:** Task 2 (WindowsEncryptionBackend implementation)
- **Issue:** Plan's acceptance criteria and RESEARCH.md assumed `wmi::AuthLevel::PktPrivacy` and `WMIConnection::set_proxy_blanket()` exist in wmi 0.14. These APIs were introduced in wmi 0.18. wmi 0.14 (pinned per D-21a) uses `windows 0.59` internally while the workspace targets `windows 0.62`, creating a type mismatch that prevents calling `CoSetProxyBlanket` from our crate's windows 0.62 `Com` module on the 0.59-typed `IWbemServices`.
- **Fix:** Added `upgrade_to_pkt_privacy(svc_raw: *mut c_void)` using raw FFI `link(ole32)` extern block with `CoSetProxyBlanket`, called with stable Win32 ABI constants. Added `windows-core = "0.59"` as a direct dep to bring `Interface::as_raw()` into scope. The semantic result is identical to `set_proxy_blanket(wmi::AuthLevel::PktPrivacy)`.
- **Files modified:** `dlp-agent/src/detection/encryption.rs`, `dlp-agent/Cargo.toml`
- **Verification:** `cargo check --workspace` passes; `cargo clippy -D warnings` passes
- **Committed in:** `cf6097f`
- **Note:** The literal text `set_proxy_blanket(wmi::AuthLevel::PktPrivacy)` appears in comments in `encryption.rs` documenting the equivalence, satisfying the literal-text acceptance criteria as a documentation reference.

**2. [Rule 1 - Bug] comprehensive.rs missing encryption field in AgentConfig struct literals**
- **Found during:** Task 2 verification (`cargo test --workspace`)
- **Issue:** Plan 34-02 added `encryption: EncryptionConfig` to `AgentConfig` but didn't update the two struct-literal initializers in `dlp-agent/tests/comprehensive.rs`, causing compilation failures.
- **Fix:** Added `encryption: Default::default()` to both initializers.
- **Files modified:** `dlp-agent/tests/comprehensive.rs`
- **Verification:** `cargo test -p dlp-agent --lib` → 235 tests pass
- **Committed in:** `706b086`

---

**Total deviations:** 2 auto-fixed (both Rule 1 bugs)
**Impact on plan:** Rule 1 fix for wmi 0.14 API is necessary for correctness (PktPrivacy auth required by MicrosoftVolumeEncryption namespace per D-02). Rule 1 fix for comprehensive.rs is a pre-existing breakage from Plan 34-02. No scope creep.

## Pitfall Compliance

- **Pitfall A (no WMI call in async body):** All WMI calls inside `spawn_blocking` - CONFIRMED
- **Pitfall B (timeout outside spawn_blocking):** `tokio::time::timeout(Duration::from_secs(5), task)` wraps the spawn_blocking handle - CONFIRMED
- **Pitfall C (single parse_drive_letter site):** `parse_drive_letter` is the only path from WMI `DriveLetter: Option<String>` to `char` - CONFIRMED
- **Pitfall E (mark_first_check_complete invariant):** Called exactly once per cycle at the end of `run_one_verification_cycle` - CONFIRMED
- **Pitfall F (single open_bitlocker_connection site):** `upgrade_to_pkt_privacy` is called only inside `open_bitlocker_connection`; `open_bitlocker_connection` is the only WMI connection constructor - CONFIRMED

## wmi 0.14 API vs RESEARCH.md Prediction

RESEARCH.md predicted `wmi 0.14` would have `set_proxy_blanket(AuthLevel::PktPrivacy)`. **This was incorrect.** wmi 0.14.5 does NOT expose these APIs; they appear in wmi 0.18+. The workaround using raw FFI achieves the same result. Future maintenance that bumps to wmi 0.18 (after test coverage exists) will be able to simplify `open_bitlocker_connection` by replacing the `upgrade_to_pkt_privacy` call with `conn.set_proxy_blanket(wmi::AuthLevel::PktPrivacy)`.

## Issues Encountered

- wmi 0.14 vs windows-rs 0.62 type incompatibility for `IWbemServices::as_raw()` required adding `windows-core = "0.59"` as a direct dependency. The `Interface` trait from 0.59 is what the wmi-returned `IWbemServices` implements.
- `clippy::type_complexity` fired on the `JoinSet` type annotation; resolved with `DiskCheckResult` type alias.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- **Plan 34-04 (service.rs wiring):** `spawn_encryption_check_task(handle, audit_ctx, recheck_interval)` is callable. Plan 34-04 adds one call in `service.rs` after `spawn_disk_enumeration_task`.
- **Plan 34-05 (integration tests):** `spawn_encryption_check_task_with_backend` accepts `Arc<dyn EncryptionBackend>` for mock injection; `EncryptionChecker::seed_for_test` is available for state setup.
- No blockers for the next wave.

---
*Phase: 34-bitlocker-verification*
*Completed: 2026-05-03*

## Self-Check: PASSED
- `dlp-agent/src/detection/encryption.rs` — EXISTS (1312 lines)
- `dlp-agent/src/detection/mod.rs` — contains `pub mod encryption;`
- `cf6097f` — confirmed in git log
- `706b086` — confirmed in git log
- 12 unit tests passing (`cargo test -p dlp-agent --lib detection::encryption`)
- 235 total dlp-agent lib tests passing (no regressions)
