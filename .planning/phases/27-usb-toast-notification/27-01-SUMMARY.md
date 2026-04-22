---
phase: 27-usb-toast-notification
plan: 01
subsystem: usb
tags: [usb, enforcement, parking_lot, cooldown, toast, notification]

requires:
  - phase: 26-abac-enforcement-convergence
    provides: UsbEnforcer with check() returning Option<Decision>, UsbDetector, DeviceRegistryCache, UsbTrustTier

provides:
  - UsbBlockResult struct with decision, identity, tier, notify fields
  - Per-drive-letter 30-second toast cooldown via last_toast: Mutex<HashMap<char, Instant>>
  - Updated check() returning Option<UsbBlockResult> with notify flag
  - Updated interception/mod.rs call site destructuring usb_result.decision

affects:
  - 27-02 (pipe2 toast broadcast — consumes UsbBlockResult.notify and identity)

tech-stack:
  added: []
  patterns:
    - "Cooldown-gated notification: should_notify() mutates Mutex<HashMap<char, Instant>>; block decision independent of notify flag"
    - "Rich result type: Option<UsbBlockResult> carries full context instead of bare Option<Decision>"

key-files:
  created: []
  modified:
    - dlp-agent/src/usb_enforcer.rs
    - dlp-agent/src/interception/mod.rs

key-decisions:
  - "UsbBlockResult derives PartialEq to allow assert_eq! with None in tests"
  - "Clippy prefers is_none_or over map_or(true, ...) — updated accordingly"
  - "interception/mod.rs renamed decision to usb_result and accesses .decision field for AuditEvent and is_denied check"

patterns-established:
  - "Notification cooldown: Mutex<HashMap<char, Instant>> + is_none_or pattern for per-key expiry"

requirements-completed:
  - USB-04

duration: 20min
completed: 2026-04-22
---

# Phase 27 Plan 01: USB Toast Notification — UsbBlockResult + Cooldown Summary

**UsbEnforcer::check() now returns Option<UsbBlockResult> carrying device identity, trust tier, decision, and a per-drive 30-second cooldown-gated notify flag for toast suppression**

## Performance

- **Duration:** ~20 min
- **Started:** 2026-04-22T16:32:00Z
- **Completed:** 2026-04-22T16:52:15Z
- **Tasks:** 1
- **Files modified:** 2

## Accomplishments

- Defined `pub struct UsbBlockResult { decision, identity, tier, notify }` with `Debug, Clone, PartialEq` derives
- Added `last_toast: Mutex<HashMap<char, Instant>>` field to `UsbEnforcer` for per-drive cooldown tracking
- Added `should_notify()` private helper using `is_none_or` for 30-second cooldown — block always enforced, only toast gated
- Changed `check()` signature from `Option<Decision>` to `Option<UsbBlockResult>`; all behavior preserved
- Updated `interception/mod.rs` call site to destructure `usb_result.decision` instead of bare `decision`
- Updated all 11 existing tests to assert on `UsbBlockResult` fields; added `test_cooldown_suppresses_second_toast`
- 12/12 tests pass; clippy clean; workspace builds clean

## Task Commits

1. **Task 1: Add UsbBlockResult, cooldown field, and update check() + tests** - `eed8651` (feat)

## Files Created/Modified

- `dlp-agent/src/usb_enforcer.rs` — UsbBlockResult struct, last_toast field, should_notify(), updated check(), updated tests
- `dlp-agent/src/interception/mod.rs` — renamed `decision` to `usb_result`, access `.decision` field at AuditEvent and is_denied call sites

## Decisions Made

- `UsbBlockResult` derives `PartialEq` so `assert_eq!(result, None)` compiles in tests without custom matchers
- Clippy `unnecessary_map_or` lint requires `is_none_or` over `map_or(true, ...)` — updated in `should_notify()`
- `interception/mod.rs` call site updated as part of the same commit (Rule 3 — blocking issue caused by changing check() return type)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Updated interception/mod.rs call site for new check() return type**
- **Found during:** Task 1 — first cargo test run
- **Issue:** `interception/mod.rs` passed `decision: Decision` to `AuditEvent::new()` and called `decision.is_denied()`; after check() now returns `Option<UsbBlockResult>`, those lines no longer compiled
- **Fix:** Renamed binding from `decision` to `usb_result`; passed `usb_result.decision` to AuditEvent and `usb_result.decision.is_denied()` for the block-notify guard
- **Files modified:** `dlp-agent/src/interception/mod.rs`
- **Verification:** `cargo test -p dlp-agent --lib usb_enforcer` and `CARGO_TARGET_DIR=target-test cargo build --all` both pass
- **Committed in:** `eed8651` (part of task commit)

**2. [Rule 1 - Bug] Added PartialEq to UsbBlockResult derive**
- **Found during:** Task 1 — first cargo test run
- **Issue:** `assert_eq!(result, None)` in tests for FullAccess/UNC/non-USB paths failed to compile — `Option<UsbBlockResult>` requires `PartialEq` on the inner type
- **Fix:** Added `PartialEq` to `#[derive(Debug, Clone, PartialEq)]` on `UsbBlockResult`
- **Files modified:** `dlp-agent/src/usb_enforcer.rs`
- **Verification:** All 12 tests compile and pass
- **Committed in:** `eed8651` (part of task commit)

**3. [Rule 1 - Bug] Replaced map_or(true) with is_none_or per clippy**
- **Found during:** Task 1 — clippy run after tests passed
- **Issue:** `clippy::unnecessary_map_or` fired on `map.get(&drive).map_or(true, |last| ...)` in `should_notify()`
- **Fix:** Replaced with `.is_none_or(|last| ...)` as clippy suggested
- **Files modified:** `dlp-agent/src/usb_enforcer.rs`
- **Verification:** `cargo clippy -p dlp-agent -- -D warnings` exits 0
- **Committed in:** `eed8651` (part of task commit)

---

**Total deviations:** 3 auto-fixed (2 Rule 1 bugs, 1 Rule 3 blocking)
**Impact on plan:** All fixes required for compilation and lint compliance. No scope creep.

## Issues Encountered

- `cargo build --all` failed due to locked `dlp-server.exe` (running service holds the file). Used `CARGO_TARGET_DIR=target-test` workaround per existing STATE.md decision. Workspace compiled cleanly.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `UsbBlockResult` is fully defined and ready for Plan 27-02 to consume `notify` and `identity` fields for Pipe 2 toast broadcast
- `interception/mod.rs` call site is updated and compiles; Plan 27-02 will extend it to broadcast `Pipe2AgentMsg::UsbBlocked` when `usb_result.notify` is true

---
*Phase: 27-usb-toast-notification*
*Completed: 2026-04-22*
