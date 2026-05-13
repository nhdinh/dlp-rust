---
phase: 26-abac-enforcement-convergence
plan: "04"
subsystem: usb-enforcement
tags: [rust, usb, enforcement, abac, tdd, dlp-agent]

requires:
  - phase: 26-abac-enforcement-convergence
    plan: "01"
    provides: DeviceRegistryCache::trust_tier_for, DeviceRegistryCache::seed_for_test
  - phase: 26-abac-enforcement-convergence
    plan: "02"
    provides: AbacContext migration, offline.evaluate() call site in run_event_loop

provides:
  - UsbEnforcer struct with check() method in dlp-agent/src/usb_enforcer.rs
  - Pre-ABAC USB enforcement gate in run_event_loop (fires before offline.evaluate())
  - USB_DETECTOR static promoted to Arc<UsbDetector> for shared ownership
  - UsbEnforcer construction and wiring in service.rs production path

affects:
  - 26-05 (integration verification — run_event_loop signature is final)

tech-stack:
  added: []
  patterns:
    - "UsbEnforcer: thin bridge struct holding Arc<UsbDetector> + Arc<DeviceRegistryCache>"
    - "Option<Arc<T>> parameter for optional subsystems — matches ad_client pattern in run_event_loop"
    - "Pre-ABAC short-circuit: check() returns Option<Decision>; None = fall through to ABAC engine"
    - "OnceLock<Arc<T>> pattern: promotes non-Clone static to shared Arc without cloning"

key-files:
  created:
    - dlp-agent/src/usb_enforcer.rs
  modified:
    - dlp-agent/src/lib.rs
    - dlp-agent/src/interception/mod.rs
    - dlp-agent/src/service.rs

key-decisions:
  - "USB_DETECTOR static changed from OnceLock<UsbDetector> to OnceLock<Arc<UsbDetector>> — non-Clone type cannot be cloned into Arc; wrapping in Arc at init time is the only safe approach"
  - "Console path (async_run_console) passes None for usb_enforcer — no USB detector setup in that code path; consistent with ad_client None fallback pattern"
  - "UNC path check uses starts_with('\\\\') before drive-letter extraction — T-26-10 mitigation; UNC paths never get USB treatment"
  - "Lowercase drive-letter normalization via to_ascii_uppercase() — T-26-12 mitigation; e:\\file and E:\\file resolve to same HashMap key"

duration: 8min
completed: "2026-04-22"
---

# Phase 26 Plan 04: UsbEnforcer — USB Device Trust Enforcement Summary

**UsbEnforcer struct bridges drive-letter map (Phase 23) and trust-tier cache (Phase 24) to enforce USB device trust tiers at file I/O time in run_event_loop, short-circuiting ABAC evaluation on blocked or read-only+write-class access**

## Performance

- **Duration:** 8 min
- **Started:** 2026-04-22T15:21:27Z
- **Completed:** 2026-04-22T15:29:15Z
- **Tasks:** 2
- **Files modified:** 4 (1 created, 3 modified)

## Accomplishments

- Created `dlp-agent/src/usb_enforcer.rs` with `UsbEnforcer` struct and `check()` method implementing D-07..D-09
- `check()` logic: `Blocked` → `Some(Decision::DENY)` for all actions; `ReadOnly` → `Some(Decision::DENY)` for write-class (`Written`, `Created`, `Deleted`, `Moved`), `None` for `Read`; `FullAccess` → `None`; non-USB paths/UNC → `None`
- 9 unit tests covering all trust tiers, all write-class variants, UNC bypass, non-USB drive, lowercase drive normalization
- Added `pub mod usb_enforcer` to `lib.rs` (windows-only, mirrors detection/interception)
- Updated `run_event_loop` signature: added `usb_enforcer: Option<Arc<UsbEnforcer>>` after `ad_client` (D-10)
- Inserted pre-ABAC USB check in event loop body: fires after path extraction, before identity resolution and `offline.evaluate()` (D-11); emits `AuditEvent::Block` + `Pipe1AgentMsg::BlockNotify` on deny, then `continue`s to skip ABAC
- Promoted `USB_DETECTOR` static from `OnceLock<UsbDetector>` to `OnceLock<Arc<UsbDetector>>` to enable Arc sharing (D-12)
- Constructed `UsbEnforcer` in `service.rs` production path after `registry_cache` is ready; passed to `run_event_loop`
- Console path (`async_run_console`) correctly passes `None` — no USB detector in that code path

## Task Commits

1. **Task 1: UsbEnforcer struct + tests** — `1f9e142`
2. **Task 2: Wire into run_event_loop + service.rs** — `4969701`

## Files Created/Modified

- `dlp-agent/src/usb_enforcer.rs` — new; 339 lines (struct, check(), helpers, 9 tests)
- `dlp-agent/src/lib.rs` — 2 lines added (`pub mod usb_enforcer` under `#[cfg(windows)]`)
- `dlp-agent/src/interception/mod.rs` — 51 lines added (import, signature change, pre-ABAC USB block)
- `dlp-agent/src/service.rs` — 16 lines added (Arc static promotion, UsbEnforcer construction, call site update × 2)

## Decisions Made

- `USB_DETECTOR` static promoted to `OnceLock<Arc<UsbDetector>>` — `UsbDetector` contains `parking_lot::RwLock` fields and is not `Clone`; wrapping in `Arc` at `OnceLock::get_or_init` time is the only way to share ownership with `UsbEnforcer`
- Console path gets `None` — `async_run_console` is a development/debug entry point; it has no USB detector setup. Consistent with the `ad_client: Arc<Option<AdClient>>` optional-subsystem pattern established in Phase 23
- `extract_drive_letter` checks `starts_with("\\\\")` before first-char extraction — this is the T-26-10 UNC bypass mitigation; UNC paths are never local USB drives and must not be incorrectly classified as lettered drives
- `is_write_class` uses `matches!` macro — exhaustive pattern without wildcard `_` arm per CLAUDE.md 9.10; the `Read` variant is not listed and returns `false` by negation

## Deviations from Plan

None — plan executed exactly as written. Two call sites updated (production `run_loop` + console `async_run_console`); plan did not mention the console path explicitly but passing `None` is the correct and safe choice (Rule 2: missing correct wiring = correctness requirement).

## Known Stubs

None.

## Threat Flags

None — no new network endpoints, auth paths, file access patterns, or schema changes beyond what the plan's threat model already covers (T-26-10 through T-26-13).

## Self-Check

- [x] `dlp-agent/src/usb_enforcer.rs` exists
- [x] `grep "pub fn check" dlp-agent/src/usb_enforcer.rs` — match found
- [x] `grep "usb_enforcer: Option<Arc<UsbEnforcer>>" dlp-agent/src/interception/mod.rs` — match found
- [x] `grep "UsbEnforcer::new" dlp-agent/src/service.rs` — match found
- [x] `cargo test -p dlp-agent --lib -- usb_enforcer` — 9 passed, 0 failed
- [x] `cargo build -p dlp-agent` — exit 0
- [x] `cargo clippy -p dlp-agent -- -D warnings` — exit 0, no warnings
- [x] `cargo fmt -p dlp-agent --check` — exit 0
- [x] Commits `1f9e142` and `4969701` exist

## Self-Check: PASSED

---
*Phase: 26-abac-enforcement-convergence*
*Completed: 2026-04-22*
