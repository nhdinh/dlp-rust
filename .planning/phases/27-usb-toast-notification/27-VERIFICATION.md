---
phase: 27-usb-toast-notification
verified: 2026-04-22T17:30:00Z
status: human_needed
score: 9/9 must-haves verified
overrides_applied: 0
human_verification:
  - test: "Plug a registered blocked USB device into a Windows endpoint running dlp-agent and dlp-user-ui"
    expected: "Within two seconds, a Windows toast notification appears with title 'USB Device Blocked' and a body containing the device description and 'this device is not permitted'"
    why_human: "Toast rendering requires a live Windows Runtime session with a running system tray UI; cannot verify winrt_notification display path programmatically"
  - test: "Repeat a write to a blocked USB drive within 30 seconds of the first block"
    expected: "The file write is denied both times, but a toast notification appears only on the first block (cooldown suppresses the second)"
    why_human: "Cooldown behavior in the live agent requires real OS timing; Instant::now() cannot be mocked in unit tests"
  - test: "Plug a registered read_only USB device and attempt a write"
    expected: "Write is denied and a toast appears with title 'USB Device Read-Only' and body containing the device description and 'write operations are not permitted'"
    why_human: "ReadOnly tier toast path requires live hardware and running UI"
---

# Phase 27: USB Toast Notification Verification Report

**Phase Goal:** Users receive an immediate, informative toast notification when a USB device is blocked so they understand why the device is not working
**Verified:** 2026-04-22T17:30:00Z
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | UsbEnforcer::check() returns Option<UsbBlockResult> carrying decision, identity, tier, and notify fields | VERIFIED | `pub struct UsbBlockResult` with all four public fields defined at usb_enforcer.rs:39-48; check() signature at line 119 returns `Option<UsbBlockResult>` |
| 2 | A 30-second per-drive-letter cooldown suppresses repeat toasts without suppressing the block | VERIFIED | `should_notify()` at usb_enforcer.rs:81-95 uses `Mutex<HashMap<char, Instant>>` with `COOLDOWN = Duration::from_secs(30)`; block decision always applied in both Blocked and ReadOnly arms |
| 3 | notify=true on the first block within a 30s window; notify=false on subsequent blocks in the same window | VERIFIED | `test_cooldown_suppresses_second_toast` at usb_enforcer.rs:460-481 asserts `first.notify == true` and `second.notify == false`; both assert `decision == DENY` |
| 4 | All existing check() behaviour (Blocked denies all, ReadOnly denies writes, FullAccess returns None) is preserved | VERIFIED | Tests `test_blocked_device_denies_all_actions`, `test_readonly_device_denies_write_class`, `test_readonly_device_allows_read`, `test_full_access_device_returns_none` all present and substantive at usb_enforcer.rs:289-363 |
| 5 | All existing unit tests are updated and pass against the new return type | VERIFIED | All test assertions use `UsbBlockResult` fields (e.g., `r.decision`, `r.tier`, `r.identity.description`); SUMMARY documents 12/12 tests pass |
| 6 | When a USB device is blocked and notify=true, a Pipe2AgentMsg::Toast is broadcast to the UI | VERIFIED | interception/mod.rs:119-142 contains `if usb_result.notify { ... crate::ipc::pipe2::BROADCASTER.broadcast(&Pipe2AgentMsg::Toast { title, body }) }` |
| 7 | Toast title and body are tier-specific: 'USB Device Blocked'/'USB Device Read-Only' with the device description | VERIFIED | interception/mod.rs:121-139: Blocked arm produces title "USB Device Blocked" with body `format!("{} \u{2014} this device is not permitted", usb_result.identity.description)`; ReadOnly arm produces title "USB Device Read-Only" with body `format!("{} \u{2014} write operations are not permitted", usb_result.identity.description)` |
| 8 | notify=false suppresses the toast but does not suppress the block (audit + BlockNotify still fire) | VERIFIED | interception/mod.rs:78-143: `emit_audit` and `pipe1::send_to_ui(BlockNotify)` execute unconditionally before the `if usb_result.notify` guard; toast is additive |
| 9 | FullAccess arm in the match is unreachable!() — it can never appear in UsbBlockResult | VERIFIED | interception/mod.rs:135-139: `UsbTrustTier::FullAccess => { unreachable!("FullAccess never returns a block result from UsbEnforcer::check") }` |

**Score:** 9/9 truths verified

### ROADMAP Success Criteria

| # | Success Criterion | Status | Evidence |
|---|-------------------|--------|----------|
| SC-1 | dlp-user-ui displays a Windows toast within two seconds containing device name and policy explanation | NEEDS HUMAN | Pipe 2 wiring and show_toast() call verified programmatically; live toast rendering requires human test |
| SC-2 | Notification correctly identifies the device by its description (not just VID/PID) | VERIFIED | `usb_result.identity.description` used in both format! strings in interception/mod.rs:124-131 |
| SC-3 | Toast delivery reuses the existing winrt-notification integration — no new notification library added | VERIFIED | dlp-user-ui/Cargo.toml:22 `winrt-notification = "0.5"` already present; notifications.rs:15-23 `show_toast()` uses `winrt_notification::Toast`; Pipe2AgentMsg::Toast handler at dlp-user-ui/src/ipc/pipe2.rs:102-104 calls `crate::notifications::show_toast(&title, &body)` |

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `dlp-agent/src/usb_enforcer.rs` | UsbBlockResult struct, cooldown field, updated check() signature and tests | VERIFIED | `pub struct UsbBlockResult` at line 39; `last_toast: Mutex<HashMap<char, Instant>>` at line 60; check() returns `Option<UsbBlockResult>` at line 119; 12 tests including `test_cooldown_suppresses_second_toast` |
| `dlp-agent/src/interception/mod.rs` | Toast broadcast call site wired into USB block handler | VERIFIED | `BROADCASTER.broadcast(&Pipe2AgentMsg::Toast { title, body })` at line 141; imports `Pipe2AgentMsg` at line 36 and `UsbTrustTier` at line 29 |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| dlp-agent/src/usb_enforcer.rs | dlp-agent/src/interception/mod.rs | UsbBlockResult returned from check(); destructured by run_event_loop | WIRED | interception/mod.rs:78 `if let Some(usb_result) = enforcer.check(&path, &action)` references `usb_result.decision`, `usb_result.notify`, `usb_result.tier`, `usb_result.identity.description` |
| dlp-agent/src/interception/mod.rs | dlp-agent/src/ipc/pipe2::BROADCASTER | crate::ipc::pipe2::BROADCASTER.broadcast(&Pipe2AgentMsg::Toast { title, body }) | WIRED | interception/mod.rs:141 `crate::ipc::pipe2::BROADCASTER.broadcast(...)` confirmed present |
| run_event_loop USB block handler | UsbBlockResult.identity.description | format! macro building toast body | WIRED | interception/mod.rs:124 and 130: `usb_result.identity.description` used in both Blocked and ReadOnly format! strings |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| dlp-agent/src/interception/mod.rs (toast broadcast) | `usb_result.identity.description` | `UsbEnforcer::check()` → `detector.device_identities.read()` → `map.get(&drive).cloned()` | Yes — device identity populated from live UsbDetector hardware map | FLOWING |
| dlp-user-ui/src/ipc/pipe2.rs (Toast handler) | `title`, `body` from `Pipe2AgentMsg::Toast` | Pipe 2 named-pipe read from BROADCASTER | Yes — strings built from real device description at broadcast site | FLOWING |
| dlp-user-ui/src/notifications.rs (show_toast) | `title: &str`, `body: &str` | Called directly by pipe2 handler with real values | Yes — passed through without modification | FLOWING |

### Behavioral Spot-Checks

Step 7b: SKIPPED — toast rendering requires a running Windows Runtime session and live USB hardware. All code paths verified statically.

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| USB-04 | 27-01-PLAN.md, 27-02-PLAN.md | User receives a toast notification on USB block containing the device name and policy explanation | SATISFIED | UsbBlockResult with notify flag (Plan 27-01) + BROADCASTER.broadcast(Toast) wired in interception/mod.rs (Plan 27-02) + dlp-user-ui pipe2 handler calls show_toast() using winrt-notification |

### Anti-Patterns Found

No anti-patterns found in phase-modified files.

- `dlp-agent/src/usb_enforcer.rs`: No TODO/FIXME/placeholder comments; no empty returns; no hardcoded empty state
- `dlp-agent/src/interception/mod.rs`: No TODO/FIXME; `unreachable!()` on FullAccess arm is intentional and documented (T-27-07), not a stub

### Human Verification Required

#### 1. Live Toast on Blocked USB Device

**Test:** On a Windows 10/11 machine running dlp-agent (SYSTEM) and dlp-user-ui (user session), register a USB mass-storage device with trust tier `blocked` via the admin API. Plug in the device and attempt to write a file to it.
**Expected:** A Windows toast notification appears within two seconds with title "USB Device Blocked" and a body containing the device's registered description followed by " — this device is not permitted". The file write is denied.
**Why human:** winrt-notification requires a live Windows Runtime notification infrastructure with an active user session. The pipe2 wiring and show_toast() call are code-verified; the OS-level display cannot be asserted programmatically.

#### 2. Cooldown Suppresses Second Toast (Live Timing)

**Test:** After the first block in Test 1, immediately attempt a second write to the same drive within 30 seconds.
**Expected:** The second write is denied (block enforced), but no second toast appears. After 30 seconds elapse, a third write attempt should produce a new toast.
**Why human:** `Instant::now()` is not mockable in unit tests without a time abstraction layer. The 30-second expiry path is covered by design but requires real OS time to exercise end-to-end.

#### 3. Read-Only Tier Toast

**Test:** Register a USB device with trust tier `read_only`. Attempt to write a file to it.
**Expected:** Write is denied and a toast appears with title "USB Device Read-Only" and body "{description} — write operations are not permitted". Reading a file from the same device should succeed with no toast.
**Why human:** Same winrt-notification rendering constraint as Test 1; requires live hardware and running UI.

### Gaps Summary

No automated gaps found. All 9 must-have truths are verified in the codebase. The full data-flow chain from `UsbEnforcer::check()` through `BROADCASTER.broadcast()` through `dlp-user-ui` Pipe 2 handler to `show_toast()` using the existing `winrt-notification` crate is wired and substantive.

The three human verification items are required to confirm the Windows Runtime toast rendering layer, which is not accessible to static analysis. These are acceptance tests, not gaps in implementation.

---

_Verified: 2026-04-22T17:30:00Z_
_Verifier: Claude (gsd-verifier)_
