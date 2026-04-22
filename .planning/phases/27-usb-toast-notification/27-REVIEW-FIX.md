---
phase: 27-usb-toast-notification
fixed_at: 2026-04-22T00:00:00Z
review_path: .planning/phases/27-usb-toast-notification/27-REVIEW.md
iteration: 1
findings_in_scope: 4
fixed: 4
skipped: 0
status: all_fixed
---

# Phase 27: Code Review Fix Report

**Fixed at:** 2026-04-22T00:00:00Z
**Source review:** .planning/phases/27-usb-toast-notification/27-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 4
- Fixed: 4
- Skipped: 0

## Fixed Issues

### WR-01: Em-dash unicode in toast body strings violates no-decorative-unicode rule

**Files modified:** `dlp-agent/src/interception/mod.rs`
**Commit:** d4c03f1
**Applied fix:** Replaced `\u{2014}` (em-dash) with plain ASCII ` - ` in both toast body format strings — the Blocked tier body (`"{} - this device is not permitted"`) and the ReadOnly tier body (`"{} - write operations are not permitted"`).

---

### WR-02: USB audit event attributes real user as "SYSTEM" despite resolvable identity

**Files modified:** `dlp-agent/src/interception/mod.rs`
**Commit:** d4c03f1
**Applied fix:** Moved the `session_map.resolve_for_path` identity resolution block from after the USB enforcement check to before it (now runs at the top of each loop iteration, before the USB `if let` block). The USB `AuditEvent::new` call now passes `user_sid.clone()` and `user_name.clone()` instead of `"SYSTEM".to_string()`. The ABAC path below is unchanged — it reuses the same bindings, eliminating the duplicate resolution.

---

### WR-03: Unnecessary clone of AuditEvent to satisfy &mut signature

**Files modified:** `dlp-agent/src/interception/mod.rs`
**Commit:** d4c03f1
**Applied fix:** Changed `let audit_event = ...` to `let mut audit_event = ...` in both the USB path (line ~91) and the ABAC path (line ~230). The `.clone()` call in `emit_audit(&ctx, &mut audit_event.clone())` was removed in both locations; `emit_audit` now receives `&mut audit_event` directly, eliminating one heap allocation per blocked event.

---

### WR-04: BlockNotify hard-codes classification "T1" for all USB blocks regardless of tier

**Files modified:** `dlp-agent/src/interception/mod.rs`
**Commit:** d4c03f1
**Applied fix:** Replaced the hard-coded `classification: "T1".to_string()` in the `Pipe1AgentMsg::BlockNotify` USB branch with a match expression on `usb_result.tier`:
- `UsbTrustTier::Blocked` => `"USB-Blocked"`
- `UsbTrustTier::ReadOnly` => `"USB-ReadOnly"`
- `UsbTrustTier::FullAccess` => `unreachable!("FullAccess never produces a block result")`

---

## Verification

- `cargo build -p dlp-agent`: clean, 0 warnings
- `cargo test -p dlp-agent --lib`: 177 passed, 0 failed

---

_Fixed: 2026-04-22T00:00:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
