---
phase: 27-usb-toast-notification
reviewed: 2026-04-22T00:00:00Z
depth: standard
files_reviewed: 2
files_reviewed_list:
  - dlp-agent/src/usb_enforcer.rs
  - dlp-agent/src/interception/mod.rs
findings:
  critical: 0
  warning: 4
  info: 3
  total: 7
status: issues_found
---

# Phase 27: Code Review Report

**Reviewed:** 2026-04-22T00:00:00Z
**Depth:** standard
**Files Reviewed:** 2
**Status:** issues_found

## Summary

Phase 27 introduces `UsbBlockResult` (usb_enforcer.rs) and wires a `Pipe2AgentMsg::Toast` broadcast
into the USB block handler (interception/mod.rs). The core logic is sound: the cooldown mechanism
correctly gates toast notifications without suppressing the block decision, and the `FullAccess` path
correctly falls through to ABAC.

Four warnings require attention before merge:

1. A `\u{2014}` em-dash is embedded in user-facing toast body strings, violating the project's
   no-emoji/no-decorative-unicode rule from CLAUDE.md.
2. The USB audit event is emitted with `"SYSTEM"` as user_sid and user_name even when the real
   Windows user identity is resolvable at that point in the loop — producing misleading audit records.
3. `AuditEvent` is cloned solely to satisfy `emit_audit`'s `&mut` signature; the clone is discarded
   immediately after the call. This is unnecessary overhead on every blocked USB event.
4. The `Pipe1AgentMsg::BlockNotify` branch inside the USB early-exit path hard-codes
   `classification: "T1".to_string()` instead of surfacing the actual tier from `usb_result.tier`,
   making audit records inaccurate when a ReadOnly device triggers a block.

---

## Warnings

### WR-01: Em-dash unicode in toast body strings violates no-decorative-unicode rule

**File:** `dlp-agent/src/interception/mod.rs:124` and `:131`
**Issue:** `\u{2014}` (em dash, —) is embedded directly in the user-facing toast body string.
CLAUDE.md section 9.2 explicitly forbids emoji and unicode that emulates emoji (decorative unicode).
An em-dash used as a visual separator in a notification body falls into this category.
**Fix:** Replace with a plain ASCII separator:
```rust
// line 124
format!("{} - this device is not permitted", usb_result.identity.description)

// line 131
format!("{} - write operations are not permitted", usb_result.identity.description)
```

---

### WR-02: USB audit event attributes real user as "SYSTEM" despite resolvable identity

**File:** `dlp-agent/src/interception/mod.rs:81-82`
**Issue:** The USB block audit event is constructed with `"SYSTEM".to_string()` for both `user_sid`
and `user_name`. At this point in the loop, `pid` is already in scope (line 72). The session_map
lookup used for ABAC events (lines 148-154) is equally valid here — the USB check fires on the same
`action` struct. Emitting `SYSTEM` as the actor produces misleading audit records: the user who
inserted the drive or triggered the file operation is attributable but not attributed.
**Fix:** Resolve the identity before the USB check branch and reuse it:
```rust
// Before the USB enforcement block, resolve identity once:
let (user_sid, user_name) = {
    let (app_path, _app_hash) = audit_emitter::get_application_metadata(pid);
    debug!(pid, path = %path, ?app_path, "file action received");
    session_map.resolve_for_path(&path)
};

// Then in the USB audit event, replace "SYSTEM" with the real values:
let audit_event = AuditEvent::new(
    EventType::Block,
    user_sid.clone(),
    user_name.clone(),
    // ...
```
This removes the duplicate identity resolution that currently exists later in the ABAC path (lines
148-154) and provides accurate user attribution in USB block audit records.

---

### WR-03: Unnecessary clone of AuditEvent to satisfy &mut signature

**File:** `dlp-agent/src/interception/mod.rs:99` and `:234`
**Issue:** `emit_audit(&ctx, &mut audit_event.clone())` clones the entire `AuditEvent` struct on
every call. The clone is discarded immediately after `emit_audit` returns. `emit_audit` takes `&mut`
because it may backfill `agent_id`, `session_id`, and user fields from ctx — it does not need
ownership. This pattern exists in both the USB path (line 99) and the ABAC path (line 234).
**Fix:** Bind the event as `mut` and pass a mutable reference directly:
```rust
let mut audit_event = AuditEvent::new( /* ... */ )
    .with_access_context(AuditAccessContext::Local)
    .with_policy( /* ... */ );

emit_audit(&ctx, &mut audit_event);
```
This eliminates an unnecessary heap allocation on every blocked event.

---

### WR-04: BlockNotify hard-codes classification "T1" for all USB blocks regardless of tier

**File:** `dlp-agent/src/interception/mod.rs:106`
**Issue:** The `Pipe1AgentMsg::BlockNotify` message sent on USB block hard-codes
`classification: "T1".to_string()`. When a `ReadOnly` device blocks a write operation the device's
actual tier (ReadOnly) is available in `usb_result.tier`, and the comment on line 84-86 acknowledges
T1 is a placeholder. Consumers of BlockNotify (UI, downstream log parsers) will see an incorrect
classification. This is distinct from the audit event T1 placeholder which has a comment explaining
the pre-classification context.
**Fix:** Derive the classification string from the enforcer result:
```rust
classification: match usb_result.tier {
    UsbTrustTier::Blocked  => "USB-Blocked".to_string(),
    UsbTrustTier::ReadOnly => "USB-ReadOnly".to_string(),
    UsbTrustTier::FullAccess => unreachable!("FullAccess never produces a block result"),
},
```
Or, if the `classification` field on `BlockNotify` is strictly a data-classification tier string
(T1–T4), the `policy_id` field should carry the USB tier context so the UI can render the correct
message.

---

## Info

### IN-01: `should_notify` acquires lock on every check for non-Blocked/ReadOnly drives

**File:** `dlp-agent/src/usb_enforcer.rs:81-95`
**Issue:** `should_notify` is only called from `check` within the `Blocked` and `ReadOnly` match
arms (lines 140, 151), so the lock is not taken for `FullAccess` or non-USB paths. This is correct
as written. However, the method is `pub(crate)`-accessible (currently private `fn`), so future
callers could invoke it outside the guard. Consider adding an inline doc comment noting that callers
must only invoke `should_notify` after confirming the tier is blocking.

---

### IN-02: `action.clone()` at loop top clones regardless of USB short-circuit

**File:** `dlp-agent/src/interception/mod.rs:70`
**Issue:** `let action = action.clone()` is the first statement in the loop body. For USB-blocked
events that short-circuit at line 143 via `continue`, the clone is used only to call `action.path()`
and `action.process_id()` — both of which are borrows. If `FileAction` is large (it carries path
strings), this is an allocation on every event including those that never reach ABAC. Consider
borrowing path and pid before the clone and deferring the clone to after the USB short-circuit.
This is a quality note, not a correctness issue.

---

### IN-03: `FullAccess` arm in toast match uses `unreachable!` without context in panic message

**File:** `dlp-agent/src/interception/mod.rs:135-139`
**Issue:** The `unreachable!` macro in the `FullAccess` arm produces a panic message that mentions
the invariant but does not include the drive letter or device identity that would aid debugging if
the invariant were ever violated. Consider adding context:
```rust
UsbTrustTier::FullAccess => unreachable!(
    "FullAccess tier must not produce a UsbBlockResult; \
     identity = {:?}", usb_result.identity
)
```

---

_Reviewed: 2026-04-22T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
