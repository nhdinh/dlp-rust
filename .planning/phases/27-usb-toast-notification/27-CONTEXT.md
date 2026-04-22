# Phase 27: USB Toast Notification - Context

**Gathered:** 2026-04-22
**Status:** Ready for planning

<domain>
## Phase Boundary

When the agent blocks a USB file operation (fully-blocked device or ReadOnly device
write attempt), `dlp-user-ui` displays a Windows toast notification within two
seconds containing the device name and a brief policy explanation.

All infrastructure already exists:
- `Pipe2AgentMsg::Toast { title, body }` is defined in `dlp-agent/src/ipc/messages.rs`
- `BROADCASTER.broadcast()` global static is ready in `dlp-agent/src/ipc/pipe2.rs`
- `dlp-user-ui/src/ipc/pipe2.rs` already routes `Toast` to `crate::notifications::show_toast()`
- `UsbEnforcer::check()` is the injection point in `run_event_loop`

Requirements in scope: USB-04

</domain>

<decisions>
## Implementation Decisions

### D-01: UsbBlockResult struct (replaces Option<Decision> return)

`UsbEnforcer::check()` signature changes from `Option<Decision>` to `Option<UsbBlockResult>`:

```rust
pub struct UsbBlockResult {
    pub decision: Decision,
    pub identity: DeviceIdentity,
    pub notify: bool,  // false when per-drive cooldown is active
}

pub fn check(&self, path: &str, action: &FileAction) -> Option<UsbBlockResult>
```

- `decision` — always `Decision::DENY` for the current logic; preserved for future tiers
- `identity` — the `DeviceIdentity` (vid, pid, serial, description) for the blocked drive
- `notify` — `true` on first block; `false` when cooldown suppresses the toast

### D-02: Per-drive toast cooldown in UsbEnforcer

`UsbEnforcer` gains a `last_toast: Mutex<HashMap<char, Instant>>` field.

- Cooldown window: **30 seconds** per drive letter
- On block: check if `last_toast[drive]` is within 30s
  - If no entry or expired: set `last_toast[drive] = Instant::now()`, set `notify = true`
  - If within window: set `notify = false` (block still applies, toast suppressed)
- `Mutex` (not `RwLock`) because every block that fires a toast writes to the map

### D-03: Toast fires for both Blocked and ReadOnly write-class blocks

Both tiers produce a toast with tier-specific copy:

| Tier | Title | Body |
|------|-------|------|
| `UsbTrustTier::Blocked` | `"USB Device Blocked"` | `"{description} — this device is not permitted"` |
| `UsbTrustTier::ReadOnly` (write op) | `"USB Device Read-Only"` | `"{description} — write operations are not permitted"` |

`notify` and `identity` are included in `UsbBlockResult` regardless of tier.
The caller (`run_event_loop`) constructs the message from `identity.description` and
the `decision` context (the tier can be inferred from the existing block reason string,
or `UsbBlockResult` can carry it — see D-04).

### D-04: Carry UsbTrustTier in UsbBlockResult for message disambiguation

`UsbBlockResult` includes `tier: UsbTrustTier` so `run_event_loop` can choose the
correct title/body without re-reading the registry:

```rust
pub struct UsbBlockResult {
    pub decision: Decision,
    pub identity: DeviceIdentity,
    pub tier: UsbTrustTier,
    pub notify: bool,
}
```

### D-05: Toast broadcast call site — run_event_loop

In `dlp-agent/src/interception/mod.rs`, after `enforcer.check()` returns `Some(result)`:

```rust
if let Some(result) = enforcer.check(&path, &action) {
    // Existing audit + BlockNotify logic (unchanged)
    // ...

    // USB-04: toast notification
    if result.notify {
        let (title, body) = match result.tier {
            UsbTrustTier::Blocked => (
                "USB Device Blocked".to_string(),
                format!("{} — this device is not permitted", result.identity.description),
            ),
            UsbTrustTier::ReadOnly => (
                "USB Device Read-Only".to_string(),
                format!("{} — write operations are not permitted", result.identity.description),
            ),
            UsbTrustTier::FullAccess => unreachable!("FullAccess never returns a block result"),
        };
        crate::ipc::pipe2::BROADCASTER.broadcast(&Pipe2AgentMsg::Toast { title, body });
    }

    continue; // skip ABAC
}
```

### Claude's Discretion

- Whether `UsbBlockResult` is defined in `usb_enforcer.rs` or `interception/mod.rs`
- Exact `Mutex` vs `std::sync::Mutex` vs `parking_lot::Mutex` choice (follow existing crate conventions — `parking_lot` is used elsewhere in the agent)
- Test helper construction for `UsbBlockResult` in updated unit tests

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements
- `.planning/REQUIREMENTS.md` — USB-04 requirement definition
- `.planning/ROADMAP.md` §Phase 27 — 3 success criteria

### Existing Infrastructure (do not redefine or replace)
- `dlp-agent/src/ipc/pipe2.rs` — `BROADCASTER` global static + `Broadcaster::broadcast()`
- `dlp-agent/src/ipc/messages.rs` — `Pipe2AgentMsg::Toast { title, body }` (already defined)
- `dlp-user-ui/src/notifications.rs` — `show_toast()` (no changes needed)
- `dlp-user-ui/src/ipc/pipe2.rs` — already routes `Toast` to `show_toast()` (no changes needed)

### Files Requiring Modification
- `dlp-agent/src/usb_enforcer.rs` — add `UsbBlockResult` struct; add `last_toast` cooldown field; change `check()` return type; update all tests
- `dlp-agent/src/interception/mod.rs` — update USB block handler to destructure `UsbBlockResult` and call `BROADCASTER.broadcast()` when `notify == true`
- `dlp-agent/src/service.rs` — update `UsbEnforcer::new()` call site if constructor signature changes

### Prior Phase Context
- `.planning/phases/26-abac-enforcement-convergence/26-CONTEXT.md` — D-07 through D-12: `UsbEnforcer` original design and wiring
- `.planning/phases/23-usb-enumeration-in-dlp-agent/23-CONTEXT.md` — `DeviceIdentity` struct fields
- `.planning/phases/24-device-registry-db-admin-api/24-CONTEXT.md` — `UsbTrustTier` enum values and `trust_tier_for()` return semantics

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `BROADCASTER.broadcast(&Pipe2AgentMsg::Toast { title, body })` — already used by `health_monitor.rs`; same pattern applies here
- `DeviceIdentity.description` — human-readable device name, already populated by Phase 23 USB enumeration
- `UsbTrustTier` enum — `Blocked`, `ReadOnly`, `FullAccess` — already in `dlp-common`
- Existing `check()` tests in `usb_enforcer.rs` — must be updated to unwrap `UsbBlockResult` instead of `Option<Decision>`

### Established Patterns
- `parking_lot::Mutex` — used in `device_registry.rs` and other agent modules; prefer over `std::sync::Mutex`
- Fire-and-forget broadcast — `BROADCASTER.broadcast()` is non-blocking; no await needed
- `#[must_use]` on `check()` — keep this attribute on the updated signature

### Integration Points
- `dlp-agent/src/interception/mod.rs:77–119` — existing USB block handler; toast call inserts at line ~117 before `continue`
- `dlp-agent/src/ipc/pipe2.rs:111` — `pub static BROADCASTER` — import path for the toast call

</code_context>

<specifics>
## Specific Ideas

- `UsbTrustTier::FullAccess` in the `match result.tier` branch is unreachable — `check()` never returns `Some(...)` for `FullAccess`. Use `unreachable!()` with a descriptive message rather than a silent `_` arm.
- Cooldown per drive letter (not per device triple) is intentional — if the same physical device is re-inserted and gets a new drive letter, it should toast again. If the same drive floods retries, the letter stays constant and dedup fires correctly.
- `notify = false` during cooldown still returns `Some(result)` — the file op is still blocked. Only the toast is suppressed. `run_event_loop` must check `result.notify` before broadcasting, not skip the block.

</specifics>

<deferred>
## Deferred Ideas

- USB-05: Audit events carrying full device identity fields (VID, PID, serial, description) on block — already deferred in REQUIREMENTS.md
- Configurable cooldown window (currently hardcoded 30s) — operator config via admin API is a future enhancement
- Toast action button ("Learn more" / "Contact IT") — winrt-notification supports action buttons; deferred as a UX enhancement beyond USB-04 scope

</deferred>

---

*Phase: 27-usb-toast-notification*
*Context gathered: 2026-04-22*
