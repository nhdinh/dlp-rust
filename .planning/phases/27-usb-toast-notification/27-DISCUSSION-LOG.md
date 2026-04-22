# Phase 27: USB Toast Notification - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-22
**Phase:** 27-usb-toast-notification
**Areas discussed:** Device info in toast, Toast deduplication, Return shape, ReadOnly write-block toast, Toast message text

---

## Device info in toast

| Option | Description | Selected |
|--------|-------------|----------|
| Return (Decision, DeviceIdentity) | Change check() return to include DeviceIdentity alongside Decision | ✓ (evolved to struct) |
| Separate check_with_identity() | Keep check() unchanged, add a richer companion method | |
| Re-lookup in run_event_loop | Second cache hit after block detected; no signature change | |

**User's choice:** Return richer type — evolved to `Option<UsbBlockResult>` struct (see Return shape area)
**Notes:** User selected the recommended option. The tuple was further promoted to a named struct to also carry `tier` and `notify`.

---

## Toast deduplication

| Option | Description | Selected |
|--------|-------------|----------|
| Per-drive cooldown in UsbEnforcer | `last_toast: Mutex<HashMap<char, Instant>>` inside UsbEnforcer; 30s window | ✓ |
| Dedup in run_event_loop | Cooldown state lives in the event loop, UsbEnforcer stays stateless | |
| No dedup — one toast per event | Simplest, potentially spammy | |

**User's choice:** Per-drive cooldown in UsbEnforcer (recommended)
**Notes:** 30s cooldown window. Dedup is per drive letter, not per device triple — correct for the retry-flood case.

---

## Return shape

| Option | Description | Selected |
|--------|-------------|----------|
| Struct return type | `Option<UsbBlockResult>` with `decision`, `identity`, `tier`, `notify` fields | ✓ |
| Option<DeviceIdentity> in tuple | `Option<(Decision, Option<DeviceIdentity>)>` — compact but harder to read | |

**User's choice:** Struct return type (recommended)
**Notes:** `UsbBlockResult` carries all needed data in one coherent type. `tier` field added to support toast message disambiguation without a second registry lookup.

---

## ReadOnly write-block toast

| Option | Description | Selected |
|--------|-------------|----------|
| Yes, toast on ReadOnly writes too | Distinct message — "USB Device Read-Only" / "write operations are not permitted" | ✓ |
| No, toast only for Blocked | Matches USB-04 literally; ReadOnly is a softer restriction | |

**User's choice:** Yes, toast on ReadOnly writes too (recommended — "pick all recommended options")
**Notes:** User confirmed all recommended options in bulk.

---

## Toast message text

Both tiers produce toasts with tier-specific copy (auto-resolved via recommended pattern):

| Tier | Title | Body |
|------|-------|------|
| Blocked | "USB Device Blocked" | "{description} — this device is not permitted" |
| ReadOnly (write) | "USB Device Read-Only" | "{description} — write operations are not permitted" |

**User's choice:** Recommended format — short, actionable, names device and restriction
**Notes:** Resolved via "pick all recommended options" instruction.

---

## Claude's Discretion

- `UsbBlockResult` definition location (usb_enforcer.rs vs interception/mod.rs)
- `parking_lot::Mutex` vs `std::sync::Mutex` for `last_toast` field
- Test helper construction for updated unit tests

## Deferred Ideas

- Configurable cooldown window (hardcoded 30s for now)
- Toast action buttons ("Contact IT") — winrt-notification supports them; out of USB-04 scope
- USB-05 audit events with full device identity — already deferred in REQUIREMENTS.md
