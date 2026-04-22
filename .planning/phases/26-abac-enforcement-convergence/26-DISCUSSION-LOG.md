# Phase 26: ABAC Enforcement Convergence - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-22
**Phase:** 26-abac-enforcement-convergence
**Areas discussed:** Condition variant shape, USB enforcement position, USB wiring into run_event_loop, Write-scope for read_only

---

## Condition Variant Shape

| Option | Description | Selected |
|--------|-------------|----------|
| 2 variants, field sub-enum | `SourceApplication { field: AppField, op, value }` + `DestinationApplication { field: AppField, op, value }` with `AppField` enum (Publisher, ImagePath, TrustTier). Produces clean JSON, 2 arms in condition_matches. | ✓ |
| 6 flat variants | `SourceApplicationPublisher`, `SourceApplicationImagePath`, etc. — consistent with flat style but 6 new arms. | |

**User's choice:** 2 variants with field sub-enum (recommended option)
**Notes:** Phase 28 TUI picker can enumerate `AppField` variants cleanly.

---

## USB Enforcement Position

| Option | Description | Selected |
|--------|-------------|----------|
| Pre-ABAC short-circuit | Check drive trust tier in `run_event_loop` before calling `offline.evaluate()`. Unconditional enforcement — tier = decision. | ✓ |
| PolicyCondition variant | New `UsbDeviceTier` condition variant. Admin authors policies to enforce USB tiers. | |

**User's choice:** Pre-ABAC short-circuit (recommended option)
**Notes:** USB-03 enforcement is unconditional per requirements — `blocked` = deny all, `read_only` = deny writes, regardless of ABAC policies. Not policy-authored.

---

## USB Wiring into run_event_loop

| Option | Description | Selected |
|--------|-------------|----------|
| UsbEnforcer wrapper struct | Thin struct wrapping both Arcs, exposes `check(path, action) -> Option<Decision>`. Passed as `Option<Arc<UsbEnforcer>>`. | ✓ |
| Two separate Arc params | Pass `Arc<UsbDetector>` and `Arc<DeviceRegistryCache>` separately. | |

**User's choice:** UsbEnforcer wrapper (recommended option)
**Notes:** Keeps `run_event_loop` signature clean — one new parameter instead of two. Follows existing `Arc<Option<AdClient>>` pattern for optional subsystems.

---

## Write-scope for read_only

| Option | Description | Selected |
|--------|-------------|----------|
| Written + Created + Deleted + Renamed | All mutation variants blocked; only Read allowed through. | ✓ |
| Written only | Only explicit write events blocked; created/deleted/renamed allowed. | |

**User's choice:** Written + Created + Deleted + Renamed (recommended option)
**Notes:** A read_only device should block all data modification operations, not just byte-writes. Deleting or renaming a file on a read_only device is also a mutation.

---

## Claude's Discretion

- Exact module-level doc structure for `UsbEnforcer`
- Whether `From<EvaluateRequest> for AbacContext` is a standalone impl or conversion helper
- Test helper construction style for `AbacContext`-based `evaluate()` tests

## Deferred Ideas

- USB-05: device identity fields in audit events on block — already deferred in REQUIREMENTS.md
- Phase 28 TUI picker for `AppField` variants
- Richer operators beyond `eq`/`ne`/`contains` for app-identity conditions
