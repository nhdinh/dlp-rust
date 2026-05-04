# Phase 36: Disk Enforcement - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-04
**Phase:** 36-disk-enforcement
**Areas discussed:** Enforcer packaging, Fail-closed behavior, Device arrival update path, AuditEvent disk identity

---

## Enforcer Packaging

| Option | Description | Selected |
|--------|-------------|----------|
| DiskEnforcer struct | New disk_enforcer.rs mirroring UsbEnforcer; Option<Arc<DiskEnforcer>> passed into run_event_loop; stateful (toast cooldown) | ✓ |
| Inline in run_event_loop | 10-15 line check after USB block before ABAC; no new struct | |

**User's choice:** DiskEnforcer struct

---

### Blocked action filter

| Option | Description | Selected |
|--------|-------------|----------|
| Block Create/Write/Move only | Matches DISK-04 exactly; reads allowed on unregistered disks | ✓ |
| Block all I/O | Stricter; blocks reads too; would require spec change | |

**User's choice:** Block Create/Write/Move only

---

### Toast notification

| Option | Description | Selected |
|--------|-------------|----------|
| Block silently + audit only | No toast; DiskEnforcer is stateless | |
| Toast + 30s cooldown | Mirrors USB Phase 27 pattern; DiskEnforcer holds last_toast cooldown map | ✓ |

**User's choice:** Toast + 30s cooldown

---

## Fail-closed Behavior

| Option | Description | Selected |
|--------|-------------|----------|
| Block all writes when not ready | True fail-closed; consistent with D-04 Phase 33 | ✓ |
| Allow during startup, block on failure | Looser; passes writes through the ~4s startup window | |
| Allow all when not ready | Weakest; disables enforcement during startup and failure | |

**User's choice:** Block all writes

---

### Serial number compound check

**Context:** User raised: if someone physically swaps a disk with another of the same model into the same port slot, the instance_id (port-based on SATA/NVMe) may be identical. The serial number is the true per-disk fingerprint.

| Option | Description | Selected |
|--------|-------------|----------|
| instance_id + serial compound check | Block if serial mismatch when both sides have it; graceful degradation when serial absent | ✓ |
| instance_id only | Simpler; physical-swap bypass possible on port-based IDs | |

**User's choice:** Compound check

---

### Allowlist map semantics

**Context:** For serial check to work, instance_id_map must not be overwritten when a swapped disk arrives.

| Option | Description | Selected |
|--------|-------------|----------|
| Arrivals update drive_letter_map only | instance_id_map frozen as allowlist; serial check works; physical swap = mismatch = blocked | ✓ |
| Arrivals update both maps | Overwrites registered serial; serial check defeated for post-startup swaps | |

**User's choice:** drive_letter_map only; instance_id_map is frozen allowlist

---

## Device Arrival Update Path

| Option | Description | Selected |
|--------|-------------|----------|
| Add disk.rs handlers; usb.rs calls them | disk logic in disk.rs; usb.rs stays USB-focused; one message loop | |
| Inline in usb.rs | Fewer files; mixes USB and disk concerns | |
| Separate hidden window for disk | Clean separation; doubles Win32 message loop infrastructure | |
| New device_watcher.rs dispatcher (user suggestion) | Refactor Win32 window out of usb.rs into dispatcher; usb.rs and disk.rs get pure handlers | ✓ |

**Notes:** User suggested a cleaner architecture — a `device_watcher.rs` module that owns the Win32 window and dispatches to both `usb.rs` and `disk.rs` handlers. User chose to do the refactor now in Phase 36 rather than defer it.

---

### Arrival audit event

| Option | Description | Selected |
|--------|-------------|----------|
| Emit DiskDiscovery audit on arrival | Immediate visibility in audit feed for unregistered disk plug-in | ✓ |
| Block audit only at first write | Admin only learns about it when writes are attempted | |

**User's choice:** Emit DiskDiscovery immediately on arrival of unregistered disk

---

## AuditEvent Disk Identity

| Option | Description | Selected |
|--------|-------------|----------|
| New blocked_disk: Option<DiskIdentity> field | Semantically clear; distinct from discovered_disks; clean SIEM filtering | ✓ |
| Reuse discovered_disks (single-element Vec) | No schema change; confusing semantics | |
| Encode in justification string | No schema change; unstructured; no per-field SIEM filtering | |

**User's choice:** New blocked_disk field on AuditEvent

---

## Claude's Discretion

- Exact method for resolving drive letter in on_disk_arrival() — recommended: filtered enumerate_fixed_disks() call
- Whether DiskEnforcer wraps get_disk_enumerator() internally or receives Arc<DiskEnumerator> at construction
- Whether on_disk_removal() emits a tracing::info! log line
- Exact toast message text
- Whether extract_disk_instance_id is moved to device_watcher.rs or kept in usb.rs

## Deferred Ideas

- Per-disk trust tiers (DISK-F4) — deferred to v0.7.1+
- Mount-time volume locking (DISK-F1) — deferred to v0.7.1+
- Read blocking on unregistered disks — explicitly rejected; not in DISK-04
- Updating instance_id_map on disk arrival — rejected; defeats serial-based swap protection
