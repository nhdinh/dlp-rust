# M005: Disk Exfiltration Prevention (v0.7.0)

**Gathered:** 2026-04-30
**Status:** In progress

## Project Description

Prevent data exfiltration via unregistered or unauthorized disk devices. Covers install-time disk enumeration, BitLocker verification, disk allowlist persistence, runtime enforcement blocking writes to unregistered drives, server-side disk registry management, admin TUI for disk operations, and USB enforcement hardening.

## Why This Milestone

USB device control (v0.6.0) blocked removable USB storage, but internal/external SATA/NVMe disks remained uncontrolled. An attacker could connect an unregistered disk and copy sensitive data. This milestone closes that gap by extending enforcement to all disk devices — not just USB — and hardening the USB enforcement layer to actually block I/O (not just log denials).

## User-Visible Outcome

### When this milestone is complete, the user can:

- See all connected disks enumerated at agent startup with BitLocker status
- Have writes to unregistered disks blocked in real-time with user notification
- Manage disk registry (register/unregister/set tier) via Admin TUI
- Rely on USB Blocked-tier devices being physically unable to write (not just audit-logged)
- Configure LDAP connection settings via Admin TUI

### Entry point / environment

- Entry point: DLP Agent service (enforcement), Admin TUI (management)
- Environment: Windows endpoint + Windows Server
- Live dependencies involved: DLP server, BitLocker API, Win32 disk/volume APIs, LDAP

## Architectural Decisions

### Two-Layer USB Enforcement (D-02/D-03)

**Decision:** Use PnP CM_Disable_DevNode as primary enforcement and Volume DACL deny-all as secondary/fallback.

**Rationale:** Either layer alone can be circumvented or fail silently. Two independent OS-enforced layers provide defense-in-depth without requiring a kernel driver.

**Alternatives Considered:**
- Kernel minifilter — too complex for this phase, deferred to v0.8.0+
- User-mode API hooking — trivially bypassed, conflicts with EDR products
- File watcher only — race conditions, cannot guarantee blocking

### Tier-Change Semantics (D-07/D-08)

**Decision:** Tier changes take effect only on physical device unplug and re-plug. No hot-reload via registry poll.

**Rationale:** Hot-applying tier changes to mounted volumes risks data corruption and race conditions. Physical re-plug is the safest state transition boundary.

## Risks and Unknowns

- USB_DEVICE to VOLUME arrival race (WR-01) — timing paths where identity reconciliation fails
- Drive-letter mislabel in disk enumeration — audit shows wrong letter for USB devices
- BitLocker API reliability on non-system drives

## Existing Codebase / Prior Art

- `dlp-agent/src/detection/disk.rs` — disk enumeration (Phase 33)
- `dlp-agent/src/detection/encryption.rs` — BitLocker verification (Phase 34)
- `dlp-agent/src/disk_enforcer.rs` — runtime disk enforcement (Phase 36)
- `dlp-agent/src/usb_enforcer.rs` — USB enforcement logic
- `dlp-agent/src/device_controller.rs` — PnP disable/enable and DACL manipulation
- `dlp-server/src/db/repositories/disk_registry.rs` — server-side disk storage

## Relevant Requirements

- DISK-01 — Install-time disk enumeration with device identification
- DISK-02 — USB vs internal disk distinction
- DISK-03 — Persistent disk allowlist surviving agent restart
- DISK-04 — Runtime write blocking to unregistered disks
- DISK-05 — Agent blocks unregistered disk I/O with user notification
- CRYPT-01 — BitLocker status detection for connected volumes
- CRYPT-02 — Periodic BitLocker re-check on interval
- ADMIN-01 — Server-side disk registry CRUD API
- ADMIN-02 — Admin TUI disk registry screen
- AUDIT-01 — Disk discovery events in audit log

## Scope

### In Scope

- Disk enumeration at agent startup (all connected drives)
- BitLocker encryption status detection
- Disk allowlist persistence (survives restart)
- Runtime enforcement (block writes to unregistered disks)
- Server-side disk registry (API + database)
- Admin TUI disk registry management screen
- LDAP configuration TUI screen
- USB enforcement fix (Blocked tier actually blocks I/O)
- Drive-letter mislabel fix

### Out of Scope / Non-Goals

- Network share monitoring (separate milestone)
- AGENT-UNKNOWN remediation (deferred to Phase 38.3)
- Kernel minifilter (deferred to v0.8.0+)
- macOS/Linux disk support

## Technical Constraints

- No kernel driver — all enforcement must be user-mode (PnP API + DACL)
- BitLocker API requires elevation (agent runs as SYSTEM)
- Volume GUID paths required for reliable disk identification (drive letters are volatile)
- Windows 0.61 crate API changes from 0.58 (newtype constructors for STORAGE_PROPERTY_ID etc.)
