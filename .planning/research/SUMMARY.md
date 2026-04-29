# Project Research Summary

**Project:** dlp-rust -- Enterprise Windows Endpoint DLP
**Domain:** Fixed Disk Exfiltration Prevention (v0.7.0)
**Researched:** 2026-04-30
**Confidence:** HIGH

## Executive Summary

v0.7.0 adds a fourth enforcement dimension to the dlp-rust endpoint agent: install-time fixed disk allowlisting with BitLocker encryption verification. The core threat is USB-bridged SATA/NVMe enclosures that report as `DRIVE_FIXED` to Windows, bypassing traditional removable-media controls. The recommended approach is a two-pass enumeration at install time (logical volume scan + physical bus type verification via `IOCTL_STORAGE_QUERY_PROPERTY`), persistence to TOML, and I/O-time blocking in the existing file interception pipeline. Disk identity is treated as a resource attribute evaluated in a pre-ABAC enforcement layer, preserving the "NTFS = coarse-grained, ABAC = fine-grained" principle.

Key risks are (1) misidentifying the system boot disk as unregistered and blocking it, which would brick the endpoint, and (2) USB bridge chips that do not pass through disk serial numbers, making stable identity hard. Mitigations: use device instance ID (not drive letter) as canonical identity, implement allowlist semantics (default-allow for known disks, not default-deny for all fixed disks), and fall back to a composite key of model + volume serial when hardware serial is absent.

## Key Findings

### Recommended Stack

Three new capability areas, minimal dependency delta. The `windows` crate upgrades from 0.58 to 0.62 to access `Win32_System_Ioctl` feature flags. One new crate, `wmi-rs` 0.14, handles BitLocker WMI queries with serde-based deserialization. All other work reuses existing infrastructure (serde, toml, uuid, axum, rusqlite, ratatui).

**Core technologies:**
- `windows` crate 0.62 (upgraded from 0.58): `Win32_System_Ioctl` for `IOCTL_STORAGE_QUERY_PROPERTY` and `STORAGE_BUS_TYPE` discrimination -- required to detect USB-bridged fixed disks
- `wmi-rs` 0.14: `Win32_EncryptableVolume` queries in the BitLocker namespace with `AuthLevel::PktPrivacy` -- the canonical programmatic API for encryption status
- Existing `serde` + `toml`: allowlist persistence in `agent-config.toml` -- follows established Phase 24/25 patterns

**Critical version requirement:** `windows = "0.62"` -- the `Win32_System_Ioctl` feature flag is not available in 0.58. The upgrade is metadata-driven; existing API signatures are preserved.

### Expected Features

**Must have (table stakes):**
- Install-time fixed disk enumeration -- every enterprise DLP product establishes a device baseline at deployment
- Persistent disk allowlist -- survival across reboots and agent restarts is non-negotiable for a security agent
- BitLocker encryption status check -- dominant Windows FDE; Microsoft Purview, Symantec, and Forcepoint all integrate it
- Runtime I/O-time blocking of unregistered fixed disks -- the core value proposition; must integrate with existing file interception
- Audit events for disk actions -- NIST 800-171, CMMC, HIPAA require audit trails for access control decisions
- Admin override/registry for post-install additions -- IT replaces drives; admins need a supported path without reinstall

**Should have (competitive):**
- USB-bridged fixed disk detection -- most commercial DLP products miss this; genuine differentiator
- Dual enforcement (mount-time + I/O-time) -- defense in depth; mount-time for UX, I/O-time for reliability
- Per-disk trust tier -- extend existing `UsbTrustTier` pattern to disks (`blocked`, `read_only`, `full_access`)

**Defer (v0.7.1+ or later milestones):**
- Grace period / quarantine mode -- operational convenience, not security-critical
- Disk discovery toast with admin request flow -- significant TUI/async workflow work
- Encryption beyond BitLocker (SED/Opal, third-party FDE) -- niche, no unified API

### Architecture Approach

The v0.7.0 feature adds four new components inside `dlp-agent` and extends two existing ones. Disk enforcement is a **pre-ABAC layer**, evaluated before USB enforcement and before ABAC evaluation in `run_event_loop`. This preserves the architecture principle that device-level coarse-grained decisions should short-circuit fine-grained policy evaluation.

**Major components:**
1. `DiskEnumerator` (`dlp-agent/src/disk/enumerator.rs`) -- install-time enumeration using `SetupDi` + `IOCTL_STORAGE_QUERY_PROPERTY`; called once at MSI install or first agent startup
2. `BitLockerChecker` (`dlp-agent/src/disk/bitlocker.rs`) -- WMI query wrapper using `wmi-rs`; called per-disk during enumeration
3. `DiskAllowlist` (`dlp-agent/src/disk/allowlist.rs`) -- in-memory `RwLock<HashSet<DiskIdentity>>` with TOML persistence; follows `DeviceRegistryCache` pattern from Phase 24
4. `DiskEnforcer` (`dlp-agent/src/disk/enforcer.rs`) -- I/O-time check in `run_event_loop`; blocks `FileAction` events targeting unregistered fixed disks

**Key architectural decisions:**
- Disk identity is a **resource attribute**, not an ABAC subject attribute. Keep it as a separate pre-ABAC enforcement layer.
- Blocking uses **I/O-time filtering** (`FileAction` drop in `DiskEnforcer::check`), not `CM_Disable_DevNode`. PnP disable on internal boot/data disks is unsafe and causes system crashes.
- USB-bridged detection uses the **PnP tree walk** (`CM_Get_Parent` to find `USB\` ancestor) already proven in Phase 31-02. When no USB ancestor is found, the disk is internal and handed to the new disk enforcement pipeline.
- Identity uses **device instance ID** as canonical key; drive letters are volatile and stored only as informational metadata.

### Critical Pitfalls

1. **Using `CM_Disable_DevNode` on internal fixed disks** -- causes BSOD if applied to the boot disk, crashes applications if applied to active data disks. Avoid: use volume-level I/O blocking (filter `FileAction` events) as the primary enforcement mechanism.

2. **Treating every `DRIVE_FIXED` disk as suspicious** -- the system boot disk and legitimate internal data disks are `DRIVE_FIXED`. Blocking them by default bricks the system. Avoid: use allowlist semantics (default-allow for install-time enumerated disks, block only new unregistered disks).

3. **Relying on `GetDriveTypeW` alone to detect USB-bridged SATA/NVMe** -- USB bridge chips (JMicron JMS583, ASMedia ASM2362) present a fixed disk signature to Windows and report `DRIVE_FIXED`. Avoid: always verify physical bus type via `IOCTL_STORAGE_QUERY_PROPERTY` or PnP tree walk.

4. **Using drive letter as disk identity** -- letters change when disks are reordered or removed, creating bypass opportunities and false positives. Avoid: use device instance ID from `SetupDi` as canonical identity, with disk serial + model as composite fallback.

5. **Auto-allowlisting all disks at install time without admin approval** -- an attacker can pre-stage a malicious USB-bridged disk before agent deployment. Avoid: enumerate at install, but require admin explicit approval to populate the allowlist. Default-deny is the secure default for post-install disks.

## Implications for Roadmap

Based on dependency analysis from all three research files, the recommended phase structure for v0.7.0:

### Phase 32-A: Disk Types + BitLocker Checker
**Rationale:** Foundation types and the WMI query layer have no dependencies on other v0.7.0 work. Must exist before enumeration or enforcement can be built.
**Delivers:** `DiskIdentity` struct in `dlp-common`, `BitLockerChecker` module in `dlp-agent`, `wmi-rs` integration with `AuthLevel::PktPrivacy`.
**Addresses:** BitLocker encryption status check (table stakes).
**Avoids:** Pitfall of using raw COM/WMI (~200 lines of error-prone code) by using `wmi-rs` ergonomic wrapper.
**Research flag:** SKIP -- well-documented WMI API, `wmi-rs` crate verified.

### Phase 32-B: Disk Enumerator
**Rationale:** Needs types from 32-A. Must be built before allowlist persistence or enforcement can consume disk identities.
**Delivers:** `DiskEnumerator` using `SetupDiGetClassDevsW(GUID_DEVINTERFACE_DISK)` + `IOCTL_STORAGE_QUERY_PROPERTY` for bus type discrimination. Two-pass algorithm: logical volume scan, then physical disk verification.
**Addresses:** Install-time fixed disk enumeration (table stakes), USB-bridged fixed disk detection (differentiator).
**Avoids:** Pitfall of relying on `GetDriveTypeW` alone; uses `STORAGE_BUS_TYPE` to distinguish USB-bridged from internal.
**Research flag:** SKIP -- `IOCTL_STORAGE_QUERY_PROPERTY` is well-documented; Phase 31-02 already proves PnP tree walk pattern.

### Phase 32-C: Disk Allowlist + TOML Persistence
**Rationale:** Needs enumeration output from 32-B. Must exist before enforcement can check against it.
**Delivers:** `DiskAllowlist` with `RwLock<HashSet<DiskIdentity>>`, TOML serialization in `AgentConfig`, `[disk_allowlist]` schema in `agent-config.toml`.
**Addresses:** Persistent disk allowlist (table stakes).
**Avoids:** Pitfall of drive-letter-based identity by using device instance ID as canonical key.
**Research flag:** SKIP -- follows established Phase 24 `DeviceRegistryCache` pattern.

### Phase 32-D: Disk Enforcer + I/O Integration
**Rationale:** Needs allowlist from 32-C. The core enforcement logic; integrates into the existing event loop.
**Delivers:** `DiskEnforcer` with `check()`, `on_disk_arrival()`, `on_disk_removal()`. Wired into `run_event_loop` before `UsbEnforcer`. Wired into `usb_wndproc` for non-USB `GUID_DEVINTERFACE_DISK` arrivals.
**Addresses:** Runtime blocking of unregistered fixed disks (table stakes), audit events for disk actions (table stakes).
**Avoids:** Pitfall of `CM_Disable_DevNode` on internal disks by using I/O-time `FileAction` filtering.
**Research flag:** LIGHT -- integration point with existing `run_event_loop` is well-understood, but test thoroughly with real USB-bridged enclosures.

### Phase 32-E: Server-Side Disk Registry
**Rationale:** Needs `DiskIdentity` serialization from 32-C. Provides central admin visibility and fleet management.
**Delivers:** `disk_registry` SQLite table, repository, admin API routes (`GET/POST/DELETE /admin/disk-registry`).
**Addresses:** Admin override/registry for post-install additions (table stakes).
**Avoids:** Pitfall of auto-allowlisting by requiring admin explicit approval through server API.
**Research flag:** SKIP -- mirrors existing `device_registry` pattern from Phase 24.

### Phase 32-F: Admin TUI Disk Registry Screen
**Rationale:** Needs server API from 32-E. Final admin-facing UX for disk management.
**Delivers:** "Disk Registry" screen in `dlp-admin-cli` System menu, list/add/delete flows.
**Addresses:** Admin override/registry for post-install additions (table stakes).
**Research flag:** SKIP -- follows established ratatui TUI patterns.

### Phase 32-G: Installer Integration
**Rationale:** Needs enumerator from 32-B and allowlist persistence from 32-C. Runs once at deployment.
**Delivers:** MSI installer step that calls `DiskEnumerator::enumerate_fixed_disks()`, writes `[disk_allowlist]` to `agent-config.toml`, and syncs to dlp-server.
**Addresses:** Install-time fixed disk enumeration (table stakes).
**Avoids:** Pitfall of auto-allowlisting everything by requiring admin explicit approval during install.
**Research flag:** LIGHT -- installer integration patterns exist but need validation for SYSTEM-context WMI queries.

### Phase Ordering Rationale

- **Types first (32-A):** `DiskIdentity` and `BitLockerChecker` are leaf dependencies. Everything else consumes them.
- **Enumeration before enforcement (32-B -> 32-C -> 32-D):** You cannot enforce against an allowlist that does not exist, and you cannot build an allowlist without knowing what to put in it.
- **Server before TUI (32-E -> 32-F):** The admin TUI consumes server API routes; the API must exist first.
- **Installer last (32-G):** The installer step calls the enumerator and writes the allowlist -- both must be stable before integrating into the MSI.
- **I/O-time blocking before mount-time (32-D only):** Mount-time blocking (`WM_DEVICECHANGE` volume lock) is deferred to v0.7.1. I/O-time blocking catches all cases including races; it is the reliable backstop.

### Research Flags

Phases likely needing deeper research during planning:
- **Phase 32-D (Disk Enforcer):** Real-world testing with USB-bridged NVMe enclosures (JMicron JMS583, ASMedia ASM2362) to confirm `BusTypeUsb` detection and I/O blocking behavior. Some exotic bridges report `BusTypeScsi` and may need fallback to PnP tree walk.
- **Phase 32-G (Installer):** Validation that WMI queries work correctly in the MSI installer's SYSTEM context, and that `AuthLevel::PktPrivacy` is compatible with the installer's security token.

Phases with standard patterns (skip research-phase):
- **Phase 32-A (Types + BitLocker):** Well-documented WMI API; `wmi-rs` crate is actively maintained and verified.
- **Phase 32-C (Allowlist):** Directly follows Phase 24 `DeviceRegistryCache` pattern.
- **Phase 32-E (Server Registry):** Mirrors existing `device_registry` table and repository.
- **Phase 32-F (Admin TUI):** Standard ratatui screen pattern; no new UI paradigms.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | `windows` 0.62 feature flags verified in docs; `wmi-rs` 0.14 actively maintained and uses official `windows` crate internally. One crate addition, one version bump -- minimal surface area. |
| Features | HIGH | Table stakes are well-understood from competitor analysis (Microsoft Purview, Symantec, Forcepoint, Digital Guardian). Differentiators are technically feasible and gaps are documented. |
| Architecture | HIGH | All patterns are proven in the existing codebase: pre-ABAC enforcement (USB Phases 23-26), TOML persistence (Phase 25), PnP tree walk (Phase 31-02), SQLite registry (Phase 24). |
| Pitfalls | HIGH | All five critical pitfalls are derived from direct codebase analysis and Windows API documentation. Phase 31-02 already proved the USB-bridged detection pattern. |

**Overall confidence:** HIGH

### Gaps to Address

- **USB bridge chip edge cases:** Some exotic USB-SATA bridges report `BusTypeScsi` instead of `BusTypeUsb`. The PnP tree walk (Phase 31-02) is the fallback, but this needs physical hardware validation during 32-D testing.
- **Disk serial number stability:** Some USB enclosures do not pass through the underlying disk serial. The composite key fallback (model + volume serial) is documented but not yet validated against real hardware.
- **Windows 0.58 -> 0.62 migration:** No documented API breaks for used modules, but metadata changes exist. Run `cargo check --workspace` immediately after bumping to catch signature changes.
- **SED/Opal detection:** Explicitly out of scope for v0.7.0, but documented as a future research item. No unified API exists.

## Sources

### Primary (HIGH confidence)
- `windows-rs` 0.62.2 docs -- `Win32_System_Ioctl` feature flag availability, `IOCTL_STORAGE_QUERY_PROPERTY`, `STORAGE_DEVICE_DESCRIPTOR`, `STORAGE_BUS_TYPE`
- Microsoft Learn -- `Win32_EncryptableVolume` WMI class, `ProtectionStatus` semantics (0/1/2)
- `wmi-rs` crate (ohadravid/wmi-rs) -- verified `AuthLevel::PktPrivacy` requirement, serde deserialization pattern
- Phase 31-02 PLAN.md (`dlp-agent/src/detection/usb.rs`) -- proven PnP tree walk pattern for USB-bridged disk detection
- `dlp-agent/src/interception/mod.rs` -- existing pre-ABAC USB enforcement integration point
- `dlp-agent/src/config.rs` -- existing TOML config structure
- `dlp-server/src/db/repositories/device_registry.rs` -- reference pattern for disk registry repository
- `dlp-common/src/endpoint.rs` -- `DeviceIdentity`, `UsbTrustTier` patterns

### Secondary (MEDIUM confidence)
- Microsoft Purview Endpoint DLP documentation -- competitor capability matrix
- Symantec DLP Device Control documentation -- confirms fixed disk blocking is table stakes
- Forcepoint DLP Endpoint documentation -- removable media control patterns
- Black Hat EU 2015 -- SED/Opal bypass research (defer scope validation)

### Tertiary (LOW confidence)
- Community discussions on USB bridge chip behavior (JMicron JMS583, ASMedia ASM2362) -- needs physical hardware validation
- Third-party FDE compatibility (VeraCrypt, McAfee) -- explicitly out of scope, no unified API

---
*Research completed: 2026-04-30*
*Ready for roadmap: yes*
