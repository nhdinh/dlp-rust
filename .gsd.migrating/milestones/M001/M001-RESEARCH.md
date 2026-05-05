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

# Architecture Patterns: Disk Exfiltration Prevention

**Domain:** Enterprise DLP — Fixed disk allowlist with BitLocker encryption check
**Researched:** 2026-04-30
**Confidence:** HIGH (existing codebase fully understood; Windows APIs well-documented)

---

## Executive Summary

The v0.7.0 disk exfiltration prevention feature adds a **fourth enforcement dimension** to the existing DLP architecture. Where v0.6.0 controls USB (removable) devices via VID/PID/Serial trust tiers, v0.7.0 controls **fixed disks** (internal SATA/NVMe, USB-bridged internal drives, eSATA enclosures) via an **install-time allowlist** with **BitLocker encryption verification**.

The feature is architecturally analogous to USB device control but differs in three critical ways:
1. **Enumeration timing**: USB devices are enumerated at runtime on plug-in; fixed disks are enumerated once at install time and persisted.
2. **Identity mechanism**: USB uses VID/PID/Serial from the USB descriptor; fixed disks use a composite identity of **device instance ID + bus type + encryption status**.
3. **Blocking mechanism**: USB uses `CM_Disable_DevNode` (PnP disable) and volume DACL modification; fixed disks must use a **different blocking strategy** because `CM_Disable_DevNode` on internal boot or data disks is unsafe and may crash the system.

**Key architectural decision**: Disk identity is a **separate enforcement layer** (not an ABAC subject attribute). The disk allowlist is evaluated before ABAC, similar to how USB trust tiers are evaluated pre-ABAC in v0.6.0. This preserves the "NTFS = coarse-grained, ABAC = fine-grained" principle from CLAUDE.md.

---

## Recommended Architecture

### High-Level Component Diagram

```
+-----------------------------------------------------------------------------+
|                           dlp-agent (Windows Service)                        |
|                                                                              |
|  +-------------------+    +-------------------+    +---------------------+  |
|  |  DiskEnumerator   |    |  DiskAllowlist    |    |   DiskEnforcer      |  |
|  |  (install-time)   |--->|  (TOML + in-mem)  |--->|  (I/O-time check)   |  |
|  +-------------------+    +-------------------+    +---------------------+  |
|           |                                               |                 |
|           v                                               v                 |
|  +-------------------+                         +---------------------+     |
|  | BitLockerChecker  |                         | FileAction filter   |     |
|  | (WMI/Win32 API)   |                         | (pre-ABAC)          |     |
|  +-------------------+                         +---------------------+     |
|                                                        |                    |
|  +-------------------+    +-------------------+       |                    |
|  |  UsbDetector      |    |  UsbEnforcer      |<------+                    |
|  |  (v0.6.0)         |    |  (v0.6.0)         |  (existing pipeline)       |
|  +-------------------+    +-------------------+                            |
|                                                                              |
|  +---------------------------------------------------------------+        |
|  |                    run_event_loop (existing)                   |        |
|  |  1. DiskEnforcer::check() -> DENY? -> audit + skip ABAC       |        |
|  |  2. UsbEnforcer::check()  -> DENY? -> audit + skip ABAC       |        |
|  |  3. ABAC evaluation (existing)                                |        |
|  +---------------------------------------------------------------+        |
+-----------------------------------------------------------------------------+
         |                                                           |
         v                                                           v
+-------------------+                                    +-------------------+
| dlp-user-ui       |                                    | dlp-server        |
| (toast on block)  |                                    | (disk_registry DB)|
+-------------------+                                    +-------------------+
```

### Component Boundaries

| Component | Responsibility | Communicates With |
|-----------|---------------|-------------------|
| `DiskEnumerator` | Install-time enumeration of all fixed disks; BitLocker status check | Writes to `agent-config.toml`; sends to `DiskAllowlist` |
| `BitLockerChecker` | Queries WMI `Win32_EncryptableVolume` for encryption status | Called by `DiskEnumerator` |
| `DiskAllowlist` | In-memory cache of allowed fixed disk identities; TOML persistence | Read by `DiskEnforcer`; written by `DiskEnumerator` + server sync |
| `DiskEnforcer` | Runtime I/O check: is the target drive on an unregistered fixed disk? | Called from `run_event_loop` pre-ABAC; emits audit events |
| `DiskRegistryCache` | Server-side polling cache (analogous to `DeviceRegistryCache`) | Polls dlp-server; read by `DiskEnforcer` |
| `disk_wndproc` | `WM_DEVICECHANGE` handler for `GUID_DEVINTERFACE_DISK` arrivals | Calls `DiskEnforcer::on_disk_arrival` for new fixed disks |

---

## Data Flow

### Install-Time Flow (One-Time)

```
Installer / Agent first startup
    |
    +---> DiskEnumerator::enumerate_fixed_disks()
    |         |
    |         +---> SetupDiGetClassDevsW(GUID_DEVINTERFACE_DISK)
    |         +---> For each disk:
    |         |       +---> Get device instance ID
    |         |       +---> IOCTL_STORAGE_QUERY_PROPERTY -> BusType (SATA/NVMe/USB/SCSI)
    |         |       +---> BitLockerChecker::is_encrypted(drive_letter)
    |         |       +---> Build DiskIdentity { instance_id, bus_type, encrypted, model }
    |         |
    |         +---> Filter: only include BusType == SATA || BusType == NVMe
    |         +---> Verify: all included disks have encrypted == true
    |         |       (warn if not; still include but flag in audit)
    |         |
    |         +---> Write DiskAllowlist to agent-config.toml
    |         +---> Send DiskAllowlist to dlp-server (POST /agent/{id}/disk-allowlist)
    |
    +---> DiskAllowlist::load_from_toml() -> in-memory HashSet<DiskIdentity>
```

### Runtime Arrival Flow (New Fixed Disk Detected)

```
Windows PnP: new fixed disk arrives
    |
    +---> WM_DEVICECHANGE -> DBT_DEVICEARRIVAL -> GUID_DEVINTERFACE_DISK
    |         |
    |         +---> disk_wndproc extracts device instance ID
    |         +---> DiskEnforcer::on_disk_arrival(instance_id, drive_letter)
    |                 |
    |                 +---> Look up in DiskAllowlist
    |                 +---> IF NOT FOUND:
    |                         +---> Block I/O to this drive letter
    |                         +---> Emit audit event (EventType::Block)
    |                         +---> Send toast notification (via Pipe 2)
    |                         +---> Optionally: CM_Disable_DevNode (see Blocking Strategy)
    |                 +---> IF FOUND:
    |                         +---> Allow I/O (fall through to ABAC)
    |
    +---> File monitor watches new drive root (existing watch_rx mechanism)
```

### Runtime I/O Flow (File Operation on Fixed Disk)

```
File monitor -> FileAction -> run_event_loop
    |
    +---> DiskEnforcer::check(path, &action)
    |         |
    |         +---> Extract drive letter from path
    |         +---> Is this drive letter a fixed disk? (GetDriveTypeW == DRIVE_FIXED)
    |         +---> IF yes AND drive not in DiskAllowlist:
    |                 +---> Return Some(DiskBlockResult) -> DENY
    |         +---> ELSE:
    |                 +---> Return None (fall through)
    |
    +---> UsbEnforcer::check(path, &action) [existing v0.6.0]
    +---> ABAC evaluation [existing]
```

---

## New Components (Detailed)

### 1. DiskEnumerator

**Location:** `dlp-agent/src/disk/enumerator.rs` (new module)

**Purpose:** One-time enumeration of all fixed disks at install/agent startup. Builds the initial allowlist.

**Key APIs:**
- `SetupDiGetClassDevsW(GUID_DEVINTERFACE_DISK, ..., DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)`
- `SetupDiEnumDeviceInfo` / `SetupDiGetDeviceInstanceIdW`
- `IOCTL_STORAGE_QUERY_PROPERTY` with `StorageAdapterProperty` -> `STORAGE_ADAPTER_DESCRIPTOR.BusType`
- `GetDriveTypeW` to confirm `DRIVE_FIXED`

**Algorithm:**
```rust
pub fn enumerate_fixed_disks() -> Vec<DiskIdentity> {
    // 1. Enumerate all disk device interfaces
    // 2. For each disk:
    //    a. Get device instance ID
    //    b. Open device handle
    //    c. IOCTL_STORAGE_QUERY_PROPERTY -> BusType
    //    d. If BusType == SATA || BusType == NVMe:
    //       - Get drive letter(s) for this disk
    //       - Check BitLocker status via WMI
    //       - Build DiskIdentity
    // 3. Return vector of DiskIdentity
}
```

**Confidence:** HIGH -- `IOCTL_STORAGE_QUERY_PROPERTY` is the standard Windows API for bus type detection. The `StorageBusType` enum includes `BusTypeSata` and `BusTypeNvme` values.

### 2. BitLockerChecker

**Location:** `dlp-agent/src/disk/bitlocker.rs` (new module)

**Purpose:** Check whether a given volume is BitLocker-encrypted.

**Key APIs:**
- WMI namespace: `root\CIMV2\Security\MicrosoftVolumeEncryption`
- WMI class: `Win32_EncryptableVolume`
- Property: `ProtectionStatus` (0 = Off, 1 = On, 2 = Unknown)

**Implementation options (ranked):**

| Approach | Complexity | Reliability | Recommendation |
|----------|-----------|-------------|----------------|
| WMI COM (`WbemScripting.SWbemLocator`) | Medium | High | **Recommended** -- standard Windows API, works in SYSTEM context |
| PowerShell invocation (`manage-bde -status`) | Low | Medium | Rejected -- spawns subprocess, parsing fragile, SYSTEM context issues |
| `GetVolumeInformationW` + `FILE_SUPPORTS_ENCRYPTION` | Low | Low | Rejected -- only indicates FS-level encryption support, not BitLocker specifically |
| `Win32_EncryptableVolume` via `wmi-rs` crate | Medium | High | Alternative if COM is problematic |

**Confidence:** HIGH -- WMI `Win32_EncryptableVolume` is the documented API for BitLocker status. The `ProtectionStatus` property is reliable.

### 3. DiskAllowlist

**Location:** `dlp-agent/src/disk/allowlist.rs` (new module)

**Purpose:** In-memory cache of allowed fixed disk identities, loaded from TOML at startup.

**Data structure:**
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DiskIdentity {
    /// Windows device instance ID (e.g., "PCIIDE\IDE_DEVICE\0").
    pub instance_id: String,
    /// Storage bus type (SATA, NVMe, etc.).
    pub bus_type: StorageBusType,
    /// Whether the volume was BitLocker-encrypted at install time.
    pub encrypted_at_install: bool,
    /// Drive letter at install time (informational; may change).
    pub install_letter: char,
    /// Disk model string from WMI or SetupDi.
    pub model: String,
}

pub struct DiskAllowlist {
    allowed: RwLock<HashSet<DiskIdentity>>,
}
```

**TOML serialization in `agent-config.toml`:**
```toml
[disk_allowlist]
# Install-time enumerated fixed disks.
# Each entry represents an approved internal disk.
# DO NOT EDIT MANUALLY -- use dlp-admin-cli or the installer.

disks = [
    { instance_id = "PCIIDE\\IDE_DEVICE\\0", bus_type = "SATA", encrypted = true, letter = "C", model = "Samsung SSD 870 EVO" },
    { instance_id = "PCI\\VEN_144D&DEV_A808\\0", bus_type = "NVMe", encrypted = true, letter = "D", model = "Samsung SSD 980 PRO" },
]
```

### 4. DiskEnforcer

**Location:** `dlp-agent/src/disk/enforcer.rs` (new module)

**Purpose:** Runtime I/O enforcement -- check if a file operation targets an unregistered fixed disk.

**Interface:**
```rust
impl DiskEnforcer {
    /// Called from run_event_loop before ABAC evaluation.
    /// Returns Some(DiskBlockResult) if the path is on an unregistered fixed disk.
    pub fn check(&self, path: &str, action: &FileAction) -> Option<DiskBlockResult>;

    /// Called from disk_wndproc on DBT_DEVICEARRIVAL for a fixed disk.
    /// Adds the drive to the blocked set if not in the allowlist.
    pub fn on_disk_arrival(&self, instance_id: &str, drive_letter: char);

    /// Called from disk_wndproc on DBT_DEVICEREMOVECOMPLETE.
    /// Removes the drive from the blocked set.
    pub fn on_disk_removal(&self, drive_letter: char);
}
```

**Integration into `run_event_loop`:**
```rust
// In dlp-agent/src/interception/mod.rs::run_event_loop:

// -- Disk enforcement (NEW v0.7.0) --
if let Some(ref disk_enforcer) = disk_enforcer {
    if let Some(disk_result) = disk_enforcer.check(&path, &action) {
        // Emit audit event, send toast, skip ABAC
        continue;
    }
}

// -- USB enforcement (existing v0.6.0) --
if let Some(ref enforcer) = usb_enforcer {
    // ... existing code ...
}
```

---

## Modified Components

### 1. `agent-config.toml` Schema

Add a `[disk_allowlist]` section. The existing `AgentConfig` struct in `dlp-agent/src/config.rs` gains:

```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AgentConfig {
    // ... existing fields ...

    /// Install-time fixed disk allowlist.
    #[serde(default)]
    pub disk_allowlist: DiskAllowlistConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DiskAllowlistConfig {
    #[serde(default)]
    pub disks: Vec<DiskIdentity>,
}
```

### 2. `run_event_loop` in `dlp-agent/src/interception/mod.rs`

Add `disk_enforcer: Option<Arc<DiskEnforcer>>` parameter. Insert disk check before USB check:

```rust
pub async fn run_event_loop(
    mut rx: mpsc::Receiver<FileAction>,
    offline: Arc<OfflineManager>,
    ctx: EmitContext,
    session_map: Arc<SessionIdentityMap>,
    ad_client: Arc<Option<dlp_common::AdClient>>,
    usb_enforcer: Option<Arc<UsbEnforcer>>,
    disk_enforcer: Option<Arc<DiskEnforcer>>,  // NEW
) { ... }
```

### 3. `UsbDetector` / `usb_wndproc` in `dlp-agent/src/detection/usb.rs`

The existing `usb_wndproc` already handles `GUID_DEVINTERFACE_DISK` for USB mass storage (Phase 31-02). For v0.7.0, we need to **distinguish USB-attached disks from internal fixed disks** in the `GUID_DEVINTERFACE_DISK` handler:

**Decision logic in `on_disk_device_arrival`:**
```rust
fn on_disk_device_arrival(detector: &UsbDetector, device_path: &str) {
    // Existing Phase 31-02 logic: walk PnP tree to find USB ancestor
    let usb_ancestor = find_usb_ancestor(device_path);

    if usb_ancestor.is_some() {
        // This is a USB-bridged disk (e.g., NVMe in USB enclosure).
        // Hand off to existing USB enforcement pipeline.
        apply_usb_tier_enforcement(...);
    } else {
        // No USB ancestor found -- this is an internal fixed disk (SATA/NVMe).
        // Hand off to NEW disk enforcement pipeline.
        let instance_id = extract_instance_id(device_path);
        let drive_letter = resolve_drive_letter(device_path);
        disk_enforcer.on_disk_arrival(&instance_id, drive_letter);
    }
}
```

**Critical insight:** The Phase 31-02 PnP tree walk already distinguishes USB from non-USB disks. When `CM_Get_Parent` walks up the tree and finds no ancestor with an instance ID starting with `USB\`, the disk is internal (SATA/NVMe/SCSI). This is the exact hook point for disk exfiltration prevention.

### 4. `dlp-server` DB Schema

Add a `disk_registry` table (analogous to `device_registry` for USB):

```sql
CREATE TABLE disk_registry (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    bus_type TEXT CHECK (bus_type IN ('SATA', 'NVMe', 'SCSI', 'USB', 'Other')),
    encrypted_at_install BOOLEAN NOT NULL DEFAULT 0,
    install_letter TEXT,
    model TEXT,
    registered_at TEXT NOT NULL,
    UNIQUE(agent_id, instance_id)
);
```

Add admin API routes:
- `GET /admin/disk-registry` -- list registered disks per agent
- `POST /admin/disk-registry` -- add a disk to the allowlist
- `DELETE /admin/disk-registry/{id}` -- remove a disk

### 5. `dlp-admin-cli` TUI

Add a "Disk Registry" screen under the System menu (following the pattern of Device Registry, Managed Origins, SIEM Config, Alert Config).

---

## Patterns to Follow

### Pattern 1: Pre-ABAC Enforcement Layer
**What:** Evaluate disk allowlist before ABAC, skip ABAC if blocked.
**When:** For coarse-grained, device-level decisions that do not need user/context attributes.
**Example:** The existing USB enforcement in `run_event_loop` (lines 89-162) already does this. Disk enforcement follows the same pattern.

### Pattern 2: Static + Runtime Cache
**What:** Load allowlist from TOML at startup into an `RwLock<HashSet>`. Runtime arrivals check against the in-memory set.
**When:** Fast I/O-time lookups are required; disk identity does not change frequently.
**Example:** The existing `DeviceRegistryCache` for USB (Phase 24) follows this pattern.

### Pattern 3: Installer-Time One-Shot Enumeration
**What:** Run disk enumeration once during MSI installation or first agent startup, persist results to TOML.
**When:** The set of "legitimate" internal disks is stable; new disks are exceptional events.
**Why not runtime enumeration?** Internal disks are present at boot; there is no "arrival" event for boot disks. Install-time enumeration captures the baseline.

### Pattern 4: PnP Tree Walk for Bus Type Classification
**What:** Use `CM_Get_Parent` + `CM_Get_Device_IDW` to walk the PnP tree and find the USB ancestor.
**When:** Distinguishing USB-bridged disks from internal SATA/NVMe disks that both fire `GUID_DEVINTERFACE_DISK`.
**Example:** Phase 31-02 `on_disk_device_arrival` already implements this walk. The absence of a `USB\` ancestor means the disk is internal.

---

## Anti-Patterns to Avoid

### Anti-Pattern 1: Using `CM_Disable_DevNode` on Internal Boot Disks
**What:** Calling `CM_Disable_DevNode` on the system boot disk or active data disks.
**Why bad:** Disabling the boot disk causes an immediate system crash (BSOD). Disabling a data disk may corrupt open file handles and crash applications.
**Instead:** Use **volume-level I/O blocking** (filter `FileAction` events in `DiskEnforcer::check`) rather than PnP disable for internal fixed disks. The `DeviceController` pattern (Phase 31) is ONLY safe for USB devices.

### Anti-Pattern 2: Treating Disk Identity as ABAC Subject Attribute
**What:** Adding `disk: Option<DiskIdentity>` to `AbacContext` and `Subject`.
**Why bad:** Disk identity is a **resource attribute** (the disk being written to), not a subject attribute (the user or their device). Conflating them violates the ABAC model from CLAUDE.md.
**Instead:** Keep disk enforcement as a **separate pre-ABAC layer**, analogous to USB enforcement. If ABAC integration is needed later, add a `destination_storage` field to `Resource`, not `Subject`.

### Anti-Pattern 3: Relying on Drive Letter as Disk Identity
**What:** Using `C:` or `D:` as the disk identifier in the allowlist.
**Why bad:** Drive letters are not stable. A disk may be reassigned (e.g., if another disk is removed, `D:` may become `E:`). This creates a bypass opportunity.
**Instead:** Use the **device instance ID** (from SetupDi) as the canonical identity. Drive letters are stored as informational metadata only.

### Anti-Pattern 4: Blocking All `DRIVE_FIXED` Disks by Default
**What:** Treating every `GetDriveTypeW == DRIVE_FIXED` disk as suspicious.
**Why bad:** The system boot disk and legitimate internal data disks are `DRIVE_FIXED`. Blocking them by default would brick the system.
**Instead:** Use an **allowlist** (not a blocklist). Only disks NOT in the install-time allowlist are blocked. The default posture for known internal disks is ALLOW.

### Anti-Pattern 5: Using `GetDriveTypeW` Alone to Detect USB-Bridged SATA
**What:** Relying on `DRIVE_REMOVABLE` vs `DRIVE_FIXED` to distinguish USB from internal.
**Why bad:** USB-bridged SATA/NVMe enclosures (common exfiltration vector) report as `DRIVE_FIXED` because the USB-SATA bridge chip presents a fixed disk signature to Windows.
**Instead:** Use the **PnP tree walk** (`CM_Get_Parent` to find `USB\` ancestor) to determine the true bus topology. This is what Phase 31-02 already does.

---

## Scalability Considerations

| Concern | At 1 endpoint | At 10K endpoints | At 100K endpoints |
|---------|--------------|------------------|-------------------|
| Disk allowlist storage | Single TOML file (~1 KB) | Server DB table with 10K rows | Server DB table with 100K rows; consider partitioning by agent_id |
| Install-time enumeration | ~100 ms per endpoint | N/A (per-endpoint operation) | N/A |
| Runtime I/O check | O(1) HashSet lookup | O(1) per endpoint | O(1) per endpoint |
| Server sync | One POST at install | Batch inserts during mass deployment | Use agent config push (existing) to distribute allowlists |
| Audit event volume | Low (only on block) | Medium | High -- ensure audit buffer batching is configured |

---

## Blocking Strategy Comparison

| Mechanism | USB (v0.6.0) | Fixed Disk (v0.7.0) | Rationale |
|-----------|-------------|---------------------|-----------|
| PnP disable (`CM_Disable_DevNode`) | Yes | **No** | Unsafe for boot/data disks |
| Volume DACL modification | Yes (ReadOnly tier) | **Possible** | Can remove write ACEs for non-allowlisted disks |
| I/O event filtering (`FileAction` drop) | Yes (fallback) | **Primary** | Safe for all disk types; no system instability |
| Device instance ID matching | VID/PID/Serial | Instance ID + BusType | USB uses descriptor IDs; internal disks use PnP IDs |
| Enumeration timing | Runtime (plug-in) | Install-time + runtime arrival | Internal disks are present at boot; USB is hot-plugged |

**Recommended blocking strategy for v0.7.0:**
1. **Primary:** I/O event filtering in `DiskEnforcer::check` -- drop `FileAction::Created`/`Written`/`Moved` events targeting unregistered fixed disks.
2. **Secondary (optional):** Volume DACL modification on arrival for unregistered disks -- strip write/delete ACEs. Restore on removal. This provides defense-in-depth even if the file monitor misses an event.

---

## Integration Points Summary

| Integration Point | Existing Code | New Code | Change Type |
|-------------------|--------------|----------|-------------|
| `run_event_loop` | `UsbEnforcer::check` then ABAC | Add `DiskEnforcer::check` before USB | Modified |
| `usb_wndproc` | Handles `GUID_DEVINTERFACE_DISK` for USB | Add branch for non-USB (internal) disks | Modified |
| `AgentConfig` | TOML with `monitored_paths`, `excluded_paths` | Add `disk_allowlist: DiskAllowlistConfig` | Modified |
| `agent-config.toml` | Existing fields | Add `[disk_allowlist]` section | Modified (schema) |
| `dlp-server` DB | `device_registry` table for USB | Add `disk_registry` table | New |
| `dlp-server` API | `/admin/device-registry` | Add `/admin/disk-registry` | New |
| `dlp-admin-cli` TUI | Device Registry screen | Add Disk Registry screen | New |
| `AuditEvent` | USB block events | Disk block events (same schema, different `reason`) | No change (reuses existing) |

---

## Build Order Recommendation

Based on dependency analysis:

1. **Phase 32-A: Disk types + BitLocker checker** (dlp-common + dlp-agent)
   - Add `DiskIdentity`, `StorageBusType` to `dlp-common`
   - Create `BitLockerChecker` in `dlp-agent/src/disk/bitlocker.rs`
   - No dependencies on other v0.7.0 work

2. **Phase 32-B: DiskEnumerator** (dlp-agent)
   - Create `DiskEnumerator` using `SetupDi` + `IOCTL_STORAGE_QUERY_PROPERTY`
   - Depends on Phase 32-A

3. **Phase 32-C: DiskAllowlist + TOML persistence** (dlp-agent)
   - Create `DiskAllowlist` with `RwLock<HashSet<DiskIdentity>>`
   - Add TOML serialization to `AgentConfig`
   - Depends on Phase 32-A, 32-B

4. **Phase 32-D: DiskEnforcer + I/O integration** (dlp-agent)
   - Create `DiskEnforcer` with `check()`, `on_disk_arrival()`, `on_disk_removal()`
   - Wire into `run_event_loop` before `UsbEnforcer`
   - Wire into `usb_wndproc` for non-USB `GUID_DEVINTERFACE_DISK` arrivals
   - Depends on Phase 32-C

5. **Phase 32-E: Server-side disk registry** (dlp-server)
   - Add `disk_registry` table, repository, admin API routes
   - Depends on Phase 32-C (needs `DiskIdentity` serialization)

6. **Phase 32-F: Admin TUI Disk Registry screen** (dlp-admin-cli)
   - Add System menu entry, list/add/delete screens
   - Depends on Phase 32-E

7. **Phase 32-G: Installer integration** (installer)
   - Add disk enumeration step to MSI installer
   - Write `disk_allowlist` section to `agent-config.toml`
   - Depends on Phase 32-B, 32-C

---

## Key Questions Answered

### Where does disk enumeration run?
**Answer:** Primarily at **install time** (MSI installer) or **first agent startup**. The installer runs `DiskEnumerator::enumerate_fixed_disks()`, writes results to `agent-config.toml`, and sends to dlp-server. The agent loads the allowlist from TOML at startup. Runtime arrival of new fixed disks is handled by `disk_wndproc` (hooked into the existing `GUID_DEVINTERFACE_DISK` notification path).

### How does the disk allowlist flow?
**Answer:** **Bidirectional**. The installer/agent writes to TOML (local persistence) AND sends to dlp-server (central registry). The agent loads from TOML at startup. Admin can modify the allowlist server-side; the agent polls for updates via the existing config push mechanism. The TOML is the source of truth for offline operation.

### What Windows event signals a new fixed disk arrival?
**Answer:** `WM_DEVICECHANGE` with `wParam == DBT_DEVICEARRIVAL` and `dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE` with `classguid == GUID_DEVINTERFACE_DISK`. The existing Phase 31-02 code already registers for this notification. The v0.7.0 work adds a branch in the handler for disks that do NOT have a USB ancestor in the PnP tree.

### How to block unregistered fixed disks?
**Answer:** **NOT** with `CM_Disable_DevNode` (unsafe for internal disks). Instead:
1. **Primary:** Filter `FileAction` events in `DiskEnforcer::check` -- deny writes/creates/moves to unregistered fixed disks.
2. **Secondary (optional):** Volume DACL modification -- strip write ACEs on arrival for unregistered disks.

### Should disk identity be an ABAC subject attribute?
**Answer:** **No.** Disk identity is a **resource attribute** (the storage being written to), not a subject attribute. Keep it as a separate pre-ABAC enforcement layer, following the same pattern as USB enforcement in v0.6.0. If ABAC integration is needed in the future, add `destination_storage` to `Resource`, not `Subject`.

### What is the integration with existing file_monitor?
**Answer:** The `file_monitor` already watches all drive roots (including new fixed disks) via the `watch_rx` channel. The `DiskEnforcer::check` is called from `run_event_loop` for every `FileAction` event. If the path is on an unregistered fixed disk, the event is dropped (operation blocked) before reaching ABAC evaluation.

---

## Sources

- [Microsoft Docs: WM_DEVICECHANGE and DBT_DEVICEARRIVAL](https://docs.microsoft.com/zh-cn/windows-hardware/drivers/kernel/processing-an-application-notification) -- HIGH confidence (official docs)
- [Microsoft Docs: Device Control Overview](https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-endpoint/device-control-overview.md) -- HIGH confidence (official docs). Confirms Defender Device Control does NOT support fixed/internal hard disks -- only removable media, CD/DVD, WPD, printers.
- [Microsoft Docs: Win32_EncryptableVolume WMI class](https://learn.microsoft.com/en-us/windows/win32/secprov/win32-encryptablevolume) -- HIGH confidence (official WMI docs)
- [Microsoft Docs: IOCTL_STORAGE_QUERY_PROPERTY](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ni-ntddstor-ioctl_storage_query_property) -- HIGH confidence (official DDK docs)
- [Phase 31-02 PLAN.md](.planning/phases/31-usb-cm-blocking/31-02-PLAN.md) -- HIGH confidence (direct codebase). Documents the `GUID_DEVINTERFACE_DISK` PnP tree walk pattern that distinguishes USB from internal disks.
- [dlp-agent/src/detection/usb.rs](dlp-agent/src/detection/usb.rs) -- HIGH confidence (direct codebase). The existing `on_disk_device_arrival` function already walks the PnP tree; absence of `USB\` ancestor means internal disk.
- [dlp-agent/src/interception/mod.rs](dlp-agent/src/interception/mod.rs) -- HIGH confidence (direct codebase). Shows the pre-ABAC USB enforcement integration point where disk enforcement will be added.
- [dlp-agent/src/config.rs](dlp-agent/src/config.rs) -- HIGH confidence (direct codebase). Shows existing TOML config structure.
- [dlp-server/src/db/repositories/device_registry.rs](dlp-server/src/db/repositories/device_registry.rs) -- HIGH confidence (direct codebase). Reference pattern for the new `disk_registry` repository.
- [dlp-common/src/endpoint.rs](dlp-common/src/endpoint.rs) -- HIGH confidence (direct codebase). Shows `DeviceIdentity`, `UsbTrustTier` patterns to follow for `DiskIdentity`.

# Technology Stack — v0.7.0 Disk Exfiltration Prevention

**Project:** dlp-rust
**Milestone:** v0.7.0 — Install-Time Fixed Disk Allowlist with BitLocker Verification
**Researched:** 2026-04-30
**Scope:** NEW capabilities only — fixed disk enumeration, BitLocker encryption verification,
persistent disk allowlist, runtime blocking of unregistered fixed disks.
Existing capabilities (axum 0.8, rusqlite, ratatui, windows 0.58, prost, JWT, r2d2) are NOT re-researched.

---

## Verdict

Three new capability areas. Two are covered by adding new `windows` crate feature flags to existing
Cargo.toml entries (zero new crates for Win32 work). One new crate (`wmi-rs`) for BitLocker WMI queries.
The `windows` crate should be upgraded from 0.58 to 0.62 to access the new feature flags.

---

## windows Crate Upgrade: 0.58 -> 0.62

**Current version:** `windows = "0.58"` (both `dlp-agent` and `dlp-user-ui`)
**Target version:** `windows = "0.62"` (latest stable as of 2025-10-06, version 0.62.2)

**Why upgrade:** The new feature flags needed for v0.7.0 (`Win32_System_Ioctl`,
`Win32_System_Wmi`) are available in 0.62. The 0.58 codebase has reports of a regression with
`Win32_Devices_DeviceAndDriverInstallation` not resolving correctly; 0.62 is the stable target all
current documentation points to. The upgrade involves metadata-driven code generation changes, not
public API redesigns — existing feature flags and function signatures are preserved.

**Risk:** MEDIUM. The windows-rs project does break binary metadata between minor versions. Run
`cargo check --workspace` after bumping to catch any signature changes in the existing `windows`
API surface used by the current agent (predominantly `Win32_UI_WindowsAndMessaging`,
`Win32_System_Threading`, `Win32_Storage_FileSystem`). These modules have been stable across 0.58
through 0.62.

---

## Capability 1: Fixed Disk Enumeration (DRIVE_FIXED)

**Crate:** `windows` (existing, feature additions only)
**Feature additions to `dlp-agent/Cargo.toml`:**

```toml
windows = { version = "0.62", features = [
    # --- existing features omitted for brevity ---
    # NEW for v0.7.0 fixed disk enumeration:
    "Win32_System_Ioctl",        # IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_DEVICE_DESCRIPTOR
] }
```

**Why `Win32_System_Ioctl`:** Provides `IOCTL_STORAGE_QUERY_PROPERTY`, `STORAGE_DEVICE_DESCRIPTOR`,
`STORAGE_PROPERTY_QUERY`, and `STORAGE_BUS_TYPE` — the canonical way to query bus type (USB vs
SATA vs NVMe) for a physical disk device. This is REQUIRED to distinguish USB-bridged fixed disks
from genuine internal SATA/NVMe drives (both report `DRIVE_FIXED` via `GetDriveTypeW`).

**API surface in `windows::Win32::System::Ioctl`:**
- `STORAGE_DEVICE_DESCRIPTOR` — struct with `BusType: STORAGE_BUS_TYPE` field
- `STORAGE_PROPERTY_QUERY` — input struct for `DeviceIoControl`
- `IOCTL_STORAGE_QUERY_PROPERTY` — IOCTL code for `DeviceIoControl`
- `StorageDeviceProperty` — `STORAGE_PROPERTY_ID` constant
- `STORAGE_BUS_TYPE` — enum with `BusTypeUsb`, `BusTypeSata`, `BusTypeNvme`, `BusTypeAta`

**Disk enumeration strategy (two-pass):**

Pass 1 — Logical volume scan (existing pattern, no new APIs):
```rust
// Iterate A..=Z, call GetDriveTypeW (already in Win32_Storage_FileSystem)
// Filter to DRIVE_FIXED (value = 3)
// Collect drive letters reporting as fixed
```

Pass 2 — Physical disk bus type verification (NEW):
```rust
// For each fixed drive letter, open physical drive handle:
// CreateFileW(r"\\.\PhysicalDriveN", ...)
// Call DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, ...)
// Read STORAGE_DEVICE_DESCRIPTOR.BusType
// BusTypeUsb -> USB-bridged (treat as external / blockable)
// BusTypeSata / BusTypeNvme -> internal (allowlist candidate)
```

**Critical insight:** `GetDriveTypeW` alone is INSUFFICIENT. NVMe USB bridges (e.g., JMicron
JMS583, ASMedia ASM2362) report `DRIVE_FIXED` (type 3) because Windows sees them through a SCSI
translation layer. The ONLY reliable discriminator is the physical bus type from
`IOCTL_STORAGE_QUERY_PROPERTY`.

**Where this code lives:** New module `dlp-agent/src/disk_enumerator.rs`. Called once at install
time (not continuously at runtime) to build the initial allowlist. The enumeration result is
persisted to `agent-config.toml` and optionally synced to the server-side registry.

**Confidence:** HIGH — `IOCTL_STORAGE_QUERY_PROPERTY` and `STORAGE_DEVICE_DESCRIPTOR` are
well-documented Win32 APIs with stable signatures across Windows versions. Confirmed present in
windows-rs 0.62 docs.

---

## Capability 2: BitLocker Encryption Verification

**Crate:** `wmi-rs = "0.14"` (NEW — one crate addition)

**Why `wmi-rs` over raw `windows` crate WMI:**
- The `windows` crate exposes `IWbemServices` and COM interfaces in `Win32_System_Wmi`, but using
them directly requires ~200 lines of COM initialization, WQL string building, `VARIANT` handling,
and `SafeArray` iteration. This is error-prone and verbose.
- `wmi-rs` provides an ergonomic Rust wrapper around WMI COM that handles connection,
authentication, query execution, and `serde`-based deserialization in ~10 lines of user code.
- The crate is actively maintained (latest 0.14.0, MIT license, uses the modern `windows` crate
internally, not legacy `winapi`).

**Cargo.toml addition:**

```toml
# dlp-agent/Cargo.toml [dependencies]
wmi-rs = { version = "0.14", features = ["serde"] }
# serde is already in workspace dependencies; no additional serde needed
```

**API pattern for BitLocker status query:**

```rust
use wmi_rs::{AuthLevel, WMIConnection};
use serde::Deserialize;

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_EncryptableVolume")]
#[serde(rename_all = "PascalCase")]
struct EncryptableVolume {
    device_id: String,
    drive_letter: Option<String>,
    protection_status: Option<u32>,  // 0=Unprotected, 1=Protected, 2=Unknown
}

fn query_bitlocker_status() -> Result<Vec<EncryptableVolume>, Box<dyn std::error::Error>> {
    let wmi_con = WMIConnection::with_namespace_path(
        r"ROOT\CIMV2\Security\MicrosoftVolumeEncryption"
    )?;
    wmi_con.set_proxy_blanket(AuthLevel::PktPrivacy)?;  // REQUIRED for BitLocker namespace

    let volumes: Vec<EncryptableVolume> = wmi_con.query()?;
    Ok(volumes)
}
```

**ProtectionStatus values:**

| Value | Meaning | Action for Allowlist |
|-------|---------|---------------------|
| 0 | Unprotected (not encrypted) | Block or warn — disk is unencrypted |
| 1 | Protected (encrypted) | Allow — disk meets encryption requirement |
| 2 | Unknown | Block — cannot verify encryption state |

**Critical requirements:**
1. **Namespace:** Must use `ROOT\CIMV2\Security\MicrosoftVolumeEncryption` (NOT standard `ROOT\CIMV2`)
2. **Authentication:** Must call `set_proxy_blanket(AuthLevel::PktPrivacy)` — without this, query fails with access denied
3. **Privileges:** Must run as Administrator (the agent already runs as LocalSystem, so this is satisfied)
4. **Serde attributes:** `#[serde(rename_all = "PascalCase")]` is mandatory — WMI uses PascalCase property names

**Extended struct for richer verification:**

```rust
#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_EncryptableVolume")]
#[serde(rename_all = "PascalCase")]
struct EncryptableVolume {
    device_id: String,
    drive_letter: Option<String>,
    protection_status: Option<u32>,
    conversion_status: Option<u32>,      // 0=FullyDecrypted, 1=FullyEncrypted, 2=EncryptionInProgress
    encryption_method: Option<u32>,      // 0=None, 1=AES_128_WITH_DIFFUSER, 3=AES_128, 4=AES_256, 6=XTS_AES_128, 7=XTS_AES_256
    encryption_percentage: Option<u32>,  // 0-100, only meaningful during conversion
}
```

**Where this code lives:** New module `dlp-agent/src/encryption_checker.rs`. Called during install-time
enumeration (after fixed disk discovery, before allowlist persistence). Results stored alongside each
disk entry in the allowlist.

**Confidence:** HIGH — `wmi-rs` 0.14 is actively maintained, uses the official `windows` crate
internally, and the BitLocker namespace pattern is well-documented across Microsoft docs and
community examples. The `AuthLevel::PktPrivacy` requirement is explicitly documented in the crate.

---

## Capability 3: Disk Identity and Allowlist Persistence

**No new crates needed.** Uses existing stack:
- `serde` + `serde_json` / `toml` — for allowlist serialization
- `uuid` (workspace) — for generating stable allowlist entry IDs
- `dlp-common` — for shared `DeviceIdentity` type (extended with disk-specific fields)

**Disk identity fields (extension to existing types):**

```rust
// In dlp-common/src/endpoint.rs — extend DeviceIdentity or create new FixedDiskIdentity
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FixedDiskIdentity {
    /// Drive letter at install time (may change — not stable identity).
    pub drive_letter: String,
    /// Volume serial number from GetVolumeInformationW (stable across formats).
    pub volume_serial: String,
    /// Volume GUID path (most stable logical identifier).
    pub volume_guid: String,
    /// Physical disk path (e.g., "\\.\PhysicalDrive0").
    pub physical_disk_path: String,
    /// Disk model from STORAGE_DEVICE_DESCRIPTOR (e.g., "Samsung SSD 970 EVO").
    pub model: String,
    /// Disk serial number from STORAGE_DEVICE_DESCRIPTOR (hardware serial).
    pub disk_serial: String,
    /// Bus type: "SATA", "NVMe", "USB", "ATA", etc.
    pub bus_type: String,
    /// BitLocker protection status: 0=unprotected, 1=protected, 2=unknown.
    pub bitlocker_status: u32,
    /// Whether this disk was in the allowlist at install time.
    pub is_allowed: bool,
    /// ISO 8601 timestamp of when this entry was created.
    pub registered_at: String,
}
```

**Persistence strategy:**

1. **Agent local:** Extend `AgentConfig` in `dlp-agent/src/config.rs` with:
   ```toml
   [[fixed_disk_allowlist]]
   drive_letter = "C"
   volume_serial = "1234ABCD"
   volume_guid = "\\\\?\\Volume{...}\\"
   physical_disk_path = "\\\\.\\PhysicalDrive0"
   model = "Samsung SSD 970 EVO"
   disk_serial = "S123456789"
   bus_type = "NVMe"
   bitlocker_status = 1
   is_allowed = true
   registered_at = "2026-04-30T10:00:00Z"
   ```

2. **Server-side:** New table `fixed_disk_registry` in dlp-server SQLite DB, mirroring the
   `device_registry` pattern from Phase 24. Admin TUI screen for viewing/managing disk entries.

3. **Runtime check:** On agent startup and on `WM_DEVICECHANGE` arrival for fixed disks,
   compare the discovered disk against the allowlist. If not found → block I/O (same pattern as
   USB unregistered device fallback in `UsbEnforcer`).

**Confidence:** HIGH — extends existing patterns (TOML config, SQLite registry, `DeviceIdentity`
struct) with no new dependencies.

---

## Capability 4: Runtime Blocking of Unregistered Fixed Disks

**No new crates needed.** Reuses existing enforcement infrastructure:
- `dlp-agent/src/interception/` — existing file I/O interception layer
- `dlp-agent/src/usb_enforcer.rs` — pattern for drive-letter-based blocking
- `dlp-agent/src/detection/usb.rs` — `WM_DEVICECHANGE` notification infrastructure

**Integration approach:**

1. Extend `UsbDetector` (or create `FixedDiskDetector`) to track fixed disk arrivals/removals.
2. On `DBT_DEVICEARRIVAL` for `GUID_DEVINTERFACE_VOLUME` with `DRIVE_FIXED`:
   - Query `IOCTL_STORAGE_QUERY_PROPERTY` to get bus type and identity.
   - Check allowlist (local TOML + server cache).
   - If not in allowlist → block all I/O to this drive letter (same `UsbBlockResult` pattern).
3. Hook into existing `InterceptionEngine` event loop — check fixed disk block BEFORE ABAC
   evaluation (defense in depth: NTFS ALLOW + Fixed Disk DENY = DENY).

**Confidence:** HIGH — mirrors the proven USB enforcement pattern from Phases 23-26.

---

## Summary: Dependency Delta for v0.7.0

### `Cargo.toml` workspace — no changes needed

### `dlp-agent/Cargo.toml`

```toml
[dependencies]
# Bump existing:
windows = { version = "0.62", features = [
    # ... all existing features ...
    # NEW additions for v0.7.0:
    "Win32_System_Ioctl",          # IOCTL_STORAGE_QUERY_PROPERTY for bus type detection
] }

# NEW:
wmi-rs = { version = "0.14", features = ["serde"] }   # BitLocker encryption status via WMI
```

### `dlp-user-ui/Cargo.toml`

No changes. Fixed disk enumeration and BitLocker checks run in `dlp-agent` (SYSTEM session),
not in the user UI process.

### `dlp-common/Cargo.toml`

No new dependencies. Add `FixedDiskIdentity` struct to `endpoint.rs`.

### `dlp-server/Cargo.toml`

No new dependencies. Add `fixed_disk_registry` table migration to existing SQLite schema.

---

## What NOT to Add

| Rejected option | Reason |
|----------------|--------|
| `winapi` crate | Legacy, unmaintained. All needed APIs are in `windows` crate. |
| `setupapi` crate | Unmaintained thin wrapper. Use `windows` feature flag directly. |
| Raw COM/WMI via `windows::Win32::System::Wmi` | Too verbose (~200 lines vs ~10 with `wmi-rs`). `wmi-rs` handles COM init, WQL, VARIANTs. |
| `manage-bde` CLI invocation | Spawning a subprocess is slow, fragile, and requires parsing text output. WMI is the programmatic API. |
| `bitlocker` crate (if one existed) | No actively maintained Rust crate for BitLocker. WMI is the canonical Windows API. |
| `sysinfo` crate | Cross-platform abstraction that doesn't expose Windows-specific bus type or BitLocker info. |
| `ntapi` crate | Overkill — `IOCTL_STORAGE_QUERY_PROPERTY` is a documented public API, not an undocumented NT syscall. |
| Separate `dlp-disk-enumerator` crate | Overkill — disk enumeration is a single module (~200 lines) in `dlp-agent`. |
| `Win32_System_Wmi` feature flag (raw) | Only needed if using raw COM. `wmi-rs` handles this internally via its own `windows` dependency. |
| Volume GUID as sole identity | Volume GUID changes on format. Combine with disk serial + model for stable identity. |
| Drive letter as identity | Drive letters are NOT stable — they change when disks are reordered or removed. |

---

## Key Integration Points

| New capability | Lives in | Communicates with |
|---------------|----------|-------------------|
| Fixed disk enumeration (`GetDriveTypeW` + `IOCTL_STORAGE_QUERY_PROPERTY`) | `dlp-agent/src/disk_enumerator.rs` (new) | `AgentConfig` (TOML persistence), server API (sync) |
| BitLocker verification (`wmi-rs` + `Win32_EncryptableVolume`) | `dlp-agent/src/encryption_checker.rs` (new) | `disk_enumerator.rs` — called per-disk during enumeration |
| Disk allowlist enforcement | `dlp-agent/src/interception/` (extend) | `UsbEnforcer`-style block result, audit emitter |
| Fixed disk registry DB | `dlp-server/src/db.rs` (extend) | Admin TUI screen (mirror device registry pattern) |
| Admin disk management TUI | `dlp-admin-cli/src/screens/` (new screen) | dlp-server API for CRUD on `fixed_disk_registry` |

---

## Confidence Assessment

| Area | Confidence | Reason |
|------|------------|--------|
| `IOCTL_STORAGE_QUERY_PROPERTY` API surface | HIGH | Confirmed in microsoft.github.io/windows-docs-rs for 0.62; stable Win32 API |
| `STORAGE_BUS_TYPE` discrimination (USB vs SATA/NVMe) | HIGH | Well-documented Windows storage API; used by sysinfo and other Rust crates |
| `wmi-rs` 0.14 for BitLocker queries | HIGH | Actively maintained, uses official `windows` crate, BitLocker namespace pattern verified |
| `AuthLevel::PktPrivacy` requirement | HIGH | Explicitly documented in wmi-rs crate and Microsoft WMI docs |
| `Win32_EncryptableVolume.ProtectionStatus` semantics | HIGH | Microsoft Learn documents values 0/1/2 |
| Windows 0.58 -> 0.62 migration risk | MEDIUM | No documented API surface breaks for used modules; metadata changes exist |
| USB bridge detection accuracy | MEDIUM-HIGH | `BusTypeUsb` catches USB bridges, but some exotic bridges may report `BusTypeScsi`. Need fallback to parent PnP tree walk (already proven in Phase 31). |
| Disk serial number stability | MEDIUM | Some USB enclosures do not pass through disk serial; may need fallback to model + volume serial composite key |

---

## Sources

- [windows-rs 0.62.2 Cargo.toml feature flags (docs.rs)](https://docs.rs/crate/windows/latest/source/Cargo.toml.orig)
- [windows-rs releases page — 0.58 through 0.62.2 dates](https://github.com/microsoft/windows-rs/releases)
- [IOCTL_STORAGE_QUERY_PROPERTY in windows::Win32::System::Ioctl (docs-rs)](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Ioctl/constant.IOCTL_STORAGE_QUERY_PROPERTY.html)
- [STORAGE_DEVICE_DESCRIPTOR in windows::Win32::System::Ioctl (docs-rs)](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Ioctl/struct.STORAGE_DEVICE_DESCRIPTOR.html)
- [StorageDeviceProperty in windows::Win32::System::Ioctl (docs-rs)](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Ioctl/constant.StorageDeviceProperty.html)
- [GetDriveTypeW in windows::Win32::Storage::FileSystem (docs-rs)](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Storage/FileSystem/fn.GetDriveTypeW.html)
- [wmi-rs crate — GitHub (ohadravid/wmi-rs)](https://github.com/ohadravid/wmi-rs)
- [wmi-rs crate — crates.io](https://crates.io/crates/wmi-rs)
- [Win32_EncryptableVolume class — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secprov/win32-encryptablevolume)
- [Query BitLocker status PowerShell/WMI — GitHub Gist](https://gist.github.com/43309ac879db58563c63e4856f3a3a11)
- [Win32_DiskDrive class — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-diskdrive)
- [MSFT_PhysicalDisk class — Windows Storage Management API](https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-physicaldisk)
- [How to find out if disk is SSD — Rust Users Forum](https://users.rust-lang.org/t/how-to-find-out-if-the-disk-that-my-current-process-uses-is-ssd/76034)
- [IOCTL_STORAGE_QUERY_PROPERTY — NtDoc](https://ntdoc.m417z.com/ioctl_storage_query_property)
- [Managing WMI on Windows — Rust Users Forum](https://users.rust-lang.org/t/managing-wmi-on-windows/119352)

# Feature Landscape: Disk Exfiltration Prevention (v0.7.0)

**Domain:** Enterprise Endpoint DLP — Fixed Disk Control & Encryption Verification
**Researched:** 2026-04-30
**Research Mode:** Ecosystem

---

## Table Stakes

Features users expect from any enterprise endpoint DLP product with disk control capabilities. Missing these makes the product feel incomplete.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **Install-time disk enumeration** | Every competing product establishes a device baseline at agent deployment. Admins expect a known-good starting state. | Medium | Must enumerate all `DRIVE_FIXED` volumes, not just `DRIVE_REMOVABLE`. USB-bridged SATA/NVMe enclosures report as fixed. |
| **Persistent disk allowlist** | Without persistence, a reboot or agent restart loses enforcement state. Table stakes for any security agent. | Low | Store in `agent-config.toml` (existing pattern) + server-side registry. Must survive agent restarts and system reboots. |
| **BitLocker encryption status check** | BitLocker is the dominant Windows FDE. Every enterprise DLP product checks it. Microsoft Purview, Symantec, Forcepoint all integrate. | Medium | Use WMI `Win32_EncryptableVolume` (admin required, `PktPrivacy`) or undocumented `System.Volume.BitLockerProtection` property (no admin). |
| **Runtime blocking of unregistered disks** | The core value proposition. If a new fixed disk appears post-install and is not on the allowlist, block it. | High | Must handle both mount-time detection (volume arrival) and I/O-time enforcement (file interception layer). |
| **Audit events for disk actions** | Compliance frameworks (NIST 800-171, CMMC, HIPAA) require audit trails for all access control decisions. | Low | Reuse existing audit event pipeline. Add `DiskIdentity` fields (serial, model, bus type, encryption status). |
| **Admin override/registry for post-install additions** | IT replaces failed drives, adds storage. Admins need a supported path to update the allowlist without reinstalling the agent. | Medium | Admin TUI screen + server API endpoint. Must require authentication and log the override. |

### Sources — Table Stakes
- [Microsoft Purview Endpoint DLP — Removable Storage Policy](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/effectively-protect-sensitive-data-in-cloud-and-devices-using/ba-p/3733599)
- [Symantec DLP Device Control — USB/Fixed Disk Blocking](https://knowledge.broadcom.com/external/article/155346/how-to-block-usb-hard-drives-but-allow-r.html)
- [Forcepoint DLP Endpoint — Removable Media Control](https://help.forcepoint.com/F1E/en-us/v20/ep_install/C899EA85-ABE0-4EAE-85C0-0EA1409B2059.html)
- [Lake Ridge — NIST/CMMC DLP + MDM Configuration](https://lakeridge.io/how-to-configure-mdm-and-dlp-to-meet-nist-sp-800-171-rev2-cmmc-20-level-2-control-mpl2-388-and-prevent-unowned-usb-use)
- [BitLocker WMI Documentation — Win32_EncryptableVolume](https://itm4n.github.io/bitlocker-little-secrets-the-undocumented-fve-api/)

---

## Differentiators

Features that set a product apart. Not universally expected, but highly valued when present.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| **USB-bridged fixed disk detection** | Most DLP products only handle `DRIVE_REMOVABLE`. Detecting USB-bridged SATA/NVMe enclosures (which report as `DRIVE_FIXED`) is a genuine gap in commercial products. | High | Requires PnP tree walking (`SetupDi` + `CM_Get_Parent`) or `Win32_DiskDrive.InterfaceType` WMI query to distinguish USB bus from internal SATA/NVMe. |
| **Dual enforcement: mount-time + I/O-time** | Mount-time blocking prevents volume mount entirely (best UX — drive never appears). I/O-time blocking catches races and bypass attempts. Defense in depth. | High | Mount-time: `WM_DEVICECHANGE` / `RegisterDeviceNotification` + volume lock. I/O-time: existing file interception filter already handles this. |
| **Encryption verification beyond BitLocker** | Check for self-encrypting drives (SED/Opal), third-party FDE (VeraCrypt, McAfee), or hardware-encrypted USB enclosures. | Medium-High | SED/Opal via `IOCTL_SCSI_MINIPORT` or `StorageDeviceEncryptionProperty`. Third-party FDE is harder — no unified API. |
| **Grace period / quarantine mode for new disks** | Instead of immediate hard-block, allow a configurable grace period (e.g., 24h) during which the disk is read-only, giving IT time to review and allowlist. Reduces helpdesk tickets. | Medium | Requires temporary policy state + timer. Must not be default — default must be deny. |
| **Disk discovery toast notification with admin request flow** | When a new disk is blocked, user gets a toast with "Request Access" button. Admin gets a pending approval in TUI. Low-friction exception workflow. | Medium | Reuse existing toast notification infrastructure (Phase 27). Add new admin TUI screen for pending approvals. |
| **Per-disk trust tier (like USB trust tiers)** | Extend the existing `UsbTrustTier` pattern to disks: `blocked`, `read_only`, `full_access`. A disk can be allowlisted but restricted to read-only. | Low-Medium | Reuse existing trust tier enum and evaluator logic. Add `DiskTrustTier` to ABAC subject attributes. |
| **SIEM-enriched disk identity fields** | Send disk serial, model, firmware, bus type, encryption method, and protection status to SIEM. Enables correlation across the fleet. | Low | Extend existing `AuditEvent` struct. Reuse SIEM relay pipeline. |

### Sources — Differentiators
- [Black Hat EU 2015 — Bypassing SEDs in Enterprise](https://blackhat.com/docs/eu-15/materials/eu-15-Boteanu-Bypassing-Self-Encrypting-Drives-SED-In-Enterprise-Environments.pdf)
- [Usb.Events Library — Cross-Platform USB Detection](https://github.com/Jinjinov/Usb.Events)
- [Symantec DLP Known Issues — Virtual Drive / I/O Blocking](https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/26-1/new-and-changed/release-notes/dlp-known-issues.html)
- [Endpoint Protector — USB Enforced Encryption](https://www.endpointprotector.com/solutions/enforced-encryption)

---

## Anti-Features

Features to explicitly NOT build. These create operational pain, security holes, or scope creep.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| **User self-allowlist** | End users cannot be trusted to assess disk security. Self-allowlisting defeats the purpose of enterprise DLP. | All allowlist changes must flow through admin TUI or server API with authenticated admin session. |
| **Automatic allowlist of all disks at install time** | If the agent auto-allowlists everything it sees at install, an attacker can pre-stage a malicious USB-bridged disk before agent deployment. | Enumerate at install, but require admin explicit approval to populate the allowlist. Default-deny is the secure default. |
| **Blocking only at mount time** | Race conditions exist: a disk can be connected before the agent starts, or the agent can miss a volume arrival event. I/O-time enforcement is the reliable backstop. | Implement both mount-time (best UX) and I/O-time (reliable) blocking. |
| **Supporting non-Windows encryption APIs** | macOS FileVault and Linux LUKS are out of scope for this Windows-first DLP product. Checking them adds complexity with no value. | Scope encryption checks to Windows BitLocker only. Document that third-party FDE detection is best-effort. |
| **Drive letter as disk identifier** | Drive letters are volatile (D: today, E: tomorrow). Using them as allowlist keys creates false positives and false negatives. | Use persistent identifiers: disk serial number, PnP device instance ID, or volume GUID path (`\\?\Volume{GUID}\`). |
| **Grace period as default behavior** | A default grace period creates a window of vulnerability. New disks should be blocked immediately unless explicitly configured otherwise. | Make grace period opt-in per policy. Default is immediate block. |

---

## Feature Dependencies

```
Install-Time Disk Enumeration
    --> Persistent Disk Allowlist (needs something to persist)
    --> BitLocker Encryption Check (per-disk property to store)
    --> Audit Events (discovery events to emit)

Persistent Disk Allowlist
    --> Runtime Blocking (needs allowlist to check against)
    --> Admin Override/Registry (needs allowlist to mutate)

Runtime Blocking
    --> Mount-Time Blocking (volume arrival detection)
    --> I/O-Time Blocking (file interception integration)

USB-Bridged Fixed Disk Detection
    --> Install-Time Enumeration (must classify bus type)
    --> Runtime Blocking (must apply blocking logic)

Grace Period / Quarantine Mode
    --> Runtime Blocking (temporary policy override)
    --> Admin Override (conversion from quarantine to allowlist)

Disk Discovery Toast + Admin Request
    --> Runtime Blocking (trigger condition)
    --> Existing Toast Infrastructure (Phase 27)
    --> Admin TUI Screen (new screen for pending approvals)

Per-Disk Trust Tier
    --> Persistent Disk Allowlist (trust tier per entry)
    --> ABAC Evaluator (disk trust tier as subject attribute)
    --> Existing USB Trust Tier Pattern (reuse)
```

---

## MVP Recommendation

### Prioritize (Phase 1 of v0.7.0)

1. **Install-time enumeration of fixed disks** — Establish the baseline. Must detect USB-bridged enclosures (the whole point of this milestone).
2. **BitLocker encryption status check** — Table stakes. Use WMI `Win32_EncryptableVolume` with `PktPrivacy`.
3. **Persistent disk allowlist in agent-config.toml** — Reuse existing TOML persistence pattern.
4. **Runtime blocking of unregistered fixed disks at I/O time** — Most reliable enforcement point. Integrate with existing file interception.
5. **Audit events for disk block/discovery** — Compliance requirement. Extend existing `AuditEvent`.

### Defer (Phase 2+ of v0.7.0 or later milestones)

- **Mount-time blocking**: Higher complexity, race-condition prone. I/O-time blocking catches all cases.
- **Grace period / quarantine mode**: Nice-to-have operational convenience. Can be added without breaking existing behavior.
- **Disk discovery toast with admin request flow**: Requires new TUI screen and async approval workflow. Significant UX work.
- **Encryption beyond BitLocker**: SED/Opal detection is niche; third-party FDE has no unified API. Best-effort documentation only.
- **Per-disk trust tier**: Extends the model but is not required for the core "block unregistered disks" use case.

### Rationale

The core threat model is: "attacker plugs in a USB-bridged SATA/NVMe enclosure and copies sensitive data." The MVP must:
- Detect these devices (they look like fixed disks)
- Know which were present at install (the baseline)
- Block new ones (the enforcement)
- Log everything (compliance)

Everything else is optimization and operational convenience.

---

## Competitor Capability Matrix

| Capability | Microsoft Purview | Symantec DLP | Forcepoint DLP | Digital Guardian | DLP-RUST (Target) |
|------------|-------------------|--------------|----------------|------------------|-------------------|
| Fixed disk blocking | Indirect (via Defender Device Control) | Yes (Device Control tab) | Yes (Endpoint Removable Media) | Yes (Removable Media Control) | **Yes (MVP)** |
| USB-bridged fixed disk detection | No (treats as fixed disk) | Limited | Limited | Limited | **Yes (Differentiator)** |
| BitLocker integration | Native (same vendor) | Via SEE RME | No | No | **Yes (MVP)** |
| Install-time baseline | Yes (policy deployment) | Yes (agent config) | Yes (endpoint profile) | Yes (agent deployment) | **Yes (MVP)** |
| Admin override post-install | Yes (Intune/Compliance Portal) | Yes (Enforce Server) | Yes (DLP Console) | Yes (DGMC) | **Yes (MVP)** |
| Grace period for new devices | No | No | No | No | **Defer (Differentiator)** |
| Mount-time + I/O-time dual block | No (primarily I/O-time) | No (primarily I/O-time) | No (primarily I/O-time) | No (primarily I/O-time) | **Defer (Differentiator)** |
| SED/Opal detection | No | No | No | No | **Defer (Differentiator)** |

**Confidence:** MEDIUM — based on product documentation and community discussions. Vendor implementations may have undocumented capabilities.

---

## Key Questions Answered

### Should the feature block at mount time, I/O time, or both?

**Answer: Both, but I/O-time first.**

- **I/O-time blocking** is the reliable backstop. The existing file interception layer already inspects every file operation. Adding a "is the target volume on the disk allowlist?" check is a natural extension. This catches all cases, including races and agent restart scenarios.
- **Mount-time blocking** provides better UX (the drive letter never appears to the user) but is less reliable. Volume arrival events can be missed, and filter drivers have race conditions during fast mount/unmount cycles.
- **Recommendation:** Implement I/O-time blocking in the MVP. Add mount-time blocking as a Phase 2 enhancement for improved UX.

### What encryption standards beyond BitLocker should be checked?

**Answer: BitLocker is the MVP. SED/Opal is a differentiator. Third-party FDE is out of scope.**

- **BitLocker**: Native Windows API, well-documented, dominant enterprise standard. Must support.
- **Self-Encrypting Drives (SED/Opal)**: Hardware encryption at the drive controller. Can be detected via `IOCTL_SCSI_MINIPORT` or `StorageDeviceEncryptionProperty`. However, USB-bridged SEDs lose Opal manageability — the USB bridge chip does not pass TCG Opal commands. Detection is possible; enforcement is limited.
- **Third-party FDE (VeraCrypt, McAfee, etc.)**: No unified API. Each product modifies the boot process and disk stack differently. Checking for them reliably requires product-specific heuristics. Not worth the complexity for a Windows-first product.
- **Recommendation:** BitLocker check in MVP. Document SED/Opal as a future research item. Explicitly exclude third-party FDE from scope.

### What is the UX for "admin wants to add a new disk after install"?

**Answer: Two paths — proactive admin TUI and reactive user request.**

- **Proactive (Admin TUI):** Admin navigates to a "Disk Registry" screen in `dlp-admin-cli`. Sees a list of disks discovered across the fleet (populated by agent audit events). Selects a disk, reviews its encryption status and bus type, and clicks "Add to Allowlist." The server pushes the updated allowlist to the agent via existing config polling.
- **Reactive (User Request):** User plugs in a new disk, gets blocked, sees a toast notification with "Request Access." The request appears in the admin TUI as a pending approval. Admin approves → disk is added to allowlist and user is notified.
- **Recommendation:** Implement the proactive path in MVP. The reactive path requires significant TUI and async workflow work — defer to Phase 2.

### Should there be a grace period or quarantine mode for new disks?

**Answer: Yes, but opt-in and not default.**

- **Grace period** (e.g., 24 hours read-only access) reduces helpdesk load in organizations where users legitimately need to connect new storage frequently. The disk is detected, blocked from writes, and an admin notification is sent.
- **Quarantine mode** is a stronger variant: the disk is mounted but all I/O is redirected to a contained temporary storage (Forcepoint uses this pattern with a default 500MB containment buffer).
- **Risk:** Any grace period is a window of vulnerability. Default must be immediate block.
- **Recommendation:** Add a policy-configurable grace period as a Phase 2 feature. Default is `0` (immediate block). Document the security trade-off clearly.

---

## Sources

### Official Documentation
- [Microsoft Purview Endpoint DLP Documentation](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/effectively-protect-sensitive-data-in-cloud-and-devices-using/ba-p/3733599)
- [Broadcom Symantec DLP Device Control](https://knowledge.broadcom.com/external/article/155346/how-to-block-usb-hard-drives-but-allow-r.html)
- [Broadcom Symantec Endpoint Encryption RME FAQs](https://knowledge.broadcom.com/external/article/222689/symantec-endpoint-encryption-removable-m.html)
- [Forcepoint DLP Endpoint Supported Removable Media](https://help.forcepoint.com/F1E/en-us/v20/ep_install/C899EA85-ABE0-4EAE-85C0-0EA1409B2059.html)
- [Forcepoint DLP Endpoint Settings — Disk Space](https://help.forcepoint.com/dlp/90/dlphelp/CD069C77-5BB9-458D-86EE-485AD3E425B1.html)
- [Digital Guardian Agent for Windows Release Notes](https://hstechdocs.helpsystems.com/releasenotes/Content/_ProductPages/Digital%20Guardian/Digital%20Guardian_windows_agent.htm)

### Technical References
- [BitLocker's Undocumented FVE API](https://itm4n.github.io/bitlocker-little-secrets-the-undocumented-fve-api/)
- [WMI-rs Rust Crate for BitLocker](https://github.com/ohadravid/wmi-rs)
- [Black Hat EU 2015 — Bypassing SEDs in Enterprise](https://blackhat.com/docs/eu-15/materials/eu-15-Boteanu-Bypassing-Self-Encrypting-Drives-SED-In-Enterprise-Environments.pdf)
- [TCG Opal 2.0 SED Specification](https://computingworlds.com/blog/post/opal-2.0-sed)

### Compliance & Best Practices
- [Lake Ridge — NIST SP 800-171 / CMMC 2.0 DLP + MDM](https://lakeridge.io/how-to-configure-mdm-and-dlp-to-meet-nist-sp-800-171-rev2-cmmc-20-level-2-control-mpl2-388-and-prevent-unowned-usb-use)
- [Lake Ridge — Endpoint DLP + USB Whitelisting for NIST](https://lakeridge.io/how-to-configure-endpoint-dlp-and-usb-whitelisting-to-meet-nist-sp-800-171-rev2-cmmc-20-level-2-control-mpl2-387)

### Community & Implementation
- [Usb.Events — Cross-Platform USB Detection (.NET)](https://github.com/Jinjinov/Usb.Events)
- [Tim Golden — Detect Device Insertion in Python](https://timgolden.me.uk/python/win32_how_i/detect-device-insertion.html)
- [Ravichaganti — Monitoring Volume Change Events in PowerShell](https://ravichaganti.com/blog/monitoring-volume-change-events-in-powershell-using-wmi/)

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Competitor capabilities | MEDIUM | Based on public documentation and community discussions. Vendor implementations may have undocumented features. |
| BitLocker API | HIGH | Well-documented WMI API. Rust `wmi-rs` crate verified. |
| USB-bridged fixed disk detection | MEDIUM-HIGH | PnP tree walking (`SetupDi` + `CM_Get_Parent`) is a known technique. Already implemented in Phase 31 of this project. |
| SED/Opal detection | LOW | Limited public documentation on programmatic detection. USB bridge chips break Opal manageability. |
| Third-party FDE compatibility | LOW | No unified API. Product-specific heuristics required. |
| Grace period UX patterns | MEDIUM | Observed in EDR/EPP products (quarantine). Less common in DLP specifically. |

# Domain Pitfalls: Disk Exfiltration Prevention

**Domain:** Windows Endpoint DLP — Fixed Disk Allowlist with BitLocker Encryption Verification
**Researched:** 2026-04-30
**Confidence:** MEDIUM-HIGH (existing codebase knowledge HIGH; BitLocker API specifics MEDIUM; industry precedent MEDIUM)

---

## Critical Pitfalls

Mistakes that cause rewrites, system unbootability, or silent security bypasses.

### Pitfall 1: Boot Disk Incorrectly Flagged as Unregistered

**What goes wrong:** The install-time disk enumeration captures all fixed disks. If the system boot disk (C:) is not pre-populated in the allowlist or the BitLocker check fails spuriously, the agent blocks the boot disk on next startup. The system becomes unbootable or the agent cannot load its own configuration.

**Why it happens:**
- The boot disk may not have a drive letter at the exact moment of enumeration (e.g., during Windows PE install, or if the system uses mount points).
- BitLocker may report "suspended" during Windows Update or firmware updates, causing the encryption check to fail even though the disk is legitimate.
- The enumeration runs before all disk drivers are fully loaded, causing the boot disk to be missed.

**Consequences:**
- System unbootable (BSOD or boot loop).
- Agent cannot read its own config from C:\ProgramData\DLP\.
- Requires Safe Mode or recovery media to fix.

**Prevention:**
- **Never block the boot volume.** Always identify the boot volume (via `GetSystemDirectoryW` or `GetWindowsDirectoryW`) and unconditionally add it to the allowlist regardless of BitLocker state.
- Store the allowlist in the Windows Registry (HKLM) or a well-known path that is accessible before the agent's full config is loaded.
- During install-time enumeration, query `GetSystemDirectoryW` to determine the boot drive letter and mark it as `is_boot_disk = true` in the allowlist entry.
- Implement a "fail-open" for the boot disk specifically: if the boot disk is ever not found in the allowlist, log CRITICAL and allow it rather than block.

**Detection:**
- Install-time logs must record: "Boot disk identified as C:, added to allowlist unconditionally."
- UAT test: simulate allowlist missing boot disk entry; verify agent logs CRITICAL and does not block C:.

**Phase to address:** Phase 33 (Install-time enumeration) — this is a design-invariant, not an implementation detail.

---

### Pitfall 2: USB-to-SATA/NVMe Bridges Bypass Detection (DRIVE_FIXED)

**What goes wrong:** USB bridge chips (Realtek RTL9210, JMicron JMS583, ASMedia ASM2362) report connected drives as `DRIVE_FIXED` instead of `DRIVE_REMOVABLE`. The existing `GetDriveTypeW`-based detection in `dlp-agent/src/detection/usb.rs` (used for USB blocking) completely misses these devices. A user can exfiltrate data via a USB-NVMe enclosure that appears as a fixed internal drive.

**Why it happens:**
- These bridge chips present the USB mass storage device as a SCSI disk to Windows.
- Windows classifies SCSI disks as `DRIVE_FIXED` regardless of their physical connection.
- The existing USB detection path in the agent only blocks `DRIVE_REMOVABLE` drives.
- The Phase 31-02 gap closure (GUID_DEVINTERFACE_DISK + PnP tree walk) was designed for USB device *control* (disabling devices by VID/PID), not for fixed disk *allowlisting*.

**Consequences:**
- Complete bypass of disk exfiltration prevention.
- Data exfiltration via commodity USB-NVMe enclosures (~$20 on Amazon).
- The bypass is silent — no audit event, no block, no toast notification.

**Prevention:**
- **Do not rely on `GetDriveTypeW` for security decisions.** Use a multi-factor detection approach:
  1. **PnP tree walk:** For every fixed disk, walk up the PnP tree via `CM_Get_Parent`. If any ancestor has an instance ID starting with `USB\`, the disk is USB-attached regardless of `GetDriveTypeW`.
  2. **SPDRP_REMOVAL_POLICY:** Query `SetupDiGetDeviceRegistryPropertyW` with `SPDRP_REMOVAL_POLICY` (0x001F). Values `CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL` (1) = internal; `CM_REMOVAL_POLICY_EXPECT_ORDERLY_REMOVAL` (2) or `CM_REMOVAL_POLICY_EXPECT_SURPRISE_REMOVAL` (3) = removable.
  3. **Bus type query:** Query `SPDRP_BUSNUMBER` or `SPDRP_LOCATION_INFORMATION` to detect USB bus attachment.
- The fixed disk allowlist must treat USB-attached fixed disks as **unregistered by default** unless explicitly added to the allowlist by an admin.
- Reuse the existing PnP tree walk logic from `on_disk_device_arrival` in `dlp-agent/src/detection/usb.rs` (proven in Phase 31-02).

**Detection:**
- UAT test with RTL9210, JMS583, and ASM2362 enclosures.
- Verify that `DRIVE_FIXED` USB disks are blocked unless in allowlist.
- Check logs for "USB-attached fixed disk detected" entries.

**Phase to address:** Phase 34 (Runtime blocking of unregistered fixed disks).

**Sources:**
- [Microsoft VB WinAPI Discussion — Alternative to GetDriveType for large USB drives](https://microsoft.public.vb.winapi.narkive.com/PCVEx2sx/alternative-to-getdrivetype-for-large-usb-drives) — confirms USB HDDs report DRIVE_FIXED
- [Microsoft Defender Device Control Overview](https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-endpoint/device-control-overview.md) — documents removable SSD/UAS support added in v4.18.2105, implying prior gap
- Phase 31-02 gap closure debug log (`.planning/debug/phase31-test6-rework.md`) — Realtek RTL9210 NVMe USB device bypassed DRIVE_REMOVABLE detection

---

### Pitfall 3: BitLocker API Reliability Issues

**What goes wrong:** The BitLocker encryption check fails intermittently or returns misleading results. Disks that are encrypted are reported as unencrypted, or disks with suspended encryption are reported as fully protected.

**Why it happens:**
- **WMI `Win32_EncryptableVolume` timeouts:** WMI queries can hang for 60+ seconds during system startup or when the WMI repository is corrupted. The default timeout may not be sufficient.
- **LocalSystem access issues:** While LocalSystem typically has full WMI access, certain BitLocker WMI namespaces (`ROOT\CIMV2\Security\MicrosoftVolumeEncryption`) may require explicit security descriptor permissions that are not granted to SYSTEM on all systems.
- **Suspended encryption state:** BitLocker can be "suspended" during Windows Updates, firmware updates, or BitLocker management operations. In this state, the volume is technically encrypted but the protector is temporarily removed. A naive check of `ProtectionStatus` may return "Unprotected" (0) even though the data is still encrypted.
- **FVE API vs WMI discrepancy:** The undocumented `fveapi.dll` (`FveGetStatus`) may return different results than WMI, particularly for authentication mode detection.

**Consequences:**
- False negatives: encrypted disks are blocked because the check failed.
- False positives: unencrypted disks are allowed because suspended state was misread.
- Admin confusion and help desk tickets.

**Prevention:**
- **Use multiple check methods with consensus:**
  1. **Primary:** WMI `Win32_EncryptableVolume.GetProtectionStatus()` — `ProtectionStatus == 1` means protected.
  2. **Secondary:** WMI `Win32_EncryptableVolume.GetConversionStatus()` — `ConversionStatus == 1` means fully encrypted.
  3. **Tertiary (fallback):** Registry check `HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus\BootStatus` — non-zero means BitLocker is configured.
  4. **Quaternary (fallback):** Check for the presence of the FVE metadata block via `DeviceIoControl` with `FSCTL_QUERY_FVE_STATE` (undocumented but stable).
- **Treat "suspended" as encrypted for allowlist purposes.** A disk that was encrypted at install time and later suspended (e.g., for a Windows Update) should remain in the allowlist. The allowlist entry should record the encryption state at install time and not re-verify it on every boot unless explicitly configured to do so.
- **Implement WMI query timeouts:** Use `IWbemServices::ExecQuery` with a timeout (e.g., 5 seconds), not the default 60+ seconds. If WMI times out, fall back to registry checks.
- **Cache the install-time result:** The allowlist should store `encryption_verified_at: <timestamp>` and `encryption_method: "BitLocker"`. Do not re-query BitLocker status on every agent startup — only at install time and when admin explicitly requests a re-scan.

**Detection:**
- Log all BitLocker check results with method used, raw values, and fallback chain.
- UAT: test with suspended BitLocker state; verify disk remains allowed.
- UAT: test with corrupted WMI repository; verify fallback methods work.

**Phase to address:** Phase 33 (Install-time enumeration) and Phase 35 (Admin override/registry updates).

**Sources:**
- [ITM4N — BitLocker's Little Secrets: The Undocumented FVE API](https://itm4n.github.io/bitlocker-little-secrets-the-undocumented-fve-api/) — documents FVE API privilege requirements and WMI limitations
- [Zabbix ZBX-17974 — WMI queries do not timeout correctly](https://support.zabbix.com/browse/ZBX-17974) — WMI timeout property limitations
- [PDQ — WMI operation timed out](https://help.pdq.com/hc/en-us/articles/220532387-WMI-operation-timed-out) — WMI timeout troubleshooting

---

### Pitfall 4: False Positives on System Recovery Partitions, Virtual Disks, and RAM Disks

**What goes wrong:** The install-time enumeration captures all fixed disks, including system recovery partitions (e.g., Windows RE), virtual disks (VHD/VHDX mounts from Hyper-V, WSL, or development tools), and RAM disks (e.g., ImDisk, AMD RAMDisk). These are incorrectly treated as "unregistered fixed disks" and blocked.

**Why it happens:**
- System recovery partitions are fixed disks with no drive letter (mount points or hidden).
- Virtual disks mounted from VHD/VHDX files report as `DRIVE_FIXED` and have a disk device instance ID.
- RAM disks report as `DRIVE_FIXED` and may have a generic device instance ID.
- The enumeration logic does not distinguish between "physical internal disk" and "virtual/transient disk."

**Consequences:**
- System recovery operations fail (e.g., Windows Reset, system restore).
- Development workflows break (WSL2 VHD, Docker Desktop VHDX).
- RAM disk users cannot use their configured temp drives.
- Silent failures that are hard to diagnose — the user sees "access denied" with no DLP notification.

**Prevention:**
- **Exclude by device instance ID pattern:**
  - Recovery partitions: instance IDs containing `Recovery` or matching known Windows RE patterns.
  - Virtual disks: instance IDs containing `VMBUS` (Hyper-V), `VHD` or `VHDX` in the path.
  - RAM disks: instance IDs from known RAM disk drivers (e.g., `ImDisk`, `SoftPerfect`).
- **Exclude by disk characteristics:**
  - No drive letter + mount point under `\Recovery` = recovery partition.
  - Disk size < 1 GB and no file system = likely recovery or EFI partition.
  - Disk backed by a file (check `IOCTL_STORAGE_QUERY_PROPERTY` for `StorageDeviceTrimProperty` or query VHD backing file).
- **Exclude by bus type:** Query `SPDRP_BUSNUMBER` or `SPDRP_LOCATION_INFORMATION`. Virtual disks often report bus types like `VMBUS` or `FileBackedVirtual`.
- **Whitelist known-safe device classes:** Use `SetupDiGetClassDevsW` with `GUID_DEVINTERFACE_VOLUME` and filter by `SPDRP_CLASS` = `Volume` vs `DiskDrive`.
- **Do not block disks without a drive letter unless explicitly configured.** The current USB blocking only affects drives with letters; fixed disk blocking should follow the same pattern to avoid breaking mount-point-based recovery partitions.

**Detection:**
- UAT on a machine with Windows RE partition: verify it is not blocked.
- UAT with WSL2 enabled: verify VHD is not blocked.
- UAT with ImDisk RAM disk: verify it is not blocked.

**Phase to address:** Phase 33 (Install-time enumeration).

---

### Pitfall 5: Race Condition Between Disk Arrival and Policy Check

**What goes wrong:** A new fixed disk is connected (e.g., a USB-bridged SATA drive) and a file write occurs before the agent has completed the allowlist check. The write is allowed because the disk has not yet been classified as unregistered.

**Why it happens:**
- Disk arrival notifications (`WM_DEVICECHANGE` with `DBT_DEVICEARRIVAL`) are asynchronous.
- The agent's file interception hook (`file_monitor.rs`) runs in a separate thread from the device notification handler.
- If a write occurs in the window between disk mount and allowlist check completion, the write is not blocked.
- The window can be hundreds of milliseconds on a loaded system.

**Consequences:**
- Data exfiltration in the race window.
- The bypass is probabilistic — hard to reproduce in testing but exploitable by an attacker who knows the timing.

**Prevention:**
- **Default-deny for unknown fixed disks.** The file interception layer should treat any fixed disk that is NOT in the allowlist as blocked until proven otherwise. This is the inverse of the current USB model (which defaults to allowing unknown USB devices until the registry cache is checked).
  - Current USB model: disk arrives -> allow all -> check registry -> block if blocked tier.
  - Fixed disk model: disk arrives -> block all -> check allowlist -> allow if in allowlist.
- **Pre-populate the allowlist at install time.** The install-time enumeration creates the baseline allowlist. At runtime, only *new* disks (not in the allowlist) need to be checked. New disks should be blocked immediately on arrival, before any file I/O can occur.
- **Use a two-phase enforcement:**
  1. On `DBT_DEVICEARRIVAL` for `GUID_DEVINTERFACE_DISK`: immediately add the disk to a "pending verification" set.
  2. The file interception layer checks: if disk is in "pending verification", block the write.
  3. Once the allowlist check completes (async), move the disk to "allowed" or "blocked" set.
- **Hook at a lower level.** The current `notify` crate + `ReadDirectoryChangesW` approach has inherent latency. For fixed disk blocking, consider using a kernel minifilter driver (future phase) or at minimum, hook `CreateFileW`/`NtCreateFile` to block before the file handle is opened.

**Detection:**
- Stress test: connect USB-NVMe bridge and immediately write a file via script. Verify the write is blocked.
- Log the time delta between `DBT_DEVICEARRIVAL` and first file I/O on the disk.

**Phase to address:** Phase 34 (Runtime blocking of unregistered fixed disks).

---

### Pitfall 6: Performance Impact of Disk Enumeration at Install Time or Startup

**What goes wrong:** The install-time enumeration queries BitLocker status for all fixed disks via WMI. On systems with many disks (e.g., servers with RAID arrays, workstations with multiple NVMe drives), this can take 10+ seconds, causing installer timeout or poor UX. At agent startup, re-enumerating disks delays service readiness.

**Why it happens:**
- WMI queries are slow — each `Win32_EncryptableVolume` query can take 500ms-2s.
- Systems with 4+ physical disks + virtual disks = 8+ WMI queries.
- The installer may have a 30-second timeout for custom actions.
- Agent startup delay causes the service to be marked as "not responding" by Windows SCM.

**Consequences:**
- Installer rollback or incomplete installation.
- Windows Service Control Manager marks the agent as failed startup.
- User perception of poor performance.

**Prevention:**
- **Parallelize enumeration:** Use `rayon` or `tokio::task::spawn_blocking` to query disks concurrently. The WMI queries are independent per disk.
- **Cache aggressively:** The install-time result is written to `agent-config.toml` and the Windows Registry. The agent startup reads from this cache — no re-enumeration needed on normal startup.
- **Lazy re-verification:** Only re-verify BitLocker status when an admin requests it or when a disk change is detected (via `WM_DEVICECHANGE`).
- **Timeout individual queries:** Each WMI query should have a 3-second timeout. If a disk times out, mark it as "verification failed — manual review required" and continue.
- **Progress indication:** In the installer UI, show a progress bar with per-disk status ("Checking Disk C:...", "Checking Disk D:...").

**Detection:**
- Log total enumeration time and per-disk query time.
- UAT on a 4-disk workstation: verify install completes in < 10 seconds.

**Phase to address:** Phase 33 (Install-time enumeration).

---

### Pitfall 7: Disks Allowed at Install but Later Have Encryption Removed

**What goes wrong:** A disk is in the allowlist because it was BitLocker-encrypted at install time. Later, an admin suspends or disables BitLocker on that disk (e.g., for troubleshooting). The disk remains in the allowlist and continues to be allowed even though it is no longer encrypted.

**Why it happens:**
- The allowlist is a snapshot at install time.
- There is no periodic re-verification of encryption status.
- BitLocker suspension is a common troubleshooting step.
- An attacker with admin rights can suspend BitLocker and then exfiltrate data.

**Consequences:**
- Encryption requirement is effectively bypassed after install.
- Admin action (BitLocker suspension) creates a security gap.
- Compliance audit fails because allowed disks are not actually encrypted.

**Prevention:**
- **Periodic re-verification (configurable):** The agent should re-check BitLocker status for all allowed disks on a schedule (e.g., daily, or on every agent config poll from the server). If a disk is no longer encrypted, emit an audit event and optionally block it.
- **Admin-configurable policy:** Allow the admin to choose between:
  - `strict`: block immediately if encryption is removed.
  - `audit_only`: log an alert but continue allowing (for troubleshooting scenarios).
  - `disabled`: never re-verify (not recommended).
- **Detect BitLocker suspension events:** Listen for Windows event log entries from the `BitLocker-API` source (Event ID 768 for suspension, 769 for resumption). Trigger an immediate re-verification on these events.
- **Store encryption state in allowlist entry:** Each allowlist entry should include `encryption_verified_at`, `encryption_method`, and `encryption_status`. The admin TUI should show a warning icon for entries where the last verification is > N days old.

**Detection:**
- UAT: suspend BitLocker on an allowed disk; verify audit event is emitted.
- UAT: with `strict` policy, verify the disk is blocked after suspension.

**Phase to address:** Phase 35 (Admin override/registry) and Phase 36 (Audit events).

---

### Pitfall 8: Silent Failure Modes

**What goes wrong:** The disk blocking mechanism fails silently in one of several ways: the disk is not detected, the encryption check returns a false negative, or the block is not enforced. None of these failures produce visible errors or alerts.

**Why it happens:**
- **Disk not detected:** The `GUID_DEVINTERFACE_DISK` notification may not fire for certain disk types (e.g., some RAID controllers, iSCSI disks). The agent relies on this notification for runtime blocking.
- **Encryption check false negative:** WMI returns `ProtectionStatus = 0` (unprotected) for a disk that is actually encrypted but in a transitional state. The disk is then treated as unencrypted and blocked, but the user sees no explanation.
- **Block not enforced:** The file interception layer uses `notify` crate (`ReadDirectoryChangesW`) which only detects changes after they occur. It cannot prevent the initial write. For fixed disks, this means the first write to an unregistered disk always succeeds.

**Consequences:**
- Security control appears to work but does not.
- Exfiltration occurs without any audit trail.
- Compliance audit passes (controls are "implemented") but actual protection is missing.

**Prevention:**
- **Comprehensive logging:** Every disk arrival, every allowlist check, every block/allow decision must be logged at INFO level or higher. Include: disk instance ID, drive letter, bus type, detection method, allowlist match result, encryption check result, final decision.
- **Self-test on startup:** The agent should perform a lightweight self-test on startup: verify that the file interception layer is active, verify that the allowlist is loaded, verify that a test path (e.g., a non-existent drive) is correctly classified. Log "self-test passed" or "self-test failed."
- **Health check endpoint:** The agent's internal health check (used by `dlp-server` heartbeat) should include: allowlist count, last allowlist update time, disk blocking active flag.
- **Fail-closed for detection failures:** If a disk cannot be classified (detection failed, WMI timeout, PnP tree walk failed), default to BLOCK and emit an audit event. Do not default to ALLOW.
- **Use pre-operation blocking:** The current `notify`-based approach is post-operation. For fixed disk blocking, the interception must happen at `CreateFileW`/`NtCreateFile` time, before the write occurs. This requires either:
  - Extending the existing detour-based I/O interception (if already in place for file_monitor.rs).
  - Using a Windows minifilter driver (future phase, but the architecture should be designed to accommodate it).

**Detection:**
- Automated UAT: simulate disk arrival + immediate file write; verify write is blocked AND audit event is emitted.
- Automated UAT: simulate WMI timeout; verify disk is blocked (fail-closed) and audit event explains the timeout.
- Review logs for "disk arrival detected but no block/allow decision logged" patterns.

**Phase to address:** Phase 34 (Runtime blocking) and Phase 36 (Audit events).

---

## Moderate Pitfalls

### Pitfall 9: Allowlist Format Versioning and Migration

**What goes wrong:** The allowlist is stored in `agent-config.toml` and the Windows Registry. When the allowlist schema changes (e.g., adding `encryption_method` field), existing allowlists become invalid or are silently ignored.

**Why it happens:**
- TOML deserialization with `serde` fails if expected fields are missing.
- Registry values may be read as strings and not parsed correctly after schema changes.
- No version field in the allowlist data structure.

**Consequences:**
- Agent fails to load allowlist on upgrade.
- All fixed disks are treated as unregistered (fail-closed) — system may become unusable.
- Requires manual registry/TOML editing to fix.

**Prevention:**
- Include `allowlist_version: u32` in the allowlist structure. Bump on schema changes.
- Implement migration logic: if version < current, migrate in-place (add default values for new fields).
- Use `serde(default)` for all new fields to maintain backward compatibility.
- Store allowlist in both TOML and Registry with the same schema. TOML is the source of truth; Registry is the runtime cache.

**Phase to address:** Phase 33 (Install-time enumeration).

---

### Pitfall 10: Admin Override Creates Audit Gap

**What goes wrong:** An admin adds a disk to the allowlist via the TUI or registry edit. The disk is not encrypted, but the admin override bypasses the encryption check. There is no audit event recording that an override was used, and no expiration on the override.

**Why it happens:**
- The admin override path may skip the encryption check entirely.
- Audit events for admin actions on the allowlist may not be implemented.
- No TTL or review date on override entries.

**Consequences:**
- Unencrypted disks remain in the allowlist indefinitely.
- Compliance audit cannot trace why an unencrypted disk was allowed.
- Former admin's overrides persist after they leave the organization.

**Prevention:**
- **Always audit admin overrides:** Every allowlist add/update/delete must emit an `AuditEvent` with `EventType::AdminAction`, including the admin's identity, the disk details, and whether the encryption check was bypassed.
- **Require justification for overrides:** The admin TUI should prompt for a free-text justification when adding an unencrypted disk. Store the justification in the allowlist entry.
- **Enforce TTL on overrides:** Allowlist entries added via override should have an `expires_at` field (default: 30 days). The agent should emit a warning audit event 7 days before expiration and block the disk after expiration unless re-approved.
- **Require secondary approval for overrides:** For high-security environments, require a second admin to approve override entries (future phase).

**Phase to address:** Phase 35 (Admin override/registry).

---

### Pitfall 11: Disk Serial Number Collisions and Spoofing

**What goes wrong:** Two different disks have the same serial number (collisions), or an attacker spoofs the serial number of an allowed disk to bypass blocking.

**Why it happens:**
- Some USB bridge chips use a fixed serial number (e.g., `0123456789ABCDEF`) for all devices.
- Some manufacturers do not set unique serial numbers.
- USB device descriptors can be modified by firmware (e.g., BadUSB attacks).
- The allowlist may key only on serial number, not on a composite key.

**Consequences:**
- Collision: an unregistered disk with the same serial as an allowed disk is incorrectly allowed.
- Spoofing: an attacker clones the serial of an allowed disk and bypasses blocking.

**Prevention:**
- **Use composite key for allowlist:** `(bus_type, vendor_id, product_id, serial_number, disk_size)` or `(device_instance_id, disk_size)`. Do not rely on serial number alone.
- **Include disk size in allowlist entry:** Disk size is harder to spoof and helps disambiguate collisions.
- **Verify device instance ID:** The Windows PnP device instance ID includes the bus location and is harder to spoof than USB descriptors. Store the instance ID in the allowlist entry.
- **Detect serial number collisions:** During install-time enumeration, if two disks have the same serial number, log a WARNING and require admin manual review.

**Phase to address:** Phase 33 (Install-time enumeration).

---

## Minor Pitfalls

### Pitfall 12: Drive Letter Reassignment Breaks Allowlist

**What goes wrong:** A disk in the allowlist is assigned drive letter D: at install time. Later, the drive letter changes to E: (e.g., due to disk reconfiguration or another disk being inserted). The agent cannot find the disk in the allowlist because it is keyed by drive letter.

**Why it happens:**
- Drive letters are not stable identifiers. They can change on reboot, disk insertion, or manual reassignment.
- The allowlist may use drive letter as the primary key.

**Consequences:**
- Allowed disk is incorrectly blocked after drive letter change.
- User confusion and help desk tickets.

**Prevention:**
- **Key allowlist by physical disk identifier, not drive letter.** Use the PnP device instance ID or disk signature (via `IOCTL_DISK_GET_DRIVE_LAYOUT_EX`) as the primary key. Drive letter should be a secondary, volatile attribute.
- **Update drive letter on arrival:** When a `GUID_DEVINTERFACE_DISK` arrival fires, look up the disk by its physical ID and update the drive letter in the allowlist entry.

**Phase to address:** Phase 33 (Install-time enumeration).

---

### Pitfall 13: Agent Config Poll Overwrites Local Allowlist

**What goes wrong:** The agent polls `dlp-server` for config updates. If the server sends an empty or corrupted allowlist, the agent overwrites its local allowlist and blocks all fixed disks.

**Why it happens:**
- The agent config sync mechanism treats the server response as authoritative.
- No validation of the allowlist before applying it.
- Network issues or server bugs can cause empty responses.

**Consequences:**
- All fixed disks blocked until admin fixes.
- System may become unbootable if the boot disk entry is missing from the server response.

**Prevention:**
- **Validate server response:** Before applying a new allowlist, verify: (1) boot disk is present, (2) allowlist is not empty (unless explicitly configured to allow empty), (3) all entries have required fields.
- **Atomic update:** Write the new allowlist to a temporary TOML file, validate it, then rename it over the existing file. If validation fails, keep the old allowlist and log an error.
- **Server-side validation:** The `dlp-server` admin API should reject allowlist updates that remove the boot disk or are otherwise invalid.

**Phase to address:** Phase 35 (Admin override/registry).

---

## Phase-Specific Warnings

| Phase Topic | Likely Pitfall | Mitigation |
|-------------|---------------|------------|
| Phase 33: Install-time enumeration | Boot disk blocked | Unconditional boot disk allowlisting; fail-open for boot disk |
| Phase 33: Install-time enumeration | USB bridges missed | Use PnP tree walk + SPDRP_REMOVAL_POLICY, not GetDriveTypeW |
| Phase 33: Install-time enumeration | BitLocker check false negative | Multi-method consensus; treat suspended as encrypted; cache result |
| Phase 33: Install-time enumeration | Recovery/VHD/RAM disks blocked | Exclude by instance ID pattern, bus type, and disk size |
| Phase 33: Install-time enumeration | Installer timeout / poor UX | Parallelize queries; timeout individual queries; show progress |
| Phase 34: Runtime blocking | Race condition: write before check | Default-deny for unknown fixed disks; pre-operation blocking |
| Phase 34: Runtime blocking | USB-bridged fixed disks bypass | Reuse Phase 31-02 PnP tree walk; block USB-attached fixed disks by default |
| Phase 34: Runtime blocking | Silent failure (no detection, no block) | Comprehensive logging; self-test on startup; health check endpoint |
| Phase 35: Admin override | Unencrypted disks allowed indefinitely | Audit all overrides; require justification; enforce TTL |
| Phase 35: Admin override | Server poll overwrites local allowlist | Validate before apply; atomic update; server-side validation |
| Phase 36: Audit events | Missing disk block/discovery events | Log every arrival, every check, every decision with full context |

---

## Sources

### Primary (HIGH confidence)
- `dlp-agent/src/detection/usb.rs` — existing USB detection code, PnP tree walk, `GetDriveTypeW` usage
- `dlp-agent/src/device_controller.rs` — `CM_Disable_DevNode`, `CM_Enable_DevNode`, volume DACL manipulation
- Phase 31-02 plan and debug log (`.planning/phases/31-usb-cm-blocking/31-02-PLAN.md`, `.planning/debug/phase31-test6-rework.md`) — Realtek RTL9210 NVMe USB bridge bypass
- `dlp-agent/src/interception/file_monitor.rs` — file interception layer (notify-based)
- `.planning/PROJECT.md` — project context, existing architecture, crate structure

### Secondary (MEDIUM confidence)
- [ITM4N — BitLocker's Little Secrets: The Undocumented FVE API](https://itm4n.github.io/bitlocker-little-secrets-the-undocumented-fve-api/) — FVE API vs WMI, privilege requirements
- [Microsoft Defender Device Control Overview](https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-endpoint/device-control-overview.md) — Microsoft's approach to removable storage, BitLocker integration, DRIVE_FIXED handling
- [Microsoft VB WinAPI Discussion — Alternative to GetDriveType](https://microsoft.public.vb.winapi.narkive.com/PCVEx2sx/alternative-to-getdrivetype-for-large-usb-drives) — USB HDDs report DRIVE_FIXED
- [Zabbix ZBX-17974](https://support.zabbix.com/browse/ZBX-17974) — WMI timeout limitations
- [PDQ — WMI operation timed out](https://help.pdq.com/hc/en-us/articles/220532387-WMI-operation-timed-out) — WMI timeout troubleshooting

### Tertiary (LOW confidence — WebSearch only, single source)
- [Cyberhaven — DLP False Positives](https://www.cyberhaven.com/blog/5-reasons-you-cant-afford-to-ignore-false-positives) — general DLP false positive statistics
- [ManageEngine — Endpoint DLP False Positives](https://www.manageengine.com/endpoint-dlp/how-to/raise-false-positives.html) — false positive handling patterns
- [Forcepoint DLP + Malwarebytes compatibility issue](https://forums.malwarebytes.com/topic/190604-mbae-forcepoint-dlp-endpoint-agent-causing-false-positives/) — DLP endpoint agent conflict precedent