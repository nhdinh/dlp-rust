# Phase 33: Disk Enumeration - Context

**Gathered:** 2026-04-30
**Status:** Ready for planning

<domain>
## Phase Boundary

Agent discovers and accurately classifies all fixed disks (`DRIVE_FIXED`) with device identity (instance ID, bus type, model, drive letter) and emits audit events. This phase establishes the raw data that Phase 34 (BitLocker verification), Phase 35 (allowlist persistence), and Phase 36 (enforcement) will consume.

**In scope:**
- Enumerate all fixed disks at first agent startup
- Capture device instance ID, bus type, model, drive letter for each disk
- Distinguish USB-bridged SATA/NVMe enclosures from genuine internal disks
- Emit disk discovery audit events with full identity

**Out of scope:**
- BitLocker/encryption verification (Phase 34)
- Allowlist persistence to TOML (Phase 35)
- Runtime blocking of unregistered disks (Phase 36)
- Admin TUI/API for disk management (Phases 37-38)
- Non-Windows platforms (Windows-only per PROJECT.md)

</domain>

<decisions>
## Implementation Decisions

### Enumeration Trigger
- **D-01:** Enumeration fires at **first agent startup**, not install-time. If an allowlist already exists from a prior run, the agent preserves it and appends newly discovered disks.
- **D-02:** New disks added post-startup are detected via the existing `WM_DEVICECHANGE` listener infrastructure on `GUID_DEVINTERFACE_DISK` (same notification window used for USB in Phase 23/31). No separate polling mechanism.
- **D-03:** Enumeration runs **asynchronously in a background task** spawned during service startup. A fast synchronous path (`GetDriveTypeW` scan) confirms the agent can enumerate, then the deep identity query (WMI/SetupDi/IOCTL) runs async.
- **D-04:** On enumeration failure: **retry 3 times with exponential backoff** (200ms -> 4s), then **fail closed** — no unregistered fixed-disk I/O is allowed until enumeration succeeds. A high-severity audit event is emitted on failure.
- **D-05:** Enumerate **all fixed disks** via WMI `Win32_DiskDrive` / SetupDi regardless of drive letter. However, only disks with drive letters go into the enforcement allowlist. Unpartitioned/unmounted disks are captured for audit visibility but cannot be enforced (no I/O path to intercept).
- **D-06:** Disk discovery emits **one aggregated audit event** containing all discovered disks. This follows the existing audit pattern (fewer SIEM events) and uses a new `EventType::DiskDiscovery` variant.
- **D-07:** On agent restart, **preserve existing allowlist, append new disks**. This ensures admin manual edits (Phase 37) are not overwritten.

### Module Location
- **D-08:** Disk enumeration logic lives in a new `dlp-common/src/disk.rs` module, following the Phase 32 pattern (`dlp-common/src/usb.rs`). This makes it reusable by `dlp-agent` (enumeration), `dlp-admin-cli` (Phase 38 scan screen), and any future server-side validation.

### Disk Identity Data Model
- **D-09:** New `DiskIdentity` struct in `dlp-common/src/disk.rs` — separate from the USB-focused `DeviceIdentity`. These are fundamentally different identity domains (USB uses VID/PID/serial; disk uses instance_id/bus_type/model).
- **D-10:** `DiskIdentity` fields:
  ```rust
  pub struct DiskIdentity {
      pub instance_id: String,        // Canonical key (e.g., "PCIIDE\IDECHANNEL\4&1234")
      pub bus_type: BusType,          // SATA, NVMe, USB, SCSI, Unknown
      pub model: String,              // Drive model string (e.g., "WDC WD10EZEX-00BN5A0")
      pub drive_letter: Option<char>, // Volatile — may be absent or change
      pub serial: Option<String>,     // Drive serial number (may not be available)
      pub size_bytes: Option<u64>,    // Drive capacity
      pub is_boot_disk: bool,         // True for the system boot volume
  }
  ```
- **D-11:** `BusType` enum maps Windows `STORAGE_BUS_TYPE` values relevant to this project:
  ```rust
  pub enum BusType {
      Sata,
      Nvme,
      Usb,      // USB-bridged enclosure
      Scsi,
      Unknown,
  }
  ```
  Derives `Serialize`/`Deserialize` with snake_case for TOML/JSON compatibility.

### USB-Bridged Detection Strategy
- **D-12:** `IOCTL_STORAGE_QUERY_PROPERTY` is the **primary** detection method. Query `StorageDeviceProperty` to get the `STORAGE_DEVICE_DESCRIPTOR`, read the `BusType` field directly. This is efficient and unambiguous for most cases.
- **D-13:** `PnP tree walk` (`CM_Get_Parent` to find `USB\` ancestor) is the **fallback** when:
  - `IOCTL_STORAGE_QUERY_PROPERTY` fails (e.g., no handle available)
  - The bus type is ambiguous (some exotic bridge chips report `BusTypeScsi` instead of `BusTypeUsb`)
  - Cross-validation is needed for high-assurance classification
- **D-14:** A disk is classified as **USB-bridged** if either method indicates USB ancestry. Both methods are attempted; `BusType::Usb` is assigned if either succeeds.

### Boot Disk Handling
- **D-15:** The **boot disk is enumerated** and included in the audit event, but it is **auto-allowlisted** with `is_boot_disk: true`. Phase 36 enforcement will skip blocking any disk marked `is_boot_disk`.
- **D-16:** Boot disk detection uses `GetSystemDirectoryW` to resolve the Windows system path, extracts the drive letter, and cross-references with enumerated disks.

### Claude's Discretion
- Exact retry intervals for enumeration failure (recommended: 200ms, 1s, 4s)
- Whether `BusType` enum includes `SataExpress`, `Sd`, `Mmc` variants (recommended: no, map to `Unknown`)
- Exact WMI query string for `Win32_DiskDrive` (recommended: `SELECT DeviceID, Model, Size, InterfaceType, SerialNumber FROM Win32_DiskDrive WHERE MediaType = 'Fixed hard disk media'`)
- Whether to include `STORAGE_PROPERTY_ID::StorageAdapterProperty` query in addition to `StorageDeviceProperty` (recommended: no, device property is sufficient)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements and Roadmap
- `.planning/ROADMAP.md` — Phase 33 goal, success criteria
- `.planning/REQUIREMENTS.md` — DISK-01, DISK-02, AUDIT-01 requirement definitions
- `.planning/PROJECT.md` — Architecture, tech stack, key design decisions

### Prior Phase Context (patterns and proven approaches)
- `.planning/phases/31-usb-cm-blocking/31-CONTEXT.md` — PnP tree walk (`CM_Get_Parent` → `USB\` ancestor) proven for USB-bridged detection; `Path::exists` for drive letter detection
- `.planning/phases/32-usb-scan-register-cli/32-CONTEXT.md` — `dlp-common/src/usb.rs` pattern for shared Win32 enumeration modules
- `.planning/phases/30-automated-uat-infrastructure/30-CONTEXT.md` — Test patterns, mock Win32 API approach

### Key Source Files (read before touching)
- `dlp-agent/src/detection/usb.rs` — `UsbDetector`, `usb_wndproc`, `WM_DEVICECHANGE` infrastructure, `GUID_DEVINTERFACE_DISK` handling, PnP tree walk (`on_disk_device_arrival`)
- `dlp-agent/src/detection/mod.rs` — Detection module exports
- `dlp-agent/src/service.rs` — Service startup, background task spawning, global static setup (`set_registry_cache`, etc.)
- `dlp-agent/src/device_controller.rs` — `DeviceController`, CM_* API usage pattern
- `dlp-common/src/endpoint.rs` — `DeviceIdentity`, `UsbTrustTier` (existing USB identity types — do NOT conflate with disk identity)
- `dlp-common/src/audit.rs` — `AuditEvent`, `EventType` (add `DiskDiscovery` variant here)
- `dlp-common/src/usb.rs` — Phase 32 shared USB enumeration module (template for new `disk.rs`)
- `dlp-common/src/lib.rs` — Module exports (add `pub mod disk`)
- `dlp-agent/src/config.rs` — `AgentConfig`, TOML load/save pattern (Phase 35 will extend this)
- `dlp-agent/src/audit_emitter.rs` — Audit event emission pattern

### Windows API References
- `IOCTL_STORAGE_QUERY_PROPERTY` — `windows` crate feature `Win32_System_Ioctl` (verify in `windows` 0.62)
- `STORAGE_DEVICE_DESCRIPTOR` — contains `BusType` field
- `STORAGE_BUS_TYPE` — Windows enum values: BusTypeSata = 8, BusTypeNvme = 17, BusTypeUsb = 7, BusTypeScsi = 1
- `CM_Get_Parent`, `CM_Get_Device_IDW` — cfgmgr32 API (already linked via `dlp-agent`)
- `Win32_DiskDrive` WMI class — for physical disk enumeration
- `GetSystemDirectoryW` — for boot disk detection

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `dlp-common/src/usb.rs` — Proven pattern for shared Win32 enumeration: `#[cfg(windows)]` guarded functions, stub returning `vec![]` on non-Windows. Copy this pattern for `disk.rs`.
- `UsbDetector` (`dlp-agent/src/detection/usb.rs`) — Has `GUID_DEVINTERFACE_DISK` notification handling, PnP tree walk (`on_disk_device_arrival`), `disk_path_to_instance_id`. The disk enumeration logic can reuse much of this.
- `DeviceController` (`dlp-agent/src/device_controller.rs`) — Demonstrates CM_* API usage, error type pattern with `thiserror`.
- `AuditEvent` (`dlp-common/src/audit.rs`) — Add `DiskDiscovery` to `EventType` enum; add `disk_identity: Option<DiskIdentity>` field or use a new `discovered_disks: Vec<DiskIdentity>` field.
- `AgentConfig` (`dlp-agent/src/config.rs`) — TOML serialization pattern; Phase 35 will add `[disk_allowlist]` section.

### Established Patterns
- `#[cfg(windows)]` modules in `dlp-common` with non-Windows stubs returning empty collections (Phase 32 pattern)
- `parking_lot::RwLock` for shared in-memory state (drive letter → identity maps)
- `tracing::{info, warn, debug}` for structured logging with field values
- Hidden window + `std::thread` for `WM_DEVICECHANGE` (thread-affine Windows message delivery)
- `std::sync::OnceLock` for global static references set during service startup
- WMI queries via `wmi-rs` crate (check if already in Cargo.toml)

### Integration Points
- `dlp-agent/src/service.rs::run_loop()` — spawn background task for disk enumeration after setting global statics
- `dlp-agent/src/detection/mod.rs` — add `pub mod disk; pub use disk::DiskEnumerator;`
- `dlp-common/src/lib.rs` — add `pub mod disk; pub use disk::{DiskIdentity, BusType, enumerate_fixed_disks};`
- `dlp-common/src/audit.rs` — add `EventType::DiskDiscovery` and `discovered_disks: Option<Vec<DiskIdentity>>` to `AuditEvent`
- `dlp-agent/src/audit_emitter.rs` — emit aggregated disk discovery event after enumeration completes
- `dlp-agent/src/interception/mod.rs::run_event_loop()` — Phase 36 will add pre-ABAC fixed-disk check here

### Windows Crate Feature Flags
- `Win32_System_Ioctl` — needed for `IOCTL_STORAGE_QUERY_PROPERTY` (verify available in `windows` 0.62; STATE.md notes this as a potential blocker)
- `Win32_Devices_DeviceAndDriverInstallation` — already enabled (CM_* APIs)
- `Win32_Storage_FileSystem` — already enabled (`GetDriveTypeW`)
- `Win32_System_SystemInformation` — for `GetSystemDirectoryW`

</code_context>

<specifics>
## Specific Requirements

### Disk Enumeration API
```rust
/// Enumerate all fixed disks on the system.
///
/// Returns a Vec of DiskIdentity for every physical fixed disk found,
/// regardless of whether it has a drive letter.
#[cfg(windows)]
pub fn enumerate_fixed_disks() -> Result<Vec<DiskIdentity>, DiskError>;

/// Determine if a disk is USB-bridged using IOCTL + PnP walk.
#[cfg(windows)]
pub fn is_usb_bridged(instance_id: &str) -> Result<bool, DiskError>;

/// Identify the system boot disk from enumerated list.
pub fn identify_boot_disk(disks: &[DiskIdentity]) -> Option<&DiskIdentity>;
```

### DiskIdentity serde example
```toml
[[disk_allowlist]]  # Phase 35 will add this section
instance_id = "PCIIDE\IDECHANNEL\4&1234&0&0"
bus_type = "sata"
model = "WDC WD10EZEX-00BN5A0"
drive_letter = "C"
serial = "WD-12345678"
size_bytes = 1000204886016
is_boot_disk = true
```

### Audit event shape (DiskDiscovery)
```json
{
  "timestamp": "2026-04-30T12:00:00Z",
  "event_type": "DISK_DISCOVERY",
  "agent_id": "WORKSTATION01",
  "discovered_disks": [
    {
      "instance_id": "PCIIDE\\IDECHANNEL\\4&1234",
      "bus_type": "sata",
      "model": "WDC WD10EZEX-00BN5A0",
      "drive_letter": "C",
      "is_boot_disk": true
    }
  ]
}
```

</specifics>

<deferred>
## Deferred Ideas

- **Per-disk trust tier** (`blocked`, `read_only`, `full_access`) — deferred to v0.7.1+ (DISK-F4). Phase 36 will implement binary allow/block, not tiered.
- **Mount-time blocking (volume lock)** — deferred to v0.7.1+ (DISK-F1). Phase 36 uses I/O-time blocking only.
- **Grace period / quarantine mode** — deferred to v0.7.1+ (DISK-F2).
- **User self-allowlist request flow** — deferred to v0.7.1+ (DISK-F3).
- **SED/Opal self-encrypting drive detection** — deferred to v0.7.1+ (CRYPT-F1).
- **Third-party FDE detection (VeraCrypt, McAfee)** — deferred to v0.7.1+ (CRYPT-F2).

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 33-disk-enumeration*
*Context gathered: 2026-04-30*
