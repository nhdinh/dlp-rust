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
