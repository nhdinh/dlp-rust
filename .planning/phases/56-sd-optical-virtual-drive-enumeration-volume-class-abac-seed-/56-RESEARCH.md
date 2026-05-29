# Phase 56: SD/Optical/Virtual Drive Enumeration + Volume-Class ABAC (SEED-004) - Research

**Researched:** 2026-05-29
**Domain:** Windows volume classification (GetDriveTypeW + WMI), ABAC attribute extension, hook DLL path analysis, ratatui TUI conditions builder
**Confidence:** HIGH

## Summary

Phase 56 extends the existing device-watcher and ABAC engine to classify all Windows volumes into six `VolumeClass` variants (`LocalNTFS`, `USBRemovable`, `SDCard`, `Optical`, `Virtual`, `NetworkShare`). The classification uses a hybrid approach: `GetDriveTypeW` for coarse bucketing, then WMI `Win32_DiskDrive` queries for disambiguation of removable drives (USB vs SD) and fixed drives (local vs virtual). Two new ABAC attributes (`source_volume_class`, `destination_volume_class`) enable policy expressions like "DENY copy from LocalNTFS T4 to Optical". The admin TUI Conditions Builder gains two new dropdown attributes, and the existing allowlist screens render volume-class badges.

The existing `GUID_DEVINTERFACE_VOLUME` registration already fires for ALL volume arrivals -- physical USB, SD, optical, virtual (VHD, ISO), and network. No new `RegisterDeviceNotificationW` GUID registrations are needed. The 500 ms deferred processing pattern from Phase 38.2 is preserved.

**Primary recommendation:** Implement `VolumeClass` as a new enum in `dlp-common`, extend `AbacContext` with `Option<VolumeClass>` fields, add two `PolicyCondition` variants with `eq`/`ne`/`in` operators, wire volume-class resolution into the hook DLL's `classify_and_log_path` via a thread-local cache (keyed by drive letter, TTL 30s), extend `usb.rs` to emit `VolumeArrival` audit events with WMI disambiguation, and extend the admin TUI conditions builder with two new dropdown attributes.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Volume class detection | API / Backend (dlp-agent) | OS (Windows WMI) | Agent queries WMI on `WM_DEVICECHANGE`; OS provides the data |
| ABAC attribute evaluation | API / Backend (dlp-server) | — | `PolicyStore::evaluate` owns condition matching |
| Hook DLL volume-class resolution | Browser / Client (hook DLL) | — | Resolved at trampoline time from path; hot path requires thread-local cache |
| Volume arrival audit events | API / Backend (dlp-agent) | — | `device_watcher` → `usb.rs` emits via `EmitContext` |
| Admin TUI conditions builder | Browser / Client (dlp-admin-cli) | — | ratatui 3-step picker pattern |
| Admin TUI allowlist badges | Browser / Client (dlp-admin-cli) | — | Rendered as colored badges in existing list |

## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01:** Extend existing `GetDriveTypeW` + WMI hybrid approach. `GetDriveTypeW` provides coarse bucket. For `DRIVE_REMOVABLE`, query `Win32_DiskDrive` via `wmi` crate to disambiguate `USBRemovable` (BusType=USB) from `SDCard` (BusType=SD or MediaType contains "Removable media" + absence of USB). For `DRIVE_FIXED`, distinguish `LocalNTFS` from `Virtual` via `Win32_DiskDrive.Model` containing "Msft Virtual Disk" or `InterfaceType` = "File-backed Virtual".
- **D-02:** Single `Virtual` class for all virtual drives (Daemon Tools, VHD, VHDX, Explorer-mounted ISO). No sub-classification.
- **D-03:** Optical drives (`DRIVE_CDROM` from `GetDriveTypeW`) map directly to `Optical`. No WMI disambiguation needed.
- **D-04:** Network shares (`DRIVE_REMOTE` from `GetDriveTypeW` or UNC path prefix `\\`) map to `NetworkShare`. Path-based detection without WMI query.
- **D-05:** SD card detection: `Win32_DiskDrive` where `MediaType` = "Removable media" AND (`BusType` = "SD" OR `InterfaceType` = "SD"). Fallback: if `GetDriveTypeW` returns `DRIVE_REMOVABLE` and the disk model contains "SD" or "MMC", classify as `SDCard`.
- **D-06:** `source_volume_class` and `destination_volume_class` are fields on `AbacContext` (not `Resource`). They are `Option<VolumeClass>` -- `None` when the operation has no filesystem source/destination.
- **D-07:** Add two new `PolicyCondition` variants: `SourceVolumeClass { op: String, value: VolumeClass }` and `DestinationVolumeClass { op: String, value: VolumeClass }`. Supported operators: `eq`, `ne`, `in`.
- **D-08:** Hook DLL resolves volume class at trampoline time: extract drive letter from path (or detect UNC prefix) → look up `VolumeClass` in a thread-local cache (keyed by drive letter, TTL 30s) → populate `AbacContext.source_volume_class` / `destination_volume_class`.
- **D-09:** Server-side ABAC evaluation also resolves volume class when `resource_path` is present, using the same drive-letter → class logic.
- **D-10:** Extend `ConditionAttribute` enum with `SourceVolumeClass` and `DestinationVolumeClass`, appended after `DestinationOrigin` in the `ATTRIBUTES` array. Labels: "Source Volume Class", "Destination Volume Class". Step 2 operators: `eq`, `ne`, `in`. Step 3 value picker: dropdown of six enum values.
- **D-11:** Extend existing USB/disk allowlist screens with a `volume_class: VolumeClass` column/badge.
- **D-12:** Conditions Builder dropdown for volume class values uses the same ratatui `List` picker pattern as `Classification` (T1-T4) and `DeviceTrust`.
- **D-13:** No new `RegisterDeviceNotificationW` GUID registrations needed. The existing `GUID_DEVINTERFACE_VOLUME` handler already fires for ALL volume arrivals.
- **D-14:** Preserve the 500 ms deferred processing pattern for all volume arrivals.
- **D-15:** Virtual drive arrival emits `VolumeArrival` with `volume_class = Virtual`. Virtual drive removal emits no audit event. Optical drive tray open/close may trigger spurious arrival/removal; the 500ms defer + duplicate suppression handles this.
- **D-16:** New `EventType::VolumeArrival` with a `volume_class: VolumeClass` field. Emitted once per distinct device arrival.
- **D-17:** The existing `DiskDiscovery` event remains unchanged -- it covers fixed disks only. `VolumeArrival` is the new general-purpose event for all volume classes.

### Claude's Discretion
- The `VolumeClass` enum should derive `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq`, `Serialize`, `Deserialize`, `Display`, `Default` (with `LocalNTFS` as default).
- Volume class cache in the hook DLL should be a thread-local `RefCell<HashMap<char, (VolumeClass, Instant)>>` with 30-second TTL, not a global cache.
- WMI queries for volume classification should be batched where possible (e.g., enumerate all `Win32_LogicalDisk` → `Win32_DiskDrive` associations once at agent startup, then refresh on `WM_DEVICECHANGE`).
- The integration test for DRIVE-02 should use an actual optical drive if available on the test endpoint, or mock the WMI response if not.

### Deferred Ideas (OUT OF SCOPE)
- Virtual drive sub-classification (Daemon Tools vs VHD vs ISO vs RAM disk)
- Volume-class-specific grace periods
- Volume-class-based mount-time blocking
- Network share server-specific classification
- Volume class in the shared-memory classification cache (Phase 50)

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| DRIVE-01 | Volume class detection via `GetDriveTypeW` + WMI (`Win32_DiskDrive`/`Win32_LogicalDisk`) for six-value enum | Microsoft docs confirm `GetDriveTypeW` return values [CITED: learn.microsoft.com]; WMI `Win32_DiskDrive` properties verified [CITED: learn.microsoft.com]; existing `wmi` 0.18 crate usage pattern in `encryption.rs` [VERIFIED: codebase] |
| DRIVE-02 | `source_volume_class` + `destination_volume_class` ABAC attributes added to ABAC engine (9 → 11 attrs); ABAC evaluator handles new variants; admin TUI Conditions Builder dropdown | Existing `PolicyCondition` enum pattern with 9 variants [VERIFIED: codebase]; `condition_matches` match arm pattern [VERIFIED: codebase]; TUI 3-step builder pattern [VERIFIED: codebase] |
| DRIVE-03 | Hook DLL volume-class resolution at trampoline time with thread-local cache | Existing `classify_and_log_path` in `trampolines.rs` [VERIFIED: codebase]; thread-local LRU pattern in `classification_cache.rs` [VERIFIED: codebase] |
| DRIVE-04 | `WM_DEVICECHANGE` handlers cover virtual mounts; `VolumeArrival` audit event emitted; 500ms defer preserved | Existing `GUID_DEVINTERFACE_VOLUME` registration fires for all volumes [CITED: learn.microsoft.com]; existing 500ms defer pattern in `device_watcher.rs` [VERIFIED: codebase] |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `wmi` | 0.18.4 | WMI queries for `Win32_DiskDrive` disambiguation | Already used in `dlp-agent/src/detection/encryption.rs` for `Win32_EncryptableVolume` [VERIFIED: codebase]; `WMIConnection::with_namespace_path` + `set_proxy_blanket` pattern established |
| `windows` | 0.62.2 | `GetDriveTypeW`, `WM_DEVICECHANGE`, `RegisterDeviceNotificationW` | Already used throughout `dlp-agent` and `dlp-hook-dll` [VERIFIED: codebase] |
| `serde` | 1.0.228 | `VolumeClass` serialization, `PolicyCondition` wire format | Workspace standard; `#[serde(tag = "attribute", rename_all = "snake_case")]` pattern already used [VERIFIED: codebase] |
| `ratatui` | 0.30.0 | Admin TUI Conditions Builder dropdowns | Already used in `dlp-admin-cli` [VERIFIED: codebase] |
| `parking_lot` | workspace | `RwLock` for `UsbDetector` extensions | Already used for `blocked_drives` and `device_identities` [VERIFIED: codebase] |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `chrono` | 0.4 | Audit event timestamps | Already in `AuditEvent` [VERIFIED: codebase] |
| `tracing` | workspace | Structured logging for volume events | Already used in `usb.rs` [VERIFIED: codebase] |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `wmi` crate | Raw COM FFI | `wmi` 0.18 is already a dependency; raw FFI adds complexity with no benefit |
| `GetDriveTypeW` alone | `IOCTL_STORAGE_QUERY_PROPERTY` | `GetDriveTypeW` is simpler and sufficient for coarse bucketing; IOCTL is overkill |
| Thread-local cache | Global `RwLock` cache | Thread-local avoids synchronization overhead in hook DLL hot path per D-08 discretion |

**Version verification:**
```bash
# Verified during research:
# wmi = "0.18.4" (crates.io)
# windows = "0.62.2" (crates.io)
# serde = "1.0.228" (crates.io)
# ratatui = "0.30.0" (crates.io)
```

## Package Legitimacy Audit

> **Required** whenever this phase installs external packages. This phase uses EXISTING dependencies only -- no new packages are added.

| Package | Registry | Age | Downloads | Source Repo | slopcheck | Disposition |
|---------|----------|-----|-----------|-------------|-----------|-------------|
| `wmi` | crates.io | 5+ yrs | ~500K | github.com/ohadravid/wmi-rs | N/A (existing) | Already approved -- used in Phase 34 |
| `windows` | crates.io | 3+ yrs | 50M+ | github.com/microsoft/windows-rs | N/A (existing) | Already approved -- Microsoft official |

**Packages removed due to slopcheck [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

*No new packages are installed in this phase. All dependencies are already in the workspace.*

## Architecture Patterns

### System Architecture Diagram

```
Windows Volume Arrival
       |
       v
+-----------------------------------+
|  WM_DEVICECHANGE (wndproc)        |
|  GUID_DEVINTERFACE_VOLUME         |
+-----------------------------------+
       |
       v
+-----------------------------------+
|  device_watcher::dispatch         |
|  (500ms defer via tokio::spawn)   |
+-----------------------------------+
       |
       v
+-----------------------------------+
|  usb.rs::handle_volume_event      |
|  + GetDriveTypeW(coarse bucket)   |
|  + WMI::Win32_DiskDrive(fine)     |
|  → VolumeClass enum               |
+-----------------------------------+
       |
       +-----> VolumeArrival audit event (EmitContext)
       |
       v
+-----------------------------------+
|  UsbDetector::volume_class_map    |
|  (RwLock<HashMap<char, VolumeClass>>)
+-----------------------------------+
       ^
       | (read by)
+-----------------------------------+
|  Hook DLL classify_and_log_path   |
|  + extract_drive_letter(path)     |
|  + thread_local cache (30s TTL)   |
|  → AbacContext.source_volume_class|
+-----------------------------------+
       |
       v
+-----------------------------------+
|  Agent pipe round-trip            |
|  HookRequest → dlp-server         |
+-----------------------------------+
       |
       v
+-----------------------------------+
|  PolicyStore::evaluate            |
|  + condition_matches (new arms)   |
|  + resolve_volume_class_from_path |
|    when resource_path present     |
|  → Decision                       |
+-----------------------------------+
```

### Recommended Project Structure

```
dlp-common/src/
├── abac.rs              # + VolumeClass enum, + AbacContext fields, + PolicyCondition variants, + resolve_volume_class_from_path
dlp-common/src/audit.rs             # + EventType::VolumeArrival
└── lib.rs               # + pub use volume_class::VolumeClass (or inline in abac.rs)

dlp-agent/src/detection/
├── usb.rs               # + volume classification logic, + VolumeArrival emission
├── device_watcher.rs    # NO CHANGES (existing handler dispatches to usb.rs)
└── mod.rs               # + pub use volume_class::VolumeClassCache (if new module)

dlp-hook-dll/src/
├── trampolines.rs       # + volume class resolution before classify_path
└── volume_class_cache.rs # NEW: thread-local cache module

dlp-server/src/
└── policy_store.rs      # + condition_matches arms for SourceVolumeClass/DestinationVolumeClass
                         # + server-side resolve_volume_class_from_path when resource_path present

dlp-admin-cli/src/
├── app.rs               # + ConditionAttribute variants, + ATTRIBUTES array
├── screens/dispatch.rs  # + operators_for arms, + value_count_for, + build_condition, + condition_to_prefill
└── screens/render.rs    # + VOLUME_CLASS_VALUES const, + picker_items arm, + step_flags
```

### Pattern 1: VolumeClass Enum
**What:** A six-value enum representing the volume class of a Windows drive.
**When to use:** Any time a drive letter needs classification for ABAC or audit purposes.
**Example:**
```rust
// Source: 56-CONTEXT.md D-01..D-05
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum VolumeClass {
    #[default]
    LocalNTFS,
    USBRemovable,
    SDCard,
    Optical,
    Virtual,
    NetworkShare,
}

impl std::fmt::Display for VolumeClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Self::LocalNTFS => "LocalNTFS",
            Self::USBRemovable => "USBRemovable",
            Self::SDCard => "SDCard",
            Self::Optical => "Optical",
            Self::Virtual => "Virtual",
            Self::NetworkShare => "NetworkShare",
        })
    }
}
```

### Pattern 2: resolve_volume_class_from_path Helper
**What:** A reusable helper that extracts drive letter or detects UNC prefix from a Windows path and returns the corresponding VolumeClass via a caller-provided lookup closure.
**When to use:** Hook DLL trampoline time (D-08) and server-side evaluation (D-09) when resource_path is present but volume class fields are not populated.
**Example:**
```rust
// Source: 56-CONTEXT.md D-08, D-09
pub fn resolve_volume_class_from_path<F>(path: &str, lookup: F) -> Option<VolumeClass>
where
    F: FnOnce(char) -> Option<VolumeClass>,
{
    if path.starts_with("\\\\") {
        return Some(VolumeClass::NetworkShare);
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        let letter = bytes[0].to_ascii_uppercase() as char;
        return lookup(letter);
    }
    if path.starts_with("\\\\?\\Volume{") {
        return Some(VolumeClass::LocalNTFS);
    }
    None
}
```

### Pattern 3: WMI Query for Volume Disambiguation
**What:** Query `Win32_DiskDrive` via the `wmi` crate to disambiguate `DRIVE_REMOVABLE` and `DRIVE_FIXED` drives.
**When to use:** When `GetDriveTypeW` returns `DRIVE_REMOVABLE` (USB vs SD) or `DRIVE_FIXED` (local vs virtual).
**Example:**
```rust
// Source: encryption.rs pattern (existing codebase) + Microsoft docs
#[cfg(windows)]
#[derive(serde::Deserialize, Debug, Clone)]
#[serde(rename = "Win32_DiskDrive")]
#[serde(rename_all = "PascalCase")]
struct WmiDiskDrive {
    #[serde(rename = "DeviceID")]
    device_id: String,
    interface_type: Option<String>,
    media_type: Option<String>,
    model: Option<String>,
}

#[cfg(windows)]
fn query_disk_drive_for_letter(letter: char) -> Result<Option<WmiDiskDrive>, String> {
    let conn = wmi::WMIConnection::with_namespace_path(r"ROOT\CIMV2")
        .map_err(|e| e.to_string())?;
    let drives: Vec<WmiDiskDrive> = conn.query().map_err(|e| e.to_string())?;
    // Map drive letter to physical disk via Win32_LogicalDiskToPartition → Win32_DiskDrive
    // ... mapping logic ...
    Ok(drives.into_iter().next())
}
```

### Pattern 4: Thread-Local Cache in Hook DLL
**What:** A thread-local `RefCell<HashMap>` with TTL for volume class lookups in the hot path.
**When to use:** Hook DLL trampoline time -- avoid cross-thread synchronization overhead.
**Example:**
```rust
// Source: classification_cache.rs pattern (existing codebase) + 56-CONTEXT.md D-08
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use dlp_common::VolumeClass;

const VOLUME_CLASS_TTL: Duration = Duration::from_secs(30);

thread_local! {
    static VOLUME_CLASS_CACHE: RefCell<HashMap<char, (VolumeClass, Instant)>> =
        RefCell::new(HashMap::new());
}

fn resolve_volume_class(letter: char) -> VolumeClass {
    VOLUME_CLASS_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some((class, inserted)) = cache.get(&letter) {
            if inserted.elapsed() < VOLUME_CLASS_TTL {
                return *class;
            }
        }
        let class = classify_drive_letter(letter);
        cache.insert(letter, (class, Instant::now()));
        class
    })
}
```

### Pattern 5: ABAC Condition Match Arms
**What:** Add two new match arms to `condition_matches` in `PolicyStore`.
**When to use:** Server-side ABAC evaluation of volume-class conditions.
**Example:**
```rust
// Source: policy_store.rs pattern (existing codebase)
fn condition_matches(
    condition: &PolicyCondition,
    ctx: &AbacContext,
    resource: &Resource,
) -> bool {
    match condition {
        // ... existing 9 arms ...
        PolicyCondition::SourceVolumeClass { op, value } => {
            volume_class_matches(op, value, ctx.source_volume_class)
        }
        PolicyCondition::DestinationVolumeClass { op, value } => {
            volume_class_matches(op, value, ctx.destination_volume_class)
        }
    }
}

fn volume_class_matches(op: &str, expected: &VolumeClass, actual: Option<VolumeClass>) -> bool {
    let Some(actual) = actual else {
        return false; // fails closed: no volume class means condition cannot be confirmed
    };
    match op {
        "eq" => actual == *expected,
        "ne" => actual != *expected,
        "in" => actual == *expected, // "in" with single value = eq; list variant not needed
        _ => false,
    }
}
```

### Pattern 6: Server-Side Path Resolution (D-09)
**What:** When the server receives an EvaluateRequest with resource_path but without pre-populated volume class fields, resolve them on-demand using the same path logic as the hook DLL.
**When to use:** Admin API checks, server-side policy simulation, or any non-hook evaluation path.
**Example:**
```rust
// Source: 56-CONTEXT.md D-09
// In PolicyStore::evaluate(), before policy iteration:
if ctx.source_volume_class.is_none() {
    if let Some(ref path) = ctx.resource_path {
        ctx.source_volume_class = resolve_volume_class_from_path(path, |letter| {
            // Server-side lookup: query agent volume_class_map or cached state
            None // fallback if no server-side cache available
        });
    }
}
```

### Pattern 7: Admin TUI Conditions Builder Extension
**What:** Add two new `ConditionAttribute` variants and extend all dispatch/render functions.
**When to use:** Admin TUI needs to build volume-class policy conditions.
**Example:**
```rust
// Source: app.rs + dispatch.rs + render.rs patterns (existing codebase)
// app.rs:
pub enum ConditionAttribute {
    // ... existing 9 variants ...
    SourceVolumeClass,
    DestinationVolumeClass,
}

pub const ATTRIBUTES: [ConditionAttribute; 11] = [
    // ... existing 9 ...
    ConditionAttribute::SourceVolumeClass,
    ConditionAttribute::DestinationVolumeClass,
];

// dispatch.rs operators_for:
ConditionAttribute::SourceVolumeClass | ConditionAttribute::DestinationVolumeClass => {
    &[("eq", true), ("ne", true), ("in", true)]
}

// dispatch.rs value_count_for:
ConditionAttribute::SourceVolumeClass | ConditionAttribute::DestinationVolumeClass => 6,

// render.rs VOLUME_CLASS_VALUES:
const VOLUME_CLASS_VALUES: [&str; 6] = [
    "LocalNTFS", "USBRemovable", "SDCard", "Optical", "Virtual", "NetworkShare",
];
```

### Anti-Patterns to Avoid
- **Using `GetDriveTypeW` alone:** `DRIVE_REMOVABLE` (2) covers both USB and SD cards; `DRIVE_FIXED` (3) covers both local disks and virtual drives. WMI disambiguation is required per D-01.
- **Global mutex for hook DLL cache:** The hook DLL hot path must not acquire cross-thread locks. Use thread-local `RefCell` per D-08 discretion.
- **Querying WMI on every hook call:** WMI queries are slow (~10-100ms). Cache results with TTL in the hook DLL.
- **Adding `VolumeClass` to `Resource`:** It describes the runtime I/O environment, not the resource itself. Belongs on `AbacContext` per D-06.
- **Sub-classifying Virtual drives:** D-02 explicitly says single `Virtual` class. Do not add DaemonTools/VHD/ISO variants.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| WMI COM initialization | Raw `CoInitializeEx` FFI | `wmi` 0.18 crate (auto-initializes via `CoIncrementMTAUsage`) | Already used in `encryption.rs`; handles COM lifecycle correctly |
| WMI query deserialization | Manual property bag parsing | `wmi` crate `#[derive(Deserialize)]` with `#[serde(rename_all = "PascalCase")]` | Type-safe, handles WMI's PascalCase naming automatically |
| Thread-local cache | Custom concurrent hash map | `std::cell::RefCell<HashMap>` in `thread_local!` | Hook DLL is single-threaded per process; `RefCell` is sufficient and faster |
| Volume GUID → drive letter | Manual registry parsing | `GetVolumePathNamesForVolumeNameW` | Windows API is the canonical source; handles mount points correctly |
| Policy condition serde | Custom serializer | `#[serde(tag = "attribute", rename_all = "snake_case")]` | Already used for 9 variants; adding 2 more follows the same pattern |
| Path → volume class resolution | Inline path parsing in every consumer | `resolve_volume_class_from_path` in `dlp-common` | Single reusable helper; consistent UNC/drive-letter/volume-GUID handling across hook DLL and server |

**Key insight:** The `wmi` crate is already a proven dependency in this codebase (Phase 34). The `Win32_DiskDrive` query pattern mirrors the existing `Win32_EncryptableVolume` query in `encryption.rs`. The ABAC condition extension follows the exact same pattern as the 9 existing variants.

## Runtime State Inventory

> This is a greenfield extension phase (adding new capabilities to existing systems). No rename/refactor/migration of stored data is required.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None -- no existing `VolumeClass` data in any datastore | N/A |
| Live service config | None -- volume class is resolved at runtime | N/A |
| OS-registered state | None -- no OS registrations of volume class | N/A |
| Secrets/env vars | None -- no secrets reference volume class | N/A |
| Build artifacts | None -- no compiled artifacts reference volume class | N/A |

**Nothing found in category:** All categories verified -- this phase adds new runtime-resolved attributes with no stored state.

## Common Pitfalls

### Pitfall 1: WMI Query Timeout on Hot Path
**What goes wrong:** Calling WMI from the hook DLL's `classify_and_log_path` blocks the trampolined API call for 10-100ms, causing application hangs.
**Why it happens:** WMI queries are slow; the hook DLL intercepts every file I/O call.
**How to avoid:** NEVER query WMI from the hook DLL. The hook DLL uses a thread-local cache populated by the agent's `UsbDetector` (which queries WMI on `WM_DEVICECHANGE`). The hook DLL only reads from the cache.
**Warning signs:** Integration tests showing >50ms latency in hook path; application UI freezing during file operations.

### Pitfall 2: `GetDriveTypeW` False Negatives for Virtual Drives
**What goes wrong:** Some virtual drives (e.g., Daemon Tools) report `DRIVE_CDROM` (5) instead of `DRIVE_FIXED` (3), causing them to be misclassified as `Optical`.
**Why it happens:** Virtual CD/DVD emulators emulate optical drives at the API level.
**How to avoid:** The classification logic must check WMI `Win32_DiskDrive.Model` for virtual indicators BEFORE mapping `DRIVE_CDROM` to `Optical`. If Model contains "Virtual" or "Daemon", classify as `Virtual` even if `GetDriveTypeW` returns `DRIVE_CDROM`.
**Warning signs:** Integration test showing Daemon Tools drive classified as `Optical` instead of `Virtual`.

### Pitfall 3: Optical Drive Tray Open/Close Spams Events
**What goes wrong:** Opening/closing an optical drive tray fires `WM_DEVICECHANGE` with `DBT_DEVICEARRIVAL`, causing duplicate `VolumeArrival` events.
**Why it happens:** The tray open/close changes the device state, triggering PnP notifications.
**How to avoid:** The 500ms deferred processing + duplicate suppression (drive letter already in the `volume_class_map`) handles this. The event is only emitted if the drive letter is NOT already in the map with the same class.
**Warning signs:** Multiple `VolumeArrival` events for the same optical drive letter within seconds.

### Pitfall 4: SD Card Reader with No Card
**What goes wrong:** An empty SD card reader might be classified as `SDCard` even though no volume is mounted.
**Why it happens:** `GetDriveTypeW` on an empty reader may return `DRIVE_REMOVABLE`.
**How to avoid:** Only emit `VolumeArrival` when `GUID_DEVINTERFACE_VOLUME` fires (which requires an actual mounted volume). The `WM_DEVICECHANGE` handler only processes volume interface events, not raw device events.
**Warning signs:** `VolumeArrival` events for drive letters with no accessible filesystem.

### Pitfall 5: UNC Path Classification
**What goes wrong:** Paths like `\\server\share\file.txt` are not classified as `NetworkShare` because the code only checks drive letters.
**Why it happens:** UNC paths have no drive letter.
**How to avoid:** Check for UNC prefix (`path.starts_with("\\\\")`) BEFORE extracting the drive letter. If UNC, return `NetworkShare` immediately. Use `resolve_volume_class_from_path` from `dlp-common` for consistent handling.
**Warning signs:** Network share copy operations not matching `destination_volume_class = NetworkShare` policies.

### Pitfall 6: `VolumeClass` Serde Backward Compatibility
**What goes wrong:** Adding `VolumeClass` to `AbacContext` breaks deserialization of old `EvaluateRequest` payloads that don't include the new fields.
**Why it happens:** `AbacContext` derives `Deserialize`; missing fields cause errors unless `#[serde(default)]` is present.
**How to avoid:** Add `#[serde(default, skip_serializing_if = "Option::is_none")]` to both new fields, matching the pattern used for `source_application`, `destination_application`, etc.
**Warning signs:** Old agents failing to deserialize `EvaluateResponse` from the server.

## Code Examples

### Verified patterns from official sources:

#### GetDriveTypeW usage (from existing codebase + Microsoft docs)
```rust
// Source: dlp-agent/src/detection/usb.rs (existing) + learn.microsoft.com
use windows::Win32::Storage::FileSystem::GetDriveTypeW;

const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;
const DRIVE_REMOTE: u32 = 4;
const DRIVE_CDROM: u32 = 5;

let root: Vec<u16> = OsStr::new(&format!("{}:\\", letter))
    .encode_wide()
    .chain(std::iter::once(0))
    .collect();
let drive_type = unsafe { GetDriveTypeW(windows::core::PCWSTR(root.as_ptr())) };
```

#### WMI query pattern (from existing encryption.rs)
```rust
// Source: dlp-agent/src/detection/encryption.rs (existing codebase)
#[cfg(windows)]
#[derive(serde::Deserialize, Debug, Clone)]
#[serde(rename = "Win32_EncryptableVolume")]
#[serde(rename_all = "PascalCase")]
struct EncryptableVolume {
    drive_letter: Option<String>,
    protection_status: Option<u32>,
    conversion_status: Option<u32>,
    encryption_method: Option<u32>,
}

let conn = wmi::WMIConnection::with_namespace_path(r"ROOT\CIMV2")?;
let volumes: Vec<EncryptableVolume> = conn.query()?;
```

#### PolicyCondition extension pattern (from existing abac.rs)
```rust
// Source: dlp-common/src/abac.rs (existing codebase)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "attribute", rename_all = "snake_case")]
pub enum PolicyCondition {
    // ... existing 9 variants ...
    SourceVolumeClass {
        #[serde(rename = "op")]
        op: String,
        value: VolumeClass,
    },
    DestinationVolumeClass {
        #[serde(rename = "op")]
        op: String,
        value: VolumeClass,
    },
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `GetDriveTypeW` only (USB detection) | `GetDriveTypeW` + WMI hybrid (6-class detection) | Phase 56 | Enables SD/optical/virtual drive policy enforcement |
| USB-only blocked-drives set | Volume-class-aware classification | Phase 56 | ABAC engine can express cross-volume policies |
| No volume-class audit events | `VolumeArrival` event with `volume_class` | Phase 56 | SIEM can alert on specific volume class arrivals |
| 9 ABAC condition attributes | 11 ABAC condition attributes | Phase 56 | Policy expressiveness grows without breaking existing policies |
| No shared path resolution helper | `resolve_volume_class_from_path` in `dlp-common` | Phase 56 | Consistent UNC/drive-letter/volume-GUID handling across hook DLL and server |

**Deprecated/outdated:**
- `UsbDetector::blocked_drives` as the sole volume tracking mechanism: Phase 56 introduces `volume_class_map` for comprehensive classification, but `blocked_drives` is retained for backward compatibility with USB-specific enforcement.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `GUID_DEVINTERFACE_VOLUME` fires for virtual mounts (VHD, ISO) | Architecture Patterns | If false, virtual mounts won't be detected; fallback to periodic polling would be needed |
| A2 | `Win32_DiskDrive.Model` contains "Virtual" or "Msft" for VHD/VHDX drives | Standard Stack | If false, virtual drives may be misclassified as `LocalNTFS`; need additional heuristics |
| A3 | SD card readers report `InterfaceType` = "SD" or `MediaType` = "Removable media" via WMI | Standard Stack | If false, SD cards may be misclassified as `USBRemovable`; fallback model-string check per D-05 handles this |
| A4 | The `wmi` crate can query `ROOT\CIMV2` without `set_proxy_blanket` (unlike BitLocker namespace) | Standard Stack | If false, queries may return ACCESS_DENIED; the encryption.rs pattern shows `set_proxy_blanket` is only needed for the Security namespace |
| A5 | `DRIVE_RAMDISK` (6) is not a production concern and can map to `LocalNTFS` fallback | Standard Stack | If false, RAM disks would be misclassified; low risk as RAM disks are rare in enterprise DLP contexts |

## Open Questions (RESOLVED)

1. **WMI query performance at scale**
   - What we know: `encryption.rs` queries all `Win32_EncryptableVolume` rows and filters in Rust; this is acceptable for <=32 volumes.
   - What's unclear: Whether querying `Win32_DiskDrive` + `Win32_LogicalDiskToPartition` association on every `WM_DEVICECHANGE` is fast enough.
   - RESOLVED: Batch the query (enumerate all disks once, cache results). The 500ms defer provides headroom. Measure in integration tests.

2. **Virtual drive emulator detection completeness**
   - What we know: Model strings like "Msft Virtual Disk" and "Virtual" cover VHD/VHDX and Hyper-V.
   - What's unclear: Whether Daemon Tools, Alcohol 120%, or other emulators use different Model strings.
   - RESOLVED: Start with known patterns; add more as discovered during integration testing. The fallback is `LocalNTFS` which is safe (fail-closed for T3/T4).

3. **Network share path edge cases**
   - What we know: UNC paths start with `\\`.
   - What's unclear: Whether mapped network drives (e.g., `Z:` mapped to `\\server\share`) report `DRIVE_REMOTE` from `GetDriveTypeW`.
   - RESOLVED: Test mapped drive classification. If `GetDriveTypeW` returns `DRIVE_REMOTE` for mapped drives, the drive-letter path already handles this.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Windows OS | All | Yes | 11/Server 2022 | — |
| WMI service | Volume classification | Yes | Built-in | `GetDriveTypeW` only (degraded) |
| `GetDriveTypeW` | Coarse volume classification | Yes | kernel32.dll | — |
| `wmi` crate (0.18) | WMI queries | Yes | 0.18.4 | None -- already in Cargo.toml |
| `windows` crate (0.62) | Win32 APIs | Yes | 0.62.2 | None -- already in Cargo.toml |
| tokio runtime | Deferred processing | Yes | workspace | — |

**Missing dependencies with no fallback:** None.

**Missing dependencies with fallback:** None.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Built-in `#[test]` + `cargo test` |
| Config file | None (standard Rust test harness) |
| Quick run command | `cargo test -p dlp-common` |
| Full suite command | `cargo test --all` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| DRIVE-01 | `VolumeClass` enum serializes/deserializes correctly | unit | `cargo test -p dlp-common volume_class` | No -- Wave 0 gap |
| DRIVE-01 | `GetDriveTypeW` + WMI disambiguation produces correct class for each drive type | integration | `cargo test -p dlp-agent --features integration-tests` | No -- Wave 0 gap |
| DRIVE-02 | `SourceVolumeClass` condition matches correctly in `PolicyStore::evaluate` | unit | `cargo test -p dlp-server policy_store` | No -- Wave 0 gap |
| DRIVE-02 | `DestinationVolumeClass` condition matches correctly | unit | `cargo test -p dlp-server policy_store` | No -- Wave 0 gap |
| DRIVE-02 | Admin TUI builds correct `PolicyCondition` from picker | unit | `cargo test -p dlp-admin-cli conditions_builder` | No -- Wave 0 gap |
| DRIVE-03 | Hook DLL thread-local cache returns correct class | unit | `cargo test -p dlp-hook-dll volume_class_cache` | No -- Wave 0 gap |
| DRIVE-04 | `VolumeArrival` event emitted on virtual mount | integration | `cargo test -p dlp-agent --features integration-tests` | No -- Wave 0 gap |

### Sampling Rate
- **Per task commit:** `cargo test -p dlp-common` (fast, covers shared types)
- **Per wave merge:** `cargo test --all` (full suite)
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `dlp-common/src/volume_class.rs` (or inline in `abac.rs`) -- `VolumeClass` enum with serde tests
- [ ] `dlp-common/src/abac.rs` -- `AbacContext` field tests for `source_volume_class` / `destination_volume_class`
- [ ] `dlp-server/src/policy_store.rs` -- `condition_matches` tests for new volume class arms
- [ ] `dlp-agent/src/detection/usb.rs` -- `VolumeClass` resolution tests (mock WMI)
- [ ] `dlp-hook-dll/src/volume_class_cache.rs` -- thread-local cache tests
- [ ] `dlp-admin-cli/src/screens/dispatch.rs` -- `build_condition` tests for volume class attributes
- [ ] `dlp-admin-cli/src/screens/render.rs` -- `picker_items` tests for volume class values

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | N/A -- volume class is not an auth factor |
| V3 Session Management | No | N/A |
| V4 Access Control | Yes | ABAC `VolumeClass` conditions enforce data exfiltration boundaries |
| V5 Input Validation | Yes | `VolumeClass` enum prevents injection; path parsing validates drive letter format |
| V6 Cryptography | No | N/A |
| V10 Malicious Code | Yes | Hook DLL cache prevents TOCTOU between classification and enforcement |

### Known Threat Patterns for Windows DLP + Volume Class

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Virtual drive bypass (mount VHD to exfiltrate) | Elevation of Privilege | `VolumeClass::Virtual` ABAC condition blocks writes to virtual drives |
| SD card exfiltration | Information Disclosure | `VolumeClass::SDCard` condition blocks T3/T4 writes |
| Optical disc burning exfiltration | Information Disclosure | `VolumeClass::Optical` condition blocks T3/T4 writes |
| Network share exfiltration | Information Disclosure | `VolumeClass::NetworkShare` condition blocks T3/T4 writes |
| Hook DLL cache poisoning | Tampering | Thread-local cache is per-process; agent populates cache via trusted WMI queries |
| WMI query spoofing | Spoofing | WMI runs as SYSTEM; untrusted users cannot spoof `Win32_DiskDrive` results |

## Sources

### Primary (HIGH confidence)
- [Microsoft Learn: GetDriveTypeW function](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypew) -- Return values, constants, limitations
- [Microsoft Learn: Win32_DiskDrive class](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-diskdrive) -- Properties: InterfaceType, MediaType, Model, PNPDeviceID
- [Microsoft Learn: GUID_DEVINTERFACE_VOLUME](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/guid-devinterface-volume) -- Fires for all volume devices including virtual
- `dlp-agent/src/detection/encryption.rs` -- Existing `wmi` 0.18 crate usage pattern with `WMIConnection::with_namespace_path` and `set_proxy_blanket`
- `dlp-common/src/abac.rs` -- `PolicyCondition` enum with 9 variants using `#[serde(tag = "attribute", rename_all = "snake_case")]`
- `dlp-server/src/policy_store.rs` -- `condition_matches` function with match arms for each condition variant
- `dlp-agent/src/detection/usb.rs` -- `UsbDetector` with `GetDriveTypeW`, `handle_volume_event_dispatch`, deferred processing
- `dlp-agent/src/detection/device_watcher.rs` -- `GUID_DEVINTERFACE_VOLUME` registration, 500ms defer pattern
- `dlp-hook-dll/src/trampolines.rs` -- `classify_and_log_path` with pipe round-trip
- `dlp-hook-dll/src/classification_cache.rs` -- Thread-local `RefCell` LRU cache pattern
- `dlp-admin-cli/src/app.rs` -- `ConditionAttribute` enum, `ATTRIBUTES` array
- `dlp-admin-cli/src/screens/dispatch.rs` -- `operators_for`, `value_count_for`, `build_condition`, `condition_to_prefill`
- `dlp-admin-cli/src/screens/render.rs` -- `picker_items`, `step_flags`, value constants

### Secondary (MEDIUM confidence)
- [WebSearch: WMI virtual disk detection](https://stackoverflow.com/questions/35336316/windows-wmi-how-to-detect-fixed-disk-drive-is-virtual) -- Community patterns for virtual disk detection via Model/PNPDeviceID
- [WebSearch: MSFT_PhysicalDisk BusType](https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-physicaldisk) -- Modern Storage Management API (not used directly; `Win32_DiskDrive` is sufficient per D-01)

### Tertiary (LOW confidence)
- None -- all critical claims verified against official Microsoft documentation or existing codebase.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all libraries are existing dependencies with proven usage in the codebase
- Architecture: HIGH -- Microsoft docs confirm `GetDriveTypeW` behavior and `GUID_DEVINTERFACE_VOLUME` coverage; existing codebase patterns are well-established
- Pitfalls: HIGH -- derived from known Windows behavior (WMI slowness, optical tray spam, UNC paths) and existing code patterns

**Research date:** 2026-05-29
**Valid until:** 2026-07-29 (stable APIs; 60 days for Windows API documentation)
