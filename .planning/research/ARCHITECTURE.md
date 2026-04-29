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
