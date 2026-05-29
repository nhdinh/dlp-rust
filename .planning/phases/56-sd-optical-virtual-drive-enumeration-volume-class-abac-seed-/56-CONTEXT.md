# Phase 56: SD/Optical/Virtual Drive Enumeration + Volume-Class ABAC (SEED-004) - Context

**Gathered:** 2026-05-29
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 56 delivers **SD card, optical (CD/DVD/Blu-ray), and virtual drive enumeration** as first-class citizens in the device-watcher and ABAC engine. Two new ABAC attributes (`source_volume_class`, `destination_volume_class`) enable policy expressions like "DENY copy from LocalNTFS T4 to Optical". The admin TUI extends existing USB/disk screens and the Conditions Builder to surface these volume classes without UI breakage.

**What Phase 56 builds:**
1. **Volume class detection** — A six-value enum (`LocalNTFS`, `USBRemovable`, `SDCard`, `Optical`, `Virtual`, `NetworkShare`) resolved via `GetDriveTypeW` + `Win32_DiskDrive`/`Win32_LogicalDisk` WMI queries (not `GetDriveTypeW` alone).
2. **Device arrival audit events** — Single distinct `VolumeArrival` audit event per mount with correct `volume_class`, emitted through the existing `device_watcher` + ` EmitContext` pipeline.
3. **ABAC attribute expansion** — `source_volume_class` and `destination_volume_class` added to `AbacContext` and `PolicyCondition`, growing the attribute set from 9 to 11 (was 5 → 7 per original SEED-004, but v0.10.0 already added application/origin attributes).
4. **Hook DLL volume-class resolution** — Path prefix analysis (drive letter or UNC prefix) → cached volume class lookup at evaluation time.
5. **Admin TUI extension** — Conditions Builder dropdowns for the two new attributes; existing USB/disk allowlist screens render SD/Optical/Virtual rows with a `volume_class` column/badge.
6. **WM_DEVICECHANGE coverage** — Virtual mounts (Daemon Tools, Explorer ISO, VHD/VHDX) covered by extending the existing `GUID_DEVINTERFACE_VOLUME` handler; 500 ms deferred processing preserved.

**What Phase 56 does NOT build:**
- Virtual drive sub-classification (Daemon Tools vs VHD vs ISO) — single `Virtual` class is sufficient per success criteria
- Volume-class-specific allowlist/grace-period behavior — existing USB/disk allowlist patterns are reused
- New `GUID_DEVINTERFACE_*` registrations — `GUID_DEVINTERFACE_VOLUME` already covers all volume arrivals
- Optical drive write-blocking at the physical layer — policy enforcement via ABAC + hook DLL only

**Depends on:** Phases 48-50 (hook DLL covers I/O for free); independent of 51-55
**Requirements:** DRIVE-01, DRIVE-02, DRIVE-03, DRIVE-04

</domain>

<decisions>
## Implementation Decisions

### Volume Class Detection Method
- **D-01:** Extend the existing `GetDriveTypeW` + WMI hybrid approach. `GetDriveTypeW` provides the coarse bucket (`DRIVE_FIXED`, `DRIVE_REMOVABLE`, `DRIVE_REMOTE`, `DRIVE_CDROM`). For `DRIVE_REMOVABLE`, query `Win32_DiskDrive` via the `wmi` crate to disambiguate `USBRemovable` (BusType=USB) from `SDCard` (BusType=SD or MediaType contains "Removable media" + absence of USB). For `DRIVE_FIXED`, distinguish `LocalNTFS` from `Virtual` via `Win32_DiskDrive.Model` containing "Msft Virtual Disk" or `InterfaceType` = "File-backed Virtual".
- **D-02:** Single `Virtual` class for all virtual drives (Daemon Tools, VHD, VHDX, Explorer-mounted ISO). No sub-classification. Virtual drive detection uses `Win32_DiskDrive` Model field pattern matching (`*Virtual*`, `*Msft*`) combined with `GetDriveTypeW` returning `DRIVE_FIXED`.
- **D-03:** Optical drives (`DRIVE_CDROM` from `GetDriveTypeW`) map directly to `Optical`. No WMI disambiguation needed.
- **D-04:** Network shares (`DRIVE_REMOTE` from `GetDriveTypeW` or UNC path prefix `\\`) map to `NetworkShare`. Path-based detection without WMI query.
- **D-05:** SD card detection: `Win32_DiskDrive` where `MediaType` = "Removable media" AND (`BusType` = "SD" OR `InterfaceType` = "SD"). Fallback: if `GetDriveTypeW` returns `DRIVE_REMOVABLE` and the disk model contains "SD" or "MMC", classify as `SDCard`.

### ABAC Attribute Integration
- **D-06:** `source_volume_class` and `destination_volume_class` are fields on `AbacContext` (not `Resource`), because they describe the runtime I/O environment, not the resource itself. They are `Option<VolumeClass>` — `None` when the operation has no filesystem source/destination (e.g., clipboard paste to browser, print).
- **D-07:** Add two new `PolicyCondition` variants: `SourceVolumeClass { op: String, value: VolumeClass }` and `DestinationVolumeClass { op: String, value: VolumeClass }`. Supported operators: `eq`, `ne`, `in` (matches any of a list — useful for "destination is removable media" policies).
- **D-08:** Hook DLL resolves volume class at trampoline time: extract drive letter from path (or detect UNC prefix) → look up `VolumeClass` in a thread-local cache (keyed by drive letter, TTL 30s) → populate `AbacContext.source_volume_class` / `destination_volume_class`. For operations like `CopyFileExW`, source path → `source_volume_class`, destination path → `destination_volume_class`.
- **D-09:** Server-side ABAC evaluation (for non-hook paths like admin API checks) also resolves volume class when `resource_path` is present, using the same drive-letter → class logic. The agent caches this locally; the server computes it on-demand.

### Admin TUI UX
- **D-10:** Extend `ConditionAttribute` enum with `SourceVolumeClass` and `DestinationVolumeClass`, appended after `DestinationOrigin` in the `ATTRIBUTES` array. Labels: "Source Volume Class", "Destination Volume Class". Step 2 operators: `eq`, `ne`, `in`. Step 3 value picker: dropdown of six enum values.
- **D-11:** Extend existing USB/disk allowlist screens (`AllowlistScreen` / `UsbEnforcementConfig` pattern) with a `volume_class: VolumeClass` column/badge. SD/Optical/Virtual rows render alongside USB rows without UI breakage — the `category` or `match_type` field already supports arbitrary strings.
- **D-12:** The Conditions Builder dropdown for volume class values uses the same ratatui `List` picker pattern as `Classification` (T1-T4) and `DeviceTrust`. No custom widget needed.

### WM_DEVICECHANGE and Virtual Mounts
- **D-13:** No new `RegisterDeviceNotificationW` GUID registrations needed. The existing `GUID_DEVINTERFACE_VOLUME` handler (`usb.rs::handle_volume_event_dispatch`) already fires for ALL volume arrivals — physical USB, SD, optical, virtual (VHD, ISO), and network. Extend this handler to classify the volume and emit a `VolumeArrival` audit event with the correct `volume_class`.
- **D-14:** Preserve the 500 ms deferred processing pattern for all volume arrivals. Virtual mounts may take a moment to assign a drive letter; the deferred path ensures `GetDriveTypeW` and WMI queries succeed.
- **D-15:** Virtual drive arrival emits `VolumeArrival` with `volume_class = Virtual`. Virtual drive removal emits no audit event (same as disk removal — informational, no allowlist change). Optical drive tray open/close may trigger spurious arrival/removal; the 500ms defer + duplicate suppression (drive letter already in map) handles this.

### Audit Event Schema
- **D-16:** New `EventType::VolumeArrival` with a `volume_class: VolumeClass` field. Emitted once per distinct device arrival. For virtual mounts, this fires when the volume is fully mounted (after 500ms defer).
- **D-17:** The existing `DiskDiscovery` event (emitted by `disk.rs`) remains unchanged — it covers fixed disks only. `VolumeArrival` is the new general-purpose event for all volume classes. Both can coexist; `VolumeArrival` subsumes USB volume arrivals that previously had no dedicated event.

### Claude's Discretion
- The `VolumeClass` enum should derive `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq`, `Serialize`, `Deserialize`, `Display`, `Default` (with `LocalNTFS` as default).
- Volume class cache in the hook DLL should be a thread-local `RefCell<HashMap<char, (VolumeClass, Instant)>>` with 30-second TTL, not a global cache, to avoid cross-thread synchronization overhead in the hot path.
- WMI queries for volume classification should be batched where possible (e.g., enumerate all `Win32_LogicalDisk` → `Win32_DiskDrive` associations once at agent startup, then refresh on `WM_DEVICECHANGE`).
- The integration test for DRIVE-02 should use an actual optical drive if available on the test endpoint, or mock the WMI response if not. The policy under test: `DENY COPY where source_volume_class = LocalNTFS AND classification = T4 AND destination_volume_class = Optical`.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Architecture
- `.planning/ROADMAP.md` — Phase 56 goal, 4 success criteria, requirements DRIVE-01..04
- `.planning/PROJECT.md` — v0.10.0 milestone context, SEED-004 fold-in (Decision 8), device enumeration patterns
- `.planning/STATE.md` — Decision 8: SEED-004 folded into v0.10.0; Decision 5: asymmetric fail semantics

### Prior Phase Context
- `.planning/phases/55-monitor-only-audit-only-per-policy-enforcement-mode/55-CONTEXT.md` — Enforcement mode integration (hook DLL evaluates policy before returning ALLOW/DENY)
- `.planning/phases/50-shared-memory-classification-cache-fail-mode-state-machine/50-CONTEXT.md` — Shared-memory cache, hook DLL fail-mode state machine
- `.planning/phases/54-admin-tui-protected-paths-bypass-alerts-screens/54-CONTEXT.md` — Admin TUI screen patterns, Conditions Builder form layout

### Existing Code Patterns
- `dlp-common/src/abac.rs` — `AbacContext`, `PolicyCondition`, `EvaluateRequest`, `EvaluateResponse`. **Extend** with `VolumeClass` and new condition variants.
- `dlp-agent/src/detection/usb.rs` — `GetDriveTypeW` volume classification, `handle_volume_event_dispatch`. **Extend** with WMI disambiguation and `VolumeArrival` emission.
- `dlp-agent/src/detection/disk.rs` — `DiskEnumerator`, `on_disk_arrival`/`on_disk_removal`, mount-time blocking. **Reference** for registry patterns and audit emission.
- `dlp-agent/src/detection/device_watcher.rs` — `GUID_DEVINTERFACE_VOLUME` registration, 500ms deferred processing. **No changes needed** — extend the usb.rs handler only.
- `dlp-admin-cli/src/app.rs` — `ConditionAttribute` enum, `ATTRIBUTES` array. **Extend** with two new variants.
- `dlp-admin-cli/src/screens/dispatch.rs` — Conditions builder dispatch, operator lookup, value count. **Extend** with volume class branching.
- `dlp-admin-cli/src/screens/render.rs` — Conditions builder render. **Extend** with volume class dropdown rendering.
- `dlp-admin-cli/src/screens/allowlist.rs` — `AllowlistScreen`, `AllowlistEntryUi`. **Extend** with `volume_class` field.

### Code Conventions
- `.planning/codebase/CONVENTIONS.md` — Rust coding standards, naming, error handling
- `.planning/codebase/STRUCTURE.md` — Workspace module organization

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`DiskEnumerator`** (`dlp-agent/src/detection/disk.rs`): In-memory registry pattern with `RwLock<Vec<T>>`, `RwLock<HashMap<K, V>>`, global `OnceLock<Arc<T>>`. Use the same pattern for a `VolumeClassCache` if a global cache is needed beyond the hook DLL's thread-local cache.
- **`UsbDetector`** (`dlp-agent/src/detection/usb.rs`): Volume classification via `GetDriveTypeW`, deferred arrival handling. Extend the classification logic with WMI fallback.
- **`DeviceWatcher`** (`dlp-agent/src/detection/device_watcher.rs`): `RegisterDeviceNotificationW` for `GUID_DEVINTERFACE_VOLUME` + `GUID_DEVINTERFACE_USB_DEVICE` + `GUID_DEVINTERFACE_DISK`. The volume handler dispatches to `usb.rs`; no new registrations needed.
- **`PolicyCondition`** (`dlp-common/src/abac.rs`): Nine existing condition variants with serde `tag = "attribute"`, `rename_all = "snake_case"`. Add two new variants following the exact same pattern.
- **`ConditionAttribute`** (`dlp-admin-cli/src/app.rs`): Nine existing attributes in display order. Add two new variants and append to `ATTRIBUTES` array.
- **`AuditEvent`** (`dlp-common/src/audit.rs`): `with_*` builder pattern for optional fields. Add `with_volume_class(VolumeClass)` if not already present.

### Established Patterns
- **WMI queries via `wmi` crate**: `dlp-common` uses `wmi` 0.14 for `Win32_DiskDrive` enumeration. Volume classification should reuse the same connection pattern (COM initialized, `WMIConnection` scoped to the query).
- **WM_DEVICECHANGE deferred processing**: `device_watcher.rs` stores `RUNTIME_HANDLE` in a `OnceLock`; arrival handlers spawn a tokio task with `tokio::time::sleep(Duration::from_millis(500))`. Preserve this exactly.
- **ABAC condition evaluation**: `PolicyStore::evaluate()` iterates conditions, matches on `PolicyCondition` variant. Add two new match arms for `SourceVolumeClass` and `DestinationVolumeClass`.
- **Hook DLL path classification**: `trampolines.rs` already extracts paths from `CopyFileExW`, `MoveFileExW`, etc. Extend the `classify_and_log_handle` / `extract_nt_path` flow to resolve volume class before calling the ABAC evaluator.
- **Admin TUI multi-step form**: Conditions Builder uses Step 1 (attribute picker) → Step 2 (operator picker) → Step 3 (value picker). Volume class follows the same three-step flow as `DeviceTrust` / `NetworkLocation`.
- **TUI config screen**: `AllowlistScreen` uses scrollable `List` with selected index, `n`/`e`/`d` key actions. Extend `AllowlistEntryUi` with `volume_class` and render it as a colored badge.

### Integration Points
- `dlp-common/src/abac.rs` — Add `VolumeClass` enum; extend `AbacContext` with `source_volume_class` and `destination_volume_class`; add `PolicyCondition::SourceVolumeClass` and `PolicyCondition::DestinationVolumeClass`.
- `dlp-common/src/lib.rs` — Export `VolumeClass` from the crate root.
- `dlp-common/src/audit.rs` — Add `VolumeClass` to audit event types (optional field on relevant events).
- `dlp-agent/src/detection/usb.rs` — Extend volume classification logic; emit `VolumeArrival` events.
- `dlp-agent/src/detection/mod.rs` — Export new volume classification module if created.
- `dlp-hook-dll/src/trampolines.rs` — Resolve volume class from path before ABAC evaluation; populate `AbacContext` fields.
- `dlp-hook-dll/src/classification_cache.rs` — Add volume class cache (thread-local, TTL 30s, keyed by drive letter).
- `dlp-server/src/policy_store.rs` — Evaluate `SourceVolumeClass` / `DestinationVolumeClass` conditions.
- `dlp-admin-cli/src/app.rs` — Extend `ConditionAttribute` and `ATTRIBUTES`.
- `dlp-admin-cli/src/screens/dispatch.rs` — Wire volume class in conditions builder dispatch.
- `dlp-admin-cli/src/screens/render.rs` — Render volume class dropdown and allowlist badges.
- `dlp-admin-cli/src/screens/allowlist.rs` — Add `volume_class` to `AllowlistEntryUi`.

</code_context>

<specifics>
## Specific Ideas

- `VolumeClass` enum values: `LocalNTFS`, `USBRemovable`, `SDCard`, `Optical`, `Virtual`, `NetworkShare`. Serialize as PascalCase matching the success criteria.
- The `VolumeClass` resolution should handle edge cases: drive letters without a mounted volume (return `LocalNTFS` as fallback for `C:`), UNC paths (return `NetworkShare`), paths with no drive letter (e.g., `\?\Volume{GUID}\...` — query `GetVolumePathNamesForVolumeNameW` or fallback to `LocalNTFS`).
- For the integration test (DRIVE-02), create a mock `Win32_DiskDrive` WMI response that reports an optical drive, then verify the ABAC policy blocks a `CopyFileExW` call to it. If no optical drive is present on the test endpoint, use a mocked WMI layer.
- The admin TUI allowlist screen should show volume class as a colored badge: `LocalNTFS` = blue, `USBRemovable` = yellow, `SDCard` = magenta, `Optical` = cyan, `Virtual` = red, `NetworkShare` = green.
- Virtual drive detection should not false-positive on RAM disks or software RAID volumes. The `Win32_DiskDrive.Model` check for "Virtual" should be precise (e.g., `Model LIKE "%Virtual Disk%" OR Model LIKE "%Msft%"`).
- SD card readers with no card inserted should not emit `VolumeArrival` — the event should only fire when a volume is actually mounted (which `GUID_DEVINTERFACE_VOLUME` guarantees).
</specifics>

<deferred>
## Deferred Ideas

- Virtual drive sub-classification (Daemon Tools vs VHD vs ISO vs RAM disk) — deferred; single `Virtual` class is sufficient for v0.10.0
- Volume-class-specific grace periods (e.g., longer grace for SD cards) — deferred; reuse existing disk grace period
- Volume-class-based mount-time blocking (block all `Optical` arrivals at mount time) — deferred to operational policy phase
- Network share server-specific classification (e.g., `NetworkShare-Trusted` vs `NetworkShare-Untrusted`) — deferred
- Volume class in the shared-memory classification cache (Phase 50) — not needed; volume class is resolved from path at evaluation time, not cached with classification

</deferred>

---

*Phase: 56-SD/Optical/Virtual Drive Enumeration + Volume-Class ABAC (SEED-004)*
*Context gathered: 2026-05-29*
