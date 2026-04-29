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
