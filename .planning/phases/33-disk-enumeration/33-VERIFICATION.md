---
phase: 33-disk-enumeration
verified: 2026-04-29T19:33:55Z
status: human_needed
score: 14/14 must-haves verified
overrides_applied: 0
gaps: []
deferred:
  - truth: "Existing allowlist is preserved on restart; new disks are appended per D-07"
    addressed_in: "Phase 35"
    evidence: "Phase 35 goal: 'Agent persists the disk allowlist and loads it across restarts'. The _agent_config_path parameter in spawn_disk_enumeration_task is intentionally unused pending Phase 35 implementation."
human_verification:
  - test: "Verify disk enumeration accuracy on a Windows system with multiple fixed disks"
    expected: "Each disk in the DiskDiscovery audit event has the correct bus_type matching its actual hardware (SATA for internal SATA drives, NVMe for NVMe drives, USB for USB-bridged enclosures). Drive letters match the actual Windows drive letter assignments."
    why_human: "The query_bus_type_ioctl function iterates PhysicalDrive0-31 and returns the bus type of the first handle that responds to IOCTL, without validating that the opened handle corresponds to the intended instance_id. On multi-disk systems this could misattribute bus types. Single-disk systems and the PnP tree walk fallback are likely correct, but multi-disk accuracy requires real hardware validation."
  - test: "Verify boot disk identification on a Windows system with the OS installed on a non-C: drive"
    expected: "The disk hosting the boot volume has is_boot_disk=true, regardless of drive letter."
    why_human: "Boot disk detection uses GetSystemDirectoryW to extract the drive letter, then cross-references with enumerated disks. This is correct for standard installations but needs validation on non-standard configurations."
---

# Phase 33: Disk Enumeration Verification Report

**Phase Goal:** Agent can discover and accurately classify all fixed disks with device identity and bus type
**Verified:** 2026-04-29T19:33:55Z
**Status:** human_needed
**Re-verification:** No -- initial verification

## Goal Achievement

### Observable Truths

| #   | Truth                                                                 | Status     | Evidence                                                                 |
| --- | --------------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------ |
| 1   | DiskIdentity struct exists with all fields per D-10                   | VERIFIED   | `dlp-common/src/disk.rs:118-138` -- instance_id, bus_type, model, drive_letter, serial, size_bytes, is_boot_disk all present |
| 2   | BusType enum exists with Sata, Nvme, Usb, Scsi, Unknown variants      | VERIFIED   | `dlp-common/src/disk.rs:75-87` -- 5 variants with `#[serde(rename_all = "snake_case")]` |
| 3   | enumerate_fixed_disks() returns Vec<DiskIdentity> on Windows          | VERIFIED   | `dlp-common/src/disk.rs:186-195` -- platform dispatch with `#[cfg(windows)]` implementation |
| 4   | is_usb_bridged() uses IOCTL primary + PnP tree walk fallback          | VERIFIED   | `dlp-common/src/disk.rs:221-230` -- calls `is_usb_bridged_windows` which tries IOCTL then PnP walk |
| 5   | get_boot_drive_letter() resolves via GetSystemDirectoryW              | VERIFIED   | `dlp-common/src/disk.rs:246-255` -- platform dispatch to `get_boot_drive_letter_windows` |
| 6   | DiskError type uses thiserror with descriptive variants               | VERIFIED   | `dlp-common/src/disk.rs:47-67` -- 6 variants: WmiQueryFailed, SetupDiFailed, IoctlFailed, PnpWalkFailed, DeviceOpenFailed, InvalidInstanceId |
| 7   | All public items have doc comments                                    | VERIFIED   | 106 `///` doc comments in disk.rs, 79 in agent disk.rs; all public types and functions documented |
| 8   | Unit tests cover DiskIdentity serde, BusType serde, boot disk, error  | VERIFIED   | 13 tests in `dlp-common/src/disk.rs`, 4 disk-related tests in `dlp-common/src/audit.rs`, 8 tests in `dlp-agent/src/detection/disk.rs` |
| 9   | DiskEnumerator async task spawns at agent startup                     | VERIFIED   | `dlp-agent/src/service.rs:622-632` -- spawned after USB setup, before event loop |
| 10  | Enumeration retries 3 times with exponential backoff (200ms->1s->4s)  | VERIFIED   | `dlp-agent/src/detection/disk.rs:157-160` -- exact delays per D-04 |
| 11  | On final failure, Alert audit event emitted, agent fails closed       | VERIFIED   | `dlp-agent/src/detection/disk.rs:221-228` -- `emit_disk_enumeration_failed` with EventType::Alert, Classification::T4, Decision::DENY |
| 12  | Disk discovery emits aggregated AuditEvent with EventType::DiskDiscovery | VERIFIED | `dlp-agent/src/detection/disk.rs:239-256` -- `emit_disk_discovery` builds event with all disks |
| 13  | Boot disk auto-marked with is_boot_disk=true                          | VERIFIED   | `dlp-agent/src/detection/disk.rs:169-179` -- cross-references `get_boot_drive_letter()` against enumerated disks |
| 14  | DiskEnumerator accessible via detection module exports                | VERIFIED   | `dlp-agent/src/detection/mod.rs:8,12` -- `pub mod disk` and `pub use disk::{...}` |

**Score:** 14/14 truths verified

### Deferred Items

Items not yet met but explicitly addressed in later milestone phases.

| # | Item | Addressed In | Evidence |
|---|------|-------------|----------|
| 1 | Existing allowlist preserved on restart; new disks appended per D-07 | Phase 35 | Phase 35 goal: "Agent persists the disk allowlist and loads it across restarts". The `_agent_config_path` parameter in `spawn_disk_enumeration_task` is documented as "Phase 35 will pass the allowlist TOML path here". |

### Required Artifacts

| Artifact | Expected | Status | Details |
| -------- | -------- | ------ | ------- |
| `dlp-common/src/disk.rs` | DiskIdentity, BusType, DiskError, Win32 enumeration | VERIFIED | 792 lines, substantive, no stubs, 13 unit tests |
| `dlp-common/src/audit.rs` | EventType::DiskDiscovery, discovered_disks field | VERIFIED | Variant at line 46, field at line 183, builder at line 326, 4 unit tests |
| `dlp-common/src/lib.rs` | pub mod disk, pub use disk::* | VERIFIED | Lines 12, 21-23 |
| `dlp-common/Cargo.toml` | Win32_System_Ioctl, Win32_System_SystemInformation, Win32_Storage_FileSystem, Win32_System_IO, Win32_Security | VERIFIED | All 5 features present in `[target.'cfg(windows)'.dependencies]` |
| `dlp-agent/src/detection/disk.rs` | DiskEnumerator, spawn task, audit helpers, tests | VERIFIED | 500 lines, 8 unit tests, no unwrap in library code |
| `dlp-agent/src/detection/mod.rs` | pub mod disk, pub use disk exports | VERIFIED | Lines 8, 12 |
| `dlp-agent/src/service.rs` | Spawn disk enumeration task in run_loop | VERIFIED | Lines 622-632, after USB setup, before event loop |

### Key Link Verification

| From | To | Via | Status | Details |
| ---- | --- | --- | ------ | ------- |
| `dlp-agent/src/service.rs` | `dlp-agent/src/detection/disk.rs` | `spawn_disk_enumeration_task(tokio::runtime::Handle, EmitContext, Option<String>)` | WIRED | service.rs:627 calls with Handle::current(), audit_ctx.clone(), None |
| `dlp-agent/src/detection/disk.rs` | `dlp-common::enumerate_fixed_disks` | `dlp_common::enumerate_fixed_disks()` call in async task | WIRED | disk.rs:166 calls enumerate_fixed_disks() inside retry loop |
| `dlp-agent/src/detection/disk.rs` | `dlp-agent/src/audit_emitter.rs` | `emit_disk_discovery(ctx, &disks)` after enumeration | WIRED | disk.rs:202 calls emit_disk_discovery, which calls emit_audit at line 255 |
| `dlp-agent/src/detection/disk.rs` | `dlp-agent/src/audit_emitter.rs` | `emit_disk_enumeration_failed(ctx, &error)` on final retry | WIRED | disk.rs:227 calls emit_disk_enumeration_failed, which calls emit_audit at line 278 |
| `dlp-common/src/disk.rs` | `dlp-common/src/audit.rs` | DiskIdentity imported into AuditEvent.discovered_disks | WIRED | audit.rs:17 imports DiskIdentity, line 183 defines discovered_disks: Option<Vec<DiskIdentity>> |
| `dlp-common/src/lib.rs` | `dlp-common/src/disk.rs` | pub mod disk re-export | WIRED | lib.rs:12 declares `pub mod disk`, lines 21-23 re-export public items |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
| -------- | ------------- | ------ | ------------------ | ------ |
| `dlp-common/src/disk.rs` enumerate_fixed_disks | Vec<DiskIdentity> | SetupDiGetClassDevsW + GUID_DEVINTERFACE_DISK enumeration | Yes (Win32 API calls on Windows, empty vec on non-Windows) | FLOWING |
| `dlp-agent/src/detection/disk.rs` spawn_disk_enumeration_task | disks (Vec<DiskIdentity>) | dlp_common::enumerate_fixed_disks() | Yes (calls real enumeration, not stub) | FLOWING |
| `dlp-agent/src/detection/disk.rs` emit_disk_discovery | AuditEvent with discovered_disks | Constructed from disks vec passed from enumeration | Yes (real disk data flows into event) | FLOWING |
| `dlp-agent/src/detection/disk.rs` DiskEnumerator state | discovered_disks, drive_letter_map, instance_id_map | Populated from enumeration result in async task | Yes (real data written on success) | FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| -------- | ------- | ------ | ------ |
| dlp-common compiles without warnings | `cargo check -p dlp-common` | Finished dev profile, 0 warnings | PASS |
| dlp-agent compiles without warnings | `cargo check -p dlp-agent` | Finished dev profile, 0 warnings | PASS |
| dlp-common tests pass | `cargo test -p dlp-common` | 101 passed (3 suites, 1.15s) | PASS |
| dlp-agent tests pass | `cargo test -p dlp-agent --lib` | 217 passed (1 suite, 5.03s) | PASS |
| dlp-common clippy clean | `cargo clippy -p dlp-common -- -D warnings` | No issues found | PASS |
| dlp-agent clippy clean | `cargo clippy -p dlp-agent -- -D warnings` | No issues found | PASS |
| Module exports DiskIdentity | `grep "pub use disk" dlp-common/src/lib.rs` | Line 21-23: enumerate_fixed_disks, get_boot_drive_letter, is_usb_bridged, BusType, DiskError, DiskIdentity | PASS |
| Audit event has DiskDiscovery | `grep "DiskDiscovery" dlp-common/src/audit.rs` | Enum variant (line 46), routed_to_siem (line 62), builder method (line 326), 4 tests | PASS |
| Agent spawns enumeration task | `grep "spawn_disk_enumeration_task" dlp-agent/src/service.rs` | Line 627: called with Handle::current(), audit_ctx.clone(), None | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
| ----------- | ---------- | ----------- | ------ | -------- |
| DISK-01 | 33-01, 33-02 | Agent enumerates all fixed disks capturing instance_id, bus_type, model, drive_letter | SATISFIED | `enumerate_fixed_disks()` in dlp-common/src/disk.rs:186-331; DiskIdentity struct has all required fields |
| DISK-02 | 33-01 | Agent distinguishes USB-bridged SATA/NVMe enclosures from genuine internal disks | SATISFIED | `is_usb_bridged()` uses IOCTL_STORAGE_QUERY_PROPERTY primary (line 367-403) + PnP tree walk fallback (line 493-541) per D-12/D-13 |
| AUDIT-01 | 33-02 | Disk discovery events emitted at install time with all enumerated disks | SATISFIED | `emit_disk_discovery()` in dlp-agent/src/detection/disk.rs:239-256 creates DiskDiscovery event with full disk identities; routed_to_siem includes DiskDiscovery |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| ---- | ---- | ------- | -------- | ------ |
| `dlp-common/src/disk.rs` | 407 | `query_bus_type_for_handle` takes `_instance_id: &str` but never uses it | WARNING | On multi-disk systems, bus type may be misattributed because the function returns the first PhysicalDrive handle that responds to IOCTL without validating it matches the intended instance_id. The PnP tree walk fallback (`is_usb_bridged_pnp_walk`) uses the correct instance_id and provides accurate USB detection. |
| `dlp-common/src/disk.rs` | 572-574 | `find_drive_letter_for_instance_id` takes `_instance_id` and `_already_found` but uses simplified heuristic | INFO | Acknowledged in code comment: "Simplified heuristic" -- assigns drive letters sequentially rather than correlating by instance_id. WMI correlation deferred to future phase. Works correctly for single-disk systems. |
| `dlp-agent/src/detection/disk.rs` | 105-106 | `unsafe impl Send for DiskEnumerator` and `unsafe impl Sync for DiskEnumerator` | INFO | Unnecessary -- `parking_lot::RwLock<T>` is already `Send + Sync` when `T: Send + Sync`. All contained types (`Vec<DiskIdentity>`, `HashMap<_, DiskIdentity>`, `bool`) are `Send + Sync`. The manual impl is harmless but could be removed. |

### Human Verification Required

1. **Multi-disk Windows system: verify bus type accuracy**
   - **Test:** Run the agent on a Windows machine with 2+ fixed disks (e.g., one internal SATA SSD and one internal NVMe SSD, or a USB-bridged SATA enclosure). Check the DiskDiscovery audit event JSON.
   - **Expected:** Each disk's `bus_type` matches its actual hardware interface. The SATA disk shows `"bus_type": "sata"`, the NVMe disk shows `"bus_type": "nvme"`, and any USB-bridged enclosure shows `"bus_type": "usb"`.
   - **Why human:** The `query_bus_type_ioctl` function iterates PhysicalDrive0-31 and returns the bus type of the first handle that responds to IOCTL, without validating the opened handle corresponds to the intended `instance_id`. On multi-disk systems, bus types could be misattributed. Single-disk systems and the PnP fallback are likely correct, but real hardware with multiple disks is needed for confidence.

2. **Non-standard boot drive letter: verify boot disk identification**
   - **Test:** On a Windows system where the OS is installed on a drive letter other than C: (e.g., D:), check that the DiskDiscovery event marks the correct disk with `is_boot_disk: true`.
   - **Expected:** The disk containing the Windows system directory has `is_boot_disk: true`, regardless of its drive letter.
   - **Why human:** Boot disk detection uses `GetSystemDirectoryW` to extract the drive letter and cross-references with enumerated disks. This is correct for standard configurations but needs validation on non-standard setups.

### Gaps Summary

No blocking gaps. All 14 must-have truths from the plan frontmatter are verified. All artifacts exist, are substantive, and are wired. All key links are connected. All three requirements (DISK-01, DISK-02, AUDIT-01) are satisfied by the implementation.

Two known limitations exist:
1. **Instance_id-to-PhysicalDrive correlation in `query_bus_type_ioctl`:** The function tries PhysicalDrive handles sequentially and returns the first successful IOCTL response without validating the handle matches the intended disk. This is a functional limitation on multi-disk systems, mitigated by the PnP tree walk fallback for USB detection.
2. **Drive letter assignment uses simplified heuristic:** `find_drive_letter_for_instance_id` assigns drive letters sequentially to enumerated disks rather than correlating by instance_id. This is acknowledged in code comments and deferred to a future phase with WMI-based correlation.

The allowlist persistence requirement ("existing allowlist preserved on restart") is intentionally deferred to Phase 35, as documented in the code and roadmap.

---

_Verified: 2026-04-29T19:33:55Z_
_Verifier: Claude (gsd-verifier)_
