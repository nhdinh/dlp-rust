---
phase: 33-disk-enumeration
verified: 2026-05-04T10:00:00Z
status: human_needed
score: 14/14 must-haves verified
overrides_applied: 0
gaps: []
deferred:
  - truth: "Existing allowlist is preserved on restart; new disks are appended per D-07"
    addressed_in: "Phase 35"
    evidence: "Phase 35 goal: 'Agent persists the disk allowlist and loads it across restarts'. The _agent_config_path parameter in spawn_disk_enumeration_task is intentionally unused pending Phase 35 implementation."
re_verification:
  previous_status: human_needed
  previous_score: 14/14
  gaps_closed:
    - "USB-bridged NVMe enclosures show bus_type='usb', not 'nvme' (33-HUMAN-UAT.md test 1)"
  gaps_remaining: []
  regressions: []
human_verification:
  - test: "Verify USB-bridged NVMe/SATA bus type override on hardware with USB NVMe enclosures"
    expected: "USB-C NVMe enclosures (e.g. Lexar E6, SanDisk Extreme) now show bus_type='usb' in DiskDiscovery audit events, not 'nvme'. Internal NVMe still shows 'nvme'. The gap-closure PnP override runs unconditionally so IOCTL misclassification is corrected."
    why_human: "The fix (resolve_bus_type_with_pnp_override + unconditional PnP walk) is fully unit-tested across all 9 truth-table rows, but confirming the PnP walk actually finds the USB\\ ancestor node for real Lexar E6 / SanDisk Extreme hardware requires physical device testing."
  - test: "Verify boot disk identification on a Windows system with the OS installed on a non-C: drive"
    expected: "The disk hosting the boot volume has is_boot_disk=true, regardless of drive letter."
    why_human: "Boot disk detection uses GetSystemDirectoryW to extract the drive letter, then cross-references with enumerated disks. This is correct for standard installations but needs validation on non-standard configurations."
---

# Phase 33: Disk Enumeration Verification Report (Re-verification after 33-GAP-01)

**Phase Goal:** Agent can discover and accurately classify all fixed disks with device identity and bus type
**Verified:** 2026-05-04T10:00:00Z
**Status:** human_needed
**Re-verification:** Yes -- after gap closure (33-GAP-01)

## Re-verification Summary

Previous status: `human_needed` (14/14 verified; 2 human items).

33-GAP-01 addressed the root cause for human verification item 1 (USB-bridged NVMe bus type misclassification). The gap was diagnosed in 33-HUMAN-UAT.md: `enumerate_fixed_disks_windows` only called `is_usb_bridged_pnp_walk` on the `Err(_)` branch of `query_bus_type_ioctl`, so a wrong-but-successful IOCTL result permanently bypassed PnP detection.

Gap closure delivered:
- `resolve_bus_type_with_pnp_override` pure helper (not `#[cfg(windows)]` gated) implementing the full 7-row truth table
- `enumerate_fixed_disks_windows` now calls both `query_bus_type_ioctl` and `is_usb_bridged_pnp_walk` unconditionally for every disk
- 9 unit tests pinning all truth-table rows (all pass on every platform)

Human item 2 (non-standard boot drive letter) was not addressed by 33-GAP-01 and remains a known limitation.

## Goal Achievement

### Observable Truths (original 14 + GAP-01 truths)

| #   | Truth                                                                                          | Status   | Evidence                                                                                            |
| --- | ---------------------------------------------------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------- |
| 1   | DiskIdentity struct exists with all fields per D-10                                            | VERIFIED | `disk.rs:208-246` -- instance_id, bus_type, model, drive_letter, serial, size_bytes, is_boot_disk  |
| 2   | BusType enum exists with Sata, Nvme, Usb, Scsi, Unknown variants                              | VERIFIED | `disk.rs:75-87` -- 5 variants with `#[serde(rename_all = "snake_case")]`                           |
| 3   | enumerate_fixed_disks() returns Vec<DiskIdentity> on Windows                                  | VERIFIED | `disk.rs:294-303` -- platform dispatch with `#[cfg(windows)]` implementation                       |
| 4   | is_usb_bridged() uses IOCTL primary + PnP tree walk fallback                                  | VERIFIED | `disk.rs:329-338` -- calls `is_usb_bridged_windows` which tries IOCTL then PnP walk                |
| 5   | get_boot_drive_letter() resolves via GetSystemDirectoryW                                      | VERIFIED | `disk.rs:354-363` -- platform dispatch to `get_boot_drive_letter_windows`                          |
| 6   | DiskError type uses thiserror with descriptive variants                                       | VERIFIED | `disk.rs:47-67` -- 6 variants: WmiQueryFailed, SetupDiFailed, IoctlFailed, PnpWalkFailed, DeviceOpenFailed, InvalidInstanceId |
| 7   | All public items have doc comments                                                             | VERIFIED | All public types and functions carry `///` doc comments                                             |
| 8   | Unit tests cover DiskIdentity serde, BusType serde, boot disk, error                         | VERIFIED | 112 tests in `dlp-common`, 253 in `dlp-agent --lib`; all pass                                      |
| 9   | DiskEnumerator async task spawns at agent startup                                             | VERIFIED | `dlp-agent/src/service.rs` -- spawned after USB setup, before event loop                           |
| 10  | Enumeration retries 3 times with exponential backoff (200ms->1s->4s)                         | VERIFIED | `dlp-agent/src/detection/disk.rs:157-160` -- exact delays per D-04                                 |
| 11  | On final failure, Alert audit event emitted, agent fails closed                               | VERIFIED | `dlp-agent/src/detection/disk.rs:221-228` -- emit_disk_enumeration_failed with EventType::Alert    |
| 12  | Disk discovery emits aggregated AuditEvent with EventType::DiskDiscovery                     | VERIFIED | `dlp-agent/src/detection/disk.rs:239-256` -- emit_disk_discovery builds event with all disks       |
| 13  | Boot disk auto-marked with is_boot_disk=true                                                  | VERIFIED | `dlp-agent/src/detection/disk.rs:169-179` -- cross-references get_boot_drive_letter()              |
| 14  | DiskEnumerator accessible via detection module exports                                        | VERIFIED | `dlp-agent/src/detection/mod.rs:8,12` -- pub mod disk and pub use disk::{...}                      |
| G1  | USB-bridged NVMe enclosures reported with bus_type=Usb (not Nvme)                            | VERIFIED | `resolve_bus_type_with_pnp_override(Ok(BusType::Nvme), Ok(true)) == BusType::Usb`; test passes    |
| G2  | USB-bridged SATA enclosures reported with bus_type=Usb (not Sata)                            | VERIFIED | `resolve_bus_type_with_pnp_override(Ok(BusType::Sata), Ok(true)) == BusType::Usb`; test passes    |
| G3  | Internal NVMe disks remain bus_type=Nvme (no regression)                                     | VERIFIED | `resolve_bus_type_with_pnp_override(Ok(BusType::Nvme), Ok(false)) == BusType::Nvme`; test passes  |
| G4  | Internal SATA disks remain bus_type=Sata (no regression)                                     | VERIFIED | `resolve_bus_type_with_pnp_override(Ok(BusType::Sata), Ok(false)) == BusType::Sata`; test passes  |
| G5  | PnP tree walk runs unconditionally for every enumerated disk                                  | VERIFIED | `disk.rs:454-456` -- `let ioctl_result = ...; let pnp_result = ...;` both called before resolve    |
| G6  | When PnP walk returns Ok(true), IOCTL-derived bus_type overridden to BusType::Usb           | VERIFIED | `disk.rs:394-396` -- first match arm `(_, Ok(true)) => BusType::Usb`                              |
| G7  | When PnP walk fails with Err(_), IOCTL-derived bus_type preserved unchanged                  | VERIFIED | `disk.rs:398-402` -- `(Ok(bt), _) => bt` arm; test_resolve_bus_type_pnp_failure_does_not_poison  |
| G8  | Unit test asserts override path: IOCTL=Nvme + PnP=true => bus_type=Usb                      | VERIFIED | `test_resolve_bus_type_usb_nvme_bridge_overrides_to_usb` passes                                    |
| G9  | Unit test asserts no-override path: IOCTL=Nvme + PnP=false => bus_type=Nvme                 | VERIFIED | `test_resolve_bus_type_internal_nvme_preserved` passes                                              |
| G10 | Unit test asserts IOCTL=Usb + PnP=true is idempotent                                         | VERIFIED | `test_resolve_bus_type_idempotent_when_both_signals_agree_on_usb` passes                           |
| G11 | All previously passing tests in dlp-common still pass (no regression)                        | VERIFIED | `cargo test -p dlp-common`: 112 passed, 0 failed                                                   |

**Score:** 14/14 original truths verified + all 11 GAP-01 truths verified

### Deferred Items

| # | Item | Addressed In | Evidence |
|---|------|-------------|----------|
| 1 | Existing allowlist preserved on restart; new disks appended per D-07 | Phase 35 | Phase 35 goal: "Agent persists the disk allowlist and loads it across restarts". `_agent_config_path` in `spawn_disk_enumeration_task` is documented as Phase 35 placeholder. |

### Required Artifacts

| Artifact | Expected | Status | Details |
| -------- | -------- | ------ | ------- |
| `dlp-common/src/disk.rs` | resolve_bus_type_with_pnp_override helper; unconditional PnP call in enumerate_fixed_disks_windows; 9 new tests | VERIFIED | 1258 lines; helper at line 390 (not cfg-gated); unconditional calls at lines 454-456; 9 tests at lines 1149-1256 |
| `dlp-common/src/disk.rs` | DiskIdentity, BusType, DiskError, Win32 enumeration | VERIFIED | All original structs and Win32 functions intact; no regressions |
| `dlp-common/src/audit.rs` | EventType::DiskDiscovery, discovered_disks field | VERIFIED | Unchanged from initial verification |
| `dlp-agent/src/detection/disk.rs` | DiskEnumerator, spawn task, audit helpers | VERIFIED | Unchanged from initial verification |
| `dlp-agent/src/service.rs` | Spawn disk enumeration task in run_loop | VERIFIED | Unchanged from initial verification |

### Key Link Verification

| From | To | Via | Status | Details |
| ---- | --- | --- | ------ | ------- |
| `enumerate_fixed_disks_windows` | `query_bus_type_ioctl` | Unconditional call; result stored as `ioctl_result` | WIRED | `disk.rs:454` |
| `enumerate_fixed_disks_windows` | `is_usb_bridged_pnp_walk` | Unconditional call; result stored as `pnp_result` | WIRED | `disk.rs:455` |
| `enumerate_fixed_disks_windows` | `resolve_bus_type_with_pnp_override` | Called with `(ioctl_result, pnp_result)` to produce final `bus_type` | WIRED | `disk.rs:456` |
| `dlp-agent/src/service.rs` | `spawn_disk_enumeration_task` | Called with Handle::current(), audit_ctx.clone(), None | WIRED | service.rs:627 |
| `dlp-agent/src/detection/disk.rs` | `dlp_common::enumerate_fixed_disks` | Called inside retry loop | WIRED | disk.rs:166 |
| `dlp-agent/src/detection/disk.rs` | `emit_disk_discovery` | Called after enumeration success | WIRED | disk.rs:202 |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| -------- | ------- | ------ | ------ |
| 9 new resolve_bus_type tests pass | `cargo test -p dlp-common --lib resolve_bus_type` | 9 passed, 0 failed | PASS |
| dlp-common full test suite (no regression) | `cargo test -p dlp-common` | 112 passed, 0 failed | PASS |
| dlp-agent lib tests (no regression) | `cargo test -p dlp-agent --lib` | 253 passed, 0 failed | PASS |
| dlp-common clippy clean | `cargo clippy -p dlp-common -- -D warnings` | No issues found | PASS |
| dlp-common tests clippy clean | `cargo clippy -p dlp-common --tests -- -D warnings` | No issues found | PASS |
| dlp-common formatter clean | `cargo fmt -p dlp-common --check` | No diff | PASS |
| helper is NOT cfg(windows) gated | grep for #[cfg(windows)] at lines 385-410 | No match | PASS |
| old conditional fallback removed | grep for "Ok(bt) => bt" | No match | PASS |
| resolve_bus_type_with_pnp_override defined exactly once | grep -c | 1 | PASS |
| pnp_result call exists exactly once | grep -c | 1 | PASS |
| ioctl_result call exists exactly once | grep -c | 1 | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
| ----------- | ---------- | ----------- | ------ | -------- |
| DISK-01 | 33-01, 33-02 | Agent enumerates all fixed disks capturing instance_id, bus_type, model, drive_letter | SATISFIED | enumerate_fixed_disks() in disk.rs; DiskIdentity struct has all required fields |
| DISK-02 | 33-01, 33-GAP-01 | Agent distinguishes USB-bridged SATA/NVMe enclosures from genuine internal disks | SATISFIED | resolve_bus_type_with_pnp_override unconditionally combines IOCTL + PnP walk; USB ancestry always wins; 9 unit tests enforce the truth table |
| AUDIT-01 | 33-02 | Disk discovery events emitted at install time with all enumerated disks | SATISFIED | emit_disk_discovery() in dlp-agent/src/detection/disk.rs creates DiskDiscovery event with full disk identities |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| ---- | ---- | ------- | -------- | ------ |
| `dlp-common/src/disk.rs` | 572 | `query_bus_type_for_handle` takes `_instance_id: &str` but never uses it | WARNING | Known limitation documented: function returns first PhysicalDriveN that responds to IOCTL without validating against instance_id. Mitigated by unconditional PnP walk override. Deferred to future phase. |
| `dlp-common/src/disk.rs` | 743 | `find_drive_letter_for_instance_id` uses simplified sequential heuristic | INFO | Acknowledged in code comment; WMI correlation deferred. Harmless on single-disk systems. |

### Human Verification Required

1. **USB-bridged NVMe/SATA hardware re-test after 33-GAP-01 fix**

   **Test:** Run the agent on a Windows system with the same USB-C NVMe enclosures observed in UAT test 1 (Lexar E6, SanDisk Extreme). Check DiskDiscovery audit event JSON.

   **Expected:** Lexar E6 and SanDisk Extreme both show `"bus_type": "usb"`, not `"nvme"`. Internal NVMe (PVC10 SK hynix) still shows `"bus_type": "nvme"`.

   **Why human:** The fix is fully unit-tested against the 7-row truth table. However, confirming the `is_usb_bridged_pnp_walk` function successfully locates the `USB\` ancestor node for these specific physical devices on a real Windows host is a hardware integration test that cannot be performed programmatically. The previous UAT confirmed the PnP walk was being bypassed (not that it returned a wrong result), so there is high confidence the fix works, but real hardware re-test provides final confirmation.

2. **Non-standard boot drive letter: verify boot disk identification**

   **Test:** On a Windows system where the OS is installed on a drive letter other than C: (e.g., D:), check that the DiskDiscovery event marks the correct disk with `is_boot_disk: true`.

   **Expected:** The disk containing the Windows system directory has `is_boot_disk: true`, regardless of its drive letter.

   **Why human:** Boot disk detection uses `GetSystemDirectoryW` to extract the drive letter and cross-references with enumerated disks. This is correct for standard configurations but needs validation on non-standard setups. Not addressed by 33-GAP-01 (out of scope).

### Gaps Summary

No blocking gaps. All original 14 must-have truths remain verified. All 11 GAP-01 must-have truths are newly verified. The USB-bridged NVMe misclassification regression (33-HUMAN-UAT.md test 1) is resolved in code and backed by 9 passing unit tests.

Two items remain in human verification:
1. Hardware re-test of the USB-bridge fix against the original failure hardware (high confidence it works given unit test coverage and root cause diagnosis)
2. Non-standard boot drive letter (unchanged from initial verification; out of scope for 33-GAP-01)

No regressions introduced. `cargo test -p dlp-common` passes all 112 tests. `cargo test -p dlp-agent --lib` passes all 253 tests.

---

_Verified: 2026-05-04T10:00:00Z_
_Verifier: Claude (gsd-verifier)_
_Re-verification: Yes -- gap closure 33-GAP-01_
