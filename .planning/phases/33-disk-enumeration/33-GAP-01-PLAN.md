---
phase: 33-disk-enumeration
plan: GAP-01
type: execute
wave: 3
gap_closure: true
depends_on:
  - 33-01-PLAN.md
  - 33-02-PLAN.md
files_modified:
  - dlp-common/src/disk.rs
autonomous: true
requirements:
  - DISK-02
must_haves:
  truths:
    - "USB-bridged NVMe enclosures are reported with bus_type=Usb (not Nvme)"
    - "USB-bridged SATA enclosures are reported with bus_type=Usb (not Sata)"
    - "Internal NVMe disks remain bus_type=Nvme (no regression)"
    - "Internal SATA disks remain bus_type=Sata (no regression)"
    - "PnP tree walk runs unconditionally for every enumerated disk -- not only on IOCTL failure"
    - "When PnP walk returns Ok(true) for USB ancestry, the IOCTL-derived bus_type is overridden to BusType::Usb"
    - "When PnP walk fails with Err(_), the IOCTL-derived bus_type is preserved unchanged (PnP failures must not poison correct IOCTL results)"
    - "Unit test asserts override path: synthetic IOCTL=Nvme + PnP=true => final bus_type=Usb"
    - "Unit test asserts no-override path: synthetic IOCTL=Nvme + PnP=false => final bus_type=Nvme"
    - "Unit test asserts pre-existing IOCTL=Usb result is preserved when PnP also returns true (idempotent)"
    - "All previously passing tests in dlp-common still pass (no regression)"
  artifacts:
    - path: "dlp-common/src/disk.rs"
      provides: "enumerate_fixed_disks_windows with unconditional PnP override; resolve_bus_type_with_pnp_override helper; new unit tests covering USB-bridge override matrix"
      min_lines: 1100
  key_links:
    - from: "dlp-common/src/disk.rs::enumerate_fixed_disks_windows"
      to: "dlp-common/src/disk.rs::is_usb_bridged_pnp_walk"
      via: "Unconditional call after IOCTL bus type resolution; override applied when PnP returns Ok(true)"
    - from: "dlp-common/src/disk.rs::enumerate_fixed_disks_windows"
      to: "dlp-common/src/disk.rs::resolve_bus_type_with_pnp_override"
      via: "Single helper function combines IOCTL primary with PnP-walk override (testable in isolation)"
---

<objective>
Fix the USB-bridged NVMe/SATA detection regression observed during Phase 33 UAT (test 1, severity major). Currently `enumerate_fixed_disks_windows` only invokes the PnP tree-walk fallback (`is_usb_bridged_pnp_walk`) on the `Err(_)` branch of `query_bus_type_ioctl`. Because `query_bus_type_ioctl` iterates `\\.\PhysicalDrive0..31` and returns the **first** successful IOCTL result without correlating the handle to the requested `instance_id`, every disk receives the bus type of `PhysicalDrive0` (typically internal NVMe). This poisons the result for USB-bridged NVMe enclosures (Lexar E6, SanDisk Extreme), which then surface as `bus_type="nvme"` instead of `"usb"`.

This plan implements the **lower-risk override fix** (per UAT diagnosis suggestion): keep `query_bus_type_ioctl` as the primary bus-type source for non-USB types (Nvme, Sata, Scsi, Unknown) and run `is_usb_bridged_pnp_walk` **unconditionally** for every enumerated disk. When the PnP walk returns `Ok(true)`, override the IOCTL-derived `BusType` to `BusType::Usb`. When the PnP walk returns `Err(_)`, preserve the IOCTL result unchanged so PnP failures never poison correct IOCTL output. The existing accurate-correlation work (mapping PhysicalDriveN handles to instance_ids via `IOCTL_STORAGE_GET_DEVICE_NUMBER`) remains a deferred follow-up.

Purpose: Restore correct bus_type classification for USB-bridged NVMe/SATA enclosures so Phase 36 enforcement (which keys allow/block decisions on `bus_type` in addition to `instance_id`) treats USB-attached drives as removable, not as trusted internal storage.

Output: A revised `dlp-common/src/disk.rs` where `enumerate_fixed_disks_windows` always consults the PnP tree walk and overrides USB ancestry on top of any IOCTL result, plus three new unit tests covering the override matrix.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/phases/33-disk-enumeration/33-CONTEXT.md
@.planning/phases/33-disk-enumeration/33-VERIFICATION.md
@.planning/phases/33-disk-enumeration/33-HUMAN-UAT.md
@.planning/phases/33-disk-enumeration/33-01-PLAN.md
@.planning/phases/33-disk-enumeration/33-01-SUMMARY.md
@dlp-common/src/disk.rs

<interfaces>
<!-- Existing functions in dlp-common/src/disk.rs the executor will modify or call. -->

```rust
// Public API (unchanged signatures):
pub fn enumerate_fixed_disks() -> Result<Vec<DiskIdentity>, DiskError>;
pub fn is_usb_bridged(instance_id: &str) -> Result<bool, DiskError>;
pub fn get_boot_drive_letter() -> Option<char>;

// Existing private Windows functions (call sites change; signatures unchanged):
#[cfg(windows)]
fn enumerate_fixed_disks_windows() -> Result<Vec<DiskIdentity>, DiskError>;

#[cfg(windows)]
fn query_bus_type_ioctl(instance_id: &str) -> Result<BusType, DiskError>;

#[cfg(windows)]
fn is_usb_bridged_pnp_walk(instance_id: &str) -> Result<bool, DiskError>;

// Domain types (unchanged):
pub enum BusType { Unknown, Sata, Nvme, Usb, Scsi }
pub struct DiskIdentity { /* instance_id, bus_type, model, drive_letter, ... */ }
pub enum DiskError { WmiQueryFailed, SetupDiFailed, IoctlFailed, PnpWalkFailed, DeviceOpenFailed, InvalidInstanceId }
```

<!-- Current (buggy) call site in enumerate_fixed_disks_windows (lines ~404-414):
let bus_type = match query_bus_type_ioctl(&instance_id) {
    Ok(bt) => bt,
    Err(_) => match is_usb_bridged_pnp_walk(&instance_id) {
        Ok(true) => BusType::Usb,
        _ => BusType::Unknown,
    },
};
-->

<!-- Target (fixed) shape -- factored into a pure helper for unit-test isolation:
fn resolve_bus_type_with_pnp_override(
    ioctl_result: Result<BusType, DiskError>,
    pnp_result: Result<bool, DiskError>,
) -> BusType {
    // Truth table:
    //   ioctl=Ok(Usb)   pnp=any        -> Usb           (idempotent)
    //   ioctl=Ok(other) pnp=Ok(true)   -> Usb           (override - the bug fix)
    //   ioctl=Ok(other) pnp=Ok(false)  -> other         (preserve IOCTL primary)
    //   ioctl=Ok(other) pnp=Err(_)     -> other         (PnP failure must not poison)
    //   ioctl=Err(_)    pnp=Ok(true)   -> Usb           (PnP rescue path)
    //   ioctl=Err(_)    pnp=Ok(false)  -> Unknown       (no signal from either)
    //   ioctl=Err(_)    pnp=Err(_)     -> Unknown       (both failed)
}
-->

From `dlp-common/src/disk.rs` test module (existing patterns to mirror):
- Tests use `#[test]` and `#[cfg(test)] mod tests { use super::*; ... }`
- Platform-specific tests use `#[cfg(windows)]` / `#[cfg(not(windows))]`
- BusType assertions use `assert_eq!(BusType::from(7), BusType::Usb)` style
- The new `resolve_bus_type_with_pnp_override` helper takes `Result<BusType, DiskError>` and `Result<bool, DiskError>` so tests can synthesize all 7 truth-table rows without any Win32 calls
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Refactor bus-type resolution into a pure, unit-testable helper and call PnP walk unconditionally in enumerate_fixed_disks_windows</name>
  <files>dlp-common/src/disk.rs</files>
  <read_first>
    dlp-common/src/disk.rs
    .planning/phases/33-disk-enumeration/33-HUMAN-UAT.md
    .planning/phases/33-disk-enumeration/33-VERIFICATION.md
  </read_first>
  <action>
1. **Add a new private helper function** `resolve_bus_type_with_pnp_override` directly above `enumerate_fixed_disks_windows` (i.e., insert at the top of the Windows implementation block, around line 369). The helper is the **single decision point** for combining the two signals and is intentionally platform-agnostic (no `#[cfg(windows)]`) so it can be unit-tested on Linux/macOS as well as Windows.

   ```rust
   /// Combine the IOCTL bus-type primary signal with the PnP tree-walk USB
   /// ancestry signal into a final `BusType`.
   ///
   /// This helper exists to fix the USB-bridged NVMe/SATA enclosure regression
   /// reported in Phase 33 UAT (33-HUMAN-UAT.md test 1). The original code only
   /// consulted the PnP walk when IOCTL failed; because `query_bus_type_ioctl`
   /// returns the first successful PhysicalDriveN IOCTL response without
   /// validating the handle corresponds to the requested `instance_id`, USB
   /// NVMe bridges (UAS / uaspstor) returned `BusTypeNvme` and the PnP fallback
   /// was permanently bypassed.
   ///
   /// # Truth Table
   ///
   /// | `ioctl_result`   | `pnp_result`     | Output         | Rationale                                   |
   /// |------------------|------------------|----------------|---------------------------------------------|
   /// | `Ok(Usb)`        | any              | `Usb`          | IOCTL already correct; idempotent override  |
   /// | `Ok(other)`      | `Ok(true)`       | `Usb`          | PnP override -- the bug fix                 |
   /// | `Ok(other)`      | `Ok(false)`      | `other`        | Preserve IOCTL primary (Sata/Nvme/Scsi)     |
   /// | `Ok(other)`      | `Err(_)`         | `other`        | PnP failure must not poison correct IOCTL   |
   /// | `Err(_)`         | `Ok(true)`       | `Usb`          | PnP rescues when IOCTL handle could not open|
   /// | `Err(_)`         | `Ok(false)`      | `Unknown`      | Neither signal indicates a bus type         |
   /// | `Err(_)`         | `Err(_)`         | `Unknown`      | Both signals failed; classify as unknown    |
   fn resolve_bus_type_with_pnp_override(
       ioctl_result: Result<BusType, DiskError>,
       pnp_result: Result<bool, DiskError>,
   ) -> BusType {
       match (ioctl_result, pnp_result) {
           // PnP confirms USB ancestry -- always overrides any IOCTL value.
           (_, Ok(true)) => BusType::Usb,
           // IOCTL succeeded; PnP either disagrees (false) or failed (Err).
           // Preserve the IOCTL primary -- PnP failures must NEVER downgrade
           // a correct IOCTL classification.
           (Ok(bt), _) => bt,
           // Both signals failed.
           (Err(_), _) => BusType::Unknown,
       }
   }
   ```

   IMPORTANT: This helper MUST NOT be gated behind `#[cfg(windows)]`. It is pure logic over `Result` values and the test suite (which runs on the developer's Windows host AND any non-Windows CI) must be able to call it directly.

2. **Modify `enumerate_fixed_disks_windows`** (lines ~404-414). Replace the existing `match query_bus_type_ioctl(&instance_id) { ... }` block with:

   ```rust
   // Resolve bus type with two independent signals:
   //   1. IOCTL_STORAGE_QUERY_PROPERTY -- primary, fast, accurate for non-USB
   //      bus types (Sata, Nvme, Scsi). Currently has a known correlation
   //      limitation: returns first successful PhysicalDriveN handle without
   //      validating it matches `instance_id` (tracked separately).
   //   2. PnP tree walk -- authoritative for USB ancestry detection. UAS /
   //      uaspstor NVMe bridges report `BusTypeNvme` via IOCTL but expose a
   //      `USB\` ancestor in the PnP device tree.
   //
   // The PnP walk runs UNCONDITIONALLY (not only on IOCTL Err) so that USB
   // ancestry overrides any wrong-but-successful IOCTL result. See
   // `resolve_bus_type_with_pnp_override` for the full truth table and the
   // 33-HUMAN-UAT.md test 1 diagnosis.
   let ioctl_result = query_bus_type_ioctl(&instance_id);
   let pnp_result = is_usb_bridged_pnp_walk(&instance_id);
   let bus_type = resolve_bus_type_with_pnp_override(ioctl_result, pnp_result);
   ```

   Both calls must execute for every iteration of the SetupDi enumeration loop. Do NOT short-circuit either call -- the cost of one extra `CM_Locate_DevNodeW` + up to 16 `CM_Get_Parent` calls per disk is negligible compared to the IOCTL itself.

3. **Update the doc comment block at the top of `query_bus_type_ioctl`** (currently lines ~474-479) to explicitly document the known correlation limitation so future readers understand WHY the PnP override exists:

   Replace:
   ```rust
   /// Query the bus type for a disk via `IOCTL_STORAGE_QUERY_PROPERTY`.
   ///
   /// Opens the disk via `\\.\PhysicalDriveN` where N is derived from the
   /// SetupDi enumeration order (0, 1, 2...). The enumeration order typically
   /// matches PhysicalDrive numbering.
   ```

   With:
   ```rust
   /// Query the bus type for a disk via `IOCTL_STORAGE_QUERY_PROPERTY`.
   ///
   /// Iterates `\\.\PhysicalDrive0..31`, opens the first handle that succeeds,
   /// sends `IOCTL_STORAGE_QUERY_PROPERTY` with `StorageDeviceProperty`, and
   /// returns the `STORAGE_DEVICE_DESCRIPTOR.BusType` field.
   ///
   /// # Known Limitation
   ///
   /// This function does NOT correlate the opened PhysicalDriveN handle to
   /// the requested `instance_id`. It returns the bus type of whichever
   /// PhysicalDriveN responds first to IOCTL, which may not be the disk
   /// the caller intended. The caller MUST combine this result with
   /// `is_usb_bridged_pnp_walk` via `resolve_bus_type_with_pnp_override`
   /// so that PnP-confirmed USB ancestry overrides any wrong-but-successful
   /// IOCTL result. See Phase 33 UAT diagnosis (33-HUMAN-UAT.md test 1).
   ```

4. **Update the doc comment of `is_usb_bridged_windows`** (currently lines ~583-587) to note the new authoritative role of `resolve_bus_type_with_pnp_override`:

   Replace:
   ```rust
   /// Windows-specific USB-bridged detection.
   ///
   /// First tries `IOCTL_STORAGE_QUERY_PROPERTY`; if that indicates USB,
   /// returns `true`. Otherwise falls back to PnP tree walk.
   ```

   With:
   ```rust
   /// Windows-specific USB-bridged detection (public API path).
   ///
   /// First tries `IOCTL_STORAGE_QUERY_PROPERTY`; if that indicates USB,
   /// returns `true`. Otherwise falls back to PnP tree walk.
   ///
   /// NOTE: `enumerate_fixed_disks_windows` does NOT call this function
   /// directly. It calls `query_bus_type_ioctl` and `is_usb_bridged_pnp_walk`
   /// independently and combines them via `resolve_bus_type_with_pnp_override`
   /// to ensure USB ancestry overrides wrong-but-successful IOCTL results.
   /// See Phase 33 UAT diagnosis (33-HUMAN-UAT.md test 1).
   ```

5. **Verify the file still compiles cleanly** with no warnings:
   ```
   cargo check -p dlp-common
   cargo clippy -p dlp-common -- -D warnings
   ```

   Expected: zero warnings, zero clippy lints.

6. **Verify all existing tests still pass** (no regression in any of the 13 existing tests in `disk.rs` plus tests in `audit.rs`):
   ```
   cargo test -p dlp-common --lib
   ```

   Expected: all currently-passing tests continue to pass.
  </action>
  <acceptance_criteria>
    - `grep -c "fn resolve_bus_type_with_pnp_override" dlp-common/src/disk.rs` == 1
    - `grep -c "let pnp_result = is_usb_bridged_pnp_walk" dlp-common/src/disk.rs` == 1
    - `grep -c "let ioctl_result = query_bus_type_ioctl" dlp-common/src/disk.rs` == 1
    - `grep -c "resolve_bus_type_with_pnp_override(ioctl_result, pnp_result)" dlp-common/src/disk.rs` == 1
    - The new helper `resolve_bus_type_with_pnp_override` is NOT gated behind `#[cfg(windows)]` (it must be callable from non-Windows test runs)
    - The original `match query_bus_type_ioctl(&instance_id) { Ok(bt) => bt, Err(_) => ... }` block in `enumerate_fixed_disks_windows` is REMOVED (the conditional fallback path is replaced)
    - `cargo check -p dlp-common` passes with zero warnings
    - `cargo clippy -p dlp-common -- -D warnings` passes
    - `cargo fmt -p dlp-common --check` passes
  </acceptance_criteria>
  <verify>
    <automated>cargo check -p dlp-common &amp;&amp; cargo clippy -p dlp-common -- -D warnings &amp;&amp; cargo fmt -p dlp-common --check</automated>
  </verify>
  <done>`enumerate_fixed_disks_windows` calls both `query_bus_type_ioctl` and `is_usb_bridged_pnp_walk` for every enumerated disk and combines the two signals through the new pure helper `resolve_bus_type_with_pnp_override`. PnP-confirmed USB ancestry overrides any wrong-but-successful IOCTL result. PnP failures do NOT poison correct IOCTL classifications. Doc comments on `query_bus_type_ioctl` and `is_usb_bridged_windows` document the override architecture and reference the UAT diagnosis. Compiles clean, clippy clean, formatted.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Add unit tests for resolve_bus_type_with_pnp_override covering the full truth-table matrix</name>
  <files>dlp-common/src/disk.rs</files>
  <read_first>
    dlp-common/src/disk.rs
  </read_first>
  <behavior>
    The 7-row truth table for `resolve_bus_type_with_pnp_override` must be exhaustively covered.

    - Test A: `Ok(Nvme) + Ok(true) -> Usb`     (the regression fix -- USB NVMe bridge)
    - Test B: `Ok(Sata) + Ok(true) -> Usb`     (regression fix -- USB SATA bridge)
    - Test C: `Ok(Nvme) + Ok(false) -> Nvme`   (genuine internal NVMe, no regression)
    - Test D: `Ok(Sata) + Ok(false) -> Sata`   (genuine internal SATA, no regression)
    - Test E: `Ok(Usb)  + Ok(true) -> Usb`     (idempotent -- both signals agree)
    - Test F: `Ok(Nvme) + Err(_)  -> Nvme`     (PnP failure must NOT poison IOCTL)
    - Test G: `Err(_)   + Ok(true) -> Usb`     (PnP rescue when IOCTL fails)
    - Test H: `Err(_)   + Ok(false) -> Unknown`(no signal from either path)
    - Test I: `Err(_)   + Err(_)   -> Unknown`(both signals failed)
  </behavior>
  <action>
1. **Add the following test functions to the existing `#[cfg(test)] mod tests { ... }` block** at the bottom of `dlp-common/src/disk.rs` (after `test_disk_identity_serializes_some_unknown_encryption_status_present` at line ~1071). All tests are platform-agnostic and run on every target (no `#[cfg(windows)]` gate).

   ```rust
   // ────────────────────────────────────────────────────────────────────────
   // resolve_bus_type_with_pnp_override -- USB-bridge override fix (33-GAP-01)
   //
   // These tests pin the truth table that fixes the Phase 33 UAT regression
   // (33-HUMAN-UAT.md test 1: USB-bridged NVMe enclosures reported as nvme).
   //
   // The helper is pure logic over Result values; no Win32 calls are made,
   // so the matrix runs on every platform.
   // ────────────────────────────────────────────────────────────────────────

   /// Helper: build a synthetic IoctlFailed error for test inputs.
   fn fake_ioctl_err() -> DiskError {
       DiskError::IoctlFailed("synthetic test error".to_string())
   }

   /// Helper: build a synthetic PnpWalkFailed error for test inputs.
   fn fake_pnp_err() -> DiskError {
       DiskError::PnpWalkFailed("synthetic test error".to_string())
   }

   #[test]
   fn test_resolve_bus_type_usb_nvme_bridge_overrides_to_usb() {
       // Regression fix for 33-HUMAN-UAT.md test 1:
       // UAS / uaspstor USB NVMe bridge reports BusTypeNvme via IOCTL
       // but PnP tree walk finds USB\ ancestor -> must classify as Usb.
       let result = resolve_bus_type_with_pnp_override(Ok(BusType::Nvme), Ok(true));
       assert_eq!(
           result,
           BusType::Usb,
           "USB-bridged NVMe enclosure must be classified as Usb when PnP confirms USB ancestry"
       );
   }

   #[test]
   fn test_resolve_bus_type_usb_sata_bridge_overrides_to_usb() {
       // Same regression fix variant: USB-bridged SATA enclosure.
       let result = resolve_bus_type_with_pnp_override(Ok(BusType::Sata), Ok(true));
       assert_eq!(
           result,
           BusType::Usb,
           "USB-bridged SATA enclosure must be classified as Usb when PnP confirms USB ancestry"
       );
   }

   #[test]
   fn test_resolve_bus_type_internal_nvme_preserved() {
       // No regression: genuine internal NVMe must remain Nvme when PnP walk
       // confirms the disk is NOT USB-attached.
       let result = resolve_bus_type_with_pnp_override(Ok(BusType::Nvme), Ok(false));
       assert_eq!(
           result,
           BusType::Nvme,
           "Internal NVMe must remain Nvme when PnP walk reports no USB ancestor"
       );
   }

   #[test]
   fn test_resolve_bus_type_internal_sata_preserved() {
       // No regression: genuine internal SATA must remain Sata.
       let result = resolve_bus_type_with_pnp_override(Ok(BusType::Sata), Ok(false));
       assert_eq!(
           result,
           BusType::Sata,
           "Internal SATA must remain Sata when PnP walk reports no USB ancestor"
       );
   }

   #[test]
   fn test_resolve_bus_type_idempotent_when_both_signals_agree_on_usb() {
       // Sanity: when IOCTL already says Usb and PnP also confirms Usb, the
       // result is Usb (no double-override, no downgrade).
       let result = resolve_bus_type_with_pnp_override(Ok(BusType::Usb), Ok(true));
       assert_eq!(result, BusType::Usb);
   }

   #[test]
   fn test_resolve_bus_type_pnp_failure_does_not_poison_correct_ioctl() {
       // Critical: a PnP walk failure must NOT downgrade a correct IOCTL
       // classification to Unknown. The IOCTL primary is preserved.
       let result = resolve_bus_type_with_pnp_override(Ok(BusType::Nvme), Err(fake_pnp_err()));
       assert_eq!(
           result,
           BusType::Nvme,
           "PnP walk Err must NOT poison correct IOCTL Nvme classification"
       );

       let result = resolve_bus_type_with_pnp_override(Ok(BusType::Sata), Err(fake_pnp_err()));
       assert_eq!(
           result,
           BusType::Sata,
           "PnP walk Err must NOT poison correct IOCTL Sata classification"
       );

       let result = resolve_bus_type_with_pnp_override(Ok(BusType::Scsi), Err(fake_pnp_err()));
       assert_eq!(
           result,
           BusType::Scsi,
           "PnP walk Err must NOT poison correct IOCTL Scsi classification"
       );
   }

   #[test]
   fn test_resolve_bus_type_pnp_rescues_when_ioctl_fails() {
       // PnP rescue path: when IOCTL cannot open any PhysicalDrive handle
       // but PnP walk still finds USB ancestry, the disk is Usb.
       let result = resolve_bus_type_with_pnp_override(Err(fake_ioctl_err()), Ok(true));
       assert_eq!(
           result,
           BusType::Usb,
           "PnP must rescue USB classification when IOCTL fails"
       );
   }

   #[test]
   fn test_resolve_bus_type_both_signals_negative_yields_unknown() {
       // Neither signal indicates anything: classify as Unknown so the
       // admin can investigate, never silently optimistic.
       let result = resolve_bus_type_with_pnp_override(Err(fake_ioctl_err()), Ok(false));
       assert_eq!(
           result,
           BusType::Unknown,
           "Both signals negative -> Unknown (never silently optimistic)"
       );
   }

   #[test]
   fn test_resolve_bus_type_both_signals_failed_yields_unknown() {
       // Both signals failed: Unknown.
       let result =
           resolve_bus_type_with_pnp_override(Err(fake_ioctl_err()), Err(fake_pnp_err()));
       assert_eq!(
           result,
           BusType::Unknown,
           "Both signals failed -> Unknown"
       );
   }
   ```

2. **Run the new tests in isolation** to confirm they all pass:
   ```
   cargo test -p dlp-common --lib resolve_bus_type
   ```

   Expected: 9 new tests, all passing.

3. **Run the full `dlp-common` test suite** to confirm no regression in any existing test:
   ```
   cargo test -p dlp-common
   ```

   Expected: previous count + 9 new tests, all passing.

4. **Run the full workspace test suite** to confirm no downstream regression in `dlp-agent` (which depends on `dlp-common::disk`):
   ```
   cargo test --all
   ```

   Expected: zero failures, zero panics.
  </action>
  <acceptance_criteria>
    - `grep -c "fn test_resolve_bus_type_usb_nvme_bridge_overrides_to_usb" dlp-common/src/disk.rs` == 1
    - `grep -c "fn test_resolve_bus_type_usb_sata_bridge_overrides_to_usb" dlp-common/src/disk.rs` == 1
    - `grep -c "fn test_resolve_bus_type_internal_nvme_preserved" dlp-common/src/disk.rs` == 1
    - `grep -c "fn test_resolve_bus_type_internal_sata_preserved" dlp-common/src/disk.rs` == 1
    - `grep -c "fn test_resolve_bus_type_idempotent_when_both_signals_agree_on_usb" dlp-common/src/disk.rs` == 1
    - `grep -c "fn test_resolve_bus_type_pnp_failure_does_not_poison_correct_ioctl" dlp-common/src/disk.rs` == 1
    - `grep -c "fn test_resolve_bus_type_pnp_rescues_when_ioctl_fails" dlp-common/src/disk.rs` == 1
    - `grep -c "fn test_resolve_bus_type_both_signals_negative_yields_unknown" dlp-common/src/disk.rs` == 1
    - `grep -c "fn test_resolve_bus_type_both_signals_failed_yields_unknown" dlp-common/src/disk.rs` == 1
    - `cargo test -p dlp-common --lib resolve_bus_type` reports 9 tests, 9 passed, 0 failed
    - `cargo test -p dlp-common` passes (no regression in any existing test)
    - `cargo test --all` passes (no downstream regression in dlp-agent or other crates)
    - `cargo clippy -p dlp-common --tests -- -D warnings` passes
  </acceptance_criteria>
  <verify>
    <automated>cargo test -p dlp-common --lib resolve_bus_type &amp;&amp; cargo test -p dlp-common &amp;&amp; cargo test --all &amp;&amp; cargo clippy -p dlp-common --tests -- -D warnings</automated>
  </verify>
  <done>Nine new unit tests in `dlp-common/src/disk.rs` exhaustively cover the truth table of `resolve_bus_type_with_pnp_override`. All 9 new tests pass. The full `dlp-common` test suite passes with no regression. The full workspace `cargo test --all` passes. Clippy on tests passes with zero warnings.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Win32 IOCTL -> bus_type field | Untrusted result -- IOCTL returns the descriptor of whichever PhysicalDriveN responded, not necessarily the requested disk |
| Win32 PnP tree (CM_*) -> USB ancestor signal | Trusted authoritative source for USB attachment classification |
| `bus_type` -> Phase 36 enforcement decision | Misclassification (NVMe vs Usb) directly affects allow/block outcome for unregistered fixed disks |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-33-GAP-01 | Tampering / Spoofing | USB-bridged NVMe enclosure presents as internal NVMe | mitigate | Run PnP tree walk unconditionally and override IOCTL bus_type when `USB\` ancestor is found. PnP tree walk uses kernel-managed device tree, which an attacker would need driver-level access to spoof |
| T-33-GAP-02 | Denial of Service | Malformed PnP node causes `CM_Get_Parent` to error in a loop | accept | The existing `is_usb_bridged_pnp_walk` already caps the walk at 16 levels and returns `Err(_)` on `CM_Locate_DevNodeW` failure. The new override logic preserves the IOCTL primary on PnP `Err(_)`, so PnP failures cannot poison correct IOCTL results or cause infinite loops |
| T-33-GAP-03 | Information Disclosure | Synthetic error strings in test helpers leak into production logs | accept | The `fake_ioctl_err()` / `fake_pnp_err()` helpers are inside `#[cfg(test)]` and never compile into release binaries |
| T-33-GAP-04 | Repudiation | Bus-type misclassification leads to silent allow of an unauthorized USB drive | mitigate | The truth-table tests T-A through T-I lock the override behavior; any future regression that re-introduces the conditional `Err(_) =>` fallback will fail tests A, B, F immediately |
</threat_model>

<verification>
1. `cargo check -p dlp-common` compiles with zero warnings
2. `cargo test -p dlp-common` passes -- no regression, 9 new tests added
3. `cargo test --all` passes -- no downstream regression in dlp-agent or other crates
4. `cargo clippy -p dlp-common -- -D warnings` passes
5. `cargo clippy -p dlp-common --tests -- -D warnings` passes
6. `cargo fmt -p dlp-common --check` passes
7. Grep confirms `resolve_bus_type_with_pnp_override` is called in `enumerate_fixed_disks_windows`
8. Grep confirms the original conditional `match query_bus_type_ioctl(&instance_id) { Ok(bt) => bt, Err(_) => ... }` block is REMOVED
9. Grep confirms PnP walk is invoked unconditionally (`let pnp_result = is_usb_bridged_pnp_walk` appears in the enumeration body, not inside an `Err(_)` arm)
10. The 9 new test functions are present and pass
</verification>

<success_criteria>
- `enumerate_fixed_disks_windows` invokes both `query_bus_type_ioctl` and `is_usb_bridged_pnp_walk` for every enumerated disk
- The pure helper `resolve_bus_type_with_pnp_override` is the single decision point combining the two signals
- USB-bridged NVMe enclosures (UAT regression hardware: Lexar E6, SanDisk Extreme) classify as `BusType::Usb`
- Internal NVMe / SATA disks remain `BusType::Nvme` / `BusType::Sata` (no regression)
- PnP walk failures (`Err(_)`) preserve the IOCTL primary -- they NEVER downgrade a correct classification to `Unknown`
- 9 new unit tests pin the full truth-table behavior; any future regression that re-introduces the bug will fail tests A, B, or F
- All existing tests in `dlp-common` and `dlp-agent` continue to pass
- Zero compiler warnings, zero clippy lints, formatter clean
- The fix is the lower-risk override approach per UAT diagnosis -- the larger structural fix (correlating PhysicalDriveN handles to instance_ids via `IOCTL_STORAGE_GET_DEVICE_NUMBER`) remains a deferred follow-up tracked separately
</success_criteria>

<output>
After completion, create `.planning/phases/33-disk-enumeration/33-GAP-01-SUMMARY.md`
</output>
