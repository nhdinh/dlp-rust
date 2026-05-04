---
phase: 33-disk-enumeration
plan: GAP-01
status: complete
completed: 2026-05-04
---

# 33-GAP-01: USB-Bridge Bus-Type Override Fix

## What Was Built

Added `resolve_bus_type_with_pnp_override` — a pure, platform-agnostic helper function in `dlp-common/src/disk.rs` that combines two independent bus-type signals into a final `BusType`:

1. **IOCTL primary** (`query_bus_type_ioctl`) — fast but has a known correlation limitation (returns first PhysicalDriveN that responds, without validating against `instance_id`)
2. **PnP tree walk** (`is_usb_bridged_pnp_walk`) — authoritative for USB ancestry detection

`enumerate_fixed_disks_windows` now calls **both** signals unconditionally for every enumerated disk and routes them through the helper. Previously, the PnP walk was only invoked when IOCTL failed — allowing USB NVMe bridges (UAS / uaspstor) to permanently bypass USB detection and surface as `bus_type=nvme`.

## Files Modified

- `dlp-common/src/disk.rs` — added helper, refactored call site, updated doc comments, added 9 tests

## Key Changes

### New helper: `resolve_bus_type_with_pnp_override`

Truth table implemented:

| `ioctl_result` | `pnp_result` | Output  | Rationale |
|----------------|--------------|---------|-----------|
| `Ok(Usb)` | any | `Usb` | Idempotent |
| `Ok(other)` | `Ok(true)` | `Usb` | Override — the bug fix |
| `Ok(other)` | `Ok(false)` | `other` | Preserve IOCTL primary |
| `Ok(other)` | `Err(_)` | `other` | PnP failure must not poison correct IOCTL |
| `Err(_)` | `Ok(true)` | `Usb` | PnP rescue path |
| `Err(_)` | `Ok(false)` | `Unknown` | No signal from either |
| `Err(_)` | `Err(_)` | `Unknown` | Both failed |

NOT gated behind `#[cfg(windows)]` — callable from any platform so tests run everywhere.

### Fixed call site in `enumerate_fixed_disks_windows`

Replaced:
```rust
let bus_type = match query_bus_type_ioctl(&instance_id) {
    Ok(bt) => bt,
    Err(_) => match is_usb_bridged_pnp_walk(&instance_id) { ... }
};
```

With:
```rust
let ioctl_result = query_bus_type_ioctl(&instance_id);
let pnp_result = is_usb_bridged_pnp_walk(&instance_id);
let bus_type = resolve_bus_type_with_pnp_override(ioctl_result, pnp_result);
```

## Tests Added

9 unit tests covering the full truth-table matrix:

- `test_resolve_bus_type_usb_nvme_bridge_overrides_to_usb` — regression fix (UAT test 1)
- `test_resolve_bus_type_usb_sata_bridge_overrides_to_usb` — regression fix variant
- `test_resolve_bus_type_internal_nvme_preserved` — no regression
- `test_resolve_bus_type_internal_sata_preserved` — no regression
- `test_resolve_bus_type_idempotent_when_both_signals_agree_on_usb` — sanity
- `test_resolve_bus_type_pnp_failure_does_not_poison_correct_ioctl` — critical safety
- `test_resolve_bus_type_pnp_rescues_when_ioctl_fails` — PnP rescue path
- `test_resolve_bus_type_both_signals_negative_yields_unknown`
- `test_resolve_bus_type_both_signals_failed_yields_unknown`

## Verification Results

| Check | Result |
|-------|--------|
| `cargo check -p dlp-common` | PASS — 0 warnings |
| `cargo clippy -p dlp-common -- -D warnings` | PASS |
| `cargo clippy -p dlp-common --tests -- -D warnings` | PASS |
| `cargo fmt -p dlp-common --check` | PASS |
| `cargo test -p dlp-common --lib resolve_bus_type` | 9/9 PASS |
| `cargo test -p dlp-common` | 112/112 PASS |
| `cargo test -p dlp-agent --lib` | 253/253 PASS |

## Self-Check: PASSED

All acceptance criteria met:
- `resolve_bus_type_with_pnp_override` present (1 definition)
- `let pnp_result = is_usb_bridged_pnp_walk` in enumeration body (unconditional)
- `let ioctl_result = query_bus_type_ioctl` in enumeration body
- Helper called with both results in enumeration body
- Old conditional `Ok(bt) => bt,` match arm removed
- Helper NOT gated behind `#[cfg(windows)]`
- All 9 test functions present and passing
- No compiler warnings, no clippy lints, formatter clean
