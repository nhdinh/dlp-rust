---
phase: 48-hook-dll-surface-expansion-crash-hardening-build-harness
plan: 04
subsystem: infra
tags: [hook-dll, x86, wow64, ci, build-harness, i686]

# Dependency graph
requires:
  - phase: 48-01
    provides: "HookInjector architecture detection and x86 dispatch"
  - phase: 48-02
    provides: "Unified hook DLL with expanded IAT surface"
  - phase: 48-03
    provides: "extract_nt_path with cfg(target_arch) offsets"
provides:
  - x86 DLL build from same source (i686-pc-windows-msvc)
  - Agent dispatches to correct DLL based on process architecture
  - CI matrix builds both x64 and x86 hook DLLs
  - Packed struct UB fix for x86 target compatibility
affects:
  - 48-01 (HookInjector uses x86 path)
  - 49 (universal injection relies on dual-arch DLLs)
  - 50 (classification cache runs in both architectures)

tech-stack:
  added: []
  patterns:
    - "Dual-arch DLL deployment: x64 + x86 from same source"
    - "Raw pointer arithmetic for packed struct field access on x86"
    - "CI matrix with rustup target installation"

key-files:
  created: []
  modified:
    - "dlp-agent/src/service.rs" - HookInjector constructed with x86 DLL path
    - ".github/workflows/build.yml" - CI installs i686 target and builds x86 DLL
    - "dlp-common/src/usb.rs" - Fixed packed struct UB for x86 build
    - "dlp-common/src/disk.rs" - Fixed packed struct UB for x86 build

key-decisions:
  - "Auto-fixed packed struct UB (Rule 1): SP_DEVICE_INTERFACE_DETAIL_DATA_W field access via raw pointer arithmetic instead of unaligned reference, required for i686-pc-windows-msvc target where the struct is packed"

patterns-established:
  - "Dual-arch DLL: agent loads both dlp_hook_dll.dll (x64) and dlp_hook_dll_x86.dll (x86)"
  - "CI target matrix: rust-toolchain step installs i686-pc-windows-msvc; separate build step for x86 DLL"
  - "Packed struct safety: use detail.add(1).cast::<u16>() instead of (*detail).DevicePath.as_ptr() on Windows packed structs"

requirements-completed:
  - BLOCK-04

# Metrics
duration: 20min
completed: 2026-05-15
---

# Phase 48 Plan 04: x86 Hook DLL Build + CI Integration Summary

**Dual-architecture hook DLL build harness: agent dispatches x64/x86 DLLs, CI builds both targets, x86-packed-struct UB fixed**

## Performance

- **Duration:** 20 min
- **Started:** 2026-05-15T17:18:21Z
- **Completed:** 2026-05-15T17:38:26Z
- **Tasks:** 3
- **Files modified:** 4

## Accomplishments

- Agent constructs HookInjector with both x64 and x86 DLL paths (service.rs)
- CI workflow installs i686-pc-windows-msvc target and builds x86 DLL (build.yml)
- x86 hook DLL builds successfully from same source with zero warnings
- Fixed packed struct UB in dlp-common (usb.rs, disk.rs) that only manifested on x86 target

## Task Commits

Each task was committed atomically:

1. **Task 1: Update service.rs to pass x86 DLL path to HookInjector** - `3166f85` (feat)
2. **Task 2: Add x86 target to CI build workflow** - `a9b0520` (feat)
3. **Task 3: Verify x86 build succeeds locally** - `f21b0f9` (fix) + `0d71a17` (style)

**Plan metadata:** pending (SUMMARY.md commit)

_Note: Task 3 had an additional style commit for rustfmt formatting across the workspace._

## Files Created/Modified

- `dlp-agent/src/service.rs` - HookInjector constructed with `Some(dll_path_x86)` in both main path and sync-client watcher thread; info! log includes both paths
- `.github/workflows/build.yml` - Added `targets: i686-pc-windows-msvc` to rust-toolchain step; added "Build x86 hook DLL" step with `-D warnings`
- `dlp-common/src/usb.rs` - Fixed packed struct UB: replaced `(*detail).DevicePath.as_ptr()` with `detail.add(1).cast::<u16>()`
- `dlp-common/src/disk.rs` - Same packed struct fix as usb.rs

## Decisions Made

- Auto-fixed packed struct UB during x86 build verification (deviation Rule 1) — the E0793 errors on `SP_DEVICE_INTERFACE_DETAIL_DATA_W` field access only manifest on i686-pc-windows-msvc where the struct is packed (1-byte aligned). Using raw pointer arithmetic (`detail.add(1).cast::<u16>()`) avoids unaligned reference UB on both x64 and x86.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed packed struct UB for x86 target compatibility**
- **Found during:** Task 3 (Verify x86 build succeeds locally)
- **Issue:** `cargo build --target i686-pc-windows-msvc -p dlp-hook-dll` failed with E0793 "reference to field of packed struct is unaligned" in `dlp-common/src/usb.rs:391` and `dlp-common/src/disk.rs:736`
- **Fix:** Replaced `(*detail).DevicePath.as_ptr()` with `detail.add(1).cast::<u16>()` in both files. The `SP_DEVICE_INTERFACE_DETAIL_DATA_W` struct is packed on x86 (1-byte aligned), making field references UB. Raw pointer arithmetic skips the `cbSize` (u32) header and directly accesses the variable-length `DevicePath` array.
- **Files modified:** `dlp-common/src/usb.rs`, `dlp-common/src/disk.rs`
- **Verification:** `cargo build --target i686-pc-windows-msvc -p dlp-hook-dll` succeeds; `RUSTFLAGS="-D warnings"` build passes; workspace tests pass (1798 passed)
- **Committed in:** `f21b0f9` (Task 3 commit)

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** Necessary correctness fix for x86 build. No scope creep.

## Issues Encountered

- x86 build revealed latent UB in packed struct field access that was benign on x64 but fatal on i686. Fixed with raw pointer arithmetic.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 48 complete (all 4 plans: 48-01, 48-02, 48-03, 48-04)
- Ready for Phase 49: Universal Injection (ETW Process Watcher + Allowlist + AppInit Fallback)
- x86 DLL artifact builds cleanly; agent dispatches correctly; CI validates both architectures

## Self-Check: PASSED

- [x] SUMMARY.md exists at `.planning/phases/48-hook-dll-surface-expansion-crash-hardening-build-harness/48-04-SUMMARY.md`
- [x] All task commits found in git history: 3166f85, a9b0520, f21b0f9, 0d71a17
- [x] Plan metadata commit found: bb3f42d
- [x] `cargo build --target i686-pc-windows-msvc -p dlp-hook-dll` succeeds
- [x] `cargo build --workspace` succeeds with zero warnings
- [x] `cargo test --workspace` passes (1798 passed, 11 ignored)
- [x] `cargo clippy --workspace -- -D warnings` clean
- [x] `cargo fmt --check` clean
- [x] `HookInjector::new` in service.rs uses `Some(x86_path)` not `None`
- [x] `extract_nt_path` uses `cfg(target_arch)` for correct x86 offsets

---
*Phase: 48-hook-dll-surface-expansion-crash-hardening-build-harness*
*Completed: 2026-05-15*
