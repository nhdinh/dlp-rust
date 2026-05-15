---
phase: 48-hook-dll-surface-expansion-crash-hardening-build-harness
plan: "05"
subsystem: build-harness
tags: [ci-cd, authenticode, signing, wix, installer, release]
dependency_graph:
  requires: [48-03, 48-04]
  provides: [BLOCK-10]
  affects: [.github/workflows/release.yml, installer/DLPAgent.wxs]
tech-stack:
  added: [GitHub Actions, signtool, WiX v4]
  patterns: [release-tag-trigger, dual-timestamp-fallback, per-binary-failure-tracking]
key-files:
  created:
    - .github/workflows/release.yml
  modified:
    - installer/DLPAgent.wxs
decisions:
  - "Removed dlp-e2e.exe from signing list: dlp-e2e is a library crate (lib.rs) producing libdlp_e2e.rlib, not an executable. The plan incorrectly listed it as a signable binary."
  - "Workflow signs 6 binaries (4 EXEs + 2 DLLs), not 7 as originally planned."
  - "x86 DLL source path uses compiler output name dlp_hook_dll.dll; WiX Name attribute renames to dlp_hook_dll_x86.dll at install time."
metrics:
  duration: "~8 minutes"
  completed_date: "2026-05-15"
---

# Phase 48 Plan 05: Authenticode Signing Pipeline + WiX Installer Update Summary

## One-liner

Created a GitHub Actions release workflow that builds x64/x86 hook DLLs, Authenticode-signs 6 binaries with DigiCert/Sectigo timestamp fallback, verifies signatures as a blocking gate, and uploads artifacts; updated the WiX installer to package both DLLs.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create release.yml with build, sign, and verify steps | fd566bf | `.github/workflows/release.yml` |
| 2 | Update installer to package both x64 and x86 DLLs | 4cd869a | `installer/DLPAgent.wxs` |
| 3 | Verify workflow syntax and installer validity | 38c7f2b | `.github/workflows/release.yml` |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed dlp-e2e.exe from signing list**
- **Found during:** Task 3 verification
- **Issue:** The plan listed `dlp-e2e.exe` as the 7th binary to sign, but `dlp-e2e` is a library crate (`lib.rs`) that produces `libdlp_e2e.rlib`, not an executable. No `dlp-e2e.exe` artifact is produced by `cargo build`.
- **Fix:** Removed `dlp-e2e.exe` from all four locations in `release.yml`: primary signing array, fallback signing array, verify array, and upload-artifact path list.
- **Files modified:** `.github/workflows/release.yml`
- **Commit:** `38c7f2b`
- **Impact:** Workflow now signs 6 binaries (4 EXEs + 2 DLLs) instead of 7. No functional change to the signing process.

## Verification Results

- `release.yml`: Structurally validated (all required elements present: checkout, toolchain, cache, build steps, signtool sign x2, signtool verify /pa, upload-artifact@v4)
- `DLPAgent.wxs`: XML parsing valid
- `cargo fmt --check`: Passes (no output)
- Legacy reference scan: No `dlp-cloud-hook.dll` references found
- Local release builds: All artifacts produced successfully
  - `target/release/dlp-agent.exe` (13.1M)
  - `target/release/dlp-user-ui.exe` (5.2M)
  - `target/release/dlp-admin-cli.exe` (7.1M)
  - `target/release/dlp-server.exe` (14.8M)
  - `target/x86_64-pc-windows-msvc/release/dlp_hook_dll.dll` (208.5K)
  - `target/i686-pc-windows-msvc/release/dlp_hook_dll.dll` (178.0K)

## Threat Model Compliance

| Threat ID | Category | Component | Disposition | Status |
|-----------|----------|-----------|-------------|--------|
| T-48-14 | Repudiation | release.yml | Mitigate: `signtool verify /pa` blocking gate | Implemented |
| T-48-15 | Denial of Service | release.yml | Mitigate: DigiCert primary + Sectigo fallback | Implemented |
| T-48-16 | Information Disclosure | release.yml | Mitigate: PFX password from GitHub secrets only | Implemented |
| T-48-17 | Tampering | release.yml | Mitigate: Per-binary failure tracking, verify gate | Implemented |

## Known Stubs

None. All files are fully wired with no placeholder data.

## Threat Flags

None. No new security-relevant surface introduced beyond the planned signing pipeline.

## Self-Check: PASSED

- [x] `.github/workflows/release.yml` exists
- [x] `installer/DLPAgent.wxs` exists and is valid XML
- [x] All three commits exist in git log (`fd566bf`, `4cd869a`, `38c7f2b`)
- [x] `cargo fmt --check` passes
- [x] No legacy `dlp-cloud-hook.dll` references
- [x] Local release builds produce all 6 expected artifacts
