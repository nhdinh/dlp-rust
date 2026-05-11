---
phase: 40-drag-and-drop
plan: 40-02
subsystem: dlp-agent
tags: [app-identity, uwp, authenticode, drag-and-drop]
dependency_graph:
  requires: [40-01]
  provides: [40-03]
  affects: [dlp-agent/detection, dlp-agent/ipc]
tech-stack:
  added: []
  patterns: [HWND-to-PID resolution, Authenticode cache, UWP AUMID detection]
key-files:
  created:
    - dlp-agent/src/detection/app_identity.rs
  modified:
    - dlp-agent/src/detection/mod.rs
    - dlp-agent/Cargo.toml
decisions: []
metrics:
  duration: "~15 minutes"
  completed_date: "2026-05-07"
---

# Phase 40 Plan 02: App Identity Resolution in dlp-agent Summary

**One-liner:** Ported the complete app identity resolution pipeline (Win32 + UWP AUMID) from dlp-user-ui to dlp-agent, enabling drag-and-drop source application identification.

## What Was Built

A new `dlp-agent/src/detection/app_identity.rs` module containing the full application identity resolution pipeline previously only available in `dlp-user-ui`:

- **`AUTHENTICODE_CACHE`** — Process-lifetime `OnceLock<Mutex<HashMap>>` caching WinVerifyTrust results per absolute image path (D-04, D-05, D-06)
- **`hwnd_to_image_path()`** — Resolves an `HWND` to its owning process's full Win32 image path via `GetWindowThreadProcessId` + `OpenProcess` + `QueryFullProcessImageNameW`
- **`hwnd_to_pid()`** — Returns the PID of a window's owning process
- **`run_wintrust()`** — Runs `WinVerifyTrust` with `WTD_REVOKE_NONE` (no CRL/OCSP network calls)
- **`extract_publisher()`** — 4-step WinCrypt sequence extracting publisher CN from Authenticode cert chain
- **`verify_and_cache()`** — Fast-path cache lookup + slow-path WinVerifyTrust + publisher extraction
- **`trust_tier_from_signature_state()`** — Maps `SignatureState` to `AppTrustTier` (Valid -> Trusted, etc.)
- **`build_app_identity_from_path()`** — Builds complete `AppIdentity` from a resolved image path
- **`resolve_app_identity()`** — Full HWND-to-AppIdentity resolution with UWP AUMID support
- **`resolve_uwp_identity()`** — Detects UWP apps by path and resolves AUMID + PackageFamilyName via `GetApplicationUserModelId`
- **`is_uwp_path()`** / **`package_family_name_from_aumid()`** — Pure logic helpers

## Windows-rs 0.62 API Adaptations

The port required several API adjustments from the dlp-user-ui's windows-rs version to dlp-agent's windows 0.62:

| API | dlp-user-ui pattern | dlp-agent 0.62 pattern |
|-----|--------------------|------------------------|
| `WinVerifyTrust` hwnd | `None` | `HWND::default()` |
| `CryptMsgGetParam` size query | Single-call with `None` buffer | Two-call pattern (size query + data fetch) |
| `CertGetNameStringW` | Returns `u32`, discard return | Returns `u32`, discard return (semicolon) |
| `GetApplicationUserModelId` | `PWSTR` raw | `Option<PWSTR>` |
| `CertCloseStore` | `HCERTSTORE` raw | `Option<HCERTSTORE>` |

## Test Coverage

13 unit tests added, all passing (313 total lib tests):

- `test_trust_tier_from_signature_state_valid_is_trusted`
- `test_trust_tier_from_signature_state_invalid_is_untrusted`
- `test_trust_tier_from_signature_state_not_signed_is_untrusted`
- `test_trust_tier_from_signature_state_unknown_is_unknown`
- `test_resolve_app_identity_none_hwnd_returns_none`
- `test_dead_hwnd_gives_unknown_identity`
- `test_verify_and_cache_returns_not_signed_for_unsigned_binary`
- `test_verify_and_cache_second_call_is_cache_hit`
- `test_verify_and_cache_different_paths_are_separate_entries`
- `test_build_app_identity_from_path_sets_image_path_field`
- `test_is_uwp_path_detects_windows_apps`
- `test_package_family_name_from_aumid`
- `test_app_identity_with_uwp_fields`

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED

- [x] `dlp-agent/src/detection/app_identity.rs` exists (867 lines)
- [x] `resolve_app_identity()` populates `aumid`, `package_family_name`, `is_uwp` fields
- [x] `cargo check -p dlp-agent` passes
- [x] `cargo test -p dlp-agent --lib` passes (313 tests)
- [x] `cargo clippy -p dlp-agent --lib -- -D warnings` passes
- [x] Commit `9f6adac` verified in git log
