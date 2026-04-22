---
phase: 25-app-identity-capture-in-dlp-user-ui
plan: "01"
subsystem: dlp-user-ui/detection
tags: [win32, authenticode, app-identity, wintrust, wincrypt, cache]
dependency_graph:
  requires:
    - dlp-common::endpoint (AppIdentity, AppTrustTier, SignatureState — Phase 22)
  provides:
    - dlp-user-ui::detection::app_identity (AUTHENTICODE_CACHE, resolve_app_identity, verify_and_cache, build_app_identity_from_path, hwnd_to_image_path)
  affects:
    - dlp-user-ui::clipboard_monitor (Plan 02 wires these functions in)
    - dlp-user-ui::ipc::pipe3 (Plan 02 replaces None placeholders with resolved identities)
tech_stack:
  added:
    - Win32_Security_WinTrust feature (WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO)
    - Win32_UI_Accessibility feature (SetWinEventHook, UnhookWinEvent — needed by Plan 02)
  patterns:
    - OnceLock<Mutex<HashMap>> process-wide static cache (mirrors Phase 24 REGISTRY_CACHE)
    - cfg(windows) gating for all Win32 API calls with non-Windows stubs
    - 4-step WinCrypt publisher extraction (CryptQueryObject -> CryptMsgGetParam -> CertFindCertificateInStore -> CertGetNameStringW)
key_files:
  created:
    - dlp-user-ui/src/detection/mod.rs
    - dlp-user-ui/src/detection/app_identity.rs
  modified:
    - dlp-user-ui/Cargo.toml (Win32_Security_WinTrust + Win32_UI_Accessibility added)
    - dlp-user-ui/src/lib.rs (mod detection; added)
decisions:
  - "Use WTD_REVOKE_NONE (WINTRUST_DATA_REVOCATION_CHECKS) not WTD_REVOCATION_CHECK_NONE (WINTRUST_DATA_PROVIDER_FLAGS) — different fields, different types in windows-rs 0.58"
  - "windows-rs 0.58 HCRYPTMSG is *mut c_void (raw pointer), not a typed alias — import removed"
  - "CryptQueryObject out-params take typed newtype pointers; cast via *mut _ as *mut _"
  - "CertFindCertificateInStore encoding param is CERT_QUERY_ENCODING_TYPE newtype, not u32 — use CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0)"
  - "CertFreeCertificateContext takes Option<*const CERT_CONTEXT> not *mut CERT_CONTEXT"
  - "#[allow(dead_code)] at module level — functions intentionally unused until Plan 02 wiring"
metrics:
  duration_seconds: 603
  completed_date: "2026-04-22"
  tasks_completed: 2
  tasks_total: 2
  files_created: 2
  files_modified: 2
  tests_added: 10
  tests_passing: 10
---

# Phase 25 Plan 01: App Identity Detection Module Summary

Win32 Authenticode verification engine with OnceLock process-lifetime cache, HWND-to-AppIdentity resolution pipeline, and WinCrypt publisher CN extraction. Satisfies APP-06 (Authenticode cache, path-keyed, no CRL network calls).

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Cargo.toml + detection module skeleton | dbf1d3b | Cargo.toml, lib.rs, detection/mod.rs, detection/app_identity.rs (placeholder) |
| 2 | Full app_identity.rs implementation + tests | 574c003 | dlp-user-ui/src/detection/app_identity.rs |

## What Was Built

### `AUTHENTICODE_CACHE` static
Process-lifetime `OnceLock<Mutex<HashMap<String, (String, SignatureState)>>>` keyed by absolute image path. Renaming a binary produces a cache miss and fresh `WinVerifyTrust` call (APP-06 SC-5, D-06). No eviction policy — bounded to ~200 unique paths per session (D-05).

### Win32 resolution pipeline (all `#[cfg(windows)]`)
- `hwnd_to_image_path`: `GetWindowThreadProcessId` -> `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` -> `QueryFullProcessImageNameW`. Works on elevated target processes.
- `hwnd_to_pid`: PID extraction for intra-app copy comparison (D-02, used by Plan 02).
- `run_wintrust`: `WinVerifyTrust` with `WTD_REVOKE_NONE` (no CRL/OCSP network calls, D-06). GUID `{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}` (`data1: 0x00AAC56B`). Two-phase: VERIFY then CLOSE to release state machine.
- `extract_publisher`: 4-step WinCrypt chain. All HCERTSTORE/HCRYPTMSG/PCCERT_CONTEXT handles closed on every exit path (T-25-04 mitigation).

### Platform-agnostic API (callable from tests and non-Windows CI)
- `verify_and_cache`: fast O(1) cache-hit path; slow path calls `run_wintrust` + `extract_publisher`.
- `trust_tier_from_signature_state`: D-07 mapping (`Valid`->`Trusted`, `Invalid`/`NotSigned`->`Untrusted`, `Unknown`->`Unknown`).
- `build_app_identity_from_path`: composes verify_and_cache + trust_tier derivation into an `AppIdentity`.
- `resolve_app_identity_from_path`: D-08 path helper (None->None, empty->`AppIdentity::default()`, path->full identity). Used by tests to exercise D-08 semantics without live HWNDs.
- `resolve_app_identity`: `#[cfg(windows)]` HWND->AppIdentity with dead-HWND fallback to `AppIdentity::default()`.

## Test Results

```
running 10 tests
test detection::app_identity::tests::test_build_app_identity_from_path_sets_image_path_field ... ok
test detection::app_identity::tests::test_dead_hwnd_gives_unknown_identity ... ok
test detection::app_identity::tests::test_resolve_app_identity_none_hwnd_returns_none ... ok
test detection::app_identity::tests::test_trust_tier_from_signature_state_invalid_is_untrusted ... ok
test detection::app_identity::tests::test_trust_tier_from_signature_state_not_signed_is_untrusted ... ok
test detection::app_identity::tests::test_trust_tier_from_signature_state_unknown_is_unknown ... ok
test detection::app_identity::tests::test_trust_tier_from_signature_state_valid_is_trusted ... ok
test detection::app_identity::tests::test_verify_and_cache_different_paths_are_separate_entries ... ok
test detection::app_identity::tests::test_verify_and_cache_returns_not_signed_for_unsigned_binary ... ok
test detection::app_identity::tests::test_verify_and_cache_second_call_is_cache_hit ... ok
test result: ok. 10 passed; 0 failed; 0 ignored
```

## Verification

```
cargo build -p dlp-user-ui                          PASS
cargo clippy -p dlp-user-ui -- -D warnings          PASS (clean)
cargo test -p dlp-user-ui -- detection              PASS (10/10)
grep -c '#[cfg(windows)]' app_identity.rs           9 (>= 4 required)
grep 'data1: 0x00AAC56B' app_identity.rs            MATCH
grep 'data1: 0x0000_AAAC' app_identity.rs           NO MATCH (correct)
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] windows-rs 0.58 type mismatches in extract_publisher**
- **Found during:** Task 2 cargo check
- **Issue:** Plan action used `HCRYPTMSG` (does not exist in windows-rs 0.58 — it's `*mut c_void`), `&mut u32` for `CryptQueryObject` out-params (need typed `CERT_QUERY_ENCODING_TYPE` pointers), raw `u32` for `CertFindCertificateInStore` encoding (needs `CERT_QUERY_ENCODING_TYPE` newtype), `*mut CERT_CONTEXT` for `CertFreeCertificateContext` (needs `Option<*const CERT_CONTEXT>`).
- **Fix:** Replaced `HCRYPTMSG` with `*mut c_void`, cast out-params via `*mut _ as *mut _`, constructed `CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0)`, wrapped cert_ctx in `Some()`.
- **Files modified:** `dlp-user-ui/src/detection/app_identity.rs`
- **Commit:** 574c003

**2. [Rule 1 - Bug] Wrong field for revocation check flag**
- **Found during:** Task 2 cargo check
- **Issue:** Plan used `WTD_REVOCATION_CHECK_NONE` (type `WINTRUST_DATA_PROVIDER_FLAGS`) for `fdwRevocationChecks` field which expects `WINTRUST_DATA_REVOCATION_CHECKS`. These are different newtypes in windows-rs 0.58.
- **Fix:** Replaced with `WTD_REVOKE_NONE` (type `WINTRUST_DATA_REVOCATION_CHECKS`), which is the correct constant for the `fdwRevocationChecks` field. Effect is identical — no CRL network calls.
- **Files modified:** `dlp-user-ui/src/detection/app_identity.rs`
- **Commit:** 574c003

**3. [Rule 2 - Missing critical functionality] #[allow(dead_code)] for pre-wiring module**
- **Found during:** Task 2 clippy -D warnings
- **Issue:** All public functions in the detection module are unused until Plan 02 wires them into clipboard_monitor. Under `-D warnings`, clippy treats "never used" as errors, blocking the build.
- **Fix:** Added `#![allow(dead_code)]` at the top of `app_identity.rs`. This is standard practice for modules that expose a public API consumed by a sibling plan.
- **Files modified:** `dlp-user-ui/src/detection/app_identity.rs`
- **Commit:** 574c003

## Known Stubs

None. All functions are fully implemented. The `resolve_app_identity` non-Windows stub returns `None` intentionally (documented behavior for non-Windows CI).

## Threat Flags

No new threat surface beyond what is documented in the plan's `<threat_model>`. All four STRIDE threats (T-25-01 through T-25-04) are mitigated in this implementation:
- T-25-01 (binary rename bypass): cache keyed by absolute path, not name
- T-25-02 (CRL network block): WTD_REVOKE_NONE applied
- T-25-03 (cache poisoning race): Mutex present; single-threaded in production
- T-25-04 (handle leaks): all HCERTSTORE/HCRYPTMSG/CERT_CONTEXT handles closed on all exit paths

## Self-Check: PASSED

- `dlp-user-ui/src/detection/app_identity.rs` exists: FOUND
- `dlp-user-ui/src/detection/mod.rs` exists: FOUND
- Commit dbf1d3b exists: FOUND
- Commit 574c003 exists: FOUND
- `cargo test -p dlp-user-ui -- detection --test-threads=1`: 10/10 PASS
- `cargo clippy -p dlp-user-ui -- -D warnings`: CLEAN
