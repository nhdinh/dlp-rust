---
id: T01
parent: S02
milestone: M017
key_files:
  - dlp-agent/src/cloud_enforcer.rs
key_decisions:
  - Kept with_paths(Vec<String>) signature unchanged to preserve TC-30..TC-33 test compatibility — each string is wrapped as OneDrive/Fallback SyncPath internally.
  - Used HKEY_USERS subkey scan as fallback when WTS SID detection fails (service in Session 0 during boot).
  - Accepted both REG_SZ and REG_EXPAND_SZ value types to handle cloud clients that store paths with %USERPROFILE% unexpanded.
duration: 
verification_result: passed
completed_at: 2026-05-09T00:35:28.567Z
blocker_discovered: false
---

# T01: Implement resolve_sync_paths() with registry discovery and fallback for all four cloud providers

**Implement resolve_sync_paths() with registry discovery and fallback for all four cloud providers**

## What Happened

Added three new public types — `CloudProvider` (enum: OneDrive, GoogleDrive, Dropbox, Box), `PathSource` (enum: Registry, Fallback), and `SyncPath` (struct: provider, path, source) — to `cloud_enforcer.rs`.

Implemented `pub fn resolve_sync_paths(user_sid: &str) -> Vec<SyncPath>` that, on Windows, probes `HKEY_USERS\{SID}\SOFTWARE\...` for each provider:
- **OneDrive**: enumerates `SOFTWARE\Microsoft\OneDrive\Accounts` subkeys and reads the `UserFolder` value from each account (handles both personal and business accounts).
- **Google Drive**: probes `SOFTWARE\Google\DriveFS` (Drive for Desktop, `DefaultMountPoint`) first, then `SOFTWARE\Google\Drive` (legacy `Path` value).
- **Dropbox**: reads `SOFTWARE\Dropbox\ks\dropbox_path`.
- **Box**: reads `SOFTWARE\Box\Box\FolderPath`.

All registry operations use RAII `RegKey` guard for `RegCloseKey`, two-pass `RegQueryValueExW` (size query then data read), and accept both `REG_SZ` and `REG_EXPAND_SZ`. Failed key opens log WARN with provider path + error code. `push_missing_fallbacks()` ensures all four providers always have at least one entry using `%USERPROFILE%`-based defaults when registry probing yields nothing. `normalize_path()` uses `PathBuf` + trailing backslash normalization; `expand_env_vars()` handles `%VARNAME%` prefix tokens.

Implemented `pub fn active_user_sid() -> String` using `WTSGetActiveConsoleSessionId` → `WTSQuerySessionInformationW(WTSUserName)` → `LookupAccountNameW` → `ConvertSidToStringSidW`. Falls back to `scan_hkey_users_for_sid()` which enumerates `HKEY_USERS` for the first `S-1-5-21-*` (non-`_Classes`) subkey when WTS fails (service in Session 0).

Updated `CloudEnforcer::new()` to call `active_user_sid()` + `resolve_sync_paths()` and store `Vec<SyncPath>`.

Kept `with_paths(Vec<String>)` signature **unchanged** for backward compat — each string is wrapped as `SyncPath { provider: OneDrive, source: Fallback }` so all pre-existing TC-30..TC-33 tests still pass without modification.

Added `with_sync_paths(Vec<SyncPath>)` constructor for typed tests.

Updated `detect_sync_provider()` to use `Iterator::find` over `Vec<SyncPath>`, returning `Option<&SyncPath>` (enum-typed provider, not substring heuristic).

Added `Default` impl delegating to `new()`.

Fixed three clippy lints: `manual_strip` → `strip_prefix`, `manual Iterator::find` → `.find()`, added `Default` derive. API shapes confirmed against windows crate 0.62 sources (`LookupAccountNameW` takes `Option<PWSTR>` for domain; `WTSQuerySessionInformationW` takes `Option<HANDLE>`; `LocalFree` takes `Option<HLOCAL>`; `RegEnumKeyExW` takes `Option<PWSTR>` for lpname/lpclass).

## Verification

cargo test -p dlp-agent cloud_enforcer: 17 passed, 0 failed. All four new S02 tests pass alongside all eleven legacy tests. Clippy errors in cloud_enforcer.rs: 0 (pre-existing errors in other files are not regressed).

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo test -p dlp-agent cloud_enforcer 2>&1 | tail -5` | 0 | ✅ pass | 18500ms |

## Deviations

active_user_sid_windows uses WTSQuerySessionInformationW with Option<HANDLE> wrapping (windows crate 0.62 API shape), confirmed against crate source rather than assuming signature from plan. PSID is in Win32::Security (not Foundation) per crate layout.

## Known Issues

None.

## Files Created/Modified

- `dlp-agent/src/cloud_enforcer.rs`
