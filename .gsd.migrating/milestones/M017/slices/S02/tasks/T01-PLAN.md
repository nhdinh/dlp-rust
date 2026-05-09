---
estimated_steps: 11
estimated_files: 2
skills_used: []
---

# T01: Implement resolve_sync_paths() with registry discovery and fallback

Add `SyncPath`, `CloudProvider`, and `PathSource` types to `cloud_enforcer.rs`. Implement `pub fn resolve_sync_paths(user_sid: &str) -> Vec<SyncPath>` that reads sync folder locations from `HKEY_USERS\{SID}\SOFTWARE\...` for all four providers (OneDrive personal+business, Google Drive+DriveFS, Dropbox, Box), with `%USERPROFILE%`-based fallbacks when registry keys are absent. Update `CloudEnforcer::new()` to call `resolve_sync_paths()` using the current user's SID (enumerate active sessions via `WTSEnumerateSessions`/`LsaEnumerateLoggedOnUsers` or use the well-known session 1 SID). Update `detect_sync_provider()` to use `SyncPath.provider` field instead of substring heuristic.

**Steps:**
1. Add to `cloud_enforcer.rs`: `pub enum CloudProvider { OneDrive, GoogleDrive, Dropbox, Box }`, `pub enum PathSource { Registry, Fallback }`, `pub struct SyncPath { pub provider: CloudProvider, pub path: String, pub source: PathSource }`.
2. Implement `pub fn resolve_sync_paths(user_sid: &str) -> Vec<SyncPath>`. For each provider, attempt registry read via `RegOpenKeyExW(HKEY_USERS, ...)` + `RegQueryValueExW`; on failure, push fallback path via `std::env::var("USERPROFILE")`. OneDrive: enumerate `HKEY_USERS\{SID}\SOFTWARE\Microsoft\OneDrive\Accounts` subkeys for any key with a `UserFolder` value (handles both Personal and Business accounts). GoogleDrive: probe `HKEY_USERS\{SID}\SOFTWARE\Google\DriveFS` first (Drive for Desktop, value `DefaultMountPoint`), then `HKEY_USERS\{SID}\SOFTWARE\Google\Drive` (legacy, value `Path`). Dropbox: probe `HKEY_USERS\{SID}\SOFTWARE\Dropbox\ks` key's `dropbox_path` value; if absent, fall back to `%USERPROFILE%\Dropbox`. Box: probe `HKEY_USERS\{SID}\SOFTWARE\Box\Box` key's `FolderPath` value.
3. Normalize all returned paths: call `PathBuf::from(raw).to_string_lossy().into_owned()`, ensure trailing backslash.
4. Update `CloudEnforcer::new()`: obtain active-user SID using `WTSGetActiveConsoleSessionId()` + `WTSQuerySessionInformationW(WTSUserName)` + `LookupAccountNameW` to get SID string; call `resolve_sync_paths(&sid)`; store `Vec<SyncPath>` as `self.sync_paths: Vec<SyncPath>` (replaces `Vec<String>`).
5. Update `detect_sync_provider(path)` to match against `self.sync_paths[i].provider` enum instead of substring match.
6. Update `with_paths(paths: Vec<String>)` to accept `Vec<SyncPath>` — or keep accepting `Vec<String>` and convert internally by wrapping each as `SyncPath { provider: CloudProvider::OneDrive, path, source: PathSource::Fallback }` to preserve test compatibility. **Prefer keeping `with_paths(Vec<String>)` signature unchanged** so TC-30..TC-33 do not require path-arg changes.
7. Add unit tests in `#[cfg(test)]` mod: `test_resolve_sync_paths_empty_sid_returns_fallbacks`, `test_sync_path_normalizes_trailing_backslash`, `test_detect_provider_by_sync_path_type`, `test_with_paths_still_works_after_sync_path_refactor`.

**Windows APIs needed (all under `windows::Win32_System_Registry` feature already in Cargo.toml):** `RegOpenKeyExW`, `RegQueryValueExW`, `RegEnumKeyExW`, `RegCloseKey`.
**For active-user SID:** `WTSGetActiveConsoleSessionId` + `WTSQuerySessionInformationW` under `Win32_System_RemoteDesktop` feature — check if present; if not, add just this feature flag. Alternatively, read `HKEY_USERS` subkeys and skip the SID lookup for new() — accept the first non-.DEFAULT, non-_Classes hive. Document the approach chosen.

## Inputs

- `dlp-agent/src/cloud_enforcer.rs`
- `dlp-agent/Cargo.toml`

## Expected Output

- `dlp-agent/src/cloud_enforcer.rs`

## Verification

cargo test -p dlp-agent cloud_enforcer 2>&1 | tail -5
