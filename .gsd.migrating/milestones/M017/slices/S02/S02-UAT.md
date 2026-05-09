# S02: Cloud Sync Interception — UAT

**Milestone:** M017
**Written:** 2026-05-09T00:54:33.038Z

# S02: Cloud Sync Interception — UAT

**Milestone:** M017
**Written:** 2026-05-09

## UAT Type

- UAT mode: artifact-driven (contract-level)
- Why this mode is sufficient: The slice establishes the enforcement contract verified by unit tests with injected fixtures and integration tests (TC-30..TC-33). Live sync client injection against a running OneDrive/Dropbox process requires a manual smoke test that is explicitly deferred to S05 UAT where end-to-end live integration is the acceptance criterion.

## Preconditions

- `dlp-agent` crate builds cleanly: `cargo build -p dlp-agent` exits 0
- No pre-existing test failures in the cloud_tc or cloud_enforcer modules
- Windows environment with HKEY_USERS available (or fallback path exercised on non-Windows CI)

## Smoke Test

Run `cargo test -p dlp-agent --test comprehensive -- cloud_tc` and confirm 4 tests pass in under 5 seconds.

## Test Cases

### 1. TC-30: Public (T1) cloud upload — allowed

1. Construct a `CloudEnforcer` with a sync folder path via `with_paths(vec!["C:\\Users\\test\\OneDrive"])`.
2. Call `enforcer.check("C:\\Users\\test\\OneDrive\\public.txt", Action::CLOUD_UPLOAD, Classification::T1)`.
3. **Expected:** Returns `None` (no enforcement action — upload allowed).

### 2. TC-31: Confidential (T3) cloud upload — blocked

1. Construct a `CloudEnforcer` with a sync folder path.
2. Call `enforcer.check("C:\\Users\\test\\OneDrive\\report.txt", Action::CLOUD_UPLOAD, Classification::T3)`.
3. **Expected:** Returns `Some(EnforcementAction::Block)` with audit event emitted.

### 3. TC-32: Restricted (T4) cloud upload — blocked with alert

1. Construct a `CloudEnforcer` with a sync folder path.
2. Call `enforcer.check("C:\\Users\\test\\OneDrive\\secret.txt", Action::CLOUD_UPLOAD, Classification::T4)`.
3. **Expected:** Returns `Some(EnforcementAction::Block)` — stricter than T3 (alert-level audit).

### 4. TC-33: File outside sync folder — no block regardless of classification

1. Construct a `CloudEnforcer` with sync folder `"C:\\Users\\test\\OneDrive"`.
2. Call `enforcer.check("C:\\Users\\test\\Documents\\secret.txt", Action::CLOUD_UPLOAD, Classification::T4)`.
3. **Expected:** Returns `None` — path is outside all registered sync folders; enforcer does not block.

### 5. Registry path discovery — all four providers present

1. Call `resolve_sync_paths("S-1-5-21-TEST")` on a machine where no sync clients are installed.
2. **Expected:** Returns exactly 4 entries (one per provider: OneDrive, GoogleDrive, Dropbox, Box), each with `source: PathSource::Fallback` and a `%USERPROFILE%`-based default path.

### 6. T2 file in sync folder — allowed

1. Construct a `CloudEnforcer` with a sync folder path.
2. Call `enforcer.check("C:\\Users\\test\\OneDrive\\internal.txt", Action::CLOUD_UPLOAD, Classification::T2)`.
3. **Expected:** Returns `None` — T2 is below the T3 block threshold.

## Edge Cases

### Empty path — short-circuits before classification

1. Call `enforcer.check("", Action::CLOUD_UPLOAD, Classification::T4)`.
2. **Expected:** Returns `None` — empty path matches no sync folder, no block.

### UNC path — short-circuits before classification

1. Call `enforcer.check("\\\\server\\share\\file.txt", Action::CLOUD_UPLOAD, Classification::T4)`.
2. **Expected:** Returns `None` — UNC path is not under any local sync folder.

### sync_process_names() covers all four providers

1. Call `sync_process_names()`.
2. **Expected:** Slice contains entries for `OneDrive.exe`, `googledrivesync.exe` or `GoogleDriveFS.exe`, `Dropbox.exe`, `Box.exe` or `BoxSync.exe`.

## Failure Signals

- Any of TC-30..TC-33 failing indicates a regression in the classification wiring or enforcer logic.
- `cargo build --workspace` failing indicates a compile-time regression in the new types or Windows API bindings.
- `resolve_sync_paths` returning fewer than 4 entries on a clean machine indicates `push_missing_fallbacks()` is broken.
- WARN logs at service start containing "failed to open registry key" for all four providers simultaneously indicates a permissions issue or HKEY_USERS access problem.

## Not Proven By This UAT

- Live sync client injection: hooking a running OneDrive, Google Drive, Dropbox, or Box process and verifying the hook DLL is loaded before a sync upload occurs. This is deferred to S05 UAT.
- WFP defense-in-depth fallback when API hook is bypassed (S01/S05 scope).
- User-visible toast notification on block (requires live service + UI; S05 scope).
- Performance under concurrent cloud upload attempts (load test; S05 scope).
- Correct SID resolution in production domain-joined environment with multiple logged-in users.

## Notes for Tester

The 10 pre-existing clippy errors in hook_injector.rs, wfp_manager.rs, and interception/mod.rs are known and pre-date this slice — do not treat them as S02 regressions. The cargo test filter `cloud_enforcer` matches the module name in the lib binary; if it reports 0 tests, use `cargo test -p dlp-agent --lib -- cloud_enforcer` to target the lib test binary explicitly.
