# S02: Cloud Sync Interception — Research

**Date:** 2026-05-09
**Scope:** Replace placeholder sync paths and classification heuristic in `CloudEnforcer` with real registry-based path discovery, real ABAC classification, and sync-client process injection wiring for all four providers (OneDrive, Google Drive, Dropbox, Box).

## Summary

S02 is a well-bounded extension of S01's established infrastructure. The S01 slice deliberately left two stubs in `cloud_enforcer.rs`:

1. **Hardcoded sync path** — `sync_paths: vec![r"C:\Users".to_string()]` (line 54). Too broad: every file under `C:\Users` is treated as a sync candidate. S02 replaces this with registry-based path discovery that resolves the actual sync folder per installed provider.

2. **Placeholder classification** — `provisional_sync_classification()` (lines 188–200) uses simple path-keyword matching ("restricted"→T4, "confidential"→T3) instead of the real ABAC engine. S02 must call the real `AbacEvaluator` (already live in `interception/mod.rs`) so classification reflects user attributes and NTFS labels, not just path text.

Additionally, S01's `HookInjector` is constructed in `run_loop_init` but never wired to a process-discovery loop. S02 must add a background watcher that discovers sync client processes by exe name, injects the hook DLL, and re-injects when clients restart.

All the hard infrastructure is already in place (IAT patching DLL, named pipe server, WFP filter, `CloudEnforcer` enforcer shape). S02 is mostly: (a) swap the path stubs for real registry reads, (b) wire classification to ABAC, (c) add a sync-process watcher loop.

## Recommendation

**Implement registry-based path discovery first**, then ABAC classification integration, then process watcher loop. This ordering matches natural risk progression: path discovery is mechanical (registry keys are documented), classification wiring requires understanding the ABAC context shape, and the process watcher is a new background task that must not destabilize the service.

Use the `windows` crate's `Win32_System_Registry` feature (already present in `dlp-agent/Cargo.toml`) for registry reads — no new dependency needed. Do NOT add `winreg` crate; the `windows` crate covers everything needed.

## Implementation Landscape

### Key Files

- `dlp-agent/src/cloud_enforcer.rs` — Primary change target. Replace `sync_paths` construction in `new()` and `detect_sync_provider()`. Replace `provisional_sync_classification()` call in `check()` with real ABAC call. Add `resolve_sync_paths() -> Vec<SyncPath>` function (new, public, testable in isolation).
- `dlp-agent/src/service.rs` — `run_loop_init` (lines ~885–930): add sync-process discovery loop; wire discovered PIDs into `HookInjector`. Currently `HookInjector` is created but never told which processes to inject into.
- `dlp-agent/src/hook_injector.rs` — Existing `inject(pid)` API is ready. S02 adds a discovery loop that calls it; no changes to `hook_injector.rs` itself expected.
- `dlp-agent/src/interception/mod.rs` — `check()` currently receives `classification` from `provisional_sync_classification()`. S02 must thread the real `AbacEvaluator` reference (already in event loop scope) into the cloud enforcer check path or resolve classification at the event-loop level before calling `enforcer.check()`.
- `dlp-agent/tests/comprehensive.rs` — TC-30..TC-33 (lines 2529–2579): already use `CloudEnforcer::with_paths()`. These tests will continue to pass; they are not stubs. No changes needed to the tests unless the ABAC integration changes the block condition for T2 paths.
- `dlp-agent/src/config.rs` — `cloud_hook_enabled` (Option<bool>), `wfp_filter_enabled` (Option<bool>), `hook_classification_timeout_ms` (Option<u64>) already present. No new config fields expected for S02, but verify `AgentConfigPayload` has corresponding fields with `serde(default)`.

### Registry Keys for Sync Path Discovery

Each provider stores its sync folder in a well-known registry location:

| Provider | Registry Key | Value Name |
|----------|-------------|------------|
| OneDrive (personal) | `HKCU\SOFTWARE\Microsoft\OneDrive\Accounts\Personal` | `UserFolder` |
| OneDrive (business) | `HKCU\SOFTWARE\Microsoft\OneDrive\Accounts\Business1` | `UserFolder` |
| Google Drive | `HKCU\SOFTWARE\Google\Drive` | `Path` (older) or check `HKCU\SOFTWARE\Google\DriveFS` |
| Dropbox | `HKCU\SOFTWARE\Dropbox\ks\dropbox_path` | `(Default)` — or parse `%APPDATA%\Dropbox\info.json` |
| Box | `HKCU\SOFTWARE\Box\Box\FolderPath` | `FolderPath` |

**Fallback paths** (when registry key absent):
- OneDrive: `%USERPROFILE%\OneDrive`
- Google Drive: `%USERPROFILE%\Google Drive` / `%USERPROFILE%\My Drive`
- Dropbox: `%USERPROFILE%\Dropbox`
- Box: `%USERPROFILE%\Box`

**Design for `resolve_sync_paths()`:**
```
pub struct SyncPath {
    pub provider: CloudProvider,
    pub path: String,          // Absolute, normalized, backslash-terminated
    pub source: PathSource,    // Registry | Fallback
}

pub enum CloudProvider { OneDrive, GoogleDrive, Dropbox, Box }
pub enum PathSource { Registry, Fallback }

pub fn resolve_sync_paths() -> Vec<SyncPath>
```

This function should be `pub` so it can be called from `service.rs` at startup and periodically re-called if provider clients are installed after agent start. It must be called per-user because registry paths are under `HKCU` — on a multi-user machine the agent (running as SYSTEM) must impersonate each interactive user session to read their `HKCU`.

**Session 0 / SYSTEM constraint (critical):** The agent runs as SYSTEM in session 0 (MEM001). `HKCU` in session 0 is not the logged-on user's hive. To read sync paths for the actual user, the code must either:
- Use `RegOpenCurrentUser()` after impersonating the target user token, OR
- Read the user-specific hive directly via `HKEY_USERS\{user-SID}\SOFTWARE\...`

The codebase already resolves user SIDs in `identity.rs` — that SID can be used to open `HKEY_USERS\{SID}\SOFTWARE\...` without impersonation. This is the preferred approach.

### Sync-Client Process Discovery

Sync clients are identified by exe name:

| Provider | Process Name(s) |
|----------|----------------|
| OneDrive | `OneDrive.exe` |
| Google Drive | `googledrivesync.exe`, `GoogleDriveFS.exe` |
| Dropbox | `Dropbox.exe` |
| Box | `Box.exe`, `BoxSync.exe` |

Use `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` + `Process32FirstW` / `Process32NextW` to enumerate. The `windows` crate's `Win32_System_Diagnostics_ToolHelp` feature is needed — **check if it's already in `dlp-agent/Cargo.toml` features list**. If not, add it (no new dependency, just a feature flag).

The watcher loop should:
1. Run every 30 seconds (background `tokio::task` or `std::thread`).
2. Enumerate all processes.
3. For each sync-client process found, check if `HookInjector::is_module_loaded()` returns true.
4. If not loaded, call `HookInjector::inject(pid)`.
5. Track injected PIDs to avoid redundant calls.

**Note:** `HookInjector::is_module_loaded()` already exists (`hook_injector.rs` lines 336–389) — the watcher can use it to avoid re-injection.

### ABAC Classification Integration

The current `check()` method calls `provisional_sync_classification(path)` which is purely path-text based. S02 must replace this with real classification.

**Option A (preferred):** Move classification into the event loop (`interception/mod.rs`) before calling `enforcer.check()`. The event loop already has `evaluator: &AbacEvaluator` in scope. Resolve the `Classification` there and pass it into an updated `check(path, action, classification)` signature.

**Option B:** Pass `Arc<AbacEvaluator>` into `CloudEnforcer` and call it inside `check()`. More self-contained but couples the enforcer to the evaluator — breaks the simple `with_paths()` test constructor.

**Recommendation: Option A** — consistent with how `UsbEnforcer` integrates (the event loop resolves context, then calls the enforcer). The `check()` signature becomes:
```rust
pub fn check(&self, path: &str, action: &FileAction, classification: Classification) -> Option<CloudBlockResult>
```

This makes the enforcer pure (no side effects, no external calls) and keeps tests simple via `with_paths()` + explicit `classification` parameter.

### Build Order

1. **`resolve_sync_paths()` function** — implement and unit-test in isolation. No service dependencies. Tests can mock registry by passing explicit `SyncPath` vecs via `with_paths()`.
2. **Update `CloudEnforcer::new()`** to call `resolve_sync_paths()` at construction. Update `detect_sync_provider()` to use provider-specific matching instead of keyword heuristic.
3. **Update `check()` signature** to accept explicit `Classification` parameter; remove `provisional_sync_classification()`.
4. **Update call sites** in `interception/mod.rs` to resolve classification before calling `enforcer.check()`.
5. **Sync-process watcher loop** — add to `service.rs` as a background task spawned in `run_loop_init` alongside `HookInjector`.
6. **Update TC-30..TC-33** if the `check()` signature changes; otherwise no test changes needed.

### Verification Approach

```bash
# Registry discovery (unit tests)
cargo test -p dlp-agent cloud_enforcer

# ABAC integration (pass/fail for each tier)
cargo test -p dlp-agent --test comprehensive -- cloud_tc

# Full workspace build
cargo build --workspace

# Clippy clean
cargo clippy --workspace -- -D warnings

# Process watcher (smoke test — requires running OneDrive.exe)
# Manual: start OneDrive, wait 60s, check agent log for "injected hook into OneDrive.exe pid=XXXX"
```

## Don't Hand-Roll

| Problem | Existing Solution | Why Use It |
|---------|------------------|------------|
| Registry reads | `windows::Win32_System_Registry` (already in Cargo.toml features) | Already a dependency; typed FFI wrappers available |
| Process enumeration | `windows::Win32_System_Diagnostics_ToolHelp` (add feature flag) | Already in workspace dependency; avoids external crate |
| Path expansion (`%USERPROFILE%`) | `std::env::var("USERPROFILE")` or `SHGetKnownFolderPath` | Already used elsewhere in agent |
| DLL injection | `HookInjector::inject(pid)` — already implemented in S01 | Do not re-implement; just call it from the watcher |

## Constraints

- Agent runs as SYSTEM in session 0 — `HKCU` is not the logged-on user's hive. Must read `HKEY_USERS\{SID}\...` using the user SID resolved from identity.rs, or impersonate via token.
- `Win32_System_Diagnostics_ToolHelp` feature may not be in `dlp-agent/Cargo.toml` yet — verify before writing code and add if missing.
- `with_paths()` constructor and test infrastructure must remain intact; the test suite relies on `CloudEnforcer::with_paths()` for all 11 unit tests and TC-30..TC-33.
- `provisional_sync_classification()` must be deleted (not merely unused) — clippy will flag dead code.
- Named pipe `PipeError::Timeout` variant is currently dead code (S01 known limitation). S02 may implement the timeout path if `hook_classification_timeout_ms` is wired; otherwise leave the variant with `#[allow(dead_code)]` or remove it if not needed.

## Common Pitfalls

- **Reading `HKCU` as SYSTEM** — returns the SYSTEM hive, not the user's OneDrive config. Use `HKEY_USERS\{SID}\SOFTWARE\...` instead. The user SID is available from `identity::resolve_user_identity()`.
- **Google Drive path key instability** — older Google Drive Sync (≤3.x) uses `HKCU\SOFTWARE\Google\Drive\Path`; newer Google Drive for Desktop (4.x+) uses a different path under `HKCU\SOFTWARE\Google\DriveFS`. Check both.
- **Dropbox `info.json`** — The registry key is the canonical source, but some enterprise Dropbox installs only have `info.json`. The fallback parser should be prepared for this.
- **Injection timing** — If the watcher runs too infrequently, a sync client that starts and immediately writes a file may upload before the hook is injected. 30s polling is acceptable for a first iteration; a future slice could use `WMI Win32_ProcessStartTrace` for event-driven injection.
- **Duplicate injection** — `HookInjector::is_module_loaded()` prevents re-injection into already-hooked processes. Always check before calling `inject()`.
- **`check()` signature change breaks tests** — TC-30..TC-33 in `comprehensive.rs` call `enforcer.check(path, action)` with two arguments. If classification becomes a third argument, all 4 comprehensive tests and 11 unit tests need updating. Consider keeping the two-argument form for backward compat and adding a separate `check_with_classification()`, or update all call sites at once.

## Open Risks

- **OneDrive multi-account** — Users may have both Personal and Business OneDrive accounts, each with a different `UserFolder`. The discovery must iterate `Accounts\*` subkeys, not just `Accounts\Personal`.
- **Dropbox Teams** — Enterprise Dropbox installations may use a different registry path under `HKCU\SOFTWARE\Dropbox\ks\team_path`. Discovery should probe both keys.
- **Google DriveFS virtual filesystem** — Google Drive for Desktop mounts as a virtual drive letter (e.g., `G:\My Drive`). IAT-patching CreateFileW in the sync client may not intercept writes that go through the virtual FS driver. WFP defense-in-depth is especially important for this provider.
- **Box Drive vs Box Sync** — Box has two distinct clients with different registry layouts. Box Drive uses `HKCU\SOFTWARE\Box\Box\FolderPath`; Box Sync may differ. Both process names should be probed.
