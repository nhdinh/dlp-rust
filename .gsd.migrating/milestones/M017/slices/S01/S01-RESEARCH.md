# S01 Research: API Hook Framework + WFP Filter

## Summary

S01 builds the foundational interception infrastructure for cloud sync blocking. It delivers:
1. A Rust `cdylib` hook DLL (`dlp_hook.dll`) that intercepts `CreateFileW`/`NtCreateFile` in sync client processes via IAT patching
2. A WFP (Windows Filtering Platform) network egress filter that blocks HTTPS uploads from sync clients as defense-in-depth
3. A named pipe protocol between the hook DLL and agent service for classification requests
4. Agent service integration to start/stop the hook injector and WFP filter

This slice owns requirements **R001** (cloud sync folder write interception) and **R004** (WFP defense-in-depth).

## Calibrated Depth: Deep

API hooking + WFP involves kernel-adjacent Windows APIs unfamiliar to this codebase, with significant stability and security risks. Multiple viable approaches exist for both hooking (IAT vs inline vs detours) and IPC (named pipes vs ALPC vs shared memory). This requires broad exploration.

---

## Existing Codebase Landscape

### Enforcer Pattern (Well-Established)
Both `UsbEnforcer` (`dlp-agent/src/usb_enforcer.rs`) and `DiskEnforcer` (`dlp-agent/src/disk_enforcer.rs`) follow the same pattern:
- `new(...) -> Self` constructor
- `check(&self, path: &str, action: &FileAction) -> Option<BlockResult>`
- `BlockResult` carries `decision: Decision`, `notify: bool`, plus identity metadata
- Enforcers are constructed in `service.rs` `run_loop_init()` and passed to `run_event_loop()`
- The event loop calls enforcers BEFORE ABAC evaluation; `Some(result)` short-circuits to block handling

**New cloud enforcer will follow this exact pattern.**

### Service Lifecycle Pattern
`service.rs` `run_loop_init()` initializes all subsystems in order:
1. Create shared caches/managers
2. Construct enforcers
3. Spawn event loop with enforcers passed in
4. Store shutdown handles in `RunLoopContext`
`run_loop_shutdown()` stops them in reverse order.

**Hook injector and WFP manager will follow this pattern** — construct in `run_loop_init`, store handles in `RunLoopContext`, tear down in `run_loop_shutdown`.

### Windows API Usage
The `windows` crate (v0.62) is already used extensively. Relevant features already enabled:
- `Win32_System_Threading` — `OpenProcess`, `CreateRemoteThread`, `GetCurrentThreadId`
- `Win32_System_Memory` — `VirtualAllocEx`, `WriteProcessMemory`, `ReadProcessMemory`
- `Win32_System_LibraryLoader` — `GetModuleHandleW`, `GetProcAddress`
- `Win32_System_Pipes` — Named pipe APIs
- `Win32_Storage_FileSystem` — File APIs
- `Win32_UI_WindowsAndMessaging` — `SetWindowsHookExW` (used by drag-drop hook)

**Missing features needed for WFP:** `Win32_NetworkManagement_WindowsFilteringPlatform` or `Win32_Networking_WinSock` — must add to `dlp-agent/Cargo.toml`.

### Drag-Drop Hook (Closest Prior Art)
`dlp-agent/src/interception/drag_drop.rs` installs a `WH_GETMESSAGE` hook via `SetWindowsHookExW`. It shows:
- How to call Windows APIs from Rust using the `windows` crate
- Thread-local hook installation pattern
- `extern "system"` callback procedures
- Message loop with `GetMessageW`/`TranslateMessage`/`DispatchMessageW`

**Key difference:** drag-drop hook runs in the agent process; cloud sync hook must be injected into foreign processes (OneDrive.exe, Dropbox.exe, etc.). This requires DLL injection via `CreateRemoteThread` + `LoadLibraryW`.

### ABAC Types
`dlp-common/src/abac.rs` defines `Action` enum. Needs new variant:
```rust
CLOUD_UPLOAD,
```
Serialized as `"CLOUD_UPLOAD"` (follow `DRAG_DROP` pattern — literal variant name).

### Config Schema
`AgentConfig` (`dlp-agent/src/config.rs`) and `AgentConfigPayload` (`dlp-agent/src/server_client.rs`) need new fields:
```rust
// In AgentConfig:
#[serde(default)]
pub cloud_hook_enabled: Option<bool>,
#[serde(default)]
pub wfp_filter_enabled: Option<bool>,
#[serde(default)]
pub hook_classification_timeout_ms: Option<u64>,
```

### Audit Pipeline
`audit_emitter.rs` shows the pattern: `AuditEvent::new(...)` + enrichment + `emit_audit()`. Hook DLL will emit through the same pipeline.

### Test Pattern
`dlp-agent/tests/comprehensive.rs` has stub tests TC-30..33 for cloud interception. Need real implementations.

---

## Implementation Landscape

### Natural Seams

1. **Hook DLL (new crate: `dlp-hook-dll`)** — Independent `cdylib` that can be built separately. Exports:
   - `HookCreateFileW`, `HookNtCreateFile` — trampolines that call original after classification
   - `UnhookAll` — restores IAT entries
   - Internal: named pipe client to agent service

2. **Hook Injector (new module: `dlp-agent/src/hook_injector.rs`)** — Agent-side module that:
   - Discovers sync client process IDs
   - Calls `CreateRemoteThread` + `LoadLibraryW` to inject `dlp_hook.dll`
   - Monitors process start events to inject into newly launched sync clients
   - Handles both x64 and x86 processes (architecture check + appropriate DLL path)

3. **WFP Manager (new module: `dlp-agent/src/wfp_manager.rs`)** — Agent-side module that:
   - Registers a WFP callout driver (user-mode, via `FwpmFilterAdd0`)
   - Filters outbound TCP/443 from sync client PIDs
   - Dynamically adds/removes process blocks via `add_process_block(pid)`
   - Unregisters cleanly on service stop

4. **Named Pipe Protocol (new module: `dlp-agent/src/hook_ipc.rs`)** — Shared protocol:
   - `HookRequest { path: String, action: HookAction }`
   - `HookResponse { decision: Decision, reason: String }`
   - Agent side: server loop on a dedicated named pipe (`\\.\pipe\DlpHookPipe`)
   - DLL side: client that connects to the pipe, sends request, waits for response

5. **Cloud Enforcer (new module: `dlp-agent/src/cloud_enforcer.rs`)** — Thin wrapper:
   - Receives `FileAction` from the event loop
   - Checks if path is inside a sync folder
   - Returns `Some(CloudBlockResult)` for T3/T4 writes
   - **Note:** The actual blocking happens in the HOOK DLL (pre-write), not here. This enforcer is a fallback for the notify-based path and for audit emission when the hook blocks.

6. **ABAC Integration** — Add `Action::CLOUD_UPLOAD` to `dlp-common/src/abac.rs`. Add path prefix rules in `PolicyMapper` for sync folders.

7. **Service Integration** — Add hook injector + WFP manager construction in `service.rs` `run_loop_init()` and shutdown in `run_loop_shutdown()`.

### What to Build First (Risk Order)

1. **Named pipe protocol** — Lowest risk, unblock everything else. Can be tested independently.
2. **Hook DLL skeleton** — Build the `cdylib` with a no-op `CreateFileW` hook that just calls original. Verify it loads in a test process.
3. **Hook injector** — Inject the skeleton DLL into a test process (notepad.exe). Verify it loads.
4. **WFP filter skeleton** — Register a WFP filter that allows everything. Verify registration/unregistration works.
5. **Hook DLL + named pipe integration** — Hook actually calls named pipe, waits for response, returns `ACCESS_DENIED` on DENY.
6. **WFP process block integration** — WFP blocks HTTPS from test process.
7. **Cloud enforcer + ABAC** — Wire up `Action::CLOUD_UPLOAD`, sync folder path resolver.
8. **End-to-end** — Full integration: hook blocks T4, WFP catches bypass.

### Riskiest Element

**Hook DLL stability in sync client processes.** OneDrive and Dropbox have anti-tampering measures (code integrity checks, self-healing IAT). IAT hooking may break on updates. Mitigation: WFP fallback + process hash monitoring to detect when hooks break.

---

## Technology Deep-Dive

### IAT Hooking Approach

**Chosen:** IAT (Import Address Table) patching, not inline hooking.
**Why:** Simpler, safer, easier to unhook. Inline hooking requires disassembly and is more fragile. Detours requires a third-party library.
**How:**
1. Parse the target module's PE import directory
2. Find `kernel32.dll!CreateFileW` and `ntdll.dll!NtCreateFile` IAT entries
3. Replace with pointer to our hook function
4. Save original pointer for trampoline

**Rust implementation:** Use the `pelite` crate (or hand-roll PE parsing) to walk IAT. The `windows` crate provides `GetModuleHandleW` and `GetProcAddress`.

### WFP Filter Design

**Chosen:** User-mode WFP via `fwpuclnt.dll` APIs (not a kernel driver).
**Filter conditions:**
- `FWPM_CONDITION_ALE_APP_ID` — matches sync client executable path
- `FWPM_CONDITION_IP_REMOTE_PORT` — 443 (HTTPS)
- `FWPM_CONDITION_IP_PROTOCOL` — TCP
- Action: `FWP_ACTION_BLOCK`

**APIs needed:**
- `FwpmEngineOpen0` — connect to WFP engine
- `FwpmFilterAdd0` — add filter
- `FwpmFilterDeleteById0` — remove filter
- `FwpmEngineClose0` — disconnect

**Crate:** The `windows` crate does NOT expose WFP APIs directly. Options:
1. Use `windows-sys` with manual bindings
2. Use the `wfp` crate (community wrapper)
3. Hand-roll FFI bindings to `fwpuclnt.dll`

**Recommendation:** Hand-roll minimal FFI bindings to `FwpmEngineOpen0`, `FwpmFilterAdd0`, `FwpmFilterDeleteById0`, `FwpmSubLayerAdd0`. Only ~5 functions needed. The `windows` crate's `GUID` and `NTSTATUS` types can be reused.

### Named Pipe Protocol

**Pipe name:** `\\.\pipe\DlpHookPipe`
**Serialization:** `bincode` for speed (hooks are in the hot path). Alternative: raw bytes with fixed-size header.
**Timeout:** Configurable, default 50ms. Hook returns `ACCESS_DENIED` if timeout expires (fail-closed).
**Agent side:** Dedicated std thread with `CreateNamedPipeW` + `ConnectNamedPipeW` + `ReadFile`/`WriteFile` loop. Each request spawns a Tokio task for classification (via `tokio::runtime::Handle::current().spawn`).

### x86/x64 Architecture Handling

Sync clients may be 32-bit or 64-bit. The agent (x64) cannot inject a 64-bit DLL into a 32-bit process.
**Solution:** Build TWO hook DLLs:
- `dlp_hook64.dll` — for x64 processes
- `dlp_hook32.dll` — for x86 processes
Injector checks target process architecture via `IsWow64Process2` (or `IsWow64Process` on Win10) and loads the appropriate DLL.

---

## What Files Change / New Files

### New Files
| File | Purpose |
|------|---------|
| `dlp-hook-dll/Cargo.toml` | New crate: hook DLL |
| `dlp-hook-dll/src/lib.rs` | DLL entry point, hook exports, IAT patching |
| `dlp-hook-dll/src/named_pipe_client.rs` | Pipe client for classification requests |
| `dlp-agent/src/hook_injector.rs` | Process discovery + DLL injection |
| `dlp-agent/src/hook_ipc.rs` | Named pipe server + protocol types |
| `dlp-agent/src/wfp_manager.rs` | WFP filter registration/management |
| `dlp-agent/src/cloud_enforcer.rs` | Sync folder path check + fallback enforcement |
| `dlp-agent/src/sync_path_resolver.rs` | Registry-based sync folder discovery |

### Modified Files
| File | Change |
|------|--------|
| `Cargo.toml` | Add `dlp-hook-dll` to workspace members |
| `dlp-agent/Cargo.toml` | Add `pelite` dep; add WFP FFI; maybe `bincode` |
| `dlp-common/src/abac.rs` | Add `Action::CLOUD_UPLOAD` |
| `dlp-agent/src/config.rs` | Add `cloud_hook_enabled`, `wfp_filter_enabled`, `hook_classification_timeout_ms` |
| `dlp-agent/src/server_client.rs` | Add corresponding payload fields |
| `dlp-agent/src/service.rs` | Construct hook injector + WFP in `run_loop_init`; shut down in `run_loop_shutdown` |
| `dlp-agent/src/interception/mod.rs` | Add cloud enforcer to `run_event_loop` params |
| `dlp-agent/tests/comprehensive.rs` | Implement TC-30..33 |

---

## Verification Strategy

| Check | How |
|-------|-----|
| Hook DLL loads in test process | Unit test: inject into notepad.exe, verify DLL is loaded via `EnumProcessModules` |
| Named pipe round-trip < 50ms | Unit test: send 1000 requests, assert p99 < 50ms |
| Hook returns ACCESS_DENIED on DENY | Integration test: mock pipe server returns DENY, verify `CreateFileW` fails with `ERROR_ACCESS_DENIED` |
| WFP filter registers | Unit test: call `register_filter()`, verify via `FwpmFilterGetById0` |
| WFP blocks HTTPS from test process | Integration test: spawn curl.exe, WFP blocks outbound 443, verify connection timeout |
| Hook returns ACCESS_DENIED when agent offline | Unit test: pipe server not running, hook called, assert immediate DENY |
| No memory leaks | Run under Application Verifier / detect handle leaks in tests |

---

## Open Questions / Blockers

1. **WFP API bindings:** The `windows` crate v0.62 does NOT include WFP APIs. Need to verify whether `windows-sys` does, or hand-roll FFI. This is a known gap.
2. **x86 build for hook DLL:** The workspace currently targets x64 only. Adding a 32-bit cdylib may require a new target triple (`i686-pc-windows-msvc`) and CI changes.
3. **IAT hooking vs sync client updates:** OneDrive self-updates frequently. IAT hooks may break. Need a process-hash monitoring mechanism (out of scope for S01, but S02 should address).
4. **WFP coexistence with VPN/EDR:** Third-party WFP filters may have higher priority. Need to test with common EDR products (CrowdStrike, SentinelOne).

---

## Sources & References

- Windows Filtering Platform docs: `resolve_library` → `windows` crate WFP bindings (not available; will need hand-roll)
- IAT hooking technique: well-documented in security research; no specific crate needed
- Named pipe IPC: already used in `dlp-agent/src/ipc/` — follow existing pattern
- PE parsing: `pelite` crate (lightweight, no deps) or `goblin` crate

---

## Recommendation to Planner

Decompose S01 into these tasks (in dependency order):
1. **T01:** Add `Action::CLOUD_UPLOAD` to ABAC types + tests
2. **T02:** Define named pipe protocol (`hook_ipc.rs`) + unit tests
3. **T03:** Build hook DLL skeleton (`dlp-hook-dll`) with no-op CreateFileW hook + injector test
4. **T04:** Implement named pipe client in hook DLL + server in agent; integration test
5. **T05:** Implement actual classification logic in hook DLL (call pipe, return DENY/ALLOW)
6. **T06:** Hand-roll WFP FFI bindings + `wfp_manager.rs` skeleton
7. **T07:** Implement WFP filter registration and process block
8. **T08:** Integrate hook injector + WFP manager into `service.rs`
9. **T09:** Implement `cloud_enforcer.rs` fallback + sync path resolver
10. **T10:** Implement TC-30..33 test stubs
