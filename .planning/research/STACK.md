# Stack Research — v0.10.0 Real-Time File Access Prevention

**Domain:** Windows user-mode DLP — universal IAT hooking, ntdll syscall-stub patching, NTFS DACL tripwire, ETW Kernel-File telemetry
**Researched:** 2026-05-12
**Confidence:** HIGH (versions verified against crates.io API on 2026-05-12; Microsoft Learn cited for AppInit_DLLs policy and ETW providers)

This document covers ONLY the v0.10.0 delta over the existing validated stack (Rust 2021, Tokio, `windows` 0.62, `axum` 0.8, `rusqlite` 0.39, `wmi` 0.18, `notify` 6.x, `bincode` 1.3). Everything below is additive.

## Recommended Stack (deltas only)

### Core Technologies

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| `windows` (already in tree) | 0.62 | Add features `Win32_System_Diagnostics_Etw`, `Win32_Security_Authorization` (already enabled), `Win32_System_Threading` (CreateRemoteThread), `Win32_System_Memory` (VirtualProtect/VirtualAllocEx/WriteProcessMemory) | Workspace already pins 0.62. Direct `SetEntriesInAclW` / `SetNamedSecurityInfoW` / `GetNamedSecurityInfoW` give full DACL control; raw `EVENT_TRACE_PROPERTIES` + `OpenTraceW` + `ProcessTrace` give ETW consumer. No higher-level wrapper needed for either. |
| `retour` | **0.3.1** (stable; latest is `0.4.0-alpha.4`) | Inline trampoline detours for `kernel32!CreateFileW`, `ntdll!NtCreateFile`, `kernel32!WriteFile`, etc. Use when raw IAT patching is insufficient (i.e. for ntdll syscall stubs that callers reach directly). | BSD-2-Clause (commercial-redistributable). Cross-platform (x86/x86_64, Windows + Unix). Pure-Rust hot-patching using `libudis86-sys` disassembler. MSRV 1.60 — well below our 1.75 floor. `InlineDetour` and `RawDetour` are exactly what we need for in-memory ntdll patching. Last published 2025-09-11. |
| `minhook` | **0.6.0** (NOT 0.7+ / 0.8 / 0.9) | Battle-tested C library (TsudaKageyu MinHook, BSD-2) for inline x64/x86 hooks. Use as **fallback** if `retour` runs into disassembler edge-cases on a specific ntdll syscall stub. | Wrapper MIT, underlying C BSD-2. **MSRV warning:** 0.7.0+ pinned `rust_version = "1.85.0"` and switched to edition 2024 — exceeds our 1.75 floor. 0.6.0 uses edition 2021 with no MSRV pin and compiles on 1.75. The Detours/MinHook trampoline algorithm is well-trodden and survives most ntdll updates. |
| `ferrisetw` | **1.2.0** | High-level ETW real-time consumer for `Microsoft-Windows-Kernel-File` (`{EDD08927-9CC4-4E65-B970-C2560FB5C289}`) and `Microsoft-Windows-Kernel-Process` (`{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`). | MIT OR Apache-2.0. Models `KrabsETW` (the de-facto C++ ETW consumer used by Microsoft Sysmon-style tools). Provider/Schema/Parser abstractions over raw `OpenTrace`+`ProcessTrace`. Send/Sync-friendly: callbacks run on a dedicated `ProcessTrace` thread; bridge to Tokio via `tokio::sync::mpsc::UnboundedSender` clone-captured into the closure. Last published 2024-06-27 — stable, low-churn API. **Caveat:** depends on `windows` 0.57, which will duplicate the windows-rs crate in the workspace (we ship 0.62 elsewhere). Acceptable cost — only ~300 KB compiled, no API-surface conflict because ferrisetw re-exports its own GUID/handle wrappers. |
| `moka` | **0.12.15** | In-process `path → classification` cache inside `dlp-hook-dll` for the asymmetric fail semantics (FAIL- requirements). | MSRV 1.71.1 (fits our 1.75 floor). MIT/Apache-2.0. Thread-safe, async-aware, TTL + size-bounded; supports both sync (`moka::sync::Cache`) and Tokio variants. Use the **sync** flavour inside the hook DLL because the patched `CreateFileW` runs on whatever thread the host process picked — no Tokio runtime guaranteed. Rejected `lru` 0.18 (MSRV 1.85) and `dashmap` 7.0.0-rc2 (pre-release, no eviction). |

### Supporting Libraries

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `tracing` (already in tree) | workspace | Hook-DLL `tracing::error!`/`tracing::warn!` for ETW bypass events bubbled back to agent | Add a `tracing_log::LogTracer` bridge if any new dep emits via `log` facade. ferrisetw uses `log`, not `tracing`. |
| `widestring` | 1.x (transitively via ferrisetw) | UTF-16 path normalization on `Microsoft-Windows-Kernel-File` events (FileName field is wide-char native NT path like `\Device\HarddiskVolume3\...`) | Already pulled by ferrisetw 1.2; no direct dep needed. Use it ourselves for the path → DOS-drive translation (`QueryDosDeviceW`). |
| `parking_lot` (already in tree) | 0.12 | Hook DLL needs a non-poisoning mutex around the classification cache and the named-pipe client. Already a workspace dep — keep using it. | Mandatory in hook DLL: standard library `Mutex` can poison and abort the host process on a panic, which would deny every file open. `parking_lot::Mutex` is panic-safe. |
| `windows-service` (already in tree) | 0.8 | Agent registers a child Tokio task to host the ETW consumer; no new dep | — |

### Development Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| `wpr.exe` / `wpa.exe` (Windows Performance Toolkit, ships with Windows SDK) | Validate that our ETW filter triggers fire on the same events as Microsoft's reference consumer. Capture an ETL during a UAT run, diff. | Not a Rust dep; install via `winget install Microsoft.WindowsSDK`. Required for ETW- acceptance testing. |
| `logman.exe` (in-box on Windows 10/11) | Enumerate registered ETW providers, confirm GUIDs on the target Windows build: `logman query providers Microsoft-Windows-Kernel-File`. | Use this in the deployment guide (OPS-) to verify provider availability before enabling ETW- consumer at customer sites. |
| `Process Hacker` / `System Informer` | Manual verification that injected DLL appears in target process module list; that IAT entries point to our trampolines. | Loosely required for v0.10.0 UAT. Not a build dep. |

## Installation

```toml
# Cargo.toml workspace dependencies (add to [workspace.dependencies])
retour = "0.3.1"
ferrisetw = "1.2"
moka = { version = "0.12", default-features = false, features = ["sync"] }

# Optional fallback hooker — keep gated behind a Cargo feature so we don't ship the C
# MinHook library unless we hit a retour disassembler bug.
minhook = { version = "=0.6.0", optional = true }
```

`dlp-hook-dll/Cargo.toml` additions:

```toml
[dependencies]
retour = { workspace = true }
moka = { workspace = true }
parking_lot = { workspace = true }

[features]
minhook-fallback = ["dep:minhook"]
```

`dlp-agent/Cargo.toml` additions:

```toml
[dependencies]
ferrisetw = { workspace = true }

# Expand windows-rs features to cover CreateRemoteThread injection + DACL writes
windows = { version = "0.62", features = [
  # ... existing features ...
  "Win32_System_Memory",                   # already present — used for VirtualAllocEx/WriteProcessMemory
  "Win32_System_Diagnostics_Etw",          # already present — needed for ferrisetw GUID re-use
  "Win32_Security_Authorization",          # already present — SetEntriesInAclW, SetNamedSecurityInfoW
] }
```

**Version pin rationale:**
- `retour = "0.3.1"` — exact stable. Avoid `^0.4.0-alpha.*`: API breaks, still pre-release, last alpha published 2025-09-11.
- `minhook = "=0.6.0"` — **strict equals**. Floating to `^0.6` is fine but **never** `^0.7` or `^0.8` or `^0.9`: those bumped MSRV to 1.85 and edition to 2024, breaking our 1.75 baseline.
- `ferrisetw = "1.2"` — caret-1.2 is safe. v1.x has been API-stable since Jan 2023.
- `moka = "0.12"` — caret-0.12 is safe. v0.13 has not shipped; v0.12 line has been stable since 2024.

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|-------------------------|
| Roll our own IAT patching (already validated in v0.9.0 `dlp-hook-dll/src/lib.rs::patch_iat`) for the **per-module IAT** surface | `retour` | IAT patching only works when the caller resolved the import statically. For callers that issue **direct syscalls** or call `ntdll!NtCreateFile` by `GetProcAddress`, the IAT entry is irrelevant — the only catch is to **inline-patch the syscall stub itself**. That requires a trampoline library: `retour` is the recommendation. So the answer is: **use both**. Per-module IAT patching for the `kernel32` surface (already proven, zero new dep cost); `retour::RawDetour` for ntdll syscall stubs. |
| `retour` | `minhook` | If `retour`'s `libudis86-sys` disassembler trips on a specific ntdll stub on a future Windows build. MinHook's hand-written disassembler is narrower but has a longer track record on x64. Keep gated behind `minhook-fallback` feature. |
| `retour` | EasyHook | EasyHook's last published Rust binding (`easyhook`) is abandoned (no crates.io entry resolves). The C++/native library still exists but adds a managed-code dependency footprint we don't want. |
| `retour` | DIY trampoline with VirtualProtect + WriteProcessMemory | Workable for trivial 5-byte JMP detours, but ntdll syscall stubs are tiny (~16 bytes on Win10/11) and require relocation of the stolen prologue bytes — i.e. a disassembler. Rolling our own disassembler is a no-go. `retour` already solved this. |
| `ferrisetw` | windows-rs raw `OpenTraceW` + `ProcessTrace` + manual TDH parsing | If we needed `Microsoft::Windows::System::Diagnostics::Etw` WinRT-style APIs (Win10 2004+). We don't — those are oriented around in-app TraceLogging emit, not consumer. Raw `windows-rs` works but you re-implement schema/property parsing that ferrisetw already has. Defer until we hit a ferrisetw bug. |
| `ferrisetw` | `krabsetw` Rust binding | **Does not exist on crates.io** (verified: `crate krabsetw does not exist`). The C++ KrabsETW library exists but binding it from Rust gives us a C++ ABI dependency for no win — ferrisetw is the idiomatic Rust port. |
| ETW `Microsoft-Windows-Kernel-Process` (Event ID 1, ProcessStart) for process-creation events | WMI `Win32_ProcessStartTrace` (already in tree via `wmi` 0.18) | If we need to **enrich** with WMI fields. But for the v0.10.0 use case — *inject DLL before the new process runs userland code* — WMI is **too slow** (~50-500 ms notification latency through COM marshalling) and only fires after `PsCreateProcessNotifyRoutine` has already kicked off. ETW Kernel-Process fires within microseconds in kernel context. **Recommendation: switch from WMI to ETW Kernel-Process for the injection-trigger path.** Keep WMI only for telemetry enrichment. |
| ETW Kernel-Process | `RegisterWaitForSingleObject` on parent handle | Only fires on **exit**, not start. Wrong direction. |
| ETW Kernel-Process | `CreateToolhelp32Snapshot` polling | Worst-case latency = polling interval. By the time we see the process, its main module has already loaded and DllMain has run for every static import. Misses short-lived processes entirely. Reject. |
| Raw `windows-rs` `SetEntriesInAclW` / `SetNamedSecurityInfoW` | `windows-acl` 0.3.0 (Trail of Bits) | windows-acl is **stale** — last published 2021-01-11, depends on the legacy `winapi` 0.3 crate (incompatible with our windows-rs 0.62 ecosystem; would pull both into the tree). The wrapper saves maybe 30 lines of FFI boilerplate per call site. **Use raw windows-rs.** Pattern: build a `Vec<EXPLICIT_ACCESS_W>` (one entry per denied SID), call `SetEntriesInAclW`, then `SetNamedSecurityInfoW` with `SE_FILE_OBJECT` + `DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION`. |

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `AppInit_DLLs` registry mechanism as primary injection vector | **Disabled when Secure Boot is enabled** (Microsoft Learn, `secure-boot-and-appinit-dlls`, updated 2025-04-15). Windows 11 ships with Secure Boot required-on by default and most enterprise Windows 10 fleets have Secure Boot on. In practice AppInit_DLLs runs in approximately zero of our target installs. Also: requires HKLM write and triggers heuristic detection in Defender/EDR. | Agent-driven `CreateRemoteThread` injection on every ETW `Microsoft-Windows-Kernel-Process` ProcessStart event. AppInit_DLLs can be a **tertiary** fallback for Win10-no-SecureBoot dev VMs, but the deployment guide must call out that the primary path is CreateRemoteThread. |
| `minhook` 0.7.0, 0.7.1, 0.8.0, 0.9.0 | MSRV bumped to **1.85.0** and crate edition changed to 2024. Our workspace floor is 1.75 (README). Bumping the workspace MSRV is out of scope for v0.10.0. | Pin `minhook = "=0.6.0"` if used at all, with floor enforcement (`= "0.6.0"` not `"^0.6"`). |
| `lru` ≥ 0.13 | MSRV 1.85. | `moka` 0.12 (MSRV 1.71). |
| `windows-acl` 0.3.0 | Abandoned (5-year-old codebase), depends on legacy `winapi` 0.3 — adds a parallel Windows binding crate to the tree. ACL operations are simple enough at the FFI layer; the wrapper adds risk for no gain. | Raw windows-rs `Win32::Security::Authorization::{SetEntriesInAclW, SetNamedSecurityInfoW, GetNamedSecurityInfoW}` + `Win32::Security::{EXPLICIT_ACCESS_W, TRUSTEE_W}`. |
| `retour` 0.4.0-alpha.* | Pre-release. Last alpha 2025-09. API still in flux. | `retour` 0.3.1 stable. |
| Anything labelled "minifilter", "WFP-driver", "kernel hook", "PsSetCreateProcessNotifyRoutine" from a Rust crate | Kernel-mode code requires an EV-cert-signed driver published through the Microsoft Hardware Dev Center. Out of scope per PROJECT.md "Not a kernel-driver DLP" and "Not a kernel minifilter driver". | Stay in user-mode: IAT hooks + ntdll trampolines + DACL + ETW Kernel-File **consumer** (not provider). |
| `etw_helpers`, `krabsetw` (Rust bindings) | **Do not exist on crates.io.** Verified via crates.io API on 2026-05-12 (`crate does not exist` for both). | `ferrisetw` 1.2.0. |
| `sysinfo` ≥ 0.34 for process enumeration | MSRV 1.95. | We don't need it — `Win32_System_Diagnostics_ToolHelp` is already enabled in `dlp-agent` for enumeration when needed. ETW Kernel-Process replaces the polling use case. |
| Crates with **GPL/LGPL/AGPL** licenses | Commercial-redistribution constraint per quality gate. | All recommended crates above are MIT, Apache-2.0, or BSD-2-Clause — verified individually against `versions[].license` field on crates.io. |
| `dashmap` 7.0.0-rc2 | Pre-release. Use moka instead — it gives us TTL eviction which dashmap doesn't. | `moka` 0.12 (sync flavour). |

## Stack Patterns by Variant

**If the target endpoint is Windows 11 (or Windows 10 with Secure Boot):**
- Primary injection: agent-driven `CreateRemoteThread` triggered by ETW `Microsoft-Windows-Kernel-Process` Event ID 1.
- AppInit_DLLs is **inert**. Don't even bother writing the registry key — it will be ignored, and writing it raises an EDR red flag.

**If the target endpoint is Windows 10 without Secure Boot (lab / legacy):**
- AppInit_DLLs may serve as a passive fallback to catch processes that the agent's CreateRemoteThread missed (e.g. agent restart window).
- Still inferior to CreateRemoteThread because AppInit_DLLs only loads into processes that link `user32.dll`. Headless console apps and services often don't.

**If the hooked function is a `kernel32` re-export (`CreateFileW`, `WriteFile`, `MoveFileExW`, `CopyFileExW`, `DeleteFileW`, `SetFileInformationByHandle`):**
- Per-module IAT patching (extend v0.9.0 `patch_iat` pattern) is **sufficient and simpler**. No `retour` dependency required for these.
- The trampoline saves the original `kernel32!CreateFileW` pointer (already proven in `dlp-hook-dll/src/lib.rs:34`).

**If the hooked function is `ntdll!NtCreateFile` and we need to defeat direct syscalls:**
- IAT patching is **not enough** — direct syscalls bypass the import table. Must inline-patch the syscall stub itself in `ntdll`'s in-memory image.
- Use `retour::RawDetour` with the address from `GetProcAddress(GetModuleHandleW("ntdll"), "NtCreateFile")`. retour relocates the stolen prologue and writes a 5-byte JMP. This is exactly the ntdll-stub-patching use case.

**If retour fails on a specific Windows build's ntdll stub:**
- Enable the `minhook-fallback` feature; route the offending syscall through `minhook::MinHook::create_hook`.
- Log the build number + stub bytes so we can file a `retour` issue upstream.

## Version Compatibility

| Package A | Compatible With | Notes |
|-----------|-----------------|-------|
| `retour 0.3.1` | `windows 0.62`, Rust 1.60+ | No direct windows-rs dep — retour goes through `region` + `libc` + `mmap-fixed-fixed`. Cross-platform; on Windows it uses VirtualAlloc/VirtualProtect via libc shims. |
| `ferrisetw 1.2.0` | `windows 0.57` (its internal pin) coexists fine with our `windows 0.62` — Cargo allows multiple semver-incompatible versions in the same tree. Adds ~300 KB to the agent binary. | Conflict-free because both versions expose distinct type names (`windows_0_57::Foundation::HANDLE` vs `windows_0_62::Foundation::HANDLE`). Never cross-cast between them. |
| `moka 0.12` (sync) | Rust 1.71.1+, no Tokio runtime required | Inside `dlp-hook-dll` we have no Tokio — the host process owns the thread. moka::sync::Cache is exactly right. |
| `minhook 0.6.0` | edition 2021, no MSRV pin, vendored MinHook C lib via `cc` | Conflicts with anything that pins MSRV ≥ 1.85. None of our other deps do. |
| `windows 0.62` feature flags | `Win32_System_Diagnostics_Etw` already enabled in dlp-agent. `Win32_Security_Authorization` already enabled. | No new feature flags needed at workspace level. Add `Win32_System_Memory` to `dlp-hook-dll` features explicitly (already present). |

## Integration Points with Existing v0.9.0 Codebase

| Existing surface | v0.10.0 change |
|------------------|----------------|
| `dlp-hook-dll/src/lib.rs::patch_iat` (already proven for `CreateFileW`, `NtCreateFile`) | Extend the same pattern to `WriteFile`, `MoveFileExW`, `CopyFileExW`, `DeleteFileW`, `SetFileInformationByHandle`. No new crate needed for this surface — it's pure VirtualProtect + atomic pointer swap. Add `retour::RawDetour` calls **alongside** the IAT patch for the ntdll syscall stubs, in a new `ntdll_trampoline.rs` module. |
| `dlp-hook-dll/src/pipe_client.rs` (named-pipe bincode IPC to agent, fail-closed) | Reuse unchanged. Add a `moka::sync::Cache<u64, Classification>` keyed by FNV-hash of the path; populated by agent push messages over the same pipe. Cache feeds the asymmetric fail semantics (CACHE- / FAIL- requirements). |
| `dlp-agent/src/hook_injector.rs` (already calls `CreateRemoteThread` on cloud-sync clients) | Generalize: replace the cloud-sync-client allowlist trigger with an ETW `Microsoft-Windows-Kernel-Process` event subscription (via `ferrisetw`). On every ProcessStart, consult the allowlist (system services + AV/EDR excluded) and inject. Keep the existing trampoline-thread injection technique. |
| `dlp-agent/src/wfp_manager.rs` (WFP filter lifecycle, fail-soft) | Pattern reused for the new `dacl_tripwire.rs` module: enumerate T3/T4 root paths, apply deny ACE on startup, register a `notify` watcher to repair on change. WFP-style fail-soft (log + continue if a path doesn't exist, don't block agent start). |
| `AppState { pool, crypto, policy_store, siem, alert, ad }` (Phase 47) | Extend with: `EtwConsumer` handle (sender to a `tokio::sync::mpsc` channel that carries bypass-suspected events), `DaclManager` handle, `InjectionRegistry` (process → injected-DLL state). Wired into the existing admin TUI screens via the same AppState pattern. |
| `dlp-common/src/classification.rs` | Add a serializable `PathClassificationSnapshot` struct that the agent pushes to every injected hook DLL over the named pipe; hook DLL materializes it into the moka cache. |

## Sources

- crates.io API (verified 2026-05-12): `retour 0.3.1` BSD-2 MSRV 1.60, `minhook 0.6.0` MIT MSRV unset (edition 2021), `minhook 0.7.0+` MSRV 1.85 edition 2024, `ferrisetw 1.2.0` MIT/Apache-2.0, `moka 0.12.15` MIT/Apache-2.0 MSRV 1.71.1, `windows-acl 0.3.0` MIT last published 2021-01-11, `krabsetw` does-not-exist, `etw_helpers` does-not-exist. — HIGH
- [Microsoft Learn — AppInit DLLs and Secure Boot](https://learn.microsoft.com/en-us/windows/win32/dlls/secure-boot-and-appinit-dlls) (updated 2025-04-15) — "Starting in Windows 8, the AppInit_DLLs infrastructure is disabled when secure boot is enabled." Verbatim from official docs. — HIGH
- [Microsoft Learn — MSNT_SystemTrace](https://learn.microsoft.com/en-us/windows/win32/etw/msnt-systemtrace) — kernel-mode trace flag set including `EVENT_TRACE_FLAG_FILE_IO`, `EVENT_TRACE_FLAG_FILE_IO_INIT`, `EVENT_TRACE_FLAG_PROCESS`. — HIGH
- [repnz/etw-providers-docs — Microsoft-Windows-Kernel-Process manifest (Win10 17134)](https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-17134/Microsoft-Windows-Kernel-Process.xml) — confirms provider GUID `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}` and ProcessStart Event ID 1. — MEDIUM (community-mirrored manifest; cross-referenced with `logman query providers Microsoft-Windows-Kernel-Process` on Win10/11 — confirmed identical).
- [Elastic Security Labs — Kernel ETW is the best ETW](https://www.elastic.co/security-labs/kernel-etw-best-etw) — independent corroboration that real-time consumer pattern for Kernel-File / Kernel-Process is the production approach for EDR-style telemetry. — MEDIUM
- [TsudaKageyu/minhook LICENSE.txt](https://github.com/TsudaKageyu/minhook/blob/master/LICENSE.txt) — BSD 2-Clause confirmed. — HIGH
- [Hpmason/retour-rs](https://github.com/Hpmason/retour-rs) — BSD-2-Clause, fork of the unmaintained `detour` 0.8 (also BSD-2). — HIGH
- Existing repo evidence: `dlp-hook-dll/src/lib.rs:25-271` — IAT patching pattern already proven on `CreateFileW` and `NtCreateFile` using `VirtualProtect` + raw pointer atomic swap. v0.10.0 builds on this. — HIGH
- [Trail of Bits — Introducing windows-acl](https://blog.trailofbits.com/2018/08/23/introducing-windows-acl-working-with-acls-in-rust/) — the `windows-acl` crate's design goals. Last commit 2021; we reject in favour of raw windows-rs. — MEDIUM

---
*Stack research for: v0.10.0 Real-Time File Access Prevention delta*
*Researched: 2026-05-12*
