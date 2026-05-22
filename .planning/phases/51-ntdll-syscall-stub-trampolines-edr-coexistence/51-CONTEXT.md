# Phase 51: ntdll Syscall-Stub Trampolines + EDR Coexistence - Context

**Gathered:** 2026-05-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 51 closes the direct-syscall bypass hole left by IAT-only hooks. It delivers in-memory ntdll syscall-stub patching via Detours-style 5-byte JMP trampolines, with EDR-safe detection and coexistence.

**What Phase 51 builds:**
1. Ntdll syscall-stub patching for `NtCreateFile`, `NtOpenFile`, `NtWriteFile`, `NtSetInformationFile`
2. EDR detection before patching — module enumeration + stub prologue inspection
3. Thread-suspend protocol for safe in-memory patching (no torn instructions)
4. 30-second re-verification thread that detects EDR overwriting our trampolines
5. `enable_ntdll_patching` policy flag (default off) with SIEM audit event at boot
6. Integration with existing IAT hooks — both layers operate independently

**What Phase 51 does NOT build:**
- Patching of non-ntdll syscall stubs (e.g., `NtQuerySystemInformation`)
- Kernel-driver or minifilter (architecturally banned per PROJECT.md)
- EDR removal or bypass (coexistence only — we detect and skip)
- x86 ntdll stub layout research (assumes same 5-byte JMP pattern; tested in CI)
- New admin TUI screen (Phase 54 builds Bypass Alerts feed that consumes our `BypassAlert` events)
- DACL tripwire (Phase 52)
- ETW bypass correlator (Phase 53)

**Depends on:** Phase 50 (shared-memory cache + fail-mode state machine must be working)
**Requirements:** BLOCK-08, BLOCK-09

</domain>

<decisions>
## Implementation Decisions

### Trampoline Implementation
- **D-01:** Use `retour` 0.3.1 crate for Detours-style 5-byte JMP trampolines. Rust-native, no C++ dependency, supports both x64 and x86 targets. Already evaluated in project research.
- **D-02:** Trampoline body reuses existing `classify_and_log_path()` flow from Phase 50. The ntdll stub trampoline calls the same classification pipeline (allowlist → LRU → shared-memory cache → pipe → fail-mode) as IAT trampolines.
- **D-03:** Keep IAT hooks AND ntdll stub patches operating independently. IAT hooks catch normal API usage; ntdll stubs catch direct-syscall bypass. Both call the same classification function. No delegation chain.

### EDR Detection and Coexistence
- **D-04:** Two-phase EDR detection: (1) fast module-enumeration pre-filter against known EDR DLL names, (2) stub prologue inspection for `0xE9` (JMP rel32) bytes with target-walk into EDR module range. Only skip patching if BOTH phases indicate EDR presence.
- **D-05:** Known EDR module list derived from existing `AllowlistCategory::Avedr` entries: CrowdStrike (`csagent.dll`, `csfalcon.dll`), SentinelOne (`SentinelAgent.dll`), Defender (`MsMpEng.exe` module range), Carbon Black (`cb.exe`). Extensible via `system_kv` without agent restart.
- **D-06:** NEVER restore "clean" ntdll bytes from disk. If EDR is detected, skip patching that stub entirely. DoppelGate-class evasion malware is detected by reading disk ntdll and comparing to memory — we avoid this classifier entirely by never touching disk.
- **D-07:** On EDR re-verification failure (trampoline overwritten), emit `BypassAlert(reason=HookOverwritten)` and leave the stub unpatched. Do NOT re-patch over EDR — that triggers an arms race.

### Thread Safety During Patch
- **D-08:** Suspend-all-other-threads protocol: enumerate process threads via `NtQuerySystemInformation(SystemProcessInformation)`, suspend all except current, verify no thread RIP lands in `[stub, stub+5]`, perform 5-byte atomic write (x86 `cmpxchg8b` or x64 guaranteed atomic), resume all threads.
- **D-09:** If any thread RIP is in the stub range during patch attempt: abort patch for that stub, emit `BypassAlert(reason=PatchRaced)`, retry on next re-verification cycle (30s). No blocking wait.
- **D-10:** Chaos-test fixture: 1000 threads spinning on `NtCreateFile` + 100 patch cycles = zero torn-instruction crashes. This is the acceptance criterion, not a unit test (requires real Windows host).

### Re-verification and Monitoring
- **D-11:** Extend existing Phase 50 background thread to also verify trampoline integrity every 30 seconds. Reuse the same `WaitForSingleObject` 100ms timer loop — add trampoline verification as an additional task.
- **D-12:** Trampoline integrity check: read first 5 bytes of stub, verify they match our JMP pattern (not original syscall prologue, not EDR JMP). If mismatch → `HookOverwritten` alert.
- **D-13:** Re-verification is per-stub, not all-or-nothing. One stub can be clean while another is overwritten by EDR.

### Feature Flag and Rollout
- **D-14:** `enable_ntdll_patching` boolean in agent config TOML, default `false`. Per-customer rollout — operator opts in after testing in their environment.
- **D-15:** SIEM event `siem.ntdll_patching_enabled` emitted at agent boot when flag is true. Includes timestamp, agent version, and EDR detection status.
- **D-16:** If EDR is detected at boot AND flag is true: emit `siem.ntdll_patching_edr_detected` (informational), disable patching for detected stubs, continue with IAT hooks only. Agent stays operational.

### x86 Support
- **D-17:** Ntdll patching applies to both x64 and x86 hook DLLs. x86 ntdll stubs use same 5-byte JMP pattern (different absolute address size). `retour` handles both architectures.
- **D-18:** x86 EDR detection uses same module enumeration + stub inspection. No architecture-specific EDR logic.

### Claude's Discretion
- `retour` chosen over custom inline asm for maintainability and cross-architecture support.
- Module enumeration pre-filter chosen to avoid reading stub bytes of every loaded DLL.
- Per-stub re-verification chosen over all-or-nothing to maximize coverage when EDR patches only some stubs.
- Existing background thread extended rather than new thread to minimize resource footprint.
- `cmpxchg8b` on x86 for atomic 5-byte write; x64 naturally atomic for aligned 8-byte reads.
</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Architecture
- `.planning/ROADMAP.md` — Phase 51 goal and 5 success criteria
- `.planning/PROJECT.md` — v0.10.0 milestone context, minifilter ban, asymmetric fail semantics
- `.planning/STATE.md` — Decision 4: "retour-based Detours-style 5-byte JMP trampoline"; `enable_ntdll_patching` policy flag
- `.planning/phases/50-shared-memory-classification-cache-fail-mode-state-machine/50-CONTEXT.md` — Shared-memory cache, fail-mode state machine, background thread decisions

### Existing Code Patterns
- `dlp-hook-dll/src/lib.rs` — `HOOKS` table with IAT patching, existing ntdll trampoline exports (`HookNtCreateFile`, etc.)
- `dlp-hook-dll/src/trampolines.rs` — `classify_and_log_path()` flow; **reuse** for ntdll stub trampolines
- `dlp-hook-dll/src/crash_guard.rs` — `guard_trampoline()`, `seh_guard()` — **reuse** for ntdll trampolines
- `dlp-hook-dll/src/fail_closed.rs` — Fail-closed return values — **reuse**
- `dlp-hook-dll/src/fail_mode.rs` — `FailModeState`, `FailState` enum — **reuse**
- `dlp-hook-dll/src/classification_cache.rs` — `CacheLookup`, shared-memory cache — **reuse**
- `dlp-agent/src/allowlist.rs` — `AllowlistCategory::Avedr`, EDR vendor paths — **reuse for EDR module list**
- `dlp-common/src/hook_ipc.rs` — `HookRequest`, `HookResponse` — **reuse**
- `dlp-common/src/classification.rs` — `Classification::is_sensitive()` — **reuse**

### Related Phase Context
- `.planning/phases/48-hook-dll-surface-expansion-crash-hardening-build-harness/48-CONTEXT.md` — Hook DLL architecture, PE utils, dual-arch build harness
- `.planning/phases/49-universal-injection-etw-process-watcher-allowlist-appinit-fa/49-CONTEXT.md` — Universal injection, process registry, allowlist patterns
</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`HOOKS` table** (`dlp-hook-dll/src/lib.rs`): Already defines `NtCreateFile`, `NtOpenFile`, `NtWriteFile`, `NtSetInformationFile` entries with `trampoline_ptr`. Add new fields: `ntdll_stub_addr`, `original_ntdll_bytes: [u8; 5]`.
- **`classify_and_log_path()`** (`dlp-hook-dll/src/trampolines.rs`): The entire classification pipeline. Ntdll stub trampolines extract path from ntdll args (UNICODE_STRING) then call this function.
- **`FailModeState`** (`dlp-hook-dll/src/fail_mode.rs`): Already integrated into trampolines. Ntdll trampolines use same state machine.
- **Agent allowlist** (`dlp-agent/src/allowlist.rs`): `Avedr` category with CrowdStrike paths. Extend module-name matching logic.
- **Background thread** (`dlp-hook-dll/src/background_thread.rs`): Phase 50's 100ms polling thread. Extend with trampoline verification callback.

### Established Patterns
- **Thread-local pre-allocated buffer**: `RefCell<Vec<u8>>` in `thread_local!()`. Ntdll trampolines should use same pattern for path extraction.
- **Architecture-correct offsets**: `cfg(target_arch = "x86_64")` vs `cfg(target_arch = "x86")` for `OBJECT_ATTRIBUTES` and `UNICODE_STRING` field offsets. Already used in trampolines.rs.
- **SEH + catch_unwind**: `guard_trampoline()` wraps all hook bodies. Ntdll trampolines must use same guard.
- **Atomic operations on shared memory**: Phase 50's atomic version flip pattern. Re-verification thread reads stub bytes atomically.

### Integration Points
- `dlp-hook-dll/src/lib.rs` — Add `ntdll_patcher.rs` module. Initialize in `DllMain` after self-allowlist check, before IAT patching.
- `dlp-hook-dll/src/lib.rs` — Extend `HookDescriptor` with ntdll stub fields.
- `dlp-hook-dll/src/trampolines.rs` — Add ntdll-specific trampoline bodies that extract path from `OBJECT_ATTRIBUTES`/`UNICODE_STRING`.
- `dlp-hook-dll/src/background_thread.rs` — Add `verify_trampolines()` callback to existing timer loop.
- `dlp-agent/src/service.rs` — Add `enable_ntdll_patching` config read, pass to injector.
- `dlp-common/src/hook_ipc.rs` — Extend `BypassAlert` with `HookOverwritten` reason variant.
- `dlp-common/src/audit.rs` — Add `ntdll_patching_enabled` and `ntdll_patching_edr_detected` event types.
</code_context>

<specifics>
## Specific Ideas

- Ntdll stub layout: `mov r10, rcx; mov eax, syscall_number; syscall; ret` on modern Windows. The 5-byte patch overwrites the first instruction with `jmp rel32` to our trampoline. On x86: `mov eax, syscall_number; mov edx, 0x7FFE0300; call dword ptr [edx]` — same 5-byte JMP pattern applies.
- EDR stub inspection: read first byte. If `0xE9` (JMP rel32), calculate target: `target = stub_addr + 5 + rel32`. Check if target falls within any loaded EDR module's `.text` section range.
- Thread enumeration: use `NtQuerySystemInformation(SystemProcessInformation)` to get thread list. Skip current thread. Suspend via `NtSuspendThread`. Resume via `NtResumeThread`.
- RIP check: `NtQueryInformationThread(ThreadContext)` to read RIP for each suspended thread. Compare against `[stub_addr, stub_addr + 5]`.
- Atomic 5-byte write on x86: use `cmpxchg8b` with a pre-aligned 8-byte buffer containing the new 5 bytes + 3 padding bytes (original). On x64: naturally atomic for aligned addresses.
- `retour` usage: `retour::RawDetour::new(stub_addr as *const (), trampoline as *const ())`. Enable with `.enable()`. The original function pointer is available for calling the unhooked stub.
- Chaos test: spawn 1000 threads in a loop calling `NtCreateFile` on a temp file. Main thread performs 100 patch/unpatch cycles. Monitor for crashes, WER events, or torn reads.
</specifics>

<deferred>
## Deferred Ideas

- Admin TUI Bypass Alerts screen (Phase 54 — consumes our `HookOverwritten` alerts)
- ETW Kernel-File consumer for bypass correlation (Phase 53)
- DACL tripwire defense-in-depth (Phase 52)
- Monitor-only / audit-only per-policy mode (Phase 55)
- SD/optical/virtual drive enumeration (Phase 56)
- Deployment guide with per-vendor EDR allowlist procedures (Phase 57)
- Non-ntdll syscall stubs (e.g., `NtQuerySystemInformation`) — not in threat model for file-I/O bypass

</deferred>

---

*Phase: 51-ntdll-syscall-stub-trampolines-edr-coexistence*
*Context gathered: 2026-05-22*
