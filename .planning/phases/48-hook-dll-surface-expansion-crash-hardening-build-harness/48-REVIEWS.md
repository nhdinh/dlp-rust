---
phase: 48
reviewers: [codex, claude]
reviewed_at: 2026-05-15T00:00:00Z
plans_reviewed:
  - 48-01-PLAN.md
  - 48-02-PLAN.md
  - 48-03-PLAN.md
  - 48-04-PLAN.md
  - 48-05-PLAN.md
---

# Cross-AI Plan Review — Phase 48

> Reviewed by: Codex CLI (gpt-5.5), Claude CLI (claude-4-sonnet)
> Review date: 2026-05-15
> Prompt: Plan-only review (no code execution)

---

## Codex Review

### Summary

Phase 48 is directionally solid: it expands the hook DLL from a narrow path-based surface into a broader Windows file-operation interception layer while adding crash containment, reusable IPC buffers, x86 support, and release signing. The biggest architectural risks are not the individual hooks, but the ordering and interaction between them: eager DllMain patching, IPC during hooked file APIs, fail-open crash behavior, handle-based classification before the agent owns a reliable handle map, and architecture-specific parsing/struct assumptions. I would treat this as a high-risk phase unless the implementation is staged behind strong harness tests and runtime kill switches.

### Strengths

- Clear wave structure: crash hardening and hook expansion come before unified refactor, x86, and signing.
- Good recognition that hook code must not panic across FFI boundaries.
- `guard_trampoline` plus fail-closed return helpers should reduce undefined behavior from Rust panics in trampolines.
- Thread-local IPC buffer reuse is a good low-allocation optimization for hot hook paths.
- Hook table refactor should reduce drift between install and uninstall logic.
- Explicitly documenting `CopyFile2` as a limitation is better than pretending the surface is complete.
- Including both Win32 and NT-layer APIs improves coverage against bypasses.
- Authenticode verification as a release gate is the right packaging posture for Windows security tooling.

### Concerns

- **HIGH: "Fail-open" crash protection conflicts with DLP enforcement goals.** The plan says layered crash protection is fail-open, while `fail_closed!` exists for deny returns. If a policy decision path panics or SEH faults, allowing the original operation can become a direct bypass. You need an explicit rule: crashes in classification, IPC serialization, or policy-deny paths should probably fail closed for write/delete/move operations, while crashes in non-sensitive telemetry paths may fail open.

- **HIGH: Eager patching in `DllMain` is dangerous.** Loader lock makes many operations unsafe: loading libraries, resolving imports that may trigger loader work, heap activity in some contexts, synchronization, IPC, and anything that may call hooked APIs recursively. If `init()` patches from `DllMain`, the implementation must be extremely constrained or defer real initialization to a worker thread created safely after process attach.

- **HIGH: Hook recursion and reentrancy are not addressed.** `pipe_client.rs` IPC, bincode serialization, allocation, logging, and Windows named-pipe calls may themselves touch file APIs or NT APIs. Without a thread-local reentrancy guard, hooks can recursively classify their own IPC/logging activity and deadlock, overflow, or deny the agent channel.

- **HIGH: Handle-based classification depends on a future handle map.** Phase 48 includes `classify_handle`, but the agent-maintained handle-to-path map is deferred to Phase 49/50. That creates an integration gap: `WriteFile`, `NtWriteFile`, `SetFileInformationByHandle`, and similar hooks may have weak or unavailable policy context in this phase. The plan should define interim behavior precisely: allow unknown handles, deny unknown handles, query path locally, or send best-effort metadata.

- **HIGH: SEH in Rust is non-trivial.** A stub `seh_guard` may give false confidence. Rust `catch_unwind` does not catch access violations, illegal instructions, stack overflows, or most native faults. If SEH is required, define whether it uses `__try/__except` in C/C++ shim, vectored exception handling, or Windows-specific compiler support.

- **HIGH: Manual PE parsing is brittle.** Hardcoded `PE_MAGIC` and `DATA_DIRECTORY_OFFSET` values are easy to get subtly wrong across PE32/PE32+, malformed modules, bound imports, forwarded exports, ASLR, section alignment, and protected processes. Since this is security-sensitive hook installation code, malformed or unusual PE files should fail safely without corrupting process memory.

- **MEDIUM: `CopyFileExW` and `MoveFileExW` semantics need careful source/destination policy.** Copy and move operations can both read from one path and write/create/delete another. The plan should specify whether policy is evaluated on source, destination, or both, and how overwrite/replace semantics are handled.

- **MEDIUM: `ReplaceFileW` has multi-path semantics.** It involves replaced file, replacement file, and optional backup file. Blocking based only on one path would leave bypasses.

- **MEDIUM: `SetFileInformationByHandle` class filtering may be incomplete.** Classes `4, 6, 10` likely cover rename/disposition-style operations depending on enum mapping, but newer info classes such as `FileRenameInfoEx`, `FileDispositionInfoEx`, and related variants may matter on modern Windows. Numeric-only checks are fragile; use named constants and include versioned variants.

- **MEDIUM: NT path extraction has edge cases.** `OBJECT_ATTRIBUTES` may be null, `ObjectName` may be relative to `RootDirectory`, strings may not be null-terminated, and NT paths can use device namespaces, volume GUIDs, short names, reparse points, symlinks, and case variation. A 32K cap is reasonable, but normalization assumptions should be explicit.

- **MEDIUM: x86 support increases ABI risk.** `OBJECT_ATTRIBUTES` and `UNICODE_STRING` layout offsets must be validated with compile-time size/layout assertions. Windows calling conventions and trampoline prolog lengths differ between x86 and x64; the hook engine must be proven on both.

- **MEDIUM: IPC schema with `action: String` is under-specified.** A stringly typed action field risks drift and parsing bugs. Use an enum with stable serialized discriminants. Include request versioning before this becomes a cross-process contract.

- **MEDIUM: `handle_value: usize` across IPC is architecture-sensitive.** If a 32-bit hook DLL talks to a 64-bit service, `usize` serialization can become ambiguous unless the protocol fixes width, e.g. `u64`, and includes source process bitness.

- **MEDIUM: Authenticode plan assumes secrets and tooling availability.** CI signing needs protected cert material, timestamp servers, fallback behavior, and a clear failure mode. "Fallback to Sectigo" should not silently sign with the wrong identity or weaken validation.

- **LOW: `bincode::serialize_into` reuse is good, but buffer lifecycle needs bounds.** If a large request ever grows the thread-local buffer, it may retain that capacity forever in every hooked thread. Consider truncating or shrinking above a threshold.

- **LOW: `CopyFile2` limitation should be enforced in tests/docs.** If it is a known bypass for this phase, it should appear in the risk register and test matrix as expected-not-covered.

### Suggestions

- Add a reentrancy guard before any IPC, logging, allocation-heavy path, or original-function fallback.
- Define a per-hook failure policy matrix: classify crash, IPC timeout, serialization failure, unknown handle, malformed path, original function pointer missing.
- Avoid doing heavy work under `DllMain`; use minimal attach logic and defer patching where possible.
- Make hook decisions typed: replace `action: String` with an enum and add protocol versioning.
- Use fixed-width IPC fields: `pid: u32`, `handle_value: u64`, `source_bitness: enum`.
- Add exhaustive tests for multi-path APIs: `CopyFileExW`, `MoveFileExW`, `ReplaceFileW`, rename, delete-on-close, overwrite, and backup path cases.
- Add architecture layout tests for x86/x64 structs and PE parsing constants.
- Add fuzz or property tests for PE parsing and NT path extraction with malformed inputs.
- Add recursion tests where IPC/logging causes file APIs to be invoked while inside a hook.
- Add timeout behavior tests for agent unavailable, pipe broken, malformed response, and slow response.
- Add a runtime kill switch or policy mode switch so a bad hook build can be disabled without uninstalling the agent.
- Treat `SetFileInformationByHandle` by named `FILE_INFO_BY_HANDLE_CLASS` values, including modern `Ex` variants where available.
- Make known limitations explicit in release notes: `CopyFile2`, memory-mapped writes if not covered, direct syscalls if applicable, raw disk/device writes, and untracked inherited/duplicated handles.

### Risk Assessment: HIGH

The plan touches injected code, trampoline patching, Windows loader behavior, NT APIs, cross-process IPC, x86/x64 ABI differences, and release signing in one phase. The crash-hardening direction is good, but several assumptions can become bypasses or process-wide crashes: eager DllMain patching, incomplete handle context, fail-open behavior, hook recursion, and manual PE/structure parsing. I would keep the phase, but require a strict harness-first rollout with per-hook tests, reentrancy protection, fixed IPC schema, and explicit failure-mode policy before treating it as production-ready.

---

## Claude Review

### Summary

Phase 48 is an ambitious five-plan phase that expands the hook DLL from 2 to 12 IAT-patched functions, adds layered crash hardening (SEH + `catch_unwind`), refactors `lib.rs` around a `HookDescriptor` metadata table, produces an x86 sibling DLL via cross-compilation, and integrates an Authenticode signing pipeline. The plans are well-scoped per wave and follow a logical dependency chain (01/02 Wave 1 -> 03/04 Wave 2 -> 05 Wave 3). The research document is thorough, with clear locked decisions and documented limitations (CopyFile2, deferred handle tracker). However, several integration risks, unsafe-code gaps, and test coverage holes exist that could cause regressions or security issues if not addressed before execution.

### Strengths

- **Clear wave separation and dependencies**: The wave structure (01/02 independent in Wave 1, 03/04 building on them in Wave 2, 05 last in Wave 3) is sound and minimizes merge conflicts.
- **HookDescriptor metadata table**: Centralizing hook metadata in a `const` array eliminates per-function duplication in `init()` and `UnhookAll()`, making future expansion straightforward.
- **Fail-open crash hardening philosophy**: Routing all exceptions to the original function is the correct choice for a DLL injected into arbitrary processes. No self-repair avoids infinite crash loops.
- **Handle-based operations deferred correctly**: Sending `HandleHookRequest` with a raw handle value and delegating path resolution to the agent (Phase 49/50) keeps DLL complexity low — the right tradeoff for crash-sensitive code.
- **Thread-local buffer for IPC**: Eliminating per-call allocations in the pipe client hot path is a meaningful performance win.
- **Authenticode signing with fallback timestamp server**: DigiCert primary + Sectigo fallback mitigates the common CI failure mode of timestamp server downtime.
- **CopyFile2 documented as known limitation**: Acknowledging the COM/IAT gap upfront prevents wasted effort and sets correct expectations.
- **32K cap on wide-string scanning**: Prevents unbounded reads on malformed `PCWSTR` pointers, a real attack vector.

### Concerns

**HIGH: SEH guard is a documented stub (Plan 48-01)**
The `seh_guard` function is explicitly called out as potentially returning `Ok(f())` with a doc-comment stub if `windows` crate SEH bindings are insufficient. SEH is the *outer* layer that catches access violations — the most common crash mode in unsafe pointer code. If SEH is a no-op, only Rust panics are caught; AVs in `pcwstr_to_string` or `extract_nt_path` will still abort the host process. This undermines the core CRIT-02 mitigation. **Recommendation**: Verify SEH bindings before Wave 1 execution, or add a small C-compiled shim as a hard dependency.

**HIGH: `extract_nt_path` hardcodes x64 offsets in Plan 48-03; x86 fix is in Plan 48-04**
Plan 48-03 writes `extract_nt_path` with `offset(0x10)` for `OBJECT_ATTRIBUTES` and `offset(0x08)` for `UNICODE_STRING` — these are x64-only values. Plan 48-04 adds `cfg(target_arch)` constants but only in the *verification* section (Task 3), not as a required code change in the plan body. If 48-03 is committed as-written, the x86 DLL will read wrong memory offsets, causing crashes in `HookNtCreateFile`, `HookNtOpenFile`, and `HookNtSetInformationFile`. **Recommendation**: Either make 48-03 add the `cfg` blocks directly, or make 48-04's offset fix a formal task with file modification.

**HIGH: `find_iat_entry` has no bounds checking (Plan 48-02)**
The PE parsing loop scans import descriptors with `desc = desc.offset(20)` and reads `name_rva` without verifying the descriptor pointer stays within the import section bounds. A malformed or adversarial PE could cause an out-of-bounds read. While the target is the host process's own module (generally trustworthy), this is still a robustness gap. **Recommendation**: Add a maximum iteration count or section-size check before the loop.

**HIGH: No test coverage for actual DLL injection + hook firing (all plans)**
The verification sections rely on `cargo test -p dlp-hook-dll` and `cargo test --workspace`, but the hook DLL's core behavior (patching IAT, trampolines intercepting calls, pipe round-trips) can only be validated by injecting into a real process. No e2e injection test exists. **Recommendation**: Add at minimum a test that calls `init()` + `UnhookAll()` on the current process and verifies IAT entries are patched/restored.

**MEDIUM: `PIPE_BUFFER` reallocation defeats zero-allocation goal (Plan 48-01)**
The thread-local buffer is initialized with `Vec::with_capacity(4096)`, but `bincode::serialize_into` on a `Vec` will reallocate if the serialized data exceeds capacity. For `HookRequest` with a long path (> ~4K), the buffer will grow on the first call and retain capacity, but the first call still allocates. More critically, `send_raw_request` (added in 48-03) returns `Vec<u8>` for the response, which is always a fresh allocation. **Recommendation**: Document that the buffer eliminates *steady-state* allocation, not *worst-case* first-call allocation. Consider capping path length earlier in the pipeline.

**MEDIUM: `guard_trampoline` generic bounds may fail on trampolines returning `HANDLE`/`NTSTATUS` (Plan 48-01)**
`guard_trampoline<T>` requires `T` to be passed through `catch_unwind`. Windows API types like `HANDLE` and `NTSTATUS` may not implement `UnwindSafe`. The plan uses `AssertUnwindSafe(f)`, but `T` itself must still be `'static` for `catch_unwind`. `BOOL`, `HANDLE`, and `NTSTATUS` are all `Copy` types so this should work, but the plan doesn't explicitly verify this. **Recommendation**: Add a compile-time test that `guard_trampoline` works with each return type.

**MEDIUM: Handle-based hooks will silently allow everything until Phase 49/50 (Plan 48-03)**
`classify_handle` sends `HandleHookRequest` to the agent, but the agent has no handle tracker. The plan states the agent will "return a default ALLOW decision for unknown handles." This means `WriteFile`, `WriteFileEx`, `SetFileInformationByHandle`, `NtWriteFile`, and `NtSetInformationFile` — 5 of the 12 hooks — will be no-ops from a DLP enforcement perspective until the handle tracker is built. This is a significant functional gap that should be flagged in the phase success criteria, not just as a "note."

**MEDIUM: Authenticode signing workflow re-signs already-signed binaries on fallback (Plan 48-05)**
The primary sign step has `continue-on-error: true`. If it fails on the *first* binary but succeeds on the rest, the fallback step (which runs if `steps.sign_primary.outcome == 'failure'`) will re-sign *all* binaries, including the ones already signed by the primary step. Double-signing is generally harmless but may confuse signature verification or timestamp chains. **Recommendation**: Split signing into per-binary steps, or track which binaries failed and only re-sign those.

**MEDIUM: No `UnhookAll` cleanup on `DLL_PROCESS_DETACH` (Plan 48-03)**
The `DllMain` calls `init()` on attach but there's no mention of calling `UnhookAll()` on `DLL_PROCESS_DETACH`. If the agent unloads the DLL (or the process exits cleanly), IAT entries remain patched. This can cause crashes if the DLL is unloaded but the IAT still points to its trampolines. **Recommendation**: Add `DLL_PROCESS_DETACH` handling to call `UnhookAll()`.

**LOW: `dlp-e2e.exe` signing scope creep (Plan 48-05)**
The plan signs `dlp-e2e.exe` "for QA team use" but this is a test harness, not a shipped binary. Including it in the signing pipeline increases CI time and certificate usage without customer-facing benefit. **Recommendation**: Either exclude it or document why QA needs signed test binaries (some EDRs block unsigned test runners).

**LOW: `copy_from_slice` in `fail_closed!` uses `NTSTATUS(0xC0000022u32 as i32)` (Plan 48-01)**
The cast `0xC0000022u32 as i32` produces `-1073741790` (i.e., `0xC0000022` sign-extended), which is correct for `NTSTATUS`. However, the `windows` crate's `NTSTATUS` type may have a different constructor. **Recommendation**: Verify the exact `NTSTATUS` constructor in the `windows` crate version used (0.62.2).

**LOW: Plan 48-05 success criteria says "signs 6 binaries" but lists 7**
The `must_haves` truths and the YAML both list 7 binaries (5 EXEs + 2 DLLs), but the success criteria says "signs 6 binaries." This is a documentation inconsistency.

### Suggestions

1. **Merge the x86 offset fix into Plan 48-03**: Don't leave x86 offsets broken between waves. Add `cfg(target_arch)` constants for `OBJECT_ATTRIBUTES_OBJECT_NAME_OFFSET` and `UNICODE_STRING_BUFFER_OFFSET` directly in 48-03's `extract_nt_path` task, then have 48-04 verify they work.

2. **Add a bounds limit to `find_iat_entry`**: Cap the import descriptor scan at a reasonable maximum (e.g., 512 descriptors) or validate against the section size to prevent unbounded reads on malformed PEs.

3. **Add `DLL_PROCESS_DETACH` cleanup**: In `lib.rs`, handle `DLL_PROCESS_DETACH` by calling `UnhookAll()` before returning, preventing dangling trampoline pointers.

4. **Add an IAT patch/restore integration test**: In the `dlp-hook-dll` test module, call `init()` and `UnhookAll()` on the current process and verify that at least one known IAT entry (e.g., `CreateFileW`) is patched and then restored. This validates the core mechanism without requiring cross-process injection.

5. **Clarify the functional gap in success criteria**: Add explicit text to Plan 48-03's success criteria stating that handle-based hooks (WriteFile, SetFileInformationByHandle, etc.) will return ALLOW until the agent-side handle tracker is implemented in a future phase.

6. **Fix the signing fallback logic**: Track per-binary signing success/failure, or sign each binary in its own step, to avoid double-signing on timestamp fallback.

7. **Add a compile-time guard for `guard_trampoline` return types**: A test that calls `guard_trampoline` with closures returning `BOOL`, `HANDLE`, and `NTSTATUS` to ensure `catch_unwind` accepts them.

8. **Consider capping the serialized payload size**: Add a `debug_assert!` or runtime check that `bincode::serialize_into` into `PIPE_BUFFER` doesn't silently reallocate, or pre-allocate a larger buffer (e.g., 16K) to cover long-path scenarios.

9. **Verify `windows` crate `NTSTATUS` constructor**: Replace `NTSTATUS(0xC0000022u32 as i32)` with whatever the `windows` 0.62.2 crate expects, possibly `NTSTATUS(-1073741790i32)` or a named constant.

### Risk Assessment: MEDIUM-HIGH

**Justification:** The phase touches highly unsafe code (raw pointers, `static mut`, FFI, IAT patching) running inside arbitrary target processes. While the architecture is sound, three HIGH-severity concerns elevate the risk:

1. **SEH stub risk**: If SEH remains a no-op, access violations in path extraction will abort host processes — the exact failure mode (CRIT-02) this phase is meant to fix.
2. **x86 offset timing**: Hardcoding x64 offsets in 48-03 and fixing them in 48-04 creates a window where x86 builds are fundamentally broken. Given that x86 correctness is a phase requirement (BLOCK-04), this is a structural issue in the plan ordering.
3. **No real injection testing**: The verification is entirely unit-test based. IAT patching bugs (wrong offsets, bad PE parsing) only manifest at runtime in a real process.

The MEDIUM concerns (buffer reallocation, silent ALLOW on handle ops, double-signing) are manageable but add operational friction. The LOW concerns are documentation/scope issues.

**Overall recommendation**: Do not execute Wave 1 until the SEH approach is validated (or a C shim is committed as a fallback), and fold the x86 offset `cfg` blocks into Plan 48-03 rather than deferring them to 48-04. With those two changes, the risk drops to **MEDIUM**.

---

## Consensus Summary

### Agreed Strengths

Both reviewers independently identified these strengths:

- **Clear wave structure and logical dependencies** — Wave 1 (crash hardening + hook expansion) -> Wave 2 (unified refactor + x86) -> Wave 3 (signing) is sound.
- **HookDescriptor metadata table** — Centralizing hook metadata in a const array is a good architectural choice that eliminates drift.
- **Fail-open crash hardening** — Routing exceptions to the original function is correct for injected DLLs; no self-repair avoids infinite loops.
- **Thread-local IPC buffer** — Zero-allocation hot path is a meaningful performance win.
- **CopyFile2 documented as limitation** — Honest scoping prevents wasted effort.
- **Authenticode with fallback timestamp** — DigiCert + Sectigo is the right CI resilience pattern.

### Agreed Concerns (Highest Priority)

Both reviewers raised these HIGH-severity concerns:

1. **SEH guard may be a no-op stub** — Codex: "SEH in Rust is non-trivial; stub gives false confidence." Claude: "SEH is the outer layer that catches AVs; if it's a no-op, only panics are caught." Both recommend verifying SEH bindings or adding a C shim before Wave 1 execution.

2. **x86 offsets hardcoded in Plan 48-03, fixed in 48-04** — Codex: "x86 support increases ABI risk." Claude: "If 48-03 is committed as-written, the x86 DLL will read wrong memory offsets." Both recommend folding `cfg(target_arch)` blocks into 48-03.

3. **Handle-based hooks are non-functional until Phase 49/50** — Codex: "Handle-based classification depends on a future handle map." Claude: "5 of the 12 hooks will be no-ops from a DLP enforcement perspective." Both recommend documenting this gap explicitly in success criteria.

4. **Eager DllMain patching is dangerous** — Codex specifically flagged this as HIGH: "Loader lock makes many operations unsafe." This was not raised by Claude but is a valid concern.

5. **Hook recursion/reentrancy not addressed** — Codex HIGH concern: "Without a thread-local reentrancy guard, hooks can recursively classify their own IPC/logging activity." This was not raised by Claude but is a valid concern.

6. **Manual PE parsing is brittle** — Codex HIGH concern about hardcoded constants and malformed PEs. Claude raised a related MEDIUM concern about bounds checking in `find_iat_entry`.

### Divergent Views

- **Fail-open vs fail-closed on crash**: Codex raised this as HIGH — "fail-open crash protection conflicts with DLP enforcement goals" — suggesting crashes in write/delete paths should fail closed. Claude did not raise this, treating fail-open as the correct choice for injected DLLs. This is a fundamental policy decision worth investigating: the user's CONTEXT.md explicitly chose fail-open (D-06), so Codex's concern may warrant revisiting that decision rather than changing the plan.

- **Risk level**: Codex rated HIGH; Claude rated MEDIUM-HIGH. The difference is that Claude believes fixing the SEH and x86 offset issues would drop risk to MEDIUM, while Codex sees additional structural risks (recursion, DllMain, PE parsing) that keep it HIGH even with fixes.

- **Signing scope**: Claude flagged `dlp-e2e.exe` signing as LOW scope creep; Codex did not mention it.

---

## Action Items for Planner

| Priority | Item | Source |
|----------|------|--------|
| P0 | Verify SEH bindings or commit C shim fallback before Wave 1 | Both (HIGH) |
| P0 | Add `cfg(target_arch)` for x86 offsets directly in Plan 48-03 | Both (HIGH) |
| P1 | Add reentrancy guard to prevent hook recursion | Codex (HIGH) |
| P1 | Add bounds checking to `find_iat_entry` PE parsing loop | Both (HIGH/MEDIUM) |
| P1 | Document handle-based hook functional gap in success criteria | Both (HIGH/MEDIUM) |
| P1 | Add `DLL_PROCESS_DETACH` cleanup calling `UnhookAll()` | Claude (MEDIUM) |
| P2 | Add IAT patch/restore integration test in current process | Claude (HIGH) |
| P2 | Replace `action: String` with typed enum in IPC schema | Codex (MEDIUM) |
| P2 | Fix signing fallback to avoid double-signing | Claude (MEDIUM) |
| P2 | Use `u64` for `handle_value` in IPC to avoid architecture ambiguity | Codex (MEDIUM) |
| P3 | Fix success criteria count (7 binaries, not 6) | Claude (LOW) |
| P3 | Verify `NTSTATUS` constructor in windows 0.62.2 | Claude (LOW) |

---

*To incorporate feedback into planning: `/gsd-plan-phase 48 --reviews`*
