---
phase: 48
reviewers: [codex]
reviewed_at: 2026-05-16T00:00:00Z
plans_reviewed:
  - 48-01-PLAN.md
  - 48-02-PLAN.md
  - 48-03-PLAN.md
  - 48-04-PLAN.md
  - 48-05-PLAN.md
---

# Cross-AI Plan Review -- Phase 48 (Cycle 4)

> Reviewed by: Codex CLI (gpt-5.5)
> Review date: 2026-05-16
> Prompt: Plan-only review (no code execution)
> Note: OpenCode unavailable (quota exceeded). Claude skipped (self).
> Prior reviews: 2026-05-15 (Codex gpt-5.5 + Claude claude-4-sonnet), 2026-05-16 Cycle 3 (Codex gpt-5.5 + OpenCode unavailable)

---

## Codex Review

### Summary

Phase 48 is directionally strong: it targets the right blockers before universal injection, especially crash containment, dual-arch build readiness, and signing. The plans are mostly well sequenced: Wave 1 establishes guardrails and hook primitives, Wave 2 integrates and expands architecture support, Wave 3 packages release trust. The highest risks are semantic mismatches around "fail-closed" versus the locked decision to fail-open on crash, incomplete treatment of asynchronous APIs and handle-based operations, and relying on manual PE/NT structure parsing without a very explicit validation harness.

### Strengths

- The phase scope is appropriately bounded. Universal injection, shared-memory cache, syscall trampolines, and ETW bypass detection are deferred.
- The `HookDescriptor` table is a good unifying abstraction for init, unhook, logging, and future surface expansion.
- Dual-arch support from the same crate is the right approach, especially with architecture-agnostic tests.
- Crash hardening is treated as a first-class requirement, not bolted on after hook expansion.
- Signing only on release tags is a sensible operational boundary.
- Including `signtool verify /pa` as a blocking gate is important and correctly called out.
- The 32K UTF-16 cap is a concrete protection against malformed or hostile wide strings.
- Thread-local buffers help avoid per-call allocation in hot hook paths.

### Concerns

- **HIGH: Fail-closed terminology conflicts with fail-open crash behavior.**
  The roadmap says "documented fail-closed returns," but D-05 and D-06 say exceptions route to the original function, meaning fail-open on crash. This needs precise taxonomy: policy deny should fail-closed; hook internal crash should fail-open.

- **HIGH: `catch_unwind` does not protect against SEH by itself.**
  Rust panics and Windows structured exceptions are different failure modes. The plan names both, but implementation details matter a lot, especially across FFI boundaries and patched stubs.

- **HIGH: Hooking async APIs is under-specified.**
  `WriteFileEx`, `CopyFileExW`, and `CopyFile2` have callback/progress semantics and may involve overlapped I/O. A simple pre-call allow/deny model may not preserve expected behavior or may miss actual write completion semantics.

- **HIGH: Handle-based hooks returning ALLOW for unknown handles weakens Phase 48 coverage.**
  This is probably acceptable as a phased limitation, but it means `WriteFile`, `NtWriteFile`, `SetFileInformationByHandle`, and `NtSetInformationFile` are not meaningfully enforceable unless the handle was previously mapped.

- **MEDIUM: Manual PE parsing is risky without strong malformed-binary tests.**
  Bounds like `MAX_IMPORT_DESCRIPTORS=512` help, but PE parsing must also validate RVA-to-section translation, integer overflow, descriptor termination, thunk bounds, ordinal imports, forwarded imports, and missing IAT cases.

- **MEDIUM: DllMain work may violate loader-lock constraints.**
  Eager patching during `DLL_PROCESS_ATTACH` can be dangerous if it calls APIs that may load DLLs, allocate, lock, initialize tracing, or touch IPC. The plan should specify exactly what is safe inside DllMain.

- **MEDIUM: Unhooking on `DLL_PROCESS_DETACH` can also be fragile.**
  During process teardown, dependencies may already be unloaded or partially torn down. Unhook should be best-effort and avoid complex work.

- **MEDIUM: Reentrancy behavior needs explicit deny/allow semantics.**
  If a hook re-enters during IPC, logging, memory allocation, or path conversion, the guard must define whether it bypasses to original, denies, or suppresses classification.

- **MEDIUM: IPC latency in hot file APIs may be significant.**
  Hooking `WriteFile` and `NtWriteFile` can put IPC on very hot paths. Even with thread-local buffers, synchronous pipe round trips can become a major performance bottleneck.

- **MEDIUM: x86 NT structure offsets are brittle.**
  Hardcoded offsets for `OBJECT_ATTRIBUTES` and `UNICODE_STRING` should be validated by compile-time layout tests or runtime sanity checks where possible.

- **LOW: The plan lists 12 hooks inconsistently.**
  The roadmap expansion list includes `CopyFile2`, but Plan 48-02's trampoline list omits `CopyFile2`. It says 12 trampolines but names 12 only if `CreateFileW` and `NtCreateFile` are included and `CopyFile2` is excluded. This needs reconciliation.

- **LOW: Signing test harness binaries is good, but local/dev unsigned behavior needs clarity.**
  Developers should still be able to run unsigned debug builds, while release packaging must enforce signatures.

### Suggestions

- Define three explicit failure classes:
  - Policy decision deny: fail-closed.
  - IPC unavailable or classifier unavailable: choose and document fail-open/fail-closed per requirement.
  - Hook crash or SEH/panic: fail-open to original function per D-05.

- Add a hook behavior matrix for every API:
  - Path source: direct path, NT path, handle map, source/destination pair.
  - Enforced action: create, write, move, copy, delete, replace, metadata mutation.
  - Unknown handle behavior.
  - Deny return value and `GetLastError` / `NTSTATUS`.
  - Async/overlapped behavior.
  - Whether Phase 48 truly enforces or only observes.

- Treat `CopyFile2` explicitly. If it has no reliable traditional IAT hook surface, either remove it from Phase 48 success criteria or document a supported interception strategy.

- Keep DllMain minimal. Prefer DllMain to disable thread notifications and start a safe initialization path only if the required operations are loader-lock safe. If eager patching remains mandatory, document the forbidden operations inside that path.

- Add focused tests for crash hardening:
  - Panic inside classification.
  - Simulated SEH/access violation inside guarded logic.
  - Reentrant hook call.
  - Malformed UTF-16 path.
  - 32K+ path input.
  - IPC unavailable.
  - Agent timeout.
  - Unknown handle.

- Add PE parser tests using fixture DLLs:
  - x86 and x64.
  - No imports.
  - Missing target import.
  - Ordinal imports.
  - Large import table.
  - Malformed descriptors.
  - Bound or delayed imports if applicable.

- Require release verification to confirm both architecture DLLs are signed and packaged:
  - `dlp_hook_dll.dll`
  - `dlp_hook_dll_x86.dll`
  - `dlp-e2e.exe`
  - service/CLI/UI/server binaries as applicable.

- Add performance acceptance criteria before universal injection:
  - Maximum hook overhead for allow path.
  - IPC timeout budget.
  - Behavior under high-frequency `WriteFile`.
  - Contention behavior across many threads.

- Add explicit ABI and FFI safety review gates for trampoline signatures, calling conventions, stack cleanup on x86, and preservation of `LastError`.

### Risk Assessment: HIGH

The phase touches injected code, trampoline patching, Windows loader behavior, NT APIs, cross-process IPC, x86/x64 ABI differences, and release signing in one phase. The crash-hardening direction is good, but several assumptions can become bypasses or process-wide crashes: eager DllMain patching, incomplete handle context, fail-open behavior, hook recursion, and manual PE/structure parsing. I would keep the phase, but require a strict harness-first rollout with per-hook tests, reentrancy protection, fixed IPC schema, and explicit failure-mode policy before treating it as production-ready.

---

## Plan-by-Plan Assessment

### Plan 48-01: Crash Hardening -- Risk: MEDIUM-HIGH

Foundational and easy to get subtly wrong. If implemented correctly, it substantially lowers Phase 49 risk; if not, it can destabilize every injected process.

### Plan 48-02: Expanded Hook Surface -- Risk: HIGH

The surface area is large, and correctness depends on API-specific semantics. This is the riskiest plan in the phase.

### Plan 48-03: Unified DLL Integration -- Risk: MEDIUM-HIGH

The architecture is sound, but DllMain and NT path extraction are high-risk implementation zones.

### Plan 48-04: x86 Sibling + CI Matrix -- Risk: MEDIUM

The build work is straightforward; runtime correctness of x86 hooks is the main risk.

### Plan 48-05: Authenticode Signing Pipeline -- Risk: MEDIUM

The plan is operationally sound but needs careful release artifact verification to avoid shipping unsigned or mismatched binaries.

---

## Consensus Summary

### Agreed Strengths (from this cycle)

- Phase scope is appropriately bounded; deferred items (universal injection, cache, ETW) are correctly left out.
- `HookDescriptor` table is a good unifying abstraction.
- Dual-arch support from same crate is the right approach.
- Crash hardening treated as first-class requirement.
- Release-tag-only signing is sensible operational boundary.
- `signtool verify /pa` blocking gate is correctly called out.
- 32K UTF-16 cap is concrete protection.
- Thread-local buffers avoid per-call allocation in hot paths.

### Agreed Concerns (Highest Priority)

1. **HIGH: Fail-closed terminology conflicts with fail-open crash behavior.** Policy deny = fail-closed; hook crash = fail-open. Need explicit taxonomy.
2. **HIGH: `catch_unwind` does not protect against SEH by itself.** Rust panics and Windows SEH are different failure modes; implementation details matter across FFI.
3. **HIGH: Hooking async APIs is under-specified.** `WriteFileEx`, `CopyFileExW` have callback/progress semantics; simple pre-call allow/deny may miss completion semantics.
4. **HIGH: Handle-based hooks returning ALLOW for unknown handles weakens coverage.** 5 of 12 hooks are non-functional until Phase 49/50 handle tracker.
5. **MEDIUM: Manual PE parsing is risky without strong malformed-binary tests.** MAX_IMPORT_DESCRIPTORS=512 helps but RVA validation, ordinal imports, forwarded imports need coverage.
6. **MEDIUM: DllMain work may violate loader-lock constraints.** Need explicit list of safe operations inside DllMain.
7. **MEDIUM: Unhooking on `DLL_PROCESS_DETACH` can be fragile.** Dependencies may already be torn down.
8. **MEDIUM: Reentrancy behavior needs explicit deny/allow semantics.** Guard must define whether reentrant call bypasses to original, denies, or suppresses.
9. **MEDIUM: IPC latency in hot file APIs may be significant.** Synchronous pipe round trips on WriteFile/NtWriteFile hot paths are a performance concern.
10. **MEDIUM: x86 NT structure offsets are brittle.** Need compile-time layout tests or runtime sanity checks.

### Divergent Views

- **Fail-open vs fail-closed on crash**: Codex (this cycle) and prior review both flagged this as HIGH. The user's CONTEXT.md explicitly chose fail-open (D-06). This is a fundamental policy decision that may warrant revisiting rather than changing the plan.
- **Risk level**: Codex rated HIGH (this cycle); prior Claude review rated MEDIUM-HIGH. The difference is that Codex sees additional structural risks (async APIs, DllMain loader lock, PE parsing, UnhookAll race) that keep it HIGH even with fixes.
- **CopyFile2 scope**: The roadmap says 11 functions plus CopyFile2 (indirect), but the plan says 12 trampolines excluding CopyFile2. This inconsistency needs reconciliation.

---

## Prior Review Retrospective (Cycle 1, 2026-05-15)

The first cross-AI review (Codex gpt-5.5 + Claude claude-4-sonnet) identified 6 HIGH-severity concerns. The plans have since been updated to address most of them:

| Prior Concern | Status in Current Plans | Resolution |
|---------------|------------------------|------------|
| SEH guard may be no-op stub | **Addressed** -- Plan 48-01 now has a BLOCKING GATE: build fails if no working SEH is available (no stub fallback) | FULLY RESOLVED |
| x86 offsets hardcoded in 48-03, fixed in 48-04 | **Addressed** -- Plan 48-03 now includes cfg(target_arch) for extract_nt_path offsets directly | FULLY RESOLVED |
| Hook recursion/reentrancy not addressed | **Addressed** -- Plan 48-01 adds with_reentrancy_guard (thread-local Cell<bool>) | FULLY RESOLVED |
| find_iat_entry has no bounds checking | **Addressed** -- Plan 48-02 adds MAX_IMPORT_DESCRIPTORS=512 | FULLY RESOLVED |
| No UnhookAll on DLL_PROCESS_DETACH | **Addressed** -- Plan 48-03 explicitly calls UnhookAll() on detach | FULLY RESOLVED |
| No test coverage for actual DLL injection | **Partially addressed** -- Plan 48-03 adds IAT patch/restore integration test in current process | PARTIALLY RESOLVED |
| Handle-based hooks non-functional until Phase 49/50 | **Documented** -- Plan 48-03 explicitly notes the gap and explains why it's acceptable | PARTIALLY RESOLVED |
| Double-signing on timestamp fallback | **Addressed** -- Plan 48-05 adds per-binary failure tracking | FULLY RESOLVED |
| action: String in IPC schema | **Not addressed** -- Still String, not enum | UNRESOLVED |
| dlp-e2e.exe signing scope creep | **Addressed** -- Removed from signing list in Plan 48-05 | FULLY RESOLVED |

### Cycle 1 Action Items -- Status

| Priority | Item | Source | Status |
|----------|------|--------|--------|
| P0 | Verify SEH bindings or commit C shim fallback before Wave 1 | Both (HIGH) | **RESOLVED** -- Blocking gate added |
| P0 | Add cfg(target_arch) for x86 offsets directly in Plan 48-03 | Both (HIGH) | **RESOLVED** -- Added to 48-03 |
| P1 | Add reentrancy guard to prevent hook recursion | Codex (HIGH) | **RESOLVED** -- with_reentrancy_guard added |
| P1 | Add bounds checking to find_iat_entry PE parsing loop | Both (HIGH/MEDIUM) | **RESOLVED** -- MAX_IMPORT_DESCRIPTORS=512 |
| P1 | Document handle-based hook functional gap in success criteria | Both (HIGH/MEDIUM) | **RESOLVED** -- Documented in 48-03 |
| P1 | Add DLL_PROCESS_DETACH cleanup calling UnhookAll() | Claude (MEDIUM) | **RESOLVED** -- Added to 48-03 |
| P2 | Add IAT patch/restore integration test in current process | Claude (HIGH) | **PARTIALLY RESOLVED** -- Test added in 48-03 |
| P2 | Replace action: String with typed enum in IPC schema | Codex (MEDIUM) | **UNRESOLVED** -- Still String |
| P2 | Fix signing fallback to avoid double-signing | Claude (MEDIUM) | **RESOLVED** -- Per-binary tracking added |
| P2 | Use u64 for handle_value in IPC to avoid architecture ambiguity | Codex (MEDIUM) | **RESOLVED** -- handle_value: u64 in HandleHookRequest |

---

## Action Items for Planner

| Priority | Item | Source | Cycle 1 Status | Cycle 2 Status | Cycle 3 Status | Cycle 4 Status |
|----------|------|--------|----------------|----------------|----------------|----------------|
| P0 | Define explicit failure taxonomy: policy deny = fail-closed, hook crash = fail-open, IPC unavailable = document choice | Codex (Cycle 2-4, HIGH) | New | New | New | New |
| P0 | Reconcile CopyFile2 scope: remove from success criteria or document interception strategy | Codex (Cycle 2-4, HIGH) | New | New | New | New |
| P0 | Document safe DllMain operations list and loader-lock constraints | Codex (Cycle 2-4, HIGH) | New | New | New | New |
| P0 | Address UnhookAll() race with active trampolines during detach | Codex (Cycle 2-4, HIGH) | New | New | New | New |
| P1 | Add explicit reentrancy fallback semantics (call original, not deny) | Codex (Cycle 2-4, MEDIUM) | New | New | New | New |
| P1 | Add PE parser malformed-binary tests (ordinal imports, forwarded imports, missing IAT) | Codex (Cycle 2-4, MEDIUM) | New | New | New | New |
| P1 | Add performance acceptance criteria for hot-path IPC latency | Codex (Cycle 2-4, MEDIUM) | New | New | New | New |
| P1 | Harden CI secret handling for Authenticode signing (KMS, tag protection) | Codex (Cycle 2-4, HIGH) | New | New | New | New |
| P2 | Replace action: String with typed enum in IPC schema | Codex (Cycle 1, MEDIUM) | **UNRESOLVED** | **UNRESOLVED** | **UNRESOLVED** | **UNRESOLVED** |
| P2 | Add compile-time layout tests for x86/x64 OBJECT_ATTRIBUTES/UNICODE_STRING offsets | Codex (Cycle 2-4, MEDIUM) | New | New | New | New |
| P2 | Add async API behavior matrix (WriteFileEx, CopyFileExW overlapped semantics) | Codex (Cycle 2-4, HIGH) | New | New | New | New |
| P3 | Clarify local/dev unsigned build behavior vs release signing | Codex (Cycle 2-4, LOW) | New | New | New | New |
| P3 | Increase pipe buffer size or make it configurable if request envelopes grow | Codex (Cycle 2-4, LOW) | New | New | New | New |

---

*To incorporate feedback into planning: `/gsd-plan-phase 48 --reviews`*
