# Phase 51: ntdll Syscall-Stub Trampolines + EDR Coexistence - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-22
**Phase:** 51-ntdll-syscall-stub-trampolines-edr-coexistence
**Areas discussed:** Trampoline Implementation, EDR Detection, Thread Safety, Re-verification, Feature Flag, x86 Support
**Mode:** --auto (all gray areas auto-selected with recommended defaults)

---

## Trampoline Implementation Library

| Option | Description | Selected |
|--------|-------------|----------|
| `retour` 0.3.1 | Rust-native Detours-style trampolines, x64+x86 support | ✓ |
| Custom inline assembly | Hand-rolled 5-byte JMP + absolute jump table | |
| Microsoft Detours | C++ library, requires FFI bindings | |

**Auto-selected:** `retour` 0.3.1 (recommended default)
**Rationale:** Already mentioned in STATE.md decision 4. Rust-native, no C++ dependency, both architectures. Matches existing research.

---

## EDR Detection Strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Module enumeration only | Walk loaded modules, check known EDR DLL names | |
| Stub prologue inspection only | Read stub bytes, detect 0xE9 JMP, walk target | |
| Both (pre-filter + confirm) | Module enum as fast pre-filter, stub inspection for confirmation | ✓ |

**Auto-selected:** Both — module enumeration pre-filter + stub prologue inspection
**Rationale:** Matches ROADMAP success criterion #2 explicitly. Fast pre-filter avoids reading stub bytes of every DLL.

---

## Thread Safety During Patch

| Option | Description | Selected |
|--------|-------------|----------|
| Suspend-all, patch, resume | Simple but risks torn instruction | |
| Suspend-all, check RIP, patch if safe | Verify no thread RIP in [stub, stub+5] before patching | ✓ |
| Windows atomic sequences | Not available for 5-byte JMP | |

**Auto-selected:** Suspend-all, check RIP in stub range, patch if safe
**Rationale:** Matches ROADMAP success criterion #4. `cmpxchg8b` on x86 for atomic write.

---

## Re-verification Thread

| Option | Description | Selected |
|--------|-------------|----------|
| New dedicated thread | Separate thread for trampoline verification | |
| Extend Phase 50 background thread | Reuse existing 100ms polling thread | ✓ |
| Agent-side pipe check | Verify via periodic pipe message | |

**Auto-selected:** Extend existing Phase 50 background thread
**Rationale:** Minimizes resource footprint. Phase 50 already has `WaitForSingleObject` loop — add verification callback.

---

## IAT vs Ntdll Hook Coexistence

| Option | Description | Selected |
|--------|-------------|----------|
| Replace IAT with ntdll | Remove IAT hooks, use ntdll stubs only | |
| Keep both independently | IAT for coverage, ntdll for bypass — both call same classify function | ✓ |
| IAT delegates to ntdll | IAT trampolines jump to ntdll stubs | |

**Auto-selected:** Keep both independently
**Rationale:** IAT hooks still catch normal API usage. Ntdll stubs catch direct-syscall bypass. Simpler than delegation chain.

---

## x86 Support

| Option | Description | Selected |
|--------|-------------|----------|
| x64 only | Ntdll patching only on x64 hook DLL | |
| Both x64 and x86 | Patch ntdll on both architectures | ✓ |

**Auto-selected:** Both x64 and x86
**Rationale:** Existing dual-arch build harness supports both. `retour` handles both. `cfg(target_arch)` already used for offsets.

---

## Feature Flag Default

| Option | Description | Selected |
|--------|-------------|----------|
| Default on | All deployments get ntdll patching | |
| Default off | Operator opts in per-customer after testing | ✓ |

**Auto-selected:** Default off
**Rationale:** Matches ROADMAP success criterion #5. EDR coexistence varies per environment. Safe rollout requires opt-in.

---

## Claude's Discretion

- `retour` chosen over custom inline asm for maintainability
- Per-stub re-verification chosen over all-or-nothing
- `cmpxchg8b` for x86 atomic 5-byte write
- Module-name matching derived from existing `AllowlistCategory::Avedr` entries

## Deferred Ideas

- Non-ntdll syscall stubs (e.g., `NtQuerySystemInformation`) — out of scope for file-IOP bypass
- Admin TUI screen for ntdll patching status — belongs in Phase 54 (Bypass Alerts)
- EDR vendor-specific bypass techniques — explicitly out of scope (coexistence only)
