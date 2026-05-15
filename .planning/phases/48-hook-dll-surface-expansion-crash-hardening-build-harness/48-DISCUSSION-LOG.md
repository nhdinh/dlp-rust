# Phase 48: Hook DLL Surface Expansion + Crash Hardening + Build Harness - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-15
**Phase:** 48-Hook DLL Surface Expansion + Crash Hardening + Build Harness
**Areas discussed:** Hook Implementation Strategy, Crash Hardening Boundaries, x86 Build Architecture, Signing Pipeline
**Mode:** --analyze (trade-off tables presented before each question)

---

## Hook Implementation Strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Hybrid (recommended) | Metadata table drives UnhookAll/logging; manual trampolines for precision. Scales cleanly without macro complexity. | ✓ |
| Fully manual | Explicit per-function IAT patching like the current code. More verbose but maximum control. | |
| Macro-generated | Proc-macro generates all stubs from a descriptor list. Less code but harder to debug. | |

**User's choice:** Hybrid (recommended)
**Notes:** User accepted the recommendation. The hybrid approach uses a `const HOOKS: &[HookDescriptor]` table for metadata while keeping each trampoline hand-written for path-extraction precision.

### Sub-questions

**Path resolution for HANDLE-based functions:**

| Option | Description | Selected |
|--------|-------------|----------|
| GetFinalPathNameByHandleW (recommended) | Query the OS for the path from the handle. Reliable but adds a syscall per hooked I/O. | |
| Require agent to maintain handle->path map | Agent tracks opened handles via hooked NtCreateFile/NtOpenFile. Hook DLL queries agent over pipe. | ✓ |
| Skip classification for HANDLE-based ops | Only classify at open-time. Simpler but misses writes to already-open T3/T4 handles. | |

**User's choice:** Require agent to maintain handle->path map
**Notes:** User preferred pushing complexity to the agent rather than adding syscalls in the hook DLL hot path.

**Fail-closed return value management:**

| Option | Description | Selected |
|--------|-------------|----------|
| Per-function constant in HookDescriptor table | Each HookDescriptor carries its own `deny_return_value`. Clean and explicit. | |
| Generic macro that matches on function signature | A macro or trait generates the correct denial return based on return type. | ✓ |
| Manual per-trampoline hardcoding | Each trampoline hardcodes its own denial return. Simple but repetitive. | |

**User's choice:** Generic macro that matches on function signature
**Notes:** User accepted recommendation for less boilerplate.

**Patch timing:**

| Option | Description | Selected |
|--------|-------------|----------|
| Eager at DllMain | All 11 IAT entries patched during DLL_PROCESS_ATTACH. | ✓ |
| Lazy on first call | Each function patched the first time it's called. | |
| Eager for create/open, lazy for write/setinfo | Patch create/open paths eagerly, defer write/setinfo to first call. | |

**User's choice:** Eager at DllMain
**Notes:** User preferred simplicity over DllMain time optimization.

---

## Crash Hardening Boundaries

| Option | Description | Selected |
|--------|-------------|----------|
| Layered: SEH outer + catch_unwind inner | SEH catches AVs in unsafe, catch_unwind catches Rust panics. Both route to fail-open. | ✓ |
| Full function wrapper | catch_unwind + SEH around entire HookXxx body. Maximum safety but more overhead. | |
| Minimal wrapper | Only around classify_path(). Low overhead but path extraction unprotected. | |

**User's choice:** Layered: SEH outer + catch_unwind inner
**Notes:** User accepted the recommendation for comprehensive protection.

### Sub-questions

**Crash fallback behavior:**

| Option | Description | Selected |
|--------|-------------|----------|
| Fail-open only (recommended) | Log the crash, call original function. No self-repair. | ✓ |
| Fail-open with one-shot retry | First crash -> fail-open + log. Second crash within 60s -> skip that function. | |
| Self-repair and retry | Attempt to restore IAT entry and re-patch. Risk of infinite loops. | |

**User's choice:** Fail-open only (recommended)
**Notes:** User prioritized host process stability over bypass resistance for crash scenarios.

**32K-char cap enforcement:**

| Option | Description | Selected |
|--------|-------------|----------|
| In pcwstr_to_string (recommended) | Central enforcement in the wide-string conversion helper. | ✓ |
| Per-trampoline before calling pcwstr_to_string | Each trampoline checks length. More explicit but repetitive. | |
| In pipe_client::send_request | Too late — string already converted. | |

**User's choice:** In pcwstr_to_string (recommended)

**catch_unwind scope:**

| Option | Description | Selected |
|--------|-------------|----------|
| Include pipe_client (recommended) | Wrap entire classify_path -> pipe_client -> decision pipeline. | ✓ |
| Only classify_path wrapper | Only wrap high-level decision logic. | |
| Wrap every internal function | Most granular but verbose. | |

**User's choice:** Include pipe_client (recommended)

**Pre-allocated buffer strategy:**

| Option | Description | Selected |
|--------|-------------|----------|
| Thread-local pre-allocated buffer (recommended) | Each thread gets a 4KiB Vec<u8> in thread_local!(). | ✓ |
| Global static buffer | Single static mut Vec — requires synchronization. | |
| Keep allocate-per-call | Current pattern. Defer optimization. | |

**User's choice:** Thread-local pre-allocated buffer (recommended)

---

## x86 Build Architecture

| Option | Description | Selected |
|--------|-------------|----------|
| Same crate, cfg(target_arch) | True "same source" — single lib.rs with conditional compilation. | ✓ |
| Shared core + thin arch wrappers | hook_core.rs has shared logic; arch-specific wrappers. | |
| Separate dlp-hook-dll-x86 crate | Clean separation but duplicated build config. | |

**User's choice:** Same crate, cfg(target_arch)
**Notes:** User accepted recommendation. IAT parsing differences localized to find_iat_entry.

### Sub-questions

**DLL naming:**

| Option | Description | Selected |
|--------|-------------|----------|
| dlp_hook_dll_x86.dll (recommended) | Explicit architecture suffix. | ✓ |
| dlp_hook_dll.dll in separate directory | Same name, different directory. | |
| You decide | Either works technically. | |

**User's choice:** dlp_hook_dll_x86.dll (recommended)

**PE parsing approach:**

| Option | Description | Selected |
|--------|-------------|----------|
| Manual with cfg(target_arch) (recommended) | Keep manual parsing with cfg blocks. | ✓ |
| Use goblin/pelite crate | Robust but adds dependency. | |
| You decide | Both work. | |

**User's choice:** Manual with cfg(target_arch) (recommended)
**Notes:** User said "All per your recommendations" — accepted all recommendations in this area.

**CI build strategy:**

| Option | Description | Selected |
|--------|-------------|----------|
| Cross-compile on x64 runner (recommended) | Install i686-pc-windows-msvc toolchain in CI. | ✓ |
| Matrix with self-hosted x86 runner | Native compilation but requires self-hosted runner. | |
| You decide | Cross-compilation is standard. | |

**User's choice:** Cross-compile on x64 runner (recommended)

**x86 ntdll hooking:**

| Option | Description | Selected |
|--------|-------------|----------|
| Hook ntdll too (recommended) | Patch NtCreateFile/NtOpenFile on x86 for completeness. | ✓ |
| Skip ntdll on x86 | Focus on kernel32 Win32 APIs. | |
| You decide | Either works. | |

**User's choice:** Hook ntdll too (recommended)

**x86 testing:**

| Option | Description | Selected |
|--------|-------------|----------|
| Architecture-agnostic tests (recommended) | Same test logic regardless of architecture. | ✓ |
| Separate x86 test suite | Dedicated test file for i686-pc-windows-msvc. | |
| You decide | Agnostic is simpler. | |

**User's choice:** Architecture-agnostic tests (recommended)

**x86 crash hardening:**

| Option | Description | Selected |
|--------|-------------|----------|
| Full hardening on x86 too (recommended) | Same catch_unwind + SEH as x64. | ✓ |
| Defer x86 hardening | Ship x86 with basic hooks only. | |
| You decide | Full hardening is consistent. | |

**User's choice:** Full hardening on x86 too (recommended)

---

## Signing Pipeline

| Option | Description | Selected |
|--------|-------------|----------|
| GitHub secret (PFX + password) | Simple; works with signtool sign /f. PFX in secrets is extractable. | ✓ |
| Azure Key Vault | HSM-backed; no secrets in CI. Requires Azure subscription. | |
| Self-hosted runner | Full control; cert on disk at build time. | |

**User's choice:** GitHub secret (PFX + password)
**Notes:** User accepted recommendation. Regular (non-EV) Authenticode cert doesn't justify Key Vault complexity for v0.10.0.

### Sub-questions

**Signing trigger:**

| Option | Description | Selected |
|--------|-------------|----------|
| Release tags only (recommended) | Only sign on release tags. | ✓ |
| Every push | Sign every commit. | |
| Manual workflow only | Only triggered by manual dispatch. | |

**User's choice:** Release tags only (recommended)

**Verify gate:**

| Option | Description | Selected |
|--------|-------------|----------|
| Sign + verify gate (recommended) | Run signtool verify /pa after signing. | ✓ |
| Sign only, no verify gate | Trust signtool exit code. | |
| You decide | Verify gate is safer. | |

**User's choice:** Sign + verify gate (recommended)

**Test harness signing:**

| Option | Description | Selected |
|--------|-------------|----------|
| Sign test harness too (recommended) | dlp-e2e binaries also signed. | ✓ |
| Skip test harness | Only sign production binaries. | |
| You decide | Signing test harness is consistent. | |

**User's choice:** Sign test harness too (recommended)

**Timestamp server:**

| Option | Description | Selected |
|--------|-------------|----------|
| DigiCert primary + Sectigo fallback (recommended) | DigiCert first, fall back to Sectigo. | ✓ |
| DigiCert only | Simpler but single point of failure. | |
| You decide | Fallback is more resilient. | |

**User's choice:** DigiCert primary + Sectigo fallback (recommended)

---

## Claude's Discretion

The user explicitly deferred to Claude's judgment on:
- PE parsing approach ("All per your recommendations")
- Installer packaging (skipped — deferred to Phase 57 OPS)
- Hook protocol versioning (skipped — deferred to Phase 50 CACHE)
- Regression test harness updates (skipped — defer to planning)

## Deferred Ideas

- Hook protocol versioning with `pid`, `tid`, `file_object`, `journal_seq` → Phase 50 (CACHE)
- Shared-memory classification cache → Phase 50
- Universal injection via ETW Process Watcher → Phase 49
- ntdll syscall-stub trampolines → Phase 51
- Installer auto-update for DLL replacement → Phase 57 (OPS)
- Azure Key Vault migration for EV code signing → Post-v0.10.0

---

*Phase: 48-Hook DLL Surface Expansion + Crash Hardening + Build Harness*
*Discussion logged: 2026-05-15*
