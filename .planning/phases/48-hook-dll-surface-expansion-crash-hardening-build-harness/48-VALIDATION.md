---
phase: 48
slug: hook-dll-surface-expansion-crash-hardening-build-harness
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-15
---

# Phase 48 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Built-in `#[test]` + `cargo test` (Rust standard) |
| **Config file** | None — inline `#[cfg(test)]` modules |
| **Quick run command** | `cargo test -p dlp-hook-dll` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~30 seconds (unit) / ~120 seconds (workspace) |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-hook-dll`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 48-01-01 | 01 | 1 | BLOCK-01 | CRIT-02 | catch_unwind catches panic in trampoline | unit | `cargo test -p dlp-hook-dll catch_unwind` | ❌ W0 | pending |
| 48-01-02 | 01 | 1 | BLOCK-01 | CRIT-02 | 32K cap truncates long paths | unit | `cargo test -p dlp-hook-dll pcwstr_cap` | ❌ W0 | pending |
| 48-01-03 | 01 | 1 | BLOCK-01 | CRIT-02 | Thread-local buffer reused | unit | `cargo test -p dlp-hook-dll buffer_reuse` | ❌ W0 | pending |
| 48-02-01 | 02 | 1 | BLOCK-02 | — | Each of 11 trampolines returns correct deny value | unit | `cargo test -p dlp-hook-dll deny_return` | ❌ W0 | pending |
| 48-02-02 | 02 | 1 | BLOCK-02 | — | HookDescriptor table enumerates all hooks | unit | `cargo test -p dlp-hook-dll hook_descriptor` | ❌ W0 | pending |
| 48-03-01 | 03 | 2 | BLOCK-03 | — | Existing dlp-e2e workspace tests pass | integration | `cargo test -p dlp-e2e` | Yes | pending |
| 48-04-01 | 04 | 2 | BLOCK-04 | — | x86 DLL builds successfully | build | `cargo build --target i686-pc-windows-msvc -p dlp-hook-dll` | ❌ W0 | pending |
| 48-04-02 | 04 | 2 | BLOCK-04 | — | HookInjector selects x86 DLL for WOW64 process | unit | `cargo test -p dlp-agent injector_x86` | Yes | pending |
| 48-05-01 | 05 | 3 | BLOCK-10 | — | Release workflow triggers on v* tags | CI | Push a test tag to fork | ❌ W0 | pending |

*Status: pending | green | red | flaky*

---

## Wave 0 Requirements

- [ ] `dlp-hook-dll/src/crash_guard.rs` — SEH + catch_unwind test fixtures
- [ ] `dlp-hook-dll/src/fail_closed.rs` — DenyReturn enum + macro tests
- [ ] `dlp-hook-dll/src/pe_utils.rs` — x86 find_iat_entry test (needs PE32 test binary or mock)
- [ ] `.github/workflows/release.yml` — signing workflow (BLOCK-10)
- [ ] `rustup target add i686-pc-windows-msvc` — CI toolchain install step
- [ ] `installer/DLPAgent.wxs` — add dlp_hook_dll.dll and dlp_hook_dll_x86.dll components

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Authenticode signature verification on physical binary | BLOCK-10 | Requires actual cert + tag push | 1. Push v0.10.0-test tag 2. Verify signtool verify /pa passes 3. Check Properties > Digital Signatures |
| x86 DLL injection into WOW64 process | BLOCK-04 | Requires 32-bit test binary + live injection | 1. Build 32-bit notepad clone 2. Run injector with IsWow64Process 3. Verify DllMain hello message in pipe |

---

## Validation Sign-Off

- [ ] All tasks have automated verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
