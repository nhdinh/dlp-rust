---
phase: 51-ntdll-syscall-stub-trampolines-edr-coexistence
reviewed: 2026-05-22T11:35:00Z
depth: standard
files_reviewed: 0
files_reviewed_list: []
findings:
  critical: 0
  warning: 4
  info: 3
  total: 7
status: issues_found
---

# Phase 51: Code Review Report

**Reviewed:** 2026-05-22T11:35:00Z
**Depth:** standard
**Files Reviewed:** 0
**Status:** issues_found

## Summary

Phase 51 consists entirely of planning and research artifacts. No source code was implemented in this phase. The deliverables are 6 execution plans (51-01 through 51-06), plus context, research, patterns, validation strategy, and discussion log documents.

This review examined all planning documents for correctness, consistency, security considerations, and adherence to project standards. While the plans are well-structured, several **HIGH-severity concerns** were identified that must be addressed before execution begins.

## Critical Issues

None. No source code was implemented in this phase.

## Warnings

### WR-01: retour Crate Version Discrepancy Between CONTEXT.md and RESEARCH.md/PATTERNS.md

**File:** `.planning/phases/51-ntdll-syscall-stub-trampolines-edr-coexistence/51-CONTEXT.md:37`, `51-RESEARCH.md:15`, `51-PATTERNS.md:526`
**Issue:** 51-CONTEXT.md states D-01 uses `retour` 0.3.1, but 51-RESEARCH.md and 51-PATTERNS.md correctly identify that 0.3.1 does not exist on crates.io and specify 0.4.0-alpha.4. The plans (51-02-PLAN.md:155) reference 0.4.0-alpha.4. This inconsistency could cause confusion during implementation if a developer reads CONTEXT.md first.
**Fix:** Update 51-CONTEXT.md D-01 to state `retour` 0.4.0-alpha.4 (not 0.3.1). Add a note that 0.3.1 was the originally intended version but does not exist on crates.io.

### WR-02: Missing `#[cfg(windows)]` Guards on New Modules in Plan Specifications

**File:** `.planning/phases/51-ntdll-syscall-stub-trampolines-edr-coexistence/51-01-PLAN.md:124`, `51-02-PLAN.md:211`
**Issue:** The plans specify creating `edr_detector.rs`, `thread_suspender.rs`, and `ntdll_patcher.rs` without requiring `#[cfg(windows)]` module declarations or conditional compilation. These modules use Windows-only APIs (NtQuerySystemInformation, EnumProcessModules, VirtualProtect) and will fail to compile on non-Windows targets. The existing codebase likely uses `#[cfg(windows)]` for hook DLL modules.
**Fix:** Add a requirement in each plan that new modules must be declared with `#[cfg(windows)]` in `lib.rs`, and all module contents must be wrapped in `#[cfg(windows)]` or the module itself conditionally compiled. Example:
```rust
#[cfg(windows)]
mod edr_detector;
#[cfg(windows)]
mod thread_suspender;
#[cfg(windows)]
mod ntdll_patcher;
```

### WR-03: Plan 02 Task 0 (Human Checkpoint) is Blocking but Not Tracked as beads Issue

**File:** `.planning/phases/51-ntdll-syscall-stub-trampolines-edr-coexistence/51-02-PLAN.md:124-144`
**Issue:** The human verification checkpoint for retour crate legitimacy is marked as `gate="blocking-human"` but there is no corresponding beads issue tracking this blocker. If the human never reviews/approves, Wave 1 execution cannot proceed, yet no issue exists to remind the operator. The checkpoint requires visiting crates.io and GitHub — manual steps that could be forgotten.
**Fix:** Create a beads issue specifically for the retour legitimacy verification checkpoint, with a dependency link to the Phase 51 epic. Set priority to P0 since it blocks all Wave 1 execution.

### WR-04: Validation Strategy Lists Non-Existent File `thread_control.rs` Instead of `thread_suspender.rs`

**File:** `.planning/phases/51-ntdll-syscall-stub-trampolines-edr-coexistence/51-VALIDATION.md:56`
**Issue:** The Wave 0 Requirements table lists `dlp-hook-dll/src/thread_control.rs` as a required module, but all plans (51-01 through 51-06) consistently name the module `thread_suspender.rs`. This inconsistency could cause confusion during Wave 0 verification.
**Fix:** Change `thread_control.rs` to `thread_suspender.rs` in 51-VALIDATION.md line 56.

## Info

### IN-01: Plan 06 Recommends `Mutex` Around `NtdllPatcher` but `RawDetour` May Not Be `Send`

**File:** `.planning/phases/51-ntdll-syscall-stub-trampolines-edr-coexistence/51-06-PLAN.md:127`
**Issue:** The plan specifies `OnceLock<std::sync::Mutex<crate::ntdll_patcher::NtdllPatcher>>`. If `retour::RawDetour` does not implement `Send` (common for handle types wrapping raw pointers), storing it inside a `Mutex` that may be accessed across threads could fail to compile. The plan does not address this potential compilation issue.
**Fix:** Add a note in Plan 06 that if `RawDetour` is not `Send`, the `NtdllPatcher` should use a pattern like storing detour handles in thread-local storage or using `unsafe impl Send` with documented safety invariants.

### IN-02: 51-VALIDATION.md `nyquist_compliant: false` and `wave_0_complete: false` Should Be Updated

**File:** `.planning/phases/51-ntdll-syscall-stub-trampolines-edr-coexistence/51-VALIDATION.md:5-6`
**Issue:** The validation document frontmatter has `nyquist_compliant: false` and `wave_0_complete: false`. These are draft markers. Since the validation strategy is now complete and documented, these should be reviewed and set to `true` if the strategy meets Nyquist criteria (automated verify on every task, no 3 consecutive tasks without verify).
**Fix:** Review the validation strategy against Nyquist criteria. If compliant, set `nyquist_compliant: true`. Wave 0 completion status should remain `false` until Wave 0 files are actually created during execution.

### IN-03: Plan 03 Trampoline Fallback Pattern Uses `panic!` in Production Code Path

**File:** `.planning/phases/51-ntdll-syscall-stub-trampolines-edr-coexistence/51-03-PLAN.md:201-204`
**Issue:** The fallback pattern in Plan 03 shows:
```rust
let fallback = crate::resolve_nt_create_file().unwrap_or_else(|| {
    panic!("NtCreateFile original unavailable and resolution failed")
});
```
Using `panic!` in a trampoline fallback path violates the project's crash-hardening principles (crash_guard.rs exists specifically to prevent panics from crashing the host process). While this is in a plan document (not source code), the plan should specify a safer fallback.
**Fix:** Update the plan to specify a graceful fallback that returns `STATUS_ACCESS_DENIED` (fail-closed) or `STATUS_UNSUCCESSFUL` instead of panicking. The `guard_trampoline` outer layer should handle this without panic.

---

_Reviewed: 2026-05-22T11:35:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
