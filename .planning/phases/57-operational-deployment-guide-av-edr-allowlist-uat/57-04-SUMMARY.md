---
phase: 57-operational-deployment-guide-av-edr-allowlist-uat
plan: 04
subsystem: docs
last_updated: 2026-05-30
dependency_graph:
  requires:
    - 57-01
  provides:
    - docs/operations/deployment-guide.md (canonical deployment reality content)
  affects:
    - docs/operations/deployment-guide.md
key_files:
  created: []
  modified:
    - docs/operations/deployment-guide.md
tech_stack:
  added: []
  patterns: []
decisions: []
metrics:
  duration_minutes: 25
  completed_date: 2026-05-30
  tasks_completed: 3
  files_created: 0
  files_modified: 1
---

# Phase 57 Plan 04: Deployment Reality Documentation Summary

One-liner: Canonical operational reality sections for the deployment guide
covering Secure Boot fallback, PPL coverage gaps, DACL tripwire backstop,
SeSystemProfilePrivilege assignment, and mechanism-qualified reboot requirements.

## What Was Built

### docs/operations/deployment-guide.md (modified, +196 lines)

Replaced placeholder content from 57-01 with definitive operational reality
documentation per D-24 (canonical ownership):

1. **Secure Boot Impact on Injection**:
   - AppInit_DLLs registry key is ignored under Secure Boot
   - Agent detects this at startup and emits `EventType::AppInitDllsDisabled` SIEM event
   - Primary injection falls back to ETW Kernel-Process watcher + CreateRemoteThread
   - Coverage is functionally identical; only mechanism changes
   - Event Viewer query documented with correct agent event source
   - **No Action Required**: operators do NOT need to disable Secure Boot

2. **CreateRemoteThread EDR Compatibility**:
   - Agent's CreateRemoteThread usage is targeted (specific PID, known DLL path)
   - Should not trigger generic injection alerts on most EDRs
   - If blocked, operator may need additional exclusion for agent service account
   - Operator-visible signal: `CreateRemoteThread failed` in agent logs + EDR console alerts

3. **PPL Coverage Gap**:
   - Protected Process Light (PPL) processes CANNOT be injected via CreateRemoteThread
   - Affected processes documented: lsass.exe, MsMpEng.exe, EDR self-processes
   - This is a Windows security feature, not a DLP limitation
   - Timing windows handled via allowlist refresh interval

4. **DACL Tripwire as Backstop**:
   - Kernel-enforced protection for T3/T4 paths even when hook cannot inject
   - Defense-in-depth: hook catches most processes; DACL catches the rest
   - Two-phase staged update mechanism documented
   - Operator-visible signal: PPL-protected process access denied silently (expected)

5. **ASCII Coverage Equivalence Table**:
   ```
   Process Type          | Injection Coverage | Backstop
   ----------------------|--------------------|------------------
   Normal user process   | Yes (hook DLL)     | DACL (T3/T4 only)
   System process        | Yes (if not PPL)   | DACL (T3/T4 only)
   PPL-protected process | No                 | DACL (T3/T4 only)
   Allowlisted process   | Skipped            | DACL (T3/T4 only)
   ```

6. **SeSystemProfilePrivilege**:
   - Required for ETW Kernel-File consumer (Phase 53) and ETW Kernel-Process watcher (Phase 49)
   - Three assignment methods documented: Group Policy, ntrights.exe, PowerShell
   - Copy-pasteable PowerShell script using secedit for privilege assignment
   - Verification via `whoami /priv`
   - Domain policy refresh behavior documented (domain GPO may override local settings)
   - Privilege persists across agent upgrades (MSI preserves service account)

7. **Mechanism-Qualified Reboot Requirements**:
   - AppInit_DLLs active (Secure Boot OFF): reboot REQUIRED
   - ETW fallback active (Secure Boot ON): service restart sufficient
   - Even with Secure Boot ON, reboot RECOMMENDED after first install
   - Reboot NOT required for agent service restarts (hot reload works)
   - Reboot IS required for installer upgrades (MSI replaces memory-mapped DLLs)

8. **Upgrade Path**:
   - MSI upgrade stops service, replaces files, requires reboot
   - Privileges preserved (service account unchanged)
   - Config and SQLite DB preserved (stored in ProgramData)

## Deviations from Plan

None — plan executed exactly as written.

## Threat Flags

No new threat flags introduced. Threat model from plan (T-57-08 through T-57-09,
T-57-17) is addressed by documented mitigations.

## Known Stubs

None — all placeholder content from 57-01 was replaced with canonical documentation.

## Self-Check: PASSED

- [x] Secure Boot section explains AppInit_DLLs inertness
- [x] Fallback to ETW + CreateRemoteThread documented
- [x] `siem.appinit_dlls_disabled` event documented
- [x] Event source/ID verified against actual agent code
- [x] PPL gap documented with affected process names
- [x] DACL tripwire documented as kernel-enforced backstop
- [x] ASCII coverage table present
- [x] SeSystemProfilePrivilege documented with 3 assignment methods
- [x] PowerShell privilege assignment is concrete and copy-pasteable
- [x] Reboot requirement explained with mechanism-qualified rationale
- [x] Upgrade path documented
- [x] Commit `942f39b` exists in git history

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| Tasks 1-3 | `942f39b` | docs(57-04): canonical deployment reality documentation |
