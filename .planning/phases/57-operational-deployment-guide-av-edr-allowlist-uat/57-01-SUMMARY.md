---
phase: 57-operational-deployment-guide-av-edr-allowlist-uat
plan: 01
subsystem: docs
last_updated: 2026-05-30
dependency_graph:
  requires: []
  provides:
    - docs/operations/deployment-guide.md
  affects: []
key_files:
  created:
    - docs/operations/deployment-guide.md
  modified: []
tech_stack:
  added: []
  patterns: []
decisions: []
metrics:
  duration_minutes: 30
  completed_date: 2026-05-30
  tasks_completed: 3
  files_created: 1
  files_modified: 0
---

# Phase 57 Plan 01: Deployment Guide Summary

One-liner: Comprehensive v0.10.0 deployment guide with Quick Start checklist,
per-vendor AV/EDR allowlist procedures for 6 enterprise vendors, troubleshooting,
and rollback procedures.

## What Was Built

### docs/operations/deployment-guide.md (created)

A 656-line operational deployment guide containing:

1. **Quick Start for Experienced Operators** — 10-bullet checklist covering MSI
   install, Authenticode verification, EDR hash exclusion, privilege assignment,
   reboot, injection verification, T4 denial test, SIEM event check, Protected
   Paths screen confirmation, and monitor mode verification.

2. **Prerequisites** — Windows 11 Pro/Enterprise, .NET 8 runtime, AD domain join,
   local admin rights, one supported EDR installed.

3. **Installation Steps** — Download MSI, run installer, verify service
   registration (`Get-Service DlpAgent`), verify auto-start.

4. **AV/EDR Allowlist Procedures** for all 6 vendors:
   - **Microsoft Defender for Endpoint** — Windows Security app + Group Policy path
   - **CrowdStrike Falcon** — Falcon console Prevention exclusions + SensorGroupingTag
   - **SentinelOne** — Certificate hash exclusion (per D-05, uses cert thumbprint)
   - **Carbon Black (VMware)** — Reputation override approach
   - **Sophos Intercept X** — Tamper protection disable requirement documented
   - **Trend Micro Apex One** — Smart scan vs conventional scan difference

   Each vendor section includes: expected detection behavior, console/UI steps
   with screenshot placeholders, hash exclusion examples (SHA-256 per D-05),
   verification command, troubleshooting note, and "Last verified" placeholder.

5. **Secure Boot & PPL Considerations** — Placeholder headers referencing Plan
   57-04 per D-24 (canonical ownership).

6. **Post-Install Verification** — 10-step checklist: service running, injection
   visible, T4 denial test, cloud sync blocking, USB/SD event, printer test,
   DACL tripwire visible, SIEM event received, admin TUI accessible, monitor
   mode confirmed.

7. **Troubleshooting** — 4 common issues: hook not injecting, T4 still writable,
   high CPU, agent won't start. Each with root cause and resolution steps.

8. **Rollback Procedure** (per D-25) — 5 steps: stop service, uninstall MSI,
   restore DACLs, optional ProgramData cleanup, verify no residual processes.

9. **Extensible Vendor Template** — End of document template for adding new EDR
   vendors (per D-04).

## Deviations from Plan

None — plan executed exactly as written.

## Threat Flags

No new threat flags introduced. Threat model from plan (T-57-01 through T-57-03)
is addressed by the documented procedures.

## Known Stubs

| Location | Stub | Resolution |
|----------|------|------------|
| Secure Boot & PPL section | Placeholder headers | Detailed content in Plan 57-04 (D-24 canonical owner) |
| Vendor sections | `[Screenshot: ...]` placeholders | To be added during UAT execution (57-03) per D-18/D-20 |
| Vendor sections | `[Last verified: YYYY-MM-DD]` | To be filled during UAT execution |

## Self-Check: PASSED

- [x] `docs/operations/deployment-guide.md` exists (>50 lines)
- [x] Contains "Quick Start for Experienced Operators" checklist
- [x] Contains all 7 major section headers
- [x] Prerequisites lists Windows 11, .NET 8, AD domain, admin rights
- [x] Quick Start references RELEASE_NOTES.md for SHA-256 hashes
- [x] All 6 vendor subsections present with complete template
- [x] Troubleshooting covers 4+ issues
- [x] Rollback Procedure documented with 5 steps
- [x] Secure Boot/PPL section has placeholder reference to 57-04
- [x] Commit `af3095f` exists in git history

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| Tasks 1-3 | `af3095f` | docs(57-01): create deployment guide with per-vendor AV/EDR allowlist procedures |
| Tracking | `818ad60` | docs(57-01): complete deployment guide plan |
