---
phase: 57-operational-deployment-guide-av-edr-allowlist-uat
plan: 02
subsystem: docs
last_updated: 2026-05-30
dependency_graph:
  requires:
    - 57-01
  provides:
    - RELEASE_NOTES.md
  affects:
    - docs/operations/deployment-guide.md
key_files:
  created:
    - RELEASE_NOTES.md
  modified: []
tech_stack:
  added: []
  patterns: []
decisions: []
metrics:
  duration_minutes: 15
  completed_date: 2026-05-30
  tasks_completed: 4
  files_created: 1
  files_modified: 0
---

# Phase 57 Plan 02: RELEASE_NOTES.md Summary

One-liner: Structured release notes with SHA-256/SHA-512 hash tables, artifact
provenance, signing certificate info, Microsoft WDSI submission flow, and
signtool verification commands.

## What Was Built

### RELEASE_NOTES.md (repo root)

A comprehensive release notes document containing:

1. **Release Engineer Checklist** — 8 mandatory items ensuring hashes,
   signatures, and provenance are verified before any release is published.

2. **Hash Generation** — PowerShell snippet using `Get-FileHash` to generate
   SHA-256 and SHA-512 hashes for all 6 shipped binaries from their installed
   paths under `C:\Program Files\DLP\`.

3. **Hash Verification** — PowerShell script that recomputes hashes and
   compares them against the values published in `RELEASE_NOTES.md`, producing
   PASS/FAIL output per binary and an overall verification result.

4. **Microsoft WDSI Submission** — Documented submission flow including the
   direct URL (`https://www.microsoft.com/en-us/wdsi/filesubmission`), form
   fields, example detection name (`Trojan:Win32/Wacatac.B!ml` per D-21 with
   explicit note that operators must record their actual detection name), and
   expected 24-72 hour turnaround.

5. **Authenticode Verification** — `signtool verify /pa` command with expected
   clean output, plus a failure mode table covering: missing intermediate CA,
   missing timestamp, expired certificate with valid timestamp, unsigned binary,
   and wrong publisher.

6. **v0.10.0 Release Section** — Structured per-release format with:
   - Summary of real-time file access prevention features
   - Artifact Provenance table (Build ID, Commit SHA, Pipeline, Built By, Build Date)
   - Signing Certificate table (Thumbprint, Issuer, Subject, Valid From, Valid To)
   - Binaries table with SHA-256 and SHA-512 columns for all 6 binaries
   - Breaking Changes, Migration Notes, Known Issues
   - Deployment Guide link

7. **Previous Releases** — Table listing v0.2.0 through v0.9.0 with dates and
   highlights (no hashes for historical releases).

## Deviations from Plan

None — plan executed exactly as written.

## Threat Flags

No new threat flags introduced. The threat model from the plan (T-57-04 through
T-57-15) is addressed by the documented checklist and verification procedures.

## Known Stubs

All `[TO BE FILLED AT RELEASE]` placeholders are intentional and required to be
replaced by the release engineer at ship time per the checklist. This is by
design (D-18, D-19) and documented in the Release Engineer Checklist.

| Location | Field | Resolution |
|----------|-------|------------|
| v0.10.0 section | All hash values | Replaced at release time by release engineer |
| v0.10.0 section | Build ID, Commit SHA, Pipeline | Replaced at release time by release engineer |
| v0.10.0 section | Certificate Thumbprint, Issuer, Subject, dates | Replaced at release time by release engineer |

## Self-Check: PASSED

- [x] `RELEASE_NOTES.md` exists at repo root
- [x] Contains "SHA-256" and "SHA-512" (6 occurrences each)
- [x] Contains "Release Engineer Checklist" with 8 items
- [x] Contains "Hash Generation" with Get-FileHash PowerShell
- [x] Contains "Hash Verification" script
- [x] All 6 binaries present in table
- [x] Contains Artifact Provenance section with Build ID, Commit SHA, Pipeline
- [x] Contains Signing Certificate section with Thumbprint, Issuer
- [x] Contains WDSI reference
- [x] Contains signtool verify reference
- [x] Placeholder entries for v0.10.0 (18 occurrences)
- [x] Previous Releases section with v0.2.0 through v0.9.0
- [x] Commit `3e64da4` exists in git history

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| Task 1-4 | `3e64da4` | docs(57-02): create RELEASE_NOTES.md with hash tables, provenance, and verification scripts |
