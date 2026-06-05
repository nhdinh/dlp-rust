# Plan 57-04 Summary: Hash Publishing and Verification

**Date:** 2026-06-05
**Status:** COMPLETED

## Changes Made

### 1. docs/RELEASE_NOTES.md

Updated the following sections:

- **SHA-256 Hashes**: Added PowerShell `Get-FileHash -Algorithm SHA256` command for all 6 binaries, plus hash table with placeholder values.
- **SHA-512 Hashes**: Added PowerShell `Get-FileHash -Algorithm SHA512` command for all 6 binaries, plus hash table with placeholder values.
- **Authenticode Verification**: Expanded with `signtool verify /pa /v` and `signtool verify /all /pa` commands, expected output (sha256 algorithm, RFC3161 timestamp), and notes on root CA installation, dual-signed DLL multi-signature output, and certificate renewal.
- **WDSI Submission**: Added full 8-step submission flow with URL, file size limit (50MB), turnaround time (24-48 hours), troubleshooting guidance, and ZIP password warning.
- **How to Verify This Release**: Added 6-step verification checklist covering hash and signature checks.

### 2. docs/operations/deployment-guide.md

Replaced the `<!-- PLACEHOLDER: HASH-PUBLISHING-START -->` to `<!-- PLACEHOLDER: HASH-PUBLISHING-END -->` block with:

- **Hash Verification Steps**: 4-step procedure using `Get-FileHash` with SHA-256 and SHA-512, with mismatch handling guidance.
- **Authenticode Signature Verification**: `signtool verify /pa /v` and `signtool verify /all /pa` commands, expected output, and notes on root CA installation via `certutil`, dual-signed DLLs, and cert renewal.
- **Microsoft WDSI Submission**: Portal URL, file prep (ZIP with password "infected", 50MB limit), 8 submission steps, turnaround time, and troubleshooting.

## Verification Results

| Check | Expected | Actual | Pass |
|-------|----------|--------|------|
| `Get-FileHash.*SHA256` in RELEASE_NOTES.md | > 0 | 1 | YES |
| `Get-FileHash.*SHA512` in RELEASE_NOTES.md | > 0 | 1 | YES |
| `wdsi` in RELEASE_NOTES.md | > 0 | 1 | YES |
| `Hash Publishing and Verification` in deployment-guide.md | > 0 | 1 | YES |
| `signtool verify /pa /v` in deployment-guide.md | > 0 | 2 | YES |
| `wdsi` in deployment-guide.md | > 0 | 1 | YES |
| No emojis in either file | 0 | 0 | YES |

## Files Modified

- `docs/RELEASE_NOTES.md`
- `docs/operations/deployment-guide.md`

## Files Created

- `.planning/phases/57-operational-deployment-guide-av-edr-allowlist-uat/57-04-SUMMARY.md` (this file)
