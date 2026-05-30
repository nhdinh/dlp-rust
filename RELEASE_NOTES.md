# DLP-RUST Release Notes

## Release Engineer Checklist

Before publishing a release, the release engineer MUST:

1. [ ] Build release artifacts (signed MSI + all binaries)
2. [ ] Verify Authenticode signature on all executables (`signtool verify /pa`)
3. [ ] Generate SHA-256 and SHA-512 hashes for all 6 binaries
4. [ ] Replace all `[TO BE FILLED AT RELEASE]` placeholders with actual values
5. [ ] Record build ID, commit SHA, and pipeline reference in Artifact Provenance
6. [ ] Record signing certificate thumbprint and issuer in Signing Certificate section
7. [ ] Run Hash Verification script to confirm computed hashes match published values
8. [ ] Commit updated RELEASE_NOTES.md with release tag

---

## Hash Generation

To generate SHA-256 and SHA-512 hashes for all binaries after installation, run:

```powershell
$binaries = @(
  "dlp-agent.exe",
  "dlp-server.exe",
  "dlp-admin-cli.exe",
  "dlp-user-ui.exe",
  "dlp-hook-dll.dll",
  "dlp-hook-dll-x86.dll"
)

foreach ($binary in $binaries) {
  $path = "C:\Program Files\DLP\$binary"
  if (Test-Path $path) {
    $sha256 = (Get-FileHash $path -Algorithm SHA256).Hash
    $sha512 = (Get-FileHash $path -Algorithm SHA512).Hash
    Write-Output "$binary | $sha256 | $sha512"
  }
}
```

## Hash Verification

To verify that locally computed hashes match the values published in this document:

```powershell
$binaries = @(
  "dlp-agent.exe",
  "dlp-server.exe",
  "dlp-admin-cli.exe",
  "dlp-user-ui.exe",
  "dlp-hook-dll.dll",
  "dlp-hook-dll-x86.dll"
)

$releaseNotes = Get-Content .\RELEASE_NOTES.md -Raw
$allPass = $true

foreach ($binary in $binaries) {
  $path = "C:\Program Files\DLP\$binary"
  if (-not (Test-Path $path)) {
    Write-Output "SKIP: $binary not found at expected path"
    continue
  }

  $actualSha256 = (Get-FileHash $path -Algorithm SHA256).Hash
  $actualSha512 = (Get-FileHash $path -Algorithm SHA512).Hash

  $expectedLine = $releaseNotes | Select-String "\| $binary \|.*\|.*\|"
  if ($expectedLine) {
    $parts = $expectedLine.Line -split "\|" | ForEach-Object { $_.Trim() }
    $expectedSha256 = $parts[2]
    $expectedSha512 = $parts[3]

    if ($actualSha256 -eq $expectedSha256 -and $actualSha512 -eq $expectedSha512) {
      Write-Output "PASS: $binary (SHA-256 + SHA-512 match)"
    } else {
      Write-Output "FAIL: $binary hash MISMATCH"
      Write-Output "  Expected SHA-256: $expectedSha256"
      Write-Output "  Actual   SHA-256: $actualSha256"
      Write-Output "  Expected SHA-512: $expectedSha512"
      Write-Output "  Actual   SHA-512: $actualSha512"
      $allPass = $false
    }
  } else {
    Write-Output "FAIL: $binary not found in RELEASE_NOTES.md"
    $allPass = $false
  }
}

if ($allPass) {
  Write-Output "`n=== ALL HASHES VERIFIED ==="
} else {
  Write-Output "`n=== HASH VERIFICATION FAILED ==="
  exit 1
}
```

## Microsoft WDSI Submission

If Microsoft Defender for Endpoint flags any DLP binary as a false positive,
submit the file to Microsoft for analysis:

**Submission URL:** https://www.microsoft.com/en-us/wdsi/filesubmission

**Form fields:**

| Field | Value |
|-------|-------|
| Product name | DLP-RUST Endpoint Agent |
| Company | [Customer Name] |
| File type | Executable |
| Detection name | [Your actual detection name from the Defender console] |
| Additional information | Enterprise DLP agent using global DLL injection for file-access monitoring. Signed with Authenticode. See attached certificate. |

**Example detection name (for reference only):** `Trojan:Win32/Wacatac.B!ml`

> **Note:** Record your actual detection name from the Defender console. The
> example above is for reference only and may differ from what appears in your
> environment.

**Expected turnaround:** 24-72 hours

**Follow-up:** Check submission status using the submission ID returned by the
WDSI portal.

**Recommendation:** WDSI submission is OPTIONAL but RECOMMENDED for Microsoft
Defender for Endpoint deployments to prevent false-positive quarantine during
rollout.

## Authenticode Verification

Verify the Authenticode signature on any shipped executable:

```cmd
signtool verify /pa "C:\Program Files\DLP\dlp-agent.exe"
```

The `/pa` switch uses the default Authenticode verification policy. Expected
clean output:

```
Successfully verified: C:\Program Files\DLP\dlp-agent.exe
Signers:
    [Your Organization Name]
    [Timestamping Authority]
```

Repeat for all executables:

```powershell
$executables = @("dlp-agent.exe", "dlp-server.exe", "dlp-admin-cli.exe", "dlp-user-ui.exe")
foreach ($exe in $executables) {
  signtool verify /pa "C:\Program Files\DLP\$exe"
}
```

### Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| "A certificate chain could not be built to a trusted root authority" | Missing intermediate certificate | Install the issuer's intermediate CA certificate into the local machine certificate store |
| "The signature timestamp is invalid or has expired" | Missing RFC-3161 timestamp | Re-sign the binary with a timestamp server (`/tr http://timestamp.digicert.com /td sha256`) |
| "The certificate has expired but the timestamp is valid" | Expected — timestamp proves validity at signing time | No action required; this is normal for long-lived releases |
| "No signature found" or "The file is not signed" | Unsigned or tampered binary | Do not install. Obtain the signed release from the official source |
| Signer name does not match expected publisher | Binary may be tampered or from an unofficial source | Do not install. Verify the download URL and checksum |

---

## v0.10.0 — [TO BE FILLED AT RELEASE]

> **Note:** Hash values below are placeholders until release day. The release
> engineer must replace them with actual artifact hashes per the checklist above.

### Summary

Real-time file access prevention via hybrid IAT hooks + DACL tripwire + ETW
bypass detection.

### Artifact Provenance

| Field | Value |
|-------|-------|
| Build ID | [TO BE FILLED AT RELEASE] |
| Commit SHA | [TO BE FILLED AT RELEASE] |
| Pipeline | [TO BE FILLED AT RELEASE] |
| Built By | [TO BE FILLED AT RELEASE] |
| Build Date | [TO BE FILLED AT RELEASE] |

### Signing Certificate

| Field | Value |
|-------|-------|
| Thumbprint | [TO BE FILLED AT RELEASE] |
| Issuer | [TO BE FILLED AT RELEASE] |
| Subject | [TO BE FILLED AT RELEASE] |
| Valid From | [TO BE FILLED AT RELEASE] |
| Valid To | [TO BE FILLED AT RELEASE] |

### Binaries

| Binary | SHA-256 | SHA-512 |
|--------|---------|---------|
| dlp-agent.exe | [TO BE FILLED AT RELEASE] | [TO BE FILLED AT RELEASE] |
| dlp-server.exe | [TO BE FILLED AT RELEASE] | [TO BE FILLED AT RELEASE] |
| dlp-admin-cli.exe | [TO BE FILLED AT RELEASE] | [TO BE FILLED AT RELEASE] |
| dlp-user-ui.exe | [TO BE FILLED AT RELEASE] | [TO BE FILLED AT RELEASE] |
| dlp-hook-dll.dll | [TO BE FILLED AT RELEASE] | [TO BE FILLED AT RELEASE] |
| dlp-hook-dll-x86.dll | [TO BE FILLED AT RELEASE] | [TO BE FILLED AT RELEASE] |

### Breaking Changes

- Agent now requires `SeSystemProfilePrivilege` for ETW Kernel-Process watcher
- AppInit_DLLs fallback replaced by ETW + `CreateRemoteThread` on Secure Boot
  hosts

### Migration Notes

- Existing v0.9.x deployments: privilege is auto-assigned by MSI installer
- No config migration required

### Known Issues

- PPL-protected processes cannot be injected (by design; DACL tripwire is
  backstop)
- ntdll patching is gated behind `enable_ntdll_patching` policy flag (default
  off)

### Deployment Guide

See [docs/operations/deployment-guide.md](docs/operations/deployment-guide.md)

---

## Previous Releases

| Version | Date | Highlights |
|---------|------|------------|
| v0.9.0 | 2026-05-09 | Cloud and print exfiltration prevention |
| v0.8.1 | 2026-05-08 | Deferred items and issue debt resolution |
| v0.8.0 | 2026-05-07 | Application-aware DLP |
| v0.7.1 | 2026-05-06 | Operational hardening |
| v0.7.0 | 2026-05-06 | Disk exfiltration prevention |
| v0.6.0 | 2026-04-29 | Endpoint hardening |
| v0.5.0 | 2026-04-21 | Boolean logic engine |
| v0.4.0 | 2026-04-20 | Policy authoring |
| v0.3.0 | 2026-04-16 | Operational hardening |
| v0.2.0 | 2026-04-13 | Feature completion |
