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
  "dlp_hook_dll.dll",
  "dlp_hook_dll_x86.dll"
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
  "dlp_hook_dll.dll",
  "dlp_hook_dll_x86.dll"
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

## v0.10.0 — Local Build (2026-06-25)

> **Note:** This is a local development build for UAT preparation. Authenticode
> signing and official pipeline build are pending release engineering.

### Summary

Real-time file access prevention via hybrid IAT hooks + DACL tripwire + ETW
bypass detection.

### Artifact Provenance

| Field | Value |
|-------|-------|
| Build ID | local-build-20260625 |
| Commit SHA | 6874bcf1b6e48a81b4e96f8f7cfc376c93d546b9 |
| Pipeline | local-cargo-build |
| Built By | dev-workstation |
| Build Date | 2026-06-25 |

### Signing Certificate

| Field | Value |
|-------|-------|
| Thumbprint | [PENDING OFFICIAL SIGNING — local build unsigned] |
| Issuer | [PENDING OFFICIAL SIGNING] |
| Subject | [PENDING OFFICIAL SIGNING] |
| Valid From | [PENDING OFFICIAL SIGNING] |
| Valid To | [PENDING OFFICIAL SIGNING] |

### Binaries

| Binary | SHA-256 | SHA-512 |
|--------|---------|---------|
| dlp-agent.exe | 2210d9b97ddceffd64a0d69e491f3a207ac8b8acf5c97457aaa5f5744c257ca2 | 279c7132038eff12755d04813d46be4808b5b319ba8e7ee8bff0db7a4c9f40515a65f0dc9e78e0f05562dcc401bf4cc48d48f4c5a557e2e4e342e6040ed9378a |
| dlp-server.exe | 7f3e0fe0d5d0836433c7629c8aee4559b3de1d4416cf7843c862bd4762a93072 | f2de3d328c7221373d856bf328df7d4c2d7842eea6da80af02a77c50f5d896e5d7bc06a5c493d02c9ce02ba03c0721981aedb4fe8e06f697646978ffa89da2de |
| dlp-admin-cli.exe | 394b34d0f5190195f973bb1bb3d335d9bd3715236c5c3632b7b25f2d84224d8c | 939963f8e871d535fb3ce7728fc2920774edf577d9ce7653104bba9f48d568f1e517362aeb7e517b72e75dbe632aa8f771fc3993c7aa9eabcf48c2956d0aead4 |
| dlp-user-ui.exe | d45739f642bc281c3d71245ccd8e6ff48e35c7ce52d3a7cd045df92a5b304c68 | c8e9fa80f50f70bdc54a72605d33ddf1493fd99d0709851702397df674097e57ee58ec1599f536822394f5620cfa4cc222bb668d560815817a62f4785347a08c |
| dlp_hook_dll.dll | c3762e1f51bf13bf5b8764f2a572f2bb4f95bc7ba742d36903630641355f8343 | 68e992b75709acb867f17d12f363d5fd9ad491d66ccd0f3fe74cb31ba5b50dea00251eef60a3dafbbe835d343c5324f7745cd14521c5318b7ff38f03fd25fc7c |
| dlp_hook_dll_x86.dll | 16e413c4d6d16b9b8aa1e4ac59af07c72f854c7aa6e056c67934dd2f3583a868 | b88c3083d265c5350fcbd58a956d2d21e085d03648dc0fc05eebb5d5b95a551a94dbd4b4fc5afb726da4350a83822531dfa4227045479dbf6d06c83dac350746 |

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
