# Release Notes -- DLP v0.10.0

## Release Date

[YYYY-MM-DD]

## Binaries

| Binary | Architecture | Path |
|--------|-------------|------|
| dlp-agent.exe | x64 | target\release\dlp-agent.exe |
| dlp-user-ui.exe | x64 | target\release\dlp-user-ui.exe |
| dlp-admin-cli.exe | x64 | target\release\dlp-admin-cli.exe |
| dlp-server.exe | x64 | target\release\dlp-server.exe |
| dlp_hook_dll.dll | x64 | target\x86_64-pc-windows-msvc\release\dlp_hook_dll.dll |
| dlp_hook_dll_x86.dll | x86 | target\i686-pc-windows-msvc\release\dlp_hook_dll.dll |

## SHA-256 Hashes

Generate SHA-256 hashes for all binaries using PowerShell:

```powershell
$binaries = @(
    "C:\Program Files\DLP\dlp-agent.exe",
    "C:\Program Files\DLP\dlp-user-ui.exe",
    "C:\Program Files\DLP\dlp-admin-cli.exe",
    "C:\Program Files\DLP\dlp-server.exe",
    "C:\Program Files\DLP\dlp_hook_dll.dll",
    "C:\Program Files\DLP\dlp_hook_dll_x86.dll"
)
foreach ($path in $binaries) {
    if (Test-Path $path) {
        $hash = Get-FileHash $path -Algorithm SHA256
        Write-Host "$(Split-Path $path -Leaf): $($hash.Hash)"
    }
}
```

| Binary | SHA-256 |
|--------|---------|
| dlp-agent.exe | [TO BE FILLED AT RELEASE] |
| dlp-user-ui.exe | [TO BE FILLED AT RELEASE] |
| dlp-admin-cli.exe | [TO BE FILLED AT RELEASE] |
| dlp-server.exe | [TO BE FILLED AT RELEASE] |
| dlp_hook_dll.dll | [TO BE FILLED AT RELEASE] |
| dlp_hook_dll_x86.dll | [TO BE FILLED AT RELEASE] |

## SHA-512 Hashes

Generate SHA-512 hashes for all binaries using PowerShell:

```powershell
$binaries = @(
    "C:\Program Files\DLP\dlp-agent.exe",
    "C:\Program Files\DLP\dlp-user-ui.exe",
    "C:\Program Files\DLP\dlp-admin-cli.exe",
    "C:\Program Files\DLP\dlp-server.exe",
    "C:\Program Files\DLP\dlp_hook_dll.dll",
    "C:\Program Files\DLP\dlp_hook_dll_x86.dll"
)
foreach ($path in $binaries) {
    if (Test-Path $path) {
        $hash = Get-FileHash $path -Algorithm SHA512
        Write-Host "$(Split-Path $path -Leaf): $($hash.Hash)"
    }
}
```

| Binary | SHA-512 |
|--------|---------|
| dlp-agent.exe | [TO BE FILLED AT RELEASE] |
| dlp-user-ui.exe | [TO BE FILLED AT RELEASE] |
| dlp-admin-cli.exe | [TO BE FILLED AT RELEASE] |
| dlp-server.exe | [TO BE FILLED AT RELEASE] |
| dlp_hook_dll.dll | [TO BE FILLED AT RELEASE] |
| dlp_hook_dll_x86.dll | [TO BE FILLED AT RELEASE] |

## Authenticode Verification

Verify the Authenticode signature and RFC-3161 timestamp on every binary after
installation:

```powershell
# Verify primary signature with verbose output (shows timestamp type)
signtool verify /pa /v "C:\Program Files\DLP\dlp-agent.exe"

# Verify ALL signatures on a binary (catches dual-signed or counter-signed artifacts)
signtool verify /all /pa "C:\Program Files\DLP\dlp_hook_dll.dll"
```

Expected output includes:

```
Index  Algorithm  Timestamp
0      sha256     RFC3161
```

All production binaries are signed with an organizational Authenticode
certificate and timestamped via RFC-3161. The timestamp server used during the
release build is `http://timestamp.digicert.com` (primary) or
`http://timestamp.sectigo.com` (fallback).

Notes:

- If `signtool verify` fails with "A certificate chain could not be built to a
trusted root authority," install the organizational root CA certificate into
the Trusted Root Certification Authorities store on the target machine.
- The hook DLLs (`dlp_hook_dll.dll` and `dlp_hook_dll_x86.dll`) may be
dual-signed. When using `signtool verify /all /pa`, multi-signature output is
expected and normal.
- If the signing certificate is renewed between releases, update the trust
store on target endpoints before deploying the new build.

## WDSI Submission

To reduce false-positive detections by Microsoft Defender, submit the DLP
binaries to the Microsoft Windows Defender SmartScreen Intelligence (WDSI)
portal.

**Portal URL:** `https://www.microsoft.com/en-us/wdsi/filesubmission`

**Steps:**

1. Navigate to the WDSI portal URL above.
2. Sign in with an enterprise Azure AD / Microsoft work account.
3. Select "Software developer" as the submission type.
4. Upload each binary. If the file is flagged as suspected malware, upload a
   ZIP archive with password `infected`.
5. Enter the company name.
6. Enter the product name: "DLP v0.10.0".
7. Enter the detection name if one was reported by Defender.
8. Submit and record the submission ID for tracking.

**File size limit:** 50 MB per submission.

**Turnaround time:** 24-48 hours.

**Troubleshooting:**

- If the submission is rejected or marked "insufficient information," re-submit
  with more detail (company name, product description, file hash, detection
  name).
- If a submission remains "pending" for more than 10 days, contact Microsoft
  support with the submission ID.

**Warning:** The ZIP password `infected` may trigger email gateway blocks if the
submission is sent via email. Use the web portal directly.

## How to Verify This Release

Use this checklist to verify the v0.10.0 release on a target endpoint:

1. Download the release artifacts and `RELEASE_NOTES.md` from the signed
   artifact store.
2. Run the SHA-256 PowerShell command above and compare each hash against the
   values in `RELEASE_NOTES.md`.
3. Run the SHA-512 PowerShell command above and compare each hash against the
   values in `RELEASE_NOTES.md`.
4. Run `signtool verify /pa /v` on each binary and confirm the timestamp type
   is `RFC3161`.
5. Run `signtool verify /all /pa` on each hook DLL and confirm all signatures
   are valid.
6. If any hash or signature check fails, re-download the artifacts from the
   signed artifact store and repeat steps 2-5. Do not install binaries that
   fail verification.

## Known Issues

- No known issues at release time.
- See [CHANGELOG.md](CHANGELOG.md) for historical issues and resolutions.

## Upgrade Notes

### SeSystemProfilePrivilege

The MSI installer preserves `SeSystemProfilePrivilege` across upgrades. After
upgrade, verify the privilege is still granted:

```powershell
sc qprivs dlp-agent | findstr SeSystemProfilePrivilege
```

If the privilege is missing, reinstall with the `PRESERVE_PRIVILEGES=1`
property or restore via Group Policy.

### Reboot Required

A reboot is required after upgrading the DLP agent. The startup
`EnumProcesses` sweep covers most running processes, but a reboot ensures
complete hook injection into all user sessions and system processes.

### EDR Allowlist Re-verification

After upgrade, re-verify EDR allowlist entries:

- Hash-based exclusions may need updating if any binary hash changed.
- Path-based exclusions remain valid if install path is unchanged.
- Allow propagation time (up to 40 minutes for CrowdStrike; 15 minutes for
  SentinelOne) before validating on production endpoints.

For per-vendor allowlist procedures, see
[docs/operations/deployment-guide.md](operations/deployment-guide.md).
