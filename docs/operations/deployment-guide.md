# Deployment Guide -- DLP v0.10.0

## Overview

This document is the master deployment guide for DLP v0.10.0. It covers pre-flight
verification, architecture reality checks, EDR allowlist procedures, hash
verification, and UAT planning for Windows enterprise deployments.

For high-level deployment architecture, see [DEPLOYMENT.md](../DEPLOYMENT.md).
For day-to-day operational procedures, see [OPERATIONAL.md](../OPERATIONAL.md).

## Prerequisites

| Requirement | Details |
|-------------|---------|
| OS | Windows 11 22H2+ or Windows Server 2022 |
| PowerShell | 5.1 or later |
| Privileges | Local Administrator |
| Tools | `signtool` (Windows SDK) |
| Endpoint | Physical host or VM with Secure Boot support |
| EDR Console | Access to at least one EDR management console for allowlist configuration |

## Pre-Flight Checks

Run these checks on every target endpoint before installing the DLP agent.

### Secure Boot Status

```powershell
$sb = Confirm-SecureBootUEFI
if ($sb) {
    Write-Host "Secure Boot: ENABLED (AppInit_DLLs is INERT -- ETW is primary)"
} else {
    Write-Host "Secure Boot: DISABLED (AppInit_DLLs may function as tertiary fallback)"
}
```

When Secure Boot is enabled (`True`), the `AppInit_DLLs` registry mechanism is
inert. The agent relies on ETW-driven injection as the primary hook delivery
mechanism. At boot, if Secure Boot is detected and `AppInit_DLLs` is disabled,
the agent emits a `siem.appinit_dlls_disabled` audit event to confirm the
configuration.

### SeSystemProfilePrivilege

```powershell
whoami /priv | findstr SeSystemProfilePrivilege
```

Expected output:

```
SeSystemProfilePrivilege        Profile system performance     Enabled
```

This privilege is required for the agent to create ETW trace sessions. The MSI
installer grants it to the `dlp-agent` service account. Verify it is present and
enabled before installation.

### Authenticode Signature Verification

Verify the Authenticode signature and RFC-3161 timestamp on every binary before
deployment:

```powershell
# Verify signature with verbose output (shows timestamp type)
signtool verify /pa /v "C:\Program Files\DLP\dlp-agent.exe"

# Verify ALL signatures on a binary (catches dual-signed or counter-signed artifacts)
signtool verify /all /pa "C:\Program Files\DLP\dlp_hook_dll.dll"
```

Expected output includes:

```
Index  Algorithm  Timestamp
0      sha256     RFC3161
```

The `/pa` switch uses the default Authenticode policy. The `/v` switch produces
verbose output including the timestamp algorithm. The `/all` switch verifies all
embedded signatures. All production binaries must show `RFC3161` (not
`Authenticode`) in the Timestamp column.

### Hash Verification

Generate SHA-256 and SHA-512 hashes for all six shipped binaries and compare
against [RELEASE_NOTES.md](../RELEASE_NOTES.md):

```powershell
$binaries = @(
    "dlp-agent.exe",
    "dlp-user-ui.exe",
    "dlp-admin-cli.exe",
    "dlp-server.exe",
    "dlp_hook_dll.dll",
    "dlp_hook_dll_x86.dll"
)

foreach ($bin in $binaries) {
    $path = "C:\Program Files\DLP\$bin"
    if (Test-Path $path) {
        $sha256 = Get-FileHash $path -Algorithm SHA256
        $sha512 = Get-FileHash $path -Algorithm SHA512
        Write-Host "$bin`:"
        Write-Host "    SHA-256: $($sha256.Hash)"
        Write-Host "    SHA-512: $($sha512.Hash)"
    } else {
        Write-Warning "Binary not found: $path"
    }
}
```

## Architecture Reality Check

Review these architectural constraints before every deployment. They affect
coverage expectations and troubleshooting.

### Secure Boot and AppInit_DLLs

When Secure Boot is enabled, the Windows kernel ignores the `AppInit_DLLs`
registry value. The agent's hook delivery tiers are:

1. **Primary:** ETW-driven injection into newly created processes.
2. **Secondary:** Startup `EnumProcesses` sweep at service start.
3. **Tertiary:** `AppInit_DLLs` registry value (active only when Secure Boot is
   **disabled**).

On Windows 11 enterprise deployments, Secure Boot is almost always enabled.
Operators must expect ETW as the sole active injection mechanism and must not
rely on `AppInit_DLLs` for coverage.

### PPL Coverage Gap

Protected Process Light (PPL) prevents injection from non-PPL processes. The
following system processes are PPL-protected and cannot receive the hook DLL:

| Process | Protection Level |
|---------|-----------------|
| `lsass.exe` | Windows TCB |
| `MsMpEng.exe` | Antimalware |
| EDR self-processes | Varies by vendor |

The agent skips injection for PPL processes and logs `Skipped(PPL)` in the audit
trail. This is expected behavior, not a failure.

### DACL Tripwire Backstop

For paths classified T3 (Confidential) and T4 (Restricted), the agent installs a
NTFS Deny ACE that persists even if the hook DLL is unloaded or the agent
service stops. This provides kernel-enforced access control independent of
user-mode hook coverage.

The DACL tripwire is documented in full in
[dpapi-recovery.md](dpapi-recovery.md). Key properties:

- The Deny ACE is applied to the protected directory tree.
- It denies write and delete access to all non-system principals.
- It survives agent restart, MSI upgrade, and manual hook unloading.
- A repair watcher re-applies the ACE within 60 seconds if `icacls /reset` is
  used to clear it.

### SeSystemProfilePrivilege Preservation

The MSI installer must preserve `SeSystemProfilePrivilege` across upgrades. If
the service account loses this privilege after an MSI reinstall, ETW trace
session creation fails and the agent falls back to reduced-coverage mode.

Post-upgrade verification:

```powershell
sc qprivs dlp-agent | findstr SeSystemProfilePrivilege
```

If the privilege is missing, restore it via Group Policy or re-run the MSI
installer with the `PRESERVE_PRIVILEGES=1` property:

```cmd
msiexec /i DLPAgent.msi PRESERVE_PRIVILEGES=1
```

### Post-Install Reboot Requirement

A reboot is **required** after installing or upgrading the DLP agent. The
startup `EnumProcesses` sweep injects the hook DLL into most running processes,
but some long-lived system processes (explorer, services) may not fully reload
the hook without a reboot.

Reboot ensures:

- All user sessions receive the hook DLL.
- ETW trace sessions start cleanly.
- `AppInit_DLLs` (if applicable) is read at boot.
- Service dependencies (UI subprocess, named pipes) initialize in the correct
  order.

## EDR Allowlist Procedures

<!-- PLACEHOLDER: EDR-VENDORS-START -->

### Vendor: Microsoft Defender for Endpoint

**Console URL:** https://security.microsoft.com
**Required Role:** Security Administrator or Global Administrator
**Propagation Time:** 15-30 minutes
**Supported Methods:** File hash indicator (preferred), Certificate indicator, Path indicator

#### Defender SKU Detection

Before configuring exclusions, verify the endpoint is running Microsoft Defender for Endpoint (not just Microsoft Defender Antivirus):

```powershell
# Check Defender AV status
$mpStatus = Get-MpComputerStatus
Write-Host "Defender Enabled: $($mpStatus.AntivirusEnabled)"
Write-Host "Real-time Protection: $($mpStatus.RealTimeProtectionEnabled)"

# Check for MDE onboarding (indicates full EDR, not just AV)
$mdeOnboarded = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
Write-Host "MDE Onboarded: $mdeOnboarded"
```

If `MDE Onboarded` is `False`, the endpoint has only Microsoft Defender Antivirus. File hash indicators require MDE. On Defender AV-only endpoints, use Group Policy or local path exclusions instead.

#### Method 1: File Hash Indicator (Preferred)

1. Enable file hash computation (one-time per endpoint):
   ```powershell
   Set-MpPreference -EnableFileHashComputation $true
   ```
2. Navigate to https://security.microsoft.com
3. Go to **System** > **Settings** > **Endpoints** > **Indicators** (under Rules)
4. Select the **File hashes** tab, then click **Add item**
5. Enter the SHA-256 hash of the binary (e.g., `dlp_hook_dll.dll`)
6. Set **Action** to **Allow**
7. Set **Scope** to the target device groups (or **All devices**)
8. Optionally set **Expiration** (recommended: 90 days for initial deployment)
9. Click **Save**

Repeat for all six shipped binaries:
- `dlp-agent.exe`
- `dlp-user-ui.exe`
- `dlp-admin-cli.exe`
- `dlp-server.exe`
- `dlp_hook_dll.dll`
- `dlp_hook_dll_x86.dll`

#### Method 2: Certificate Indicator

If hash indicators are not available (e.g., MDE not onboarded), allowlist by code-signing certificate:

1. Navigate to https://security.microsoft.com
2. Go to **System** > **Settings** > **Endpoints** > **Indicators**
3. Select the **Certificates** tab, then click **Add item**
4. Upload the `.cer` file of the DLP code-signing certificate
5. Set **Action** to **Allow**
6. Set **Scope** and save

> **Note:** Certificate indicators allow ALL binaries signed with that certificate. Ensure the private key is stored in an HSM and the certificate is not used for other software.

#### Method 3: PowerShell (New-MpThreatIntelIndicator)

Requires the **WindowsDefenderThreatIntelligence** PowerShell module (available on Windows Server 2022 with MDE unified agent):

```powershell
# Import the module (install from PowerShell Gallery if missing)
Import-Module WindowsDefenderThreatIntelligence

# Create a file hash indicator
New-MpThreatIntelIndicator `
    -Type FileSha256 `
    -Value "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899" `
    -Action Allow `
    -Title "DLP v0.10.0 dlp-agent.exe" `
    -Description "Data Loss Prevention agent binary" `
    -Severity Informational
```

> **Prerequisite:** The `WindowsDefenderThreatIntelligence` module is not installed by default on all SKUs. If the module is unavailable, use the console-based Method 1 or Method 2.

#### Verification

```powershell
# List all active file hash indicators
Get-MpThreatIntelIndicator -Type FileSha256 | Where-Object { $_.Title -like "DLP*" }

# Expected output: indicators with Action = Allow and Status = Active
```

#### ASR Rules Coexistence

Microsoft Defender Attack Surface Reduction (ASR) rules may block the DLP hook DLL from injecting into Office applications or other processes. The following ASR rules are known to interfere with DLP operation:

| ASR Rule | GUID | Recommended Action |
|----------|------|-------------------|
| Block Office applications from injecting code into other processes | 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 | Add exclusion for `C:\Program Files\DLP\*` |
| Block executable files from running unless they meet a prevalence, age, or trusted list criterion | 01443614-CD74-433A-B99E-2ECDC07BFC25 | Add exclusion for `C:\Program Files\DLP\*` |

To add an ASR exclusion:

1. Navigate to https://security.microsoft.com
2. Go to **System** > **Settings** > **Endpoints** > **Attack Surface Reduction Rules**
3. Click the rule name, then **Edit**
4. Under **Exclusions**, add: `C:\Program Files\DLP\*`
5. Save and deploy

Alternatively, via Group Policy:
- Path: `Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Attack Surface Reduction > Exclude files and paths from ASR rules`
- Value: `C:\Program Files\DLP\*`

#### IOC Exclusion Example

If Defender has already quarantined a DLP binary, create an indicator from the incident:

1. Navigate to https://security.microsoft.com
2. Go to **Incidents & alerts** > **Incidents**
3. Find the incident related to the DLP binary quarantine
4. Open the incident, select the alert, then click **Manage indicator**
5. Choose **Allow** and set scope
6. Save; the indicator overrides the quarantine after propagation

---

### Vendor: CrowdStrike Falcon

**Console URL:** https://falcon.crowdstrike.com
**Required Role:** Falcon Administrator or Falcon Prevent Administrator
**Propagation Time:** Up to 40 minutes
**Supported Methods:** ML Exclusion (path), Certificate Exclusion, Hash Exclusion (via IOA)

> **WARNING:** CrowdStrike Falcon exclusions can take up to 40 minutes to propagate to all endpoints. Do NOT install the DLP agent immediately after creating an exclusion. Wait for propagation and verify before proceeding.

#### Method 1: ML Exclusion (Path-Based)

1. Navigate to https://falcon.crowdstrike.com
2. Go to **Configuration** > **Detections Management** > **Exclusions**
3. Select the **Machine Learning Exclusions** tab
4. Click **CREATE EXCLUSION**
5. Set **Scope** to **All hosts** or select specific Host Groups
6. Set **EXCLUDED FROM** to **Detections and preventions**
7. Enter the pattern: `C:\Program Files\DLP\*`
8. (Optional) Click **Pattern Test** to validate the pattern matches expected file paths
9. Add comment: "DLP v0.10.0 hook DLL and agent binary exclusion"
10. Click **Create Exclusion**, then toggle **Enable**

> **Note:** ML exclusions are path-based. If the DLP installation path changes, update the exclusion pattern accordingly.

#### Method 2: Certificate Exclusion

If the DLP binaries are signed with an organizational code-signing certificate, exclude by certificate instead of path:

1. Navigate to https://falcon.crowdstrike.com
2. Go to **Configuration** > **Detections Management** > **Exclusions**
3. Select the **Certificate Exclusions** tab
4. Click **CREATE EXCLUSION**
5. Upload the `.cer` file or paste the certificate thumbprint
6. Set scope and save

> **Note:** Certificate exclusions apply globally to all binaries signed with the uploaded certificate. Ensure certificate private key security before using this method.

#### Method 3: FalconPy API (Python)

For programmatic exclusion management, use the CrowdStrike FalconPy SDK:

```python
from falconpy import MLExclusions

# Initialize client (API client ID and secret from Falcon console)
client = MLExclusions(client_id="YOUR_CLIENT_ID", client_secret="YOUR_CLIENT_SECRET")

# Create ML exclusion
response = client.create_exclusions(
    body={
        "value": "C:\\Program Files\\DLP\\*",
        "excluded_from": ["detect", "prevent"],
        "groups": ["all"],
        "comment": "DLP v0.10.0 agent exclusion"
    }
)

print(response["status_code"])
```

**Required API Key Scopes:**
- `ml_exclusions:write` -- to create exclusions
- `ml_exclusions:read` -- to verify exclusions

Generate API credentials in the Falcon console under **Support** > **API Clients and Keys**.

#### PowerShell Alternative (Invoke-RestMethod)

If FalconPy is not available, use PowerShell with the CrowdStrike API directly:

```powershell
$clientId = "YOUR_CLIENT_ID"
$clientSecret = "YOUR_CLIENT_SECRET"

# Region-specific base URLs:
# US-1:  https://api.crowdstrike.com
# US-2:  https://api.us-2.crowdstrike.com
# EU-1:  https://api.eu-1.crowdstrike.com
# US-GOV-1: https://api.laggar.gcw.crowdstrike.com
$baseUrl = "https://api.crowdstrike.com"

# Obtain OAuth2 token
$tokenResponse = Invoke-RestMethod -Uri "$baseUrl/oauth2/token" -Method POST `
    -Headers @{ "Content-Type" = "application/x-www-form-urlencoded" } `
    -Body "client_id=$clientId&client_secret=$clientSecret"
$token = $tokenResponse.access_token

# Create ML exclusion
$body = @{
    value = "C:\Program Files\DLP\*"
    excluded_from = @("detect", "prevent")
    groups = @("all")
    comment = "DLP v0.10.0 agent exclusion"
} | ConvertTo-Json -Depth 3

$response = Invoke-RestMethod -Uri "$baseUrl/policy/combined/ml-exclusions/v1" -Method POST `
    -Headers @{
        "Authorization" = "Bearer $token"
        "Content-Type" = "application/json"
    } `
    -Body $body

Write-Host "Status: $($response.status_code)"
```

#### Verification

1. **Console verification:** In the Falcon console, go to **Configuration** > **Detections Management** > **Exclusions** and confirm the exclusion shows **Enabled**.
2. **Endpoint verification:** On the target endpoint, run:
   ```powershell
   Get-ChildItem "C:\Program Files\DLP\dlp_hook_dll.dll" -ErrorAction SilentlyContinue
   ```
   If the file is present and not quarantined after 40 minutes, the exclusion is active.

> **Important:** If the file is quarantined before the exclusion propagates, restore it from the Falcon console under **Activity** > **Quarantined files** after the exclusion is active.

### Vendor: SentinelOne

**Console URL:** SentinelOne Management Console (tenant-specific)
**Required Role:** Site Admin or Account Admin
**Propagation Time:** Up to 15 minutes
**Supported Methods:** Hash Exclusion (preferred), Path Exclusion, Certificate Exclusion

> **Agent Requirement:** SHA-256 hash exclusions require SentinelOne agent version S-25.1.1 or later. Older agents may only support SHA-1. Verify agent version on the endpoint before using hash-based exclusions.

#### Method 1: Hash Exclusion (Preferred)

1. Navigate to the SentinelOne Management Console
2. Go to **Sentinels** > **Exclusions** (or **Policy Settings** > **Exclusions**)
3. Click **New Exclusion** > **Create Exclusion**
4. Set **Exclusion Type** to **Hash**
5. Set **OS Type** to **Windows**
6. Enter the SHA-256 hash of the binary (e.g., `dlp_hook_dll.dll`)
7. Enter **Description**: "DLP v0.10.0 hook DLL"
8. Click **Save**

Repeat for all six shipped binaries:
- `dlp-agent.exe`
- `dlp-user-ui.exe`
- `dlp-admin-cli.exe`
- `dlp-server.exe`
- `dlp_hook_dll.dll`
- `dlp_hook_dll_x86.dll`

#### Method 2: Path Exclusion

If hash exclusions are unavailable or the agent version is below S-25.1.1, use a path exclusion:

1. Navigate to the SentinelOne Management Console
2. Go to **Sentinels** > **Exclusions**
3. Click **New Exclusion** > **Create Exclusion**
4. Set **Exclusion Type** to **Path**
5. Set **OS Type** to **Windows**
6. Enter the path: `C:\Program Files\DLP\*`
7. Enter **Description**: "DLP v0.10.0 installation directory"
8. Click **Save**

#### Verification

1. **Console verification:** In the SentinelOne console, go to **Sentinels** > **Exclusions** and confirm the exclusion appears in the list with status **Active**.
2. **Endpoint verification:** On the target endpoint, verify the SentinelOne agent is running and the DLP files are present:
   ```powershell
   # Check SentinelOne agent registry (both native and WOW6432Node)
   $s1Path = "HKLM:\SOFTWARE\SentinelLabs\SentinelAgent"
   $s1PathWow = "HKLM:\SOFTWARE\WOW6432Node\SentinelLabs\SentinelAgent"
   if (Test-Path $s1Path) {
       Write-Host "SentinelOne agent found (native): $s1Path"
   } elseif (Test-Path $s1PathWow) {
       Write-Host "SentinelOne agent found (WOW6432Node): $s1PathWow"
   } else {
       Write-Warning "SentinelOne agent not detected"
   }

   # Verify DLP files are present and not quarantined
   Test-Path "C:\Program Files\DLP\dlp_hook_dll.dll"
   ```

> **Note:** Hash exclusions in SentinelOne are exact-match. If the binary is updated (e.g., MSI upgrade), the new hash must be added to the exclusion list before deployment.

---

### Vendor: Carbon Black (VMware Carbon Black Cloud)

**Console URL:** `https://[REGION].conferdeploy.net`
**Required Role:** Custom role with "Reputation" permissions
**Propagation Time:** 10-20 minutes
**Supported Methods:** Reputation Approved List (hash), Path Exclusion

> **WARNING:** Carbon Black Cloud requires a file to be "known" (previously observed or submitted) before it can be added to a reputation list. If the DLP binary has never executed on a Carbon Black-managed endpoint, you may need to run it on a pilot endpoint first or submit the hash via the console.

#### Method 1: Reputation Approved List (Hash)

1. Navigate to `https://[REGION].conferdeploy.net`
2. Go to **Enforce** > **Reputation**
3. Click **Add**
4. Set **Type** to **Hash**
5. Set **List** to **Approved List**
6. Enter the SHA-256 hash of the binary
7. Enter **Name**: "DLP v0.10.0 hook DLL"
8. Enter **Comments**: "Data Loss Prevention agent hook"
9. Click **Save**

Repeat for all six shipped binaries.

#### Method 2: Policy Exclusion (Path-Based)

If the file is not yet known to Carbon Black, use a policy-level path exclusion:

1. Navigate to `https://[REGION].conferdeploy.net`
2. Go to **Enforce** > **Policies**
3. Select the target policy (or create a new one)
4. Go to **Sensor** > **Exclusions**
5. Click **Add Exclusion**
6. Set **Type** to **Path**
7. Enter the path: `C:\Program Files\DLP\*`
8. Set **Applies To** to **All operations** (or **Scan** and **Behavior**)
9. Click **Save** and assign the policy to the target endpoints

#### Verification

1. **Console verification:** In the Carbon Black console, go to **Enforce** > **Reputation** and confirm the hash appears in the Approved List with the correct name.
2. **Endpoint verification:** On the target endpoint, verify the file is present and not quarantined:
   ```powershell
   Test-Path "C:\Program Files\DLP\dlp_hook_dll.dll"
   ```

> **Important:** If the file was not known when added to the Approved List, it may still be flagged on first execution. Use a pilot endpoint to trigger initial observation:
> 1. Install the DLP agent on a single pilot endpoint with Carbon Black.
> 2. Allow the binary to execute (it may be initially flagged).
> 3. In the Carbon Black console, go to **Investigate** > **Alerts** and locate the alert.
> 4. Click **Add to Reputation** and select **Approved List**.
> 5. Wait 10-20 minutes for propagation, then verify on the pilot endpoint.
> 6. Once verified, deploy to the remaining fleet.

> **Note:** Reputation lists in Carbon Black Cloud are global per tenant. An entry in the Approved List applies to all endpoints in the organization.

---

### Vendor: Sophos

**Console URL:** `https://central.sophos.com`
**Required Role:** Super Admin or Admin
**Propagation Time:** 5-15 minutes
**Supported Methods:** Path Exclusion ONLY (hash NOT supported)

> **Limitation:** Sophos Central does NOT support hash-based allowlisting. All exclusions must be path-based. For false-positive resolution, submit the file to SophosLabs for reclassification.

#### Method 1: Path Exclusion

1. Navigate to `https://central.sophos.com`
2. Go to **My Products** > **Endpoint Protection** > **Policies**
3. Click the **Threat Protection** policy (or create a new one)
4. Go to **Settings** > **Scanning exclusions**
5. Click **Add Exclusion**
6. Set **Type** to **File or folder**
7. Enter the path: `C:\Program Files\DLP\*`
8. Set **Active for** to **Real-time** and **Scheduled** (or **Both**)
9. Click **Add**, then **Save**

#### Method 2: SophosLabs Reclassification (False Positive Submission)

If Sophos incorrectly flags a DLP binary as malware:

1. Navigate to `https://central.sophos.com`
2. Go to **Logs & Reports** > **Events**
3. Locate the detection event for the DLP binary
4. Click **Submit for reclassification**
5. Enter **Reason**: "False positive -- legitimate Data Loss Prevention agent binary"
6. Attach the binary or provide the SHA-256 hash
7. Submit and record the case ID

> **Turnaround:** 24-72 hours for SophosLabs reclassification.

#### Verification

1. **Console verification:** In the Sophos Central console, go to **My Products** > **Endpoint Protection** > **Policies** and confirm the exclusion appears in the Threat Protection policy.
2. **Endpoint verification:**
   ```powershell
   # Verify DLP files are present
   Test-Path "C:\Program Files\DLP\dlp_hook_dll.dll"

   # Check Sophos endpoint logs for detection events
   $sophosLogPath = "C:\ProgramData\Sophos\Endpoint Defense\Logs\"
   if (Test-Path $sophosLogPath) {
       Get-ChildItem $sophosLogPath -Filter "*.log" | Select-Object -Last 5
   }
   ```

> **Note:** Path exclusions apply to the specified directory tree. If the DLP installation path changes, update the Sophos policy accordingly.

---

### Vendor: Trend Micro Apex One

**Console URL:** Apex Central (tenant-specific)
**Required Role:** Administrator
**Propagation Time:** 10-20 minutes
**Supported Methods:** Application Control Hash Allow (preferred), Scan Exclusion (path)

> **Prerequisite:** Application Control is a separately licensed feature in Trend Micro Apex One. Verify the license includes Application Control before using Method 1. If Application Control is not licensed, use Method 2 (Scan Exclusion).

#### Method 1: Application Control Hash Allow (Preferred)

1. Navigate to the Apex Central console
2. Go to **Policies** > **Policy Resources** > **Application Control Criteria**
3. Click **Add Criteria**
4. Set **Action** to **Allow**
5. Enter **Name**: "DLP v0.10.0"
6. Set **Match method** to **Hash values**
7. Set **Hash type** to **SHA-256**
8. Enter the SHA-256 hash of each DLP binary
9. Click **OK**
10. Go to **Policies** > **Policy Management**
11. Select the target policy
12. Go to **Application Control** > **Assign criteria**
13. Select the "DLP v0.10.0" criteria and click **Deploy**

Repeat hash entry for all six shipped binaries.

#### Method 2: Scan Exclusion (Path)

If Application Control is not available, use a scan exclusion:

1. Navigate to the Apex Central console
2. Go to **Policies** > **Policy Management**
3. Select the target policy
4. Go to **Scan Settings** > **Exclusion List**
5. Click **Add**
6. Set **Type** to **Folder**
7. Enter the path: `C:\Program Files\DLP\*`
8. Set **Applies to** to **Real-time scan** and **Manual scan**
9. Click **Save** and deploy the policy

#### Verification

1. **Console verification:** In the Apex Central console, go to **Policies** > **Policy Resources** > **Application Control Criteria** and confirm the "DLP v0.10.0" criteria shows **Allow** action with the correct hashes.
2. **Endpoint verification:**
   ```powershell
   # Verify Apex One services are running
   Get-Service | Where-Object {
       $_.Name -like "*Apex*One*" -or
       $_.DisplayName -like "*Apex*One*"
   }

   # Verify DLP files are present and not quarantined
   Test-Path "C:\Program Files\DLP\dlp_hook_dll.dll"
   ```

> **Note:** Application Control in Trend Micro Apex One supports PE files only (.exe, .dll, .sys). Non-PE files (scripts, configuration files) are not covered by Application Control and require scan exclusions if needed.

<!-- PLACEHOLDER: EDR-VENDORS-END -->

## Hash Publishing and Verification

### Hash Verification Steps

Generate SHA-256 and SHA-512 hashes for all six shipped binaries and compare
against [RELEASE_NOTES.md](../RELEASE_NOTES.md):

1. Open an elevated PowerShell session.
2. Run the SHA-256 verification command:
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
3. Compare each printed hash to the corresponding value in
   `RELEASE_NOTES.md`.
4. Repeat step 2 with `-Algorithm SHA512` and compare against the SHA-512
   table in `RELEASE_NOTES.md`.

If any hash does not match, do not install or run the binary. Re-download the
release artifacts from the signed artifact store and repeat verification.

### Authenticode Signature Verification

Verify the Authenticode signature and RFC-3161 timestamp on every binary before
deployment:

```powershell
# Verify signature with verbose output (shows timestamp type)
signtool verify /pa /v "C:\Program Files\DLP\dlp-agent.exe"

# Verify ALL signatures on a binary (catches dual-signed or counter-signed artifacts)
signtool verify /all /pa "C:\Program Files\DLP\dlp_hook_dll.dll"
```

Expected output includes:

```
Index  Algorithm  Timestamp
0      sha256     RFC3161
```

The `/pa` switch uses the default Authenticode policy. The `/v` switch produces
verbose output including the timestamp algorithm. The `/all` switch verifies all
embedded signatures. All production binaries must show `RFC3161` (not
`Authenticode`) in the Timestamp column.

Notes:

- If `signtool verify` fails with "A certificate chain could not be built to a
trusted root authority," install the organizational root CA certificate using
`certutil`:
  ```cmd
  certutil -addstore -f "Root" "C:\Certs\OrgRootCA.cer"
  ```
- The hook DLLs may be dual-signed. `signtool verify /all /pa` will show
  multiple signatures; this is expected and normal.
- If the signing certificate is renewed between releases, update the trust
  store on target endpoints before deploying the new build.

### Microsoft WDSI Submission

Submit signed binaries to the Microsoft Windows Defender SmartScreen
Intelligence (WDSI) portal to reduce false-positive detections.

**Portal URL:** `https://www.microsoft.com/en-us/wdsi/filesubmission`

**File Preparation:**

- If a binary is flagged as suspected malware, place it in a ZIP archive with
  password `infected` before uploading.
- Maximum file size: 50 MB per submission.

**Submission Steps:**

1. Navigate to the WDSI portal URL above.
2. Sign in with an enterprise Azure AD / Microsoft work account.
3. Select "Software developer" as the submission type.
4. Upload the binary (or the password-protected ZIP).
5. Enter the company name.
6. Enter the product name: "DLP v0.10.0".
7. Enter the detection name if Defender reported one.
8. Submit and record the submission ID for tracking.

**Turnaround:** 24-48 hours.

**Troubleshooting:**

- Rejected submission: re-submit with more detail (company name, product
  description, file hash, detection name).
- Pending longer than 10 days: contact Microsoft support with the submission ID.
- ZIP password `infected` may trigger email gateway blocks; use the web portal
  directly.

## UAT Test Matrix

This section provides the high-level UAT scope, execution order, and pass
criteria. For the full test matrix template (including the "Actual" column for
capturing results), see `.planning/milestones/v0.10.0-UAT.md`.

### UAT Scope

| Feature Area | Test Script | Hardware Required | Milestone |
|--------------|-------------|-------------------|-----------|
| Cloud Sync Regression | `Uat-CloudSync.ps1` | Cloud sync clients (OneDrive, Google Drive, Dropbox, Box) | v0.9.0 |
| Print Enforcement | `Uat-PrintEnforce.ps1` | Real printer installed | v0.9.0 |
| Hook DLL Injection | `Uat-HookInjection.ps1` | None | v0.10.0 |
| DACL Tripwire | `Uat-DaclTripwire.ps1` | None | v0.10.0 |
| ETW Consumer + ntdll Patch + Monitor Mode | `Uat-EtwConsumer.ps1`, `Uat-NtdllPatch.ps1`, `Uat-MonitorMode.ps1` | None | v0.10.0 |
| Volume Class (optional) | `Uat-VolumeClass.ps1` | SD card, optical drive, or virtual drive | v0.10.0 |
| USB Enforcement | `Uat-UsbBlock.ps1` | Physical USB removable drive | v0.7.0+ |
| CRIT-04 Benchmark | `Uat-Benchmark.ps1` | None | v0.10.0 |

### Execution Order

Run tests in the following order. Each step depends on the previous steps
passing.

1. **Prerequisites check** -- verify server, agent, JWT, T4 policy, Protected
   Path, printer, USB drive, and EDR allowlist:
   ```powershell
   .\scripts\Uat-PrereqCheck.ps1
   ```
2. **Cloud Sync Regression** -- validate the v0.9.0 baseline:
   ```powershell
   .\scripts\Uat-CloudSync.ps1
   ```
3. **Print Enforcement**:
   ```powershell
   .\scripts\Uat-PrintEnforce.ps1
   ```
4. **Hook DLL Injection**:
   ```powershell
   .\scripts\Uat-HookInjection.ps1
   ```
5. **DACL Tripwire**:
   ```powershell
   .\scripts\Uat-DaclTripwire.ps1
   ```
6. **ETW Consumer**:
   ```powershell
   .\scripts\Uat-EtwConsumer.ps1
   ```
7. **ntdll Patch**:
   ```powershell
   .\scripts\Uat-NtdllPatch.ps1
   ```
8. **Monitor Mode**:
   ```powershell
   .\scripts\Uat-MonitorMode.ps1
   ```

### Manual Volume Class Tests (if hardware available)

If optional hardware is present, run the volume class tests after Step 5
(DACL Tripwire) and before Step 6 (ETW Consumer):

```powershell
.\scripts\Uat-VolumeClass.ps1
```

The script auto-detects SD cards, optical drives, and virtual drives via WMI
(`Win32_DiskDrive` + `Win32_LogicalDisk`). Each detected volume class produces
a distinct device-arrival audit event. If no optional hardware is available,
mark Group 6 as SKIP in `.planning/milestones/v0.10.0-UAT.md` -- UAT remains
valid.

### USB Enforcement

Run the USB enforcement test after all other functional tests pass. This script
requires a physical USB removable drive and Administrator privileges:

```powershell
.\scripts\Uat-UsbBlock.ps1
```

The script auto-detects removable USB drives, presents an interactive selection
menu, registers the chosen device through the admin API, and verifies blocked
and read_only trust-tier behaviour at the kernel level. It cleans up the
registry entry and disk attributes after testing.

For full details, see `scripts/Uat-UsbBlock.ps1` and `scripts/Uat-ReadMe.md`.

### CRIT-04 Benchmark Gate

The benchmark gate is the final acceptance criterion for v0.10.0 performance.

| Benchmark | Threshold | Measurement |
|-----------|-----------|-------------|
| `cargo build --workspace --release` | <= 25% wall-clock overhead | Compare with hooks disabled vs. enabled |
| Office app launch (Word, Excel) | <= 25% wall-clock overhead | Compare with hooks disabled vs. enabled |

Run the benchmark script last, after all functional tests pass:

```powershell
.\scripts\Uat-Benchmark.ps1
```

#### Benchmark Preconditions

- The agent must be in `HEALTHY` fail-state (verify via admin TUI or
  `siem.hook_self_health` audit event).
- The classification cache must be warm (run a few file operations before
  timing).
- No other CPU-intensive processes should be running.
- The test endpoint must be on AC power (not battery).
- Close all cloud sync clients and background updaters before benchmarking.

For the full benchmark methodology, measurement commands, and baseline
recording procedure, see `scripts/Uat-Benchmark.ps1`.

### UAT Pass Criteria

UAT is considered PASSED when ALL of the following are true:

1. Every test case in Groups 1-5 and 7-8 shows PASS with no FAILs.
2. Group 6 (Volume Class) may be skipped if optional hardware is unavailable.
3. The CRIT-04 benchmark gate (BM-01 and BM-02) shows <= 25% wall-clock
   overhead versus baseline.
4. No `WerFault` event log entries name `dlp_hook_dll.dll` across the entire
   test session.
5. All audit events route to SIEM without error.
6. The `DLP_ADMIN_JWT` token remains valid for the entire session.

### Failure Escalation Procedure

If any test case FAILs:

1. Re-run the failing test in isolation to confirm reproducibility.
2. Capture the full error output, HRESULT/NTSTATUS codes, and relevant log
   excerpts in the Notes column of `.planning/milestones/v0.10.0-UAT.md`.
3. Check the following common causes:
   - Agent not running or not connected to server
   - JWT token expired or missing
   - EDR has quarantined a DLP binary (re-check allowlist)
   - Protected Path not registered or T4 policy not active
   - Secure Boot enabled but ETW consumer not started (check
     `SeSystemProfilePrivilege`)
4. If the failure is reproducible and not explained by the common causes,
   file a blocking issue and do NOT sign off until resolved.

For the full test matrix template with TC-IDs, Expected/Actual columns, and
sign-off tables, see `.planning/milestones/v0.10.0-UAT.md`.

## Troubleshooting

### Secure Boot check returns error

`Confirm-SecureBootUEFI` requires UEFI firmware. On legacy BIOS systems, the
cmdlet throws `Cmdlet not supported on this platform`. In this case, Secure
Boot is not available and `AppInit_DLLs` may function as a fallback. Document
the BIOS mode in the deployment record.

### signtool verify fails with "A certificate chain could not be built"

The target machine may be missing the issuing CA certificate in its Trusted
Publishers store. Install the organizational CA certificate before running
`signtool verify /pa`. For testing, use `signtool verify /a` to build a chain
to any available root.

### Get-FileHash produces different values than RELEASE_NOTES.md

Possible causes:

- Binary was modified after signing (tampering, partial download).
- Wrong file path (x64 vs x86 DLL mismatch).
- RELEASE_NOTES.md references a different build (check version tag).

Re-download the release artifacts from the signed artifact store and re-verify.

### SeSystemProfilePrivilege shows "Disabled"

The privilege is present but not enabled in the current token. The `dlp-agent`
service running as `LocalSystem` enables it automatically at startup. If running
manual verification from a non-service context, use `Set-TokenPrivilege.ps1`
(Lee Holmes) or restart the PowerShell session as Administrator.

### ETW consumer fails after MSI upgrade

1. Verify `SeSystemProfilePrivilege` is still granted to the service account
   (`sc qprivs dlp-agent`).
2. Check agent logs for `StartTrace` access-denied errors.
3. If privileges were lost, reinstall with `PRESERVE_PRIVILEGES=1`.
4. Reboot the endpoint.

## References

- [DEPLOYMENT.md](../DEPLOYMENT.md) -- High-level deployment overview, MSI
  paths, and signtool commands.
- [OPERATIONAL.md](../OPERATIONAL.md) -- Service names, log paths, config paths,
  and day-to-day operational procedures.
- [dpapi-recovery.md](dpapi-recovery.md) -- DACL tripwire details and recovery
  procedures.
- [CHANGELOG.md](../CHANGELOG.md) -- Version history and release notes.
