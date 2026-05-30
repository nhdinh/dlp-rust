# DLP Agent Deployment Guide

**Version:** v0.10.0
**Applies to:** dlp-agent, dlp-hook-dll, dlp-user-ui, dlp-admin-cli, dlp-server

## Quick Start for Experienced Operators

Use this checklist if you have deployed DLP agents before.

- [ ] Install signed MSI from release artifacts.
- [ ] Verify Authenticode signature via `signtool verify /pa`.
- [ ] Add hash exclusions for your EDR vendor (see Section 3; SHA-256 hashes from RELEASE_NOTES.md).
- [ ] Grant `SeSystemProfilePrivilege` to the agent service account.
- [ ] Reboot host (required for AppInit_DLLs / hook activation; see Section 4 for details).
- [ ] Verify injection via `Get-Process | Where-Object {$_.Modules -match "dlp_hook_dll"}`.
- [ ] Test T4 file denial on a sample protected path.
- [ ] Check SIEM for `DlpAgentStarted` event.
- [ ] Verify Protected Paths screen shows expected entries.
- [ ] Confirm monitor mode is active (if deploying in Audit first).

---

## 1. Prerequisites

Before installing the DLP agent, verify the following on the target host:

- Windows 11 Pro or Enterprise (build 22621 or later).
- .NET 8 runtime installed.
- Host is joined to an Active Directory domain.
- Local administrator rights on the target host.
- At least one supported EDR product installed (see Section 3 for supported vendors).
- PowerShell 5.1 or later.
- Network connectivity to the DLP policy server and SIEM relay.

## 2. Installation Steps

### Step 1: Download the signed MSI

Download `dlp-agent-v0.10.0-x64.msi` from the release artifacts page. Save it to a
local directory (for example, `C:\DLP-Install\`).

### Step 2: Verify the Authenticode signature

Before running the installer, confirm the binary is signed:

```powershell
signtool verify /pa C:\DLP-Install\dlp-agent-v0.10.0-x64.msi
```

Expected output includes:

```
Successfully verified: C:\DLP-Install\dlp-agent-v0.10.0-x64.msi
```

The `/pa` switch uses the default Authenticode policy. If verification fails, do
not proceed. Contact the release engineering team.

### Step 3: Run the installer

Run the MSI from an elevated PowerShell session:

```powershell
msiexec /i C:\DLP-Install\dlp-agent-v0.10.0-x64.msi /quiet /norestart
```

Installation defaults:

- Install path: `C:\Program Files\DLP\`
- Service account: `NT SERVICE\dlp-agent`
- ProgramData path: `C:\ProgramData\DLP\`

### Step 4: Verify the service is registered

```powershell
Get-Service dlp-agent
```

Expected: `Status = Stopped`, `StartType = Automatic`.

### Step 5: Verify auto-start configuration

```powershell
Get-CimInstance Win32_Service -Filter "Name='dlp-agent'" | Select-Object Name, StartMode, State
```

Expected: `StartMode = Auto`, `State = Stopped` (it will start after reboot).

---

## 3. AV/EDR Allowlist Procedures

The DLP agent uses global DLL injection via AppInit_DLLs and ntdll patching for
universal hook coverage. Most EDR products will flag these behaviors. Add
exclusions BEFORE starting the agent service.

Allowlist approach per D-05:

- **Path exclusion:** `C:\Program Files\DLP\`
- **Hash exclusions:** SHA-256 hashes for `dlp-agent.exe`, `dlp-hook-dll.dll`,
  and `dlp-user-ui.exe` (published in RELEASE_NOTES.md).

> **Last verified date placeholder:** All vendor sections below show a
> `[Last verified: YYYY-MM-DD]` placeholder. Replace with the actual UAT date
> and EDR version during execution.

### 3.1 Microsoft Defender for Endpoint

**Expected detection behavior:**

Defender may flag `dlp-hook-dll.dll` as `Trojan:Win32/Wacatac.B!ml` (example
only; record your actual detection name). The agent's ntdll patching and
AppInit_DLLs registration trigger behavior-based detections.

**Console / UI steps:**

1. Open **Windows Security** app.
2. Navigate to **Virus & threat protection** > **Virus & threat protection settings** > **Manage settings**.
3. Scroll to **Exclusions** and click **Add or remove exclusions**.
4. Add a **Folder** exclusion: `C:\Program Files\DLP\`.
5. Add **File** exclusions for each binary using the SHA-256 hash from RELEASE_NOTES.md:
   - `dlp-agent.exe`
   - `dlp-hook-dll.dll`
   - `dlp-user-ui.exe`

[ Screenshot: Windows Security app -> Virus & threat protection -> Exclusions ]
*(To be added during UAT execution)*

**Group Policy path (enterprise deployment):**

```
Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Exclusions
```

Policy settings:

- `Defender Exclusions` > `Path Exclusions` = `C:\Program Files\DLP\`
- `Defender Exclusions` > `Extension Exclusions` = (none required)

**Hash exclusion example (SHA-256):**

```powershell
# Example hash -- replace with actual value from RELEASE_NOTES.md
$hash = "A1B2C3D4E5F6..."  # 64-character SHA-256
Add-MpPreference -ExclusionPath "C:\Program Files\DLP\"
# Hash-based exclusions in Defender are configured via Attack Surface Reduction (ASR) or WDSI submission
```

**Verification command:**

```powershell
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

Expected: `C:\Program Files\DLP\` listed.

**Troubleshooting note:**

If Defender continues to block after exclusion, submit the binary to Microsoft
WDSI for reputation update:

```
https://www.microsoft.com/en-us/wdsi/filesubmission
```

Form values:

- Product name: DLP-RUST Endpoint Agent
- Company: [Customer Name]
- File type: Executable
- Detection name: (your actual detection name from Defender console)
- Additional information: Enterprise DLP agent using global DLL injection for file-access monitoring.

Expected turnaround: 24-72 hours.

**[Last verified: YYYY-MM-DD]**

---

### 3.2 CrowdStrike Falcon

**Expected detection behavior:**

Falcon may flag the agent for process hollowing indicators (ntdll patching) and
unknown DLL loads (AppInit_DLLs). Detections appear under **Endpoint Security** >
**Detections**.

**Console / UI steps:**

1. Log in to the Falcon console.
2. Navigate to **Configuration** > **Prevention Policies**.
3. Select the policy applied to DLP hosts (or create a new one).
4. Click **Exclusions**.
5. Add **Hash Exclusions** for each binary using SHA-256 from RELEASE_NOTES.md.
6. Add **Path Exclusion**: `C:\Program Files\DLP\`.
7. Use **SensorGroupingTag** to target the policy:
   - Tag value: `DLP-AGENT`
   - Apply tag to hosts via Falcon sensor settings or registry:
     ```powershell
     reg add "HKLM\SYSTEM\CurrentControlSet\Services\CSAgent\Sim" /v "SGTag" /t REG_SZ /d "DLP-AGENT" /f
     ```

[ Screenshot: CrowdStrike Falcon console -> Prevention -> Exclusions ]
*(To be added during UAT execution)*

**Hash exclusion example (SHA-256):**

```
Hash type: SHA256
Hash value: A1B2C3D4E5F6... (64 chars, from RELEASE_NOTES.md)
Applies to: dlp-agent.exe, dlp-hook-dll.dll, dlp-user-ui.exe
```

**Verification command:**

```powershell
# Check Falcon sensor status
& "C:\Program Files\CrowdStrike\CSFalconService.exe" -status
```

Expected: Sensor running, no detections for DLP path.

**Troubleshooting note:**

If Falcon quarantines the DLL before exclusion is applied, restore it from
**Detections** > **Action** > **Restore**, then apply the exclusion and reboot.

**[Last verified: YYYY-MM-DD]**

---

### 3.3 SentinelOne

**Expected detection behavior:**

SentinelOne may block `dlp-hook-dll.dll` as suspicious due to global injection
behavior. The recommended approach is **certificate hash exclusion** (NOT file
hash), because file hashes change per release but the code-signing certificate
remains consistent.

**Console / UI steps:**

1. Log in to the SentinelOne Management Console.
2. Navigate to **Policies** > **Exclusions**.
3. Click **Add Exclusion** > **Certificate Hash**.
4. Enter the certificate thumbprint from RELEASE_NOTES.md.
5. Set scope to **Global** or the policy applied to DLP hosts.
6. Add a **Path Exclusion** for `C:\Program Files\DLP\` as a secondary measure.

[ Screenshot: SentinelOne console -> Policies -> Exclusions -> Certificate Hash ]
*(To be added during UAT execution)*

**Certificate hash exclusion:**

```
Exclusion type: Certificate Hash
Thumbprint: AB CD EF 12 34 56 ... (40 chars, from RELEASE_NOTES.md)
Applies to: All binaries signed with this certificate
```

> **Note:** The certificate thumbprint is published in RELEASE_NOTES.md under
the release heading. If the certificate is renewed, update the thumbprint in
both the EDR console and RELEASE_NOTES.md.

**Verification command:**

```powershell
# Verify certificate on installed binary
Get-AuthenticodeSignature "C:\Program Files\DLP\dlp-agent.exe" | Select-Object -ExpandProperty SignerCertificate | Format-List Thumbprint, Subject
```

Expected: Thumbprint matches the exclusion value.

**Troubleshooting note:**

If SentinelOne continues to block after certificate exclusion, verify the
binary is actually signed (not a debug build). Unsigned builds require file-hash
exclusions, which must be updated on every release.

**[Last verified: YYYY-MM-DD]**

---

### 3.4 Carbon Black (VMware)

**Expected detection behavior:**

Carbon Black may assign a low reputation score to `dlp-hook-dll.dll` due to
unknown publisher or suspicious behavior. This triggers blocking in restrictive
policies.

**Console / UI steps:**

1. Log in to the Carbon Black Cloud console.
2. Navigate to **Enforce** > **Policies**.
3. Select the policy for DLP endpoints.
4. Go to the **Reputation** tab.
5. Click **Add Reputation Override**.
6. Select **Override type: SHA-256 Hash**.
7. Enter the SHA-256 hash from RELEASE_NOTES.md and set reputation to **Known Good**.
8. Repeat for each binary: `dlp-agent.exe`, `dlp-hook-dll.dll`, `dlp-user-ui.exe`.

[ Screenshot: Carbon Black console -> Enforce -> Policies -> Reputation Overrides ]
*(To be added during UAT execution)*

**Reputation override example:**

```
Override type: SHA-256 Hash
Hash: A1B2C3D4E5F6... (64 chars, from RELEASE_NOTES.md)
Reputation: Known Good
Description: DLP-RUST agent binary
```

**Verification command:**

```powershell
# Check Carbon Black sensor status
Get-Service cbagent
```

Expected: Service running, no reputation alerts for DLP path.

**Troubleshooting note:**

If Carbon Black has already quarantined the file, go to **Investigate** >
**Alerts**, find the DLP detection, and choose **Allow** before adding the
reputation override.

**[Last verified: YYYY-MM-DD]**

---

### 3.5 Sophos Intercept X

**Expected detection behavior:**

Sophos may flag the agent for suspicious behavior (DLL injection, memory
modification). Tamper protection can prevent the agent service from registering
AppInit_DLLs.

**Console / UI steps:**

1. Open **Sophos Central**.
2. Navigate to **Policies** > **Threat Protection**.
3. Select the policy applied to DLP hosts.
4. Under **Exclusions**, add:
   - **Path exclusion:** `C:\Program Files\DLP\`
   - **File exclusions:** `dlp-agent.exe`, `dlp-hook-dll.dll`, `dlp-user-ui.exe`
5. **Disable tamper protection temporarily** during initial install (re-enable after):
   - Sophos Central > **Settings** > **Tamper Protection** > **Disable**
   - Or use the local tamper-protection password if configured.

[ Screenshot: Sophos Central -> Policies -> Threat Protection -> Exclusions ]
*(To be added during UAT execution)*

**Hash exclusion example (SHA-256):**

```
Exclusion type: File hash (SHA-256)
Hash: A1B2C3D4E5F6... (from RELEASE_NOTES.md)
Files: dlp-agent.exe, dlp-hook-dll.dll, dlp-user-ui.exe
```

**Verification command:**

```powershell
# Check Sophos services
Get-Service SAVService, Sophos* | Select-Object Name, Status
```

Expected: All Sophos services running.

**Troubleshooting note:**

Tamper protection MUST be disabled during install because the agent modifies the
AppInit_DLLs registry key. Re-enable tamper protection after the host reboots
and the agent is confirmed working. Document the disable/enable window in your
change log.

**[Last verified: YYYY-MM-DD]**

---

### 3.6 Trend Micro Apex One

**Expected detection behavior:**

Apex One may flag the agent during smart scan (cloud-reputation check) before
local exclusions take effect. The agent may be blocked as "untested" or
"suspicious" during the initial scan.

**Console / UI steps:**

1. Log in to the Apex One web console.
2. Navigate to **Policies** > **Agent** > **Exception Lists**.
3. Create a new exception list (or edit the DLP host policy).
4. Add **Scan Exclusions**:
   - **Folder:** `C:\Program Files\DLP\`
   - **Files:** `dlp-agent.exe`, `dlp-hook-dll.dll`, `dlp-user-ui.exe`
5. Under **Scan Method**, ensure the policy uses **Conventional Scan** (not Smart
   Scan) for the DLP path, OR add hash-based exceptions to the Smart Scan
   approved list.

[ Screenshot: Apex One console -> Policies -> Agent -> Exception Lists ]
*(To be added during UAT execution)*

**Hash exclusion example (SHA-256):**

```
Exception type: File hash
Hash algorithm: SHA-256
Hash value: A1B2C3D4E5F6... (from RELEASE_NOTES.md)
Action: Allow
Scan method: Conventional scan (recommended) or Smart scan with approved hash
```

**Verification command:**

```powershell
# Check Apex One agent status
& "C:\Program Files\Trend Micro\OfficeScan Client\PccNTMon.exe" -n
```

Expected: Agent running, no detection alerts for DLP path.

**Troubleshooting note:**

If Smart Scan blocks the agent before the exception propagates, switch the DLP
host to Conventional Scan temporarily, complete the install, then revert to
Smart Scan after the hash exception is synced.

**[Last verified: YYYY-MM-DD]**

---

### 3.7 Adding a New Vendor (Extensible Template)

Use this template when adding allowlist procedures for EDR vendors not covered
above.

```markdown
### 3.N [Vendor Name]

**Expected detection behavior:**

[Describe what the vendor flags and why.]

**Console / UI steps:**

1. [Step 1]
2. [Step 2]
3. [Step 3]

[ Screenshot: [Vendor] console -> [Path] -> [Screen] ]
*(To be added during UAT execution)*

**Hash exclusion example (SHA-256):**

```
[Exclusion type and values]
```

**Verification command:**

```powershell
[PowerShell command]
```

**Troubleshooting note:**

[Common issue and resolution.]

**[Last verified: YYYY-MM-DD]**
```

---

## 4. Secure Boot & PPL Considerations

### 4.1 Secure Boot Impact on Injection

When Secure Boot is enabled, Windows ignores the `AppInit_DLLs` registry key.
The agent detects this condition at startup via `is_secure_boot_enabled()` and
emits a `SecureBootBlocksAppInit` audit event (logged at WARN level). The
primary injection mechanism automatically falls back to the ETW Process Watcher
+ `CreateRemoteThread` path.

Injection coverage is functionally identical between the two mechanisms; only
the delivery path changes:

| Mechanism | Secure Boot OFF | Secure Boot ON |
|-----------|-----------------|----------------|
| AppInit_DLLs | Active (process loads DLL at startup) | Ignored by Windows |
| ETW + CreateRemoteThread | Available fallback | Primary path |

**Verification steps for Secure Boot hosts:**

1. Check Secure Boot status:
   ```powershell
   Confirm-SecureBootUEFI
   ```
   Expected: `True`

2. Within 30 seconds of agent start, verify the `SecureBootBlocksAppInit`
   event appears in the agent log:
   ```powershell
   Select-String -Path "C:\ProgramData\DLP\logs\dlp-agent.log" `
     -Pattern "SecureBootBlocksAppInit" -SimpleMatch
   ```

3. Verify processes still receive the hook DLL via Process Hacker or:
   ```powershell
   Get-Process | Where-Object {
     $_.Modules -match "dlp_hook_dll"
   } | Select-Object Name, Id
   ```

**No action required.** Operators do NOT need to disable Secure Boot. The
fallback mechanism is automatic and transparent.

### 4.2 CreateRemoteThread EDR Compatibility

Some EDR products may block or alert on `CreateRemoteThread` calls. The agent's
usage is targeted (specific PID, known DLL path from `C:\Program Files\DLP\`)
and should not trigger generic injection alerts on most EDRs.

If an EDR does block `CreateRemoteThread`:

1. Add an additional exclusion for the agent service account
   (`NT SERVICE\DlpAgent`) in the EDR console.
2. Operator-visible signal: check the agent log for
   `CreateRemoteThread failed` messages.
3. Check the EDR console for injection-blocking alerts correlated with agent
   startup time.

### 4.3 PPL Coverage Gap

Protected Process Light (PPL) processes CANNOT be injected via
`CreateRemoteThread`. This is a Windows security feature, not a DLP limitation.

Affected processes include:

| Process | Protection Level | Why Skipped |
|---------|-----------------|-------------|
| `lsass.exe` | WinTcb / PPL | Critical system security process |
| `services.exe` | WinTcb | Service control manager |
| `csrss.exe` | WinTcb | Client-server runtime |
| `smss.exe` | WinTcb | Session manager |
| `wininit.exe` | WinTcb | Windows startup |
| `MsMpEng.exe` | AntiMalware PPL | Microsoft Defender self-protection |
| EDR self-processes | AntiMalware PPL | Vendor-specific protection |

There may be timing windows where a process starts before PPL is applied. The
agent handles this via the allowlist refresh interval (periodic re-scan).

### 4.4 DACL Tripwire as Backstop

For T3/T4 paths, the DACL tripwire provides kernel-enforced protection EVEN
when the hook cannot inject into a process.

- If a PPL-protected process (e.g., Defender scanning a T4 file) attempts to
  write or delete a protected path, NTFS returns `ERROR_ACCESS_DENIED`.
- The tripwire is defense-in-depth: the hook catches most processes; the DACL
  catches the rest.
- The two-phase staged update mechanism ensures that operator-initiated removal
  via the admin TUI does NOT trigger a tamper alert.

**Coverage summary:**

```
Process Type          | Injection Coverage | Backstop
----------------------|--------------------|------------------
Normal user process   | Yes (hook DLL)     | DACL (T3/T4 only)
System process        | Yes (if not PPL)   | DACL (T3/T4 only)
PPL-protected process | No                 | DACL (T3/T4 only)
Allowlisted process   | Skipped            | DACL (T3/T4 only)
```

**Operator-visible signal:** If a PPL-protected process attempts to access a
T4 path, the access is denied silently (no alert). This is expected behavior.

### 4.5 Coverage Equivalence

The ETW Kernel-Process + `CreateRemoteThread` fallback has functionally
identical coverage to `AppInit_DLLs`, with the following caveats:

| Factor | AppInit_DLLs | ETW + CreateRemoteThread |
|--------|--------------|--------------------------|
| Timing | DLL loads at process startup | ETW observes creation, injects shortly after |
| Typical gap | 0 ms | < 100 ms |
| Privilege | None (Windows loader) | Requires appropriate privileges |
| PPL exclusions | Skipped by OS loader | Skipped by allowlist matcher |

The agent runs as a service with sufficient rights for `CreateRemoteThread`.

### 4.6 SeSystemProfilePrivilege

`SeSystemProfilePrivilege` is required for:

- ETW Kernel-File consumer (Phase 53)
- ETW Kernel-Process watcher (Phase 49)

**Assignment methods:**

**a) Group Policy (recommended for domain-joined hosts):**

Computer Configuration -> Windows Settings -> Security Settings ->
Local Policies -> User Rights Assignment -> "Profile system performance" ->
Add `NT SERVICE\DlpAgent`

**b) Command line (requires Windows Server 2003 Resource Kit Tools):**

```batch
ntrights.exe +r SeSystemProfilePrivilege -u "NT SERVICE\DlpAgent"
```

**c) PowerShell (copy-pasteable):**

```powershell
$privilege = "SeSystemProfilePrivilege"
$account = "NT SERVICE\DlpAgent"
$tempFile = [System.IO.Path]::GetTempFileName()
secedit /export /cfg $tempFile /quiet
$content = Get-Content $tempFile
$content = $content -replace "^($privilege.*)$", "`$1,$account"
$content | Set-Content $tempFile
secedit /configure /db $env:TEMP\secedit.sdb /cfg $tempFile `
  /areas USER_RIGHTS /quiet
Remove-Item $tempFile
```

**Verification:**

```powershell
# Run as the agent service account
whoami /priv | Select-String "SeSystemProfilePrivilege"
```

Expected: `SeSystemProfilePrivilege` shown as **Enabled**.

**Privilege persistence:** The MSI installer preserves the service account
(`NT SERVICE\DlpAgent`) across upgrades, so the privilege assignment survives
agent updates.

**Domain policy refresh:** If a domain GPO overrides local user rights, the
privilege may be removed. For domain-joined hosts, assign the privilege via
domain GPO to ensure persistence.

### 4.7 Post-Install Reboot Requirement

Reboot requirements are mechanism-qualified:

| Scenario | Secure Boot OFF | Secure Boot ON |
|----------|-----------------|----------------|
| First install | Reboot REQUIRED for AppInit_DLLs hook activation | Reboot RECOMMENDED for clean ETW provider registration |
| Service restart | Not required (hot reload) | Not required (hot reload) |
| MSI upgrade | Reboot REQUIRED (DLLs may be memory-mapped) | Reboot REQUIRED (DLLs may be memory-mapped) |
| Config change | Not required | Not required |

**Rationale:**

- **AppInit_DLLs active:** New processes must be started AFTER the registry key
  is written to load the hook DLL. Existing processes are not retroactively
  injected.
- **ETW fallback:** The ETW session is registered at service start; new
  processes are observed immediately. A reboot ensures no stale ETW state from
  a previous installation.
- **MSI upgrade:** The installer stops the service and replaces files, but
  memory-mapped DLLs may persist until reboot.

### 4.8 Upgrade Path

1. MSI upgrade stops the `DlpAgent` service automatically.
2. Installer replaces executables and DLLs in `C:\Program Files\DLP\`.
3. Service account (`NT SERVICE\DlpAgent`) and privileges are preserved.
4. Configuration (`C:\ProgramData\DLP\config\`) and SQLite database
   (`C:\ProgramData\DLP\db\`) are preserved.
5. **Reboot is required** after MSI upgrade (see table above).

---

## 5. Post-Install Verification

Run this checklist after installation and reboot to confirm the deployment is
healthy.

- [ ] Service `dlp-agent` is running.
- [ ] `Get-Process | Where-Object {$_.Modules -match "dlp_hook_dll"}` returns
      at least one match.
- [ ] T4 (Restricted) file copy to a protected path is denied.
- [ ] T3 (Confidential) file copy to a protected path is denied (if policy
      enforces T3).
- [ ] T1 (Public) file copy to a protected path is allowed.
- [ ] SIEM receives `DlpAgentStarted` event within 60 seconds of service start.
- [ ] Protected Paths screen (dlp-admin-cli or admin TUI) shows expected entries.
- [ ] Monitor mode indicator is correct (Audit vs Enforce per policy).
- [ ] Agent log at `C:\ProgramData\DLP\logs\dlp-agent.log` shows no ERROR-level
      entries in the last 50 lines.
- [ ] EDR console shows no active detections for DLP binaries.

---

## 6. Troubleshooting

### Issue 1: Hook not injecting

**Symptoms:** `Get-Process | Where-Object {$_.Modules -match "dlp_hook_dll"}`
returns no matches.

**Resolution:**

1. Verify the EDR allowlist is applied (see Section 3 for your vendor).
2. Check that `SeSystemProfilePrivilege` is granted to the service account:
   ```powershell
   whoami /priv | Select-String "SeSystemProfilePrivilege"
   ```
3. Check Event Viewer for `siem.appinit_dlls_disabled` event (Secure Boot may
   be active; fallback to ntdll patching should occur).
4. Reboot the host and recheck.

---

### Issue 2: T4 file still writable

**Symptoms:** Copying a Restricted-classification file to a protected path
succeeds when it should be denied.

**Resolution:**

1. Verify the agent service is running: `Get-Service dlp-agent`.
2. Check the DACL tripwire on the protected path:
   ```powershell
   icacls "C:\Protected\Path"
   ```
3. Verify the Protected Paths screen shows the path is registered.
4. Check agent logs for `DaclTripwireRepair` events.
5. Ensure the policy bundle is loaded and the path has a T4 classification rule.

---

### Issue 3: High CPU usage

**Symptoms:** Agent process consumes excessive CPU.

**Resolution:**

1. Check ETW buffer size in the agent configuration (default is usually
   sufficient; increase only if advised by support).
2. Verify EDR allowlist coverage -- missed allowlist entries cause the EDR to
   repeatedly scan agent activity.
3. Check the hook journal ring buffer for overflow events in the agent log.
4. Review the allowlist module (`dlp-agent/src/allowlist.rs`) to confirm all
   expected process categories are excluded.

---

### Issue 4: Service fails to start after upgrade

**Symptoms:** `Start-Service dlp-agent` fails with an access-denied or
privilege error.

**Resolution:**

1. Verify `SeSystemProfilePrivilege` was preserved across the upgrade (per D-24,
   this is documented in Plan 57-04).
2. Check that the service account still has the required privileges:
   ```powershell
   sc qprivs dlp-agent
   ```
3. If the MSI reset privileges, re-grant them via Group Policy or Local Security
   Policy and reboot.
4. Check Windows Event Log (System) for service control manager errors.

---

## 7. Rollback Procedure

Use this procedure to completely remove the DLP agent and restore the host to
its pre-install state.

### Step 1: Stop the agent service

```powershell
Stop-Service dlp-agent
```

### Step 2: Uninstall the MSI

```powershell
msiexec /x dlp-agent-v0.10.0-x64.msi /quiet /norestart
```

Or use the original MSI file path if it was saved locally.

### Step 3: Restore original DACLs on protected paths

For each protected path, reset the ACL to inherited defaults:

```powershell
icacls "C:\Protected\Path" /reset /T /C
```

> **Warning:** `/reset` removes all explicit ACL entries. Ensure no other
> applications depend on custom ACLs on these paths before running this command.

### Step 4: Clean up ProgramData

Remove agent data, logs, and configuration (optional -- only if required by
your security policy):

```powershell
Remove-Item -Recurse -Force "C:\ProgramData\DLP"
```

> **Warning:** This deletes the agent database and all local logs. Back up any
> required forensic data before deletion.

### Step 5: Verify removal

```powershell
Get-Service dlp-agent          # Should error: service not found
Test-Path "C:\Program Files\DLP\"  # Should return False
```

### Step 6: Re-enable EDR tamper protection (if disabled)

If tamper protection was disabled for install (for example, Sophos), re-enable
it via the EDR console now.

---

## References

- Phase 57 context:
  `.planning/phases/57-operational-deployment-guide-av-edr-allowlist-uat/57-CONTEXT.md`
- DPAPI recovery runbook: `docs/operations/dpapi-recovery.md`
- RELEASE_NOTES.md (hashes and certificate thumbprint)
- Plan 57-04 (Secure Boot, PPL, DACL tripwire, privilege, reboot documentation)
- Service name: `dlp-agent`
- Install path: `C:\Program Files\DLP\`
- ProgramData path: `C:\ProgramData\DLP\`
