# DLP USB Write-Protection Manual UAT

This document describes how to run the real-hardware USB write-protection
verification script (`Uat-UsbBlock.ps1`) to validate DLP agent USB enforcement
before release.

---

## Prerequisites

- Windows 10 or Windows 11 machine with **Administrator access**
- **Physical USB removable drive** (mass storage, any size)
- `dlp-server` running locally or accessible via network
- `dlp-agent` running and connected to the server
- Valid admin JWT token exported in the `DLP_ADMIN_JWT` environment variable

---

## Setup

1. Start the DLP server:

   ```powershell
   cargo run --bin dlp-server
   ```

2. Start the DLP agent (in a separate terminal):

   ```powershell
   cargo run --bin dlp-agent
   ```

3. Export the admin JWT token:

   ```powershell
   $env:DLP_ADMIN_JWT = "your-jwt-token-here"
   ```

   To obtain a token, log in via the admin CLI and copy the token from the
   login response, or generate one via the server's authentication endpoint.

---

## Execution

Open an **elevated PowerShell** session (right-click PowerShell, select
"Run as Administrator"), then:

```powershell
cd C:\Path\To\dlp-rust
.\scripts\Uat-UsbBlock.ps1
```

### Optional Parameters

| Parameter         | Description                                          | Default                |
|-------------------|------------------------------------------------------|------------------------|
| `-ServerUrl`      | Base URL of the dlp-server admin API                 | `http://127.0.0.1:9090`|
| `-JwtToken`       | Admin JWT token (overrides `DLP_ADMIN_JWT` env var)  | `$env:DLP_ADMIN_JWT`   |
| `-SkipBlockedTest`| Skip the `blocked` tier verification                 | `$false`               |
| `-SkipReadOnlyTest`| Skip the `read_only` tier verification              | `$false`               |

Example with a remote server:

```powershell
.\scripts\Uat-UsbBlock.ps1 -ServerUrl "http://192.168.1.10:9090" -JwtToken "eyJhbG..."
```

---

## What the Script Does

1. **Auto-detects removable USB drives** via WMI (`Win32_DiskDrive`)
2. **Presents a numbered menu** for you to select the target drive
3. **Registers the device as `blocked`** via the admin API and verifies that
   write attempts return `ERROR_WRITE_PROTECT`
4. **Changes the tier to `read_only`** (re-registering via upsert) and verifies
   that reads are allowed but writes are still denied
5. **Cleans up** the registry entry via `DELETE /admin/device-registry/{id}`
6. **Clears disk attributes** via `IOCTL_DISK_SET_DISK_ATTRIBUTES` to remove
   any lingering read-only flags
7. **Outputs a PASS/FAIL summary** with colour-coded results

---

## Interpreting Results

| Output Colour | Meaning                                          |
|---------------|--------------------------------------------------|
| Green PASS    | Expected behaviour observed                      |
| Red FAIL      | Unexpected behaviour — investigate before release|
| Yellow WARN   | Non-blocking issue (e.g., cleanup step failed)   |
| Cyan INFO     | Informational message (e.g., registration ID)    |

If any FAIL appears:

- Check `dlp-agent` logs for USB enforcement errors
- Verify the agent has polled the server recently (config poll interval)
- Confirm the device registry API returned the expected trust tier
- Ensure no other software is interfering with disk attributes

---

## Troubleshooting

### "No removable USB drives detected"

- Ensure the USB drive is fully inserted and recognised by Windows
- Check Disk Management (`diskmgmt.msc`) to confirm the drive appears
- Some card readers report as "Fixed hard disk" rather than "Removable media";
  use a true USB flash drive or external HDD

### "Write was NOT blocked"

- Verify `dlp-agent` is running and connected to `dlp-server`
- Check that the agent has polled the device registry since registration
  (wait 30 seconds or restart the agent to force an immediate poll)
- Inspect agent logs at `C:\ProgramData\DLP\logs\` for USB enforcement trace
- Confirm the selected drive's VID/PID/Serial match the registry entry

### "Failed to clear disk attributes"

- The script includes a `finally` block that always attempts cleanup, but
  if the process is killed or the P/Invoke call fails, the disk may remain
  read-only
- **Manual recovery:** open `diskpart` and run:

  ```cmd
  diskpart
  list disk
  select disk N        <-- replace N with your disk number
  attributes disk clear readonly
  exit
  ```

### "Registration failed: 401 Unauthorized"

- The JWT token is missing or expired
- Set `$env:DLP_ADMIN_JWT` to a valid token before running the script
- Or pass `-JwtToken` explicitly on the command line

### "Registration failed: 500 Internal Server Error"

- `dlp-server` may not be running or may not be reachable at `-ServerUrl`
- Check server logs for database or pool exhaustion errors

---

## Safety Note

This script modifies **disk-level attributes** via kernel IOCTLs. While it
attempts automatic cleanup in all exit paths (including Ctrl+C interruption
via the `finally` block), unexpected termination (e.g., power loss, process
kill) may leave the disk in a read-only state.

**Always verify the drive is writable after testing** by attempting to copy a
file to it. If writes fail, use the manual `diskpart` recovery procedure
above.

**Do not run this script on drives containing critical data.** Use a spare
USB stick or an empty external drive for UAT.

---

## Script Architecture

```
Uat-UsbBlock.ps1
|-- Get-RemovableUsbDrives()      WMI query + drive letter resolution
|-- Show-DriveMenu()              Interactive numbered selection
|-- Register-Device()             POST /admin/device-registry (upsert)
|-- Remove-Device()               DELETE /admin/device-registry/{id}
|-- Test-WriteBlocked()           File write + HResult 0x80070013 check
|-- Test-ReadAllowed()            Get-ChildItem directory listing
|-- Clear-DiskReadOnly()          C# P/Invoke: DeviceIoControl IOCTL
|-- Main                          Orchestrates tests + cleanup + summary
```

The script follows the same PowerShell conventions as
`Manage-DlpAgentService.ps1` and `Manage-DlpComponents.ps1` in the same
`scripts/` directory: strict mode, typed parameters, colour-coded status
output, and comprehensive error handling.
