#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Real-hardware USB write-protection verification for DLP UAT.

.DESCRIPTION
    Auto-detects removable USB drives via WMI, presents an interactive
    selection menu, registers the chosen device through the dlp-server
    admin API, and verifies blocked and read_only trust-tier behaviour
    at the kernel level.

    The script cleans up the registry entry and disk attributes after
    testing so the drive returns to its original state.

    Requires elevation because IOCTL_DISK_SET_DISK_ATTRIBUTES needs
    administrator privileges.

.EXAMPLE
    .\Uat-UsbBlock.ps1

    Runs the full test suite (blocked + read_only) against a
    user-selected removable USB drive.

.EXAMPLE
    .\Uat-UsbBlock.ps1 -SkipBlockedTest

    Skips the blocked-tier test and only verifies read_only behaviour.

.EXAMPLE
    .\Uat-UsbBlock.ps1 -ServerUrl "http://192.168.1.10:9090" -JwtToken "eyJhbG..."

    Targets a remote dlp-server instance with an explicit JWT token.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ServerUrl = "http://127.0.0.1:9090",

    [Parameter()]
    [string]$JwtToken = $env:DLP_ADMIN_JWT,

    [Parameter()]
    [switch]$SkipBlockedTest,

    [Parameter()]
    [switch]$SkipReadOnlyTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ─── Constants ───────────────────────────────────────────────────────────────

$SCRIPT:IOCTL_DISK_SET_DISK_ATTRIBUTES = 0x7C104
$SCRIPT:DISK_ATTRIBUTE_READ_ONLY        = 0x00000001

# ─── Helpers ─────────────────────────────────────────────────────────────────

function Write-Result {
    <#
    .SYNOPSIS
        Emits a colour-coded result line.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'FAIL', 'INFO', 'WARN')]
        [string]$Level
    )
    switch ($Level) {
        'PASS' { Write-Host "  PASS: $Message" -ForegroundColor Green }
        'FAIL' { Write-Host "  FAIL: $Message" -ForegroundColor Red }
        'INFO' { Write-Host "  INFO: $Message" -ForegroundColor Cyan }
        'WARN' { Write-Host "  WARN: $Message" -ForegroundColor Yellow }
    }
}

function Get-RemovableUsbDrives {
    <#
    .SYNOPSIS
        Queries WMI for removable USB disk drives and resolves drive letters.

    .DESCRIPTION
        Uses Win32_DiskDrive filtered by MediaType or InterfaceType, then
        joins through Win32_DiskDriveToDiskPartition and
        Win32_LogicalDiskToPartition to obtain the mounted drive letter.

    .OUTPUTS
        Array of PSCustomObject with properties:
        Index, DeviceID, Model, Size, DriveLetter, SerialNumber, PNPDeviceID
    #>
    $diskDrives = Get-WmiObject -Class Win32_DiskDrive |
        Where-Object {
            $_.MediaType -eq 'Removable media' -or
            $_.InterfaceType -eq 'USB'
        }

    $results = @()
    foreach ($disk in $diskDrives) {
        $partitions = Get-WmiObject -Query `
            "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='$($disk.DeviceID)'} " +
            "WHERE AssocClass = Win32_DiskDriveToDiskPartition"

        $driveLetter = $null
        foreach ($part in $partitions) {
            $logicalDisks = Get-WmiObject -Query `
                "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($part.DeviceID)'} " +
                "WHERE AssocClass = Win32_LogicalDiskToPartition"
            foreach ($ld in $logicalDisks) {
                $driveLetter = $ld.DeviceID  # e.g. "E:"
            }
        }

        $sizeGB = if ($disk.Size) {
            [math]::Round($disk.Size / 1GB, 1)
        } else {
            0
        }

        $serial = if ($disk.SerialNumber) {
            $disk.SerialNumber.Trim()
        } else {
            'UNKNOWN'
        }

        $results += [PSCustomObject]@{
            Index       = $disk.Index
            DeviceID    = $disk.DeviceID
            Model       = $disk.Model
            SizeGB      = $sizeGB
            DriveLetter = $driveLetter
            SerialNumber = $serial
            PNPDeviceID = $disk.PNPDeviceID
        }
    }
    return $results
}

function Show-DriveMenu {
    <#
    .SYNOPSIS
        Displays a numbered menu of removable drives and returns the selection.

    .PARAMETER Drives
        Array of drive objects from Get-RemovableUsbDrives.

    .OUTPUTS
        The selected drive PSCustomObject.
    #>
    param([array]$Drives)

    Write-Host "`nDetected removable USB drives:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $Drives.Count; $i++) {
        $d = $Drives[$i]
        $letter = if ($d.DriveLetter) { "$($d.DriveLetter)" } else { "(no letter)" }
        Write-Host "  $($i + 1): Drive $letter - $($d.Model) ($($d.SizeGB) GB)" -ForegroundColor Cyan
    }

    while ($true) {
        $choice = Read-Host "`nSelect drive number"
        if ($choice -match '^\d+$') {
            $idx = [int]$choice - 1
            if ($idx -ge 0 -and $idx -lt $Drives.Count) {
                return $Drives[$idx]
            }
        }
        Write-Host "Invalid selection. Enter a number between 1 and $($Drives.Count)." -ForegroundColor Red
    }
}

function Register-Device {
    <#
    .SYNOPSIS
        Registers (upserts) a USB device via the admin API.

    .PARAMETER Drive
        Drive object containing vid/pid/serial/description.

    .PARAMETER Tier
        Trust tier: blocked, read_only, or full_access.

    .OUTPUTS
        The server response object (contains .id field).
    #>
    param(
        [Parameter(Mandatory = $true)]
        $Drive,

        [Parameter(Mandatory = $true)]
        [string]$Tier
    )

    $body = @{
        vid          = $Drive.VID
        pid          = $Drive.PID
        serial       = $Drive.SerialNumber
        description  = $Drive.Model
        trust_tier   = $Tier
    } | ConvertTo-Json

    $headers = @{
        Authorization = "Bearer $JwtToken"
    }

    $response = Invoke-RestMethod `
        -Uri "$ServerUrl/admin/device-registry" `
        -Method POST `
        -Headers $headers `
        -ContentType 'application/json' `
        -Body $body

    return $response
}

function Remove-Device {
    <#
    .SYNOPSIS
        Removes a device registry entry by its server-generated UUID.

    .PARAMETER Id
        The device id returned by Register-Device.
    #>
    param([Parameter(Mandatory = $true)][string]$Id)

    $headers = @{
        Authorization = "Bearer $JwtToken"
    }

    Invoke-RestMethod `
        -Uri "$ServerUrl/admin/device-registry/$Id" `
        -Method DELETE `
        -Headers $headers | Out-Null
}

function Test-WriteBlocked {
    <#
    .SYNOPSIS
        Attempts to write a temporary file and checks for ERROR_WRITE_PROTECT.

    .PARAMETER DriveLetter
        Drive letter with colon, e.g. "E:".

    .OUTPUTS
        $true if write was blocked (ERROR_WRITE_PROTECT), $false otherwise.
    #>
    param([Parameter(Mandatory = $true)][string]$DriveLetter)

    $testPath = "$DriveLetter\UatTestWrite.tmp"
    try {
        [System.IO.File]::WriteAllText($testPath, "DLP UAT write test")
        # If we get here, the write succeeded — cleanup and report failure.
        if (Test-Path -LiteralPath $testPath) {
            Remove-Item -LiteralPath $testPath -Force -ErrorAction SilentlyContinue
        }
        return $false
    }
    catch {
        $ex = $_.Exception
        # HResult 0x80070013 = ERROR_WRITE_PROTECT (19)
        # Also check message for "write-protect" or "media is write protected"
        $isWriteProtect = (
            ($ex.HResult -eq -2147024877) -or          # 0x80070013
            ($ex.Message -match 'write-protect') -or
            ($ex.Message -match 'media is write protected')
        )
        # Clean up in case a partial file was created.
        if (Test-Path -LiteralPath $testPath) {
            Remove-Item -LiteralPath $testPath -Force -ErrorAction SilentlyContinue
        }
        return $isWriteProtect
    }
}

function Test-ReadAllowed {
    <#
    .SYNOPSIS
        Verifies that reading (listing directory contents) succeeds.

    .PARAMETER DriveLetter
        Drive letter with colon, e.g. "E:".

    .OUTPUTS
        Number of items listed, or -1 on failure.
    #>
    param([Parameter(Mandatory = $true)][string]$DriveLetter)

    try {
        $items = Get-ChildItem -Path "$DriveLetter\" -ErrorAction Stop
        return $items.Count
    }
    catch {
        return -1
    }
}

function Clear-DiskReadOnly {
    <#
    .SYNOPSIS
        Clears the read-only disk attribute via IOCTL_DISK_SET_DISK_ATTRIBUTES.

    .DESCRIPTION
        Uses inline C# P/Invoke to call CreateFileW and DeviceIoControl on
        the physical drive.  This is required because PowerShell has no
        native cmdlet for manipulating disk attributes at the kernel level.

    .PARAMETER DriveIndex
        The Win32_DiskDrive Index value (0-based).

    .OUTPUTS
        $true on success, $false on failure.
    #>
    param([Parameter(Mandatory = $true)][int]$DriveIndex)

    $csharp = @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public class DiskAttr {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(
        IntPtr hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [StructLayout(LayoutKind.Sequential)]
    public struct SET_DISK_ATTRIBUTES {
        public uint Version;
        public uint Persist;
        public ulong AttributesMask;
        public ulong Attributes;
        public uint Alignment;
    }

    public const uint GENERIC_READ  = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint FILE_SHARE_READ  = 0x00000001;
    public const uint FILE_SHARE_WRITE = 0x00000002;
    public const uint OPEN_EXISTING = 3;
    public const uint IOCTL_DISK_SET_DISK_ATTRIBUTES = 0x7C104;
    public const ulong DISK_ATTRIBUTE_READ_ONLY = 0x00000001;

    public static bool ClearReadOnly(int driveIndex) {
        string path = @"\\.\PhysicalDrive" + driveIndex;
        IntPtr hDevice = CreateFileW(
            path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            0,
            IntPtr.Zero);

        if (hDevice == new IntPtr(-1)) {
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                "CreateFileW failed on " + path);
        }

        try {
            SET_DISK_ATTRIBUTES attrs = new SET_DISK_ATTRIBUTES();
            attrs.Version = (uint)Marshal.SizeOf(typeof(SET_DISK_ATTRIBUTES));
            attrs.Persist = 0;
            attrs.AttributesMask = DISK_ATTRIBUTE_READ_ONLY;
            attrs.Attributes = 0;

            int size = Marshal.SizeOf(attrs);
            IntPtr pBuffer = Marshal.AllocHGlobal(size);
            try {
                Marshal.StructureToPtr(attrs, pBuffer, false);
                uint bytesReturned;
                bool ok = DeviceIoControl(
                    hDevice,
                    IOCTL_DISK_SET_DISK_ATTRIBUTES,
                    pBuffer,
                    (uint)size,
                    IntPtr.Zero,
                    0,
                    out bytesReturned,
                    IntPtr.Zero);

                if (!ok) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "DeviceIoControl failed");
                }
                return true;
            }
            finally {
                Marshal.FreeHGlobal(pBuffer);
            }
        }
        finally {
            CloseHandle(hDevice);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);
}
"@

    try {
        Add-Type -TypeDefinition $csharp -Language CSharp -ErrorAction SilentlyContinue
    }
    catch {
        # Type may already be loaded from a previous run — safe to ignore.
    }

    try {
        return [DiskAttr]::ClearReadOnly($DriveIndex)
    }
    catch {
        Write-Result "ClearReadOnly error: $($_.Exception.Message)" 'WARN'
        return $false
    }
}

# ─── Main ────────────────────────────────────────────────────────────────────

Write-Host "=== DLP USB Write-Protection UAT ===" -ForegroundColor Cyan

# Validate JWT
if (-not $JwtToken) {
    Write-Error "DLP_ADMIN_JWT environment variable or -JwtToken parameter is required."
    exit 1
}

# Detect drives
$drives = Get-RemovableUsbDrives
if ($drives.Count -eq 0) {
    Write-Error "No removable USB drives detected. Insert a USB mass-storage device and try again."
    exit 1
}

# Select drive
$selected = Show-DriveMenu $drives
$driveLetter = $selected.DriveLetter
$driveIndex  = $selected.Index

if (-not $driveLetter) {
    Write-Error "Selected drive has no mounted drive letter. Ensure the drive is formatted and has a volume."
    exit 1
}

# Extract VID/PID from PNPDeviceID if available
$vid = '0000'
$pid = '0000'
if ($selected.PNPDeviceID -match 'VID_([0-9A-F]{4})&PID_([0-9A-F]{4})') {
    $vid = $Matches[1]
    $pid = $Matches[2]
}

# Attach VID/PID to the drive object for Register-Device
$selected | Add-Member -NotePropertyName VID -NotePropertyValue $vid -Force
$selected | Add-Member -NotePropertyName PID -NotePropertyValue $pid -Force

Write-Host "`nSelected: Drive $driveLetter - $($selected.Model)" -ForegroundColor Cyan
Write-Host "VID: $vid | PID: $pid | Serial: $($selected.SerialNumber)" -ForegroundColor Cyan

$passCount = 0
$failCount = 0
$registeredIds = @()

try {

    # ── Blocked tier test ────────────────────────────────────────────────────
    if (-not $SkipBlockedTest) {
        Write-Host "`n[Test] Blocked tier..." -ForegroundColor Yellow

        try {
            $device = Register-Device $selected 'blocked'
            $registeredIds += $device.id
            Write-Result "Device registered (id=$($device.id))" 'INFO'
        }
        catch {
            Write-Result "Registration failed: $($_.Exception.Message)" 'FAIL'
            $failCount++
            # Skip the rest of this test block
            $device = $null
        }

        if ($device) {
            Start-Sleep -Seconds 2  # Allow agent to poll

            $writeBlocked = Test-WriteBlocked $driveLetter
            if ($writeBlocked) {
                Write-Result "Write blocked (ERROR_WRITE_PROTECT)" 'PASS'
                $passCount++
            }
            else {
                Write-Result "Write was NOT blocked" 'FAIL'
                $failCount++
            }

            try {
                Remove-Device $device.id
                Write-Result "Registry entry removed" 'INFO'
                $registeredIds = $registeredIds | Where-Object { $_ -ne $device.id }
            }
            catch {
                Write-Result "Cleanup (remove device) failed: $($_.Exception.Message)" 'WARN'
            }
        }
    }

    # ── ReadOnly tier test ───────────────────────────────────────────────────
    if (-not $SkipReadOnlyTest) {
        Write-Host "`n[Test] ReadOnly tier..." -ForegroundColor Yellow

        try {
            $device = Register-Device $selected 'read_only'
            $registeredIds += $device.id
            Write-Result "Device registered (id=$($device.id))" 'INFO'
        }
        catch {
            Write-Result "Registration failed: $($_.Exception.Message)" 'FAIL'
            $failCount++
            $device = $null
        }

        if ($device) {
            Start-Sleep -Seconds 2  # Allow agent to poll

            # Verify read is allowed
            $itemCount = Test-ReadAllowed $driveLetter
            if ($itemCount -ge 0) {
                Write-Result "Read allowed ($itemCount items listed)" 'PASS'
                $passCount++
            }
            else {
                Write-Result "Read was blocked" 'FAIL'
                $failCount++
            }

            # Verify write is blocked
            $writeBlocked = Test-WriteBlocked $driveLetter
            if ($writeBlocked) {
                Write-Result "Write blocked on read-only device" 'PASS'
                $passCount++
            }
            else {
                Write-Result "Write was NOT blocked on read-only device" 'FAIL'
                $failCount++
            }

            try {
                Remove-Device $device.id
                Write-Result "Registry entry removed" 'INFO'
                $registeredIds = $registeredIds | Where-Object { $_ -ne $device.id }
            }
            catch {
                Write-Result "Cleanup (remove device) failed: $($_.Exception.Message)" 'WARN'
            }
        }
    }

}
finally {
    # ── Cleanup ──────────────────────────────────────────────────────────────
    Write-Host "`n[Cleanup] Clearing disk read-only attributes..." -ForegroundColor Yellow

    # Remove any remaining registry entries
    foreach ($id in $registeredIds) {
        try {
            Remove-Device $id
            Write-Result "Removed leftover registry entry $id" 'INFO'
        }
        catch {
            Write-Result "Failed to remove leftover entry $id`: $($_.Exception.Message)" 'WARN'
        }
    }

    $cleared = Clear-DiskReadOnly $driveIndex
    if ($cleared) {
        Write-Result "Disk attributes cleared" 'PASS'
    }
    else {
        Write-Result "Failed to clear disk attributes (run 'diskpart' manually: 'attributes disk clear readonly')" 'WARN'
    }
}

# ── Summary ──────────────────────────────────────────────────────────────────
Write-Host "`n=== Results ===" -ForegroundColor Cyan
Write-Result "Total PASS: $passCount" 'PASS'
Write-Result "Total FAIL: $failCount" 'FAIL'

if ($failCount -gt 0) {
    exit 1
}
exit 0
