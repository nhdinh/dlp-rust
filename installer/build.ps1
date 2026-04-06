#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Builds the DLP Agent MSI installer.

.DESCRIPTION
    This script:
      1. Builds the Rust release binaries (dlp-agent + dlp-user-ui)
      2. Compiles and links the MSI package via `wix build` (WiX v4+)
      3. Validates the output MSI

.PARAMETER Configuration
    Rust build profile. Default: release.

.PARAMETER Toolchain
    Rust toolchain to use. Default: stable.

.PARAMETER SkipRustBuild
    Skip the Rust cargo build step (use when binaries are already built).

.PARAMETER SkipValidation
    Skip MSI validation step.

.EXAMPLE
    # Full build (requires WiX and Rust installed):
    .\build.ps1

.EXAMPLE
    # Skip Rust build (binaries already present):
    .\build.ps1 -SkipRustBuild

.EXAMPLE
    # Debug build:
    .\build.ps1 -Configuration debug
#>

param(
    [ValidateSet('debug', 'release')]
    [string] $Configuration = 'release',

    [string] $Toolchain = 'stable',

    [switch] $SkipRustBuild,

    [switch] $SkipValidation
)

$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# -- Resolve script directory ------------------------------------------------
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir          # installer/  -> repo root
$InstallerDir = $ScriptDir                          # .../installer/
$DistDir   = Join-Path $InstallerDir 'dist'
$WxsFile   = Join-Path $InstallerDir 'DLPAgent.wxs'

# Resolve the release binaries relative to the repo root.
$AgentExe    = Join-Path $RepoRoot "target\$Configuration\dlp-agent.exe"
$UiExe       = Join-Path $RepoRoot "target\$Configuration\dlp-user-ui.exe"
$AdminExe    = Join-Path $RepoRoot "target\$Configuration\dlp-admin-cli.exe"
$MsiOut   = Join-Path $DistDir 'DLPAgent.msi'

# -- Helper: find tool on PATH ----------------------------------------------
function Find-Tool {
    param([string]$Name, [string]$ToolFile)
    $tool = Get-Command $ToolFile -ErrorAction SilentlyContinue
    if (-not $tool) {
        Write-Error @"
$Name not found on PATH.
Install WiX v4+ via:
    dotnet tool install --global wix

Then add required extensions:
    wix extension add WixToolset.Util.wixext
    wix extension add WixToolset.UI.wixext
"@
    }
    Write-Host "[OK] Found $Name at: $($tool.Source)" -ForegroundColor Green
    return $tool.Source
}

# -- Helper: run a command ---------------------------------------------------
function Invoke-BuildStep {
    param(
        [string]$Description,
        [string]$Command,
        [string[]]$ArgList
    )
    Write-Host ""
    Write-Host "  $Description" -ForegroundColor Cyan
    Write-Host "    > $Command $($ArgList -join ' ')"
    $start = Get-Date

    # Use Process object with async stream reads to avoid the classic
    # deadlock caused by Start-Process -RedirectStandardOutput/-Error
    # when cargo (or any verbose tool) fills the pipe buffer.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $Command
    $psi.Arguments              = $ArgList -join ' '
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true
    $psi.WorkingDirectory       = $RepoRoot

    $proc = [System.Diagnostics.Process]::Start($psi)

    # Read stdout/stderr asynchronously so the buffers never fill up.
    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()
    $proc.WaitForExit()

    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    $elapsed = (Get-Date) - $start

    # Stream stderr to the console (cargo progress goes to stderr).
    if ($stderr) {
        $stderr -split "`n" | ForEach-Object {
            $line = $_.TrimEnd()
            if ($line) { Write-Host "    $_" -ForegroundColor DarkGray }
        }
    }

    if ($proc.ExitCode -ne 0) {
        Write-Host "  FAILED (exit $($proc.ExitCode)) after $($elapsed.TotalSeconds)s" -ForegroundColor Red
        if ($stderr) {
            Write-Host "  STDERR (last 20 lines):" -ForegroundColor Red
            $stderr -split "`n" | Select-Object -Last 20 | ForEach-Object {
                Write-Host "    $_" -ForegroundColor Red
            }
        }
        throw "Build step failed: $Description"
    }
    Write-Host "  OK -- $($elapsed.TotalSeconds)s" -ForegroundColor Green
}

# -- 0. Bootstrap: create dist directory ------------------------------------
Write-Host ""
Write-Host "======================================================" -ForegroundColor Magenta
Write-Host "  DLP Agent MSI Build" -ForegroundColor Magenta
Write-Host "======================================================" -ForegroundColor Magenta

if (-not (Test-Path $DistDir)) {
    New-Item -ItemType Directory -Path $DistDir | Out-Null
    Write-Host "[OK] Created output directory: $DistDir"
}

# -- 1. Build Rust binaries -------------------------------------------------
if (-not $SkipRustBuild) {
    Write-Host ""
    Write-Host "----------------------------------------------------" -ForegroundColor Magenta
    Write-Host "  Step 1: Build Rust binaries" -ForegroundColor Magenta

    # Check Rust is installed.
    $rust = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $rust) {
        Write-Error "Rust (cargo) not found on PATH. Install from https://rustup.rs/"
    }

    # The `windows` crate with many features causes rustc to exceed its
    # default 8 MB stack in release mode (STATUS_STACK_BUFFER_OVERRUN).
    # Increase to 16 MB.
    $env:RUST_MIN_STACK = '16777216'
    Write-Host "  RUST_MIN_STACK=$env:RUST_MIN_STACK (16 MB — prevents rustc stack overflow)"

    # Build both crates.  dlp-user-ui must be built alongside dlp-agent
    # so both .exe files land in the same target directory.
    Invoke-BuildStep `
        -Description "cargo build --$Configuration -p dlp-agent -p dlp-user-ui -p dlp-admin-cli" `
        -Command cargo `
        -ArgList @('build', "--$Configuration", '-p', 'dlp-agent', '-p', 'dlp-user-ui', '-p', 'dlp-admin-cli')

    # Validate binaries exist.
    if (-not (Test-Path $AgentExe)) {
        Write-Error "Agent binary not found at: $AgentExe"
    }
    if (-not (Test-Path $UiExe)) {
        Write-Error "UI binary not found at: $UiExe"
    }
    if (-not (Test-Path $AdminExe)) {
        Write-Error "dlp-admin-cli binary not found at: $AdminExe"
    }
    $agentSize = (Get-Item $AgentExe).Length / 1MB
    $uiSize    = (Get-Item $UiExe).Length    / 1MB
    $adminSize = (Get-Item $AdminExe).Length  / 1MB
    Write-Host "  dlp-agent.exe   : $('{0:N1}' -f $agentSize) MB"
    Write-Host "  dlp-user-ui.exe : $('{0:N1}' -f $uiSize) MB"
    Write-Host "  dlp-admin-cli.exe : $('{0:N1}' -f $adminSize) MB"
} else {
    Write-Host ""
    Write-Host "[SKIP] Rust build step skipped (using existing binaries)" -ForegroundColor Yellow
}

# -- 2. Locate WiX toolset --------------------------------------------------
Write-Host ""
Write-Host "----------------------------------------------------" -ForegroundColor Magenta
Write-Host "  Step 2: Locate WiX toolset" -ForegroundColor Magenta

$wixTool = Find-Tool -Name 'WiX CLI (wix.exe)' -ToolFile 'wix'

# -- 3. Build MSI package (compile + link in one step) ---------------------
Write-Host ""
Write-Host "----------------------------------------------------" -ForegroundColor Magenta
Write-Host "  Step 3: Build MSI package (wix build)" -ForegroundColor Magenta

# Pre-build validation of .wxs file.
if (-not (Test-Path $WxsFile)) {
    Write-Error "WiX source not found: $WxsFile"
}

# wix build:
#   -ext WixToolset.Util.wixext  -- util:PermissionEx
#   -ext WixToolset.UI.wixext    -- WixUI_InstallDir
#   -d SourceDir=<path>          -- preprocessor variable for binary paths
#   -o <output>                  -- output MSI path
Invoke-BuildStep `
    -Description "wix build DLPAgent.wxs -> DLPAgent.msi" `
    -Command $wixTool `
    -ArgList @(
        'build',
        '-ext', 'WixToolset.Util.wixext',
        '-ext', 'WixToolset.UI.wixext',
        "-d", "SourceDir=$RepoRoot",
        '-o', $MsiOut,
        $WxsFile
    )

if (-not (Test-Path $MsiOut)) {
    Write-Error "wix build produced no output at: $MsiOut"
}

# -- 4. Validation --------------------------------------------------------
if (-not $SkipValidation) {
    Write-Host ""
    Write-Host "----------------------------------------------------" -ForegroundColor Magenta
    Write-Host "  Step 4: Validate MSI" -ForegroundColor Magenta

    $msiSize = (Get-Item $MsiOut).Length / 1MB
    Write-Host "  MSI size: $('{0:N1}' -f $msiSize) MB"
    Write-Host "  MSI path: $MsiOut"

    # Basic validation: try to open the MSI and enumerate components.
    # Use msiinfo (from WiX or Windows SDK) if available.
    $msiinfo = Get-Command 'msiinfo' -ErrorAction SilentlyContinue
    if ($msiinfo) {
        Write-Host "  Running: msiinfo tables $MsiOut ..."
        $tablesOut = & $msiinfo.FullName tables $MsiOut 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] MSI opens cleanly -- table enumeration succeeded" -ForegroundColor Green
        } else {
            Write-Warning "MSI table enumeration returned non-zero exit code."
        }
    } else {
        Write-Host "  [SKIP] msiinfo not on PATH -- skipping table validation" -ForegroundColor Yellow
        Write-Host "  To validate manually, open the MSI in Orca (Windows SDK) or run:" -ForegroundColor Yellow
        Write-Host "    msiexec /a `"$MsiOut`"" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "  To install on a test machine:" -ForegroundColor Cyan
    Write-Host "    msiexec /i `"$MsiOut`" /qn" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  To uninstall:" -ForegroundColor Cyan
    Write-Host "    msiexec /x `"$MsiOut`" /qn" -ForegroundColor Cyan
    Write-Host "  Or:" -ForegroundColor Cyan
    Write-Host "    sc delete dlp-agent" -ForegroundColor Cyan
} else {
    Write-Host ""
    Write-Host "[SKIP] Validation step skipped" -ForegroundColor Yellow
}

# -- Summary ---------------------------------------------------------------
Write-Host ""
Write-Host "======================================================" -ForegroundColor Magenta
Write-Host "  Build complete" -ForegroundColor Green
Write-Host ""
Write-Host "  Output: $MsiOut" -ForegroundColor Cyan
Write-Host ""
