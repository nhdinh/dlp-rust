#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Builds the DLP Agent MSI installer.

.DESCRIPTION
    This script:
      1. Builds the Rust release binaries (dlp-agent + dlp-user-ui)
      2. Compiles the WiX sources (candle.exe)
      3. Links the MSI package (light.exe)
      4. Validates the output MSI

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

# ── Resolve script directory ────────────────────────────────────────────────
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir          # dlp-agent/  → repo root
$InstallerDir = $ScriptDir                          # .../dlp-agent/installer/
$DistDir   = Join-Path $InstallerDir 'dist'
$WxsFile   = Join-Path $InstallerDir 'DLPAgent.wxs'

# Resolve the release binaries relative to the repo root.
$AgentExe = Join-Path $RepoRoot "target\$Configuration\dlp-agent.exe"
$UiExe    = Join-Path $RepoRoot "target\$Configuration\dlp-user-ui.exe"
$Wixobj   = Join-Path $DistDir 'DLPAgent.wixobj'
$CabFile  = Join-Path $DistDir 'DLP.cab'
$MsiOut   = Join-Path $DistDir 'DLPAgent.msi'

# ── Helper: find tool on PATH ──────────────────────────────────────────────
function Find-Tool {
    param([string]$Name, [string]$ToolFile)
    $tool = Get-Command $ToolFile -ErrorAction SilentlyContinue
    if (-not $tool) {
        Write-Error @"
$Name not found on PATH.
Please install WiX v3 (https://wixtoolset.org/releases/) or install via:
    dotnet tool install --global wix --version 3.14.0

After installation, ensure the tool directory is on your PATH:
    dotnet tool update --global wix --version 3.14.0
    # or add the WiX tool directory to PATH manually.
"@
    }
    Write-Host "[OK] Found $Name at: $($tool.Source)" -ForegroundColor Green
    return $tool.Source
}

# ── Helper: run a command ───────────────────────────────────────────────────
function Invoke-BuildStep {
    param(
        [string]$Description,
        [string]$Command,
        [string[]]$ArgList,
        [switch]$PassThru
    )
    Write-Host ""
    Write-Host "  $Description" -ForegroundColor Cyan
    Write-Host "    > $Command $($ArgList -join ' ')"
    $start = Get-Date
    $proc = Start-Process -FilePath $Command `
                          -ArgumentList $ArgList `
                          -NoNewWindow `
                          -Wait `
                          -PassThru:$PassThru `
                          -RedirectStandardOutput "$env:TEMP\dlp_msi_stdout.txt" `
                          -RedirectStandardError  "$env:TEMP\dlp_msi_stderr.txt"
    $elapsed = (Get-Date) - $start

    if ($proc.ExitCode -ne 0 -and -not $PassThru) {
        Write-Host "  FAILED (exit $($proc.ExitCode)) after $($elapsed.TotalSeconds)s" -ForegroundColor Red
        if (Test-Path "$env:TEMP\dlp_msi_stderr.txt") {
            Write-Host "  STDERR:" -ForegroundColor Red
            Get-Content "$env:TEMP\dlp_msi_stderr.txt" | Select-Object -First 20 | ForEach-Object {
                Write-Host "    $_" -ForegroundColor Red
            }
        }
        throw "Build step failed: $Description"
    }
    Write-Host "  OK — $($elapsed.TotalSeconds)s" -ForegroundColor Green
}

# ── 0. Bootstrap: create dist directory ────────────────────────────────────
Write-Host ""
Write-Host "══════════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host "  DLP Agent MSI Build" -ForegroundColor Magenta
Write-Host "══════════════════════════════════════════════════════" -ForegroundColor Magenta

if (-not (Test-Path $DistDir)) {
    New-Item -ItemType Directory -Path $DistDir | Out-Null
    Write-Host "[OK] Created output directory: $DistDir"
}

# ── 1. Build Rust binaries ─────────────────────────────────────────────────
if (-not $SkipRustBuild) {
    Write-Host ""
    Write-Host "────────────────────────────────────────────────────" -ForegroundColor Magenta
    Write-Host "  Step 1: Build Rust binaries" -ForegroundColor Magenta

    # Check Rust is installed.
    $rust = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $rust) {
        Write-Error "Rust (cargo) not found on PATH. Install from https://rustup.rs/"
    }

    # Build both crates.  dlp-user-ui must be built alongside dlp-agent
    # so both .exe files land in the same target directory.
    Invoke-BuildStep `
        -Description "cargo build --$Configuration -p dlp-agent -p dlp-user-ui" `
        -Command cargo `
        -ArgList @('build', "--$Configuration", '-p', 'dlp-agent', '-p', 'dlp-user-ui')

    # Validate binaries exist.
    if (-not (Test-Path $AgentExe)) {
        Write-Error "Agent binary not found at: $AgentExe"
    }
    if (-not (Test-Path $UiExe)) {
        Write-Error "UI binary not found at: $UiExe"
    }
    $agentSize = (Get-Item $AgentExe).Length / 1MB
    $uiSize    = (Get-Item $UiExe).Length    / 1MB
    Write-Host "  dlp-agent.exe   : $('{0:N1}' -f $agentSize) MB"
    Write-Host "  dlp-user-ui.exe : $('{0:N1}' -f $uiSize) MB"
} else {
    Write-Host ""
    Write-Host "[SKIP] Rust build step skipped (using existing binaries)" -ForegroundColor Yellow
}

# ── 2. Locate WiX tools ────────────────────────────────────────────────────
Write-Host ""
Write-Host "────────────────────────────────────────────────────" -ForegroundColor Magenta
Write-Host "  Step 2: Locate WiX tools" -ForegroundColor Magenta

$candle = Find-Tool -Name 'WiX compiler (candle.exe)'  -ToolFile 'candle.exe'
$light  = Find-Tool -Name 'WiX linker (light.exe)'       -ToolFile 'light.exe'

# ── 3. Compile WiX sources ────────────────────────────────────────────────
Write-Host ""
Write-Host "────────────────────────────────────────────────────" -ForegroundColor Magenta
Write-Host "  Step 3: Compile WiX sources" -ForegroundColor Magenta

# Pre-build validation of .wxs file.
if (-not (Test-Path $WxsFile)) {
    Write-Error "WiX source not found: $WxsFile"
}

# candle.exe compile:
#   -nologo         — suppress logo
#   -out <dir>      — output directory for .wixobj + .wixpdb
Invoke-BuildStep `
    -Description "WiX compile: candle.exe DLPAgent.wxs" `
    -Command $candle `
    -ArgList @(
        '-nologo',
        '-dSourceDir=' + $RepoRoot.Replace('\', '\\'),
        '-out', $DistDir,
        $WxsFile
    )

if (-not (Test-Path $Wixobj)) {
    Write-Error "WiX compile produced no .wixobj at: $Wixobj"
}

# ── 4. Link MSI package ────────────────────────────────────────────────────
Write-Host ""
Write-Host "────────────────────────────────────────────────────" -ForegroundColor Magenta
Write-Host "  Step 4: Link MSI package" -ForegroundColor Magenta

# light.exe link:
#   -nologo            — suppress logo
#   -ext WixIIsExtension — include IIS extension (ServiceInstall uses this)
#   -o <output>         — output MSI path
Invoke-BuildStep `
    -Description "WiX link: light.exe DLPAgent.wixobj → DLPAgent.msi" `
    -Command $light `
    -ArgList @(
        '-nologo',
        '-ext', 'WixIIsExtension',
        '-o', $MsiOut,
        $Wixobj
    )

if (-not (Test-Path $MsiOut)) {
    Write-Error "MSI link produced no output at: $MsiOut"
}

# ── 5. Validation ────────────────────────────────────────────────────────
if (-not $SkipValidation) {
    Write-Host ""
    Write-Host "────────────────────────────────────────────────────" -ForegroundColor Magenta
    Write-Host "  Step 5: Validate MSI" -ForegroundColor Magenta

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
            Write-Host "  [OK] MSI opens cleanly — table enumeration succeeded" -ForegroundColor Green
        } else {
            Write-Warning "MSI table enumeration returned non-zero exit code."
        }
    } else {
        Write-Host "  [SKIP] msiinfo not on PATH — skipping table validation" -ForegroundColor Yellow
        Write-Host "  To validate manually, open the MSI in Orca (Windows SDK) or run:" -ForegroundColor Yellow
        Write-Host "    msiexec /a `"$MsiOut`" -ForegroundColor Yellow
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

# ── Summary ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "══════════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host "  Build complete" -ForegroundColor Green
Write-Host ""
Write-Host "  Output: $MsiOut" -ForegroundColor Cyan
Write-Host ""
