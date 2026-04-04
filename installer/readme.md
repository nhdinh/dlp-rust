# DLP Agent MSI Installer

Builds a production-grade MSI installer for the DLP Agent Windows Service using
[WiX v3](https://wixtoolset.org/).

## Prerequisites

### 1. Rust toolchain

Install from [rustup.rs](https://rustup.rs/):

```powershell
rustup install stable
rustup default stable
```

### 2. WiX v3 toolset

Download from <https://wixtoolset.org/releases/> — install **WiX v3.14.0** or later
(the `.msi` installer is recommended for system-wide install).

Or install via dotnet tool:

```powershell
dotnet tool install --global wix --version 3.14.0
# After install, add to PATH:
$env:PATH += ";$env:LOCALAPPDATA\.dotnet\tools"
```

Verify the tools are on PATH:

```cmd
candle.exe --version
light.exe --version
```

## Build

From the `installer/` directory:

```powershell
# Full build (release binaries + MSI):
.\build.ps1

# Use pre-built binaries (skip cargo build):
.\build.ps1 -SkipRustBuild

# Debug build:
.\build.ps1 -Configuration debug
```

The MSI is written to:

```
installer/dist/DLPAgent.msi
```

## What the MSI installs

| Path | Contents |
|------|---------|
| `C:\Program Files\DLP\` | `dlp-agent.exe` + `dlp-user-ui.exe` |
| `C:\Program Files\DLP\config\` | Agent configuration (`agent-config.toml`) |
| `C:\Program Files\DLP\logs\` | Append-only audit event log |

The service is registered as `dlp-agent` (SCM) and starts automatically at boot.

## Install

On a target machine, run:

```cmd
msiexec /i DLPAgent.msi
```

Or silently:

```cmd
msiexec /i DLPAgent.msi /qn
```

The service starts automatically after installation. Verify:

```cmd
sc query dlp-agent
```

Expected state: `STATE              : 4  RUNNING`.

## Uninstall

```cmd
msiexec /x DLPAgent.msi /qn
```

Or via SCM:

```cmd
sc stop dlp-agent
sc delete dlp-agent
```

## Directory ACLs

| Directory | ACL |
|-----------|-----|
| `C:\Program Files\DLP\` | `SYSTEM` + `Administrators`: Full; `Everyone`: Read |
| `C:\Program Files\DLP\config\` | `SYSTEM`: Full; `Administrators`: Full |
| `C:\Program Files\DLP\logs\` | `SYSTEM` + `Administrators`: Append + Read; no Delete for non-admin |

## Crash Recovery

The MSI configures SCM failure actions for `dlp-agent`:

1. First failure → restart after 60 s
2. Second failure → restart after 60 s
3. Third failure → restart after 60 s
4. Subsequent failures → log `EVENT_DLP_ADMIN_STOP_FAILED` and leave service stopped

## Build on CI

Example GitHub Actions step:

```yaml
- name: Build MSI
  shell: pwsh
  run: |
    dotnet tool install --global wix --version 3.14.0
    & "$env:LOCALAPPDATA\.dotnet\tools\candle.exe" -nologo -dSourceDir='${{ github.workspace }}' -out installer/dist installer/DLPAgent.wxs
    & "$env:LOCALAPPDATA\.dotnet\tools\light.exe" -nologo -ext WixIIsExtension -o installer/dist/DLPAgent.msi installer/dist/DLPAgent.wixobj
    ls installer/dist/DLPAgent.msi
```

> **Note:** The `dlp-user-ui.exe` binary must already exist at
> `target/release/dlp-user-ui.exe` before the WiX step runs. Build it with
> `cargo build --release -p dlp-user-ui` first, or chain it in the CI pipeline.

## Known Limitations

- The MSI does **not** bundle a default `agent-config.toml`. Create it manually
  post-install at `C:\Program Files\DLP\config\agent-config.toml`.
- The MSI does **not** register the Policy Engine. Deploy the engine separately.
- Code-signing the MSI and its payloads is **not** automated here. Sign the
  `.exe` files with `signtool` before the WiX step if your environment requires
  it (required for production deployment — see `docs/SECURITY_AUDIT.md`).
