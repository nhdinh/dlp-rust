<!-- generated-by: gsd-doc-writer -->

# Getting Started — DLP-RUST

## Prerequisites

| Requirement | Version / Notes |
|-------------|-----------------|
| Rust toolchain | 1.75+ (edition 2021) — install via [rustup.rs](https://rustup.rs/) |
| MSVC toolchain | Required by `cargo build` on Windows — install via `rustup default stable-msvc` |
| OS | Windows 10/11 Enterprise or Windows Server 2019+ |
| Administrator rights | Required for Windows Service installation and most agent operations |
| WiX v3.14.0+ | Required only for MSI installer builds (`installer/readme.md`) |

## Installation

### 1. Clone the repository

```powershell
git clone https://github.com/nhdinh/dlp-rust.git
cd dlp-rust
```

### 2. Build from source

```powershell
cargo build --release
```

Builds all 5 workspace crates: `dlp-common`, `dlp-server`, `dlp-agent`, `dlp-user-ui`, `dlp-admin-cli`.

### 3. Set environment variables

```powershell
# Required in production — server refuses to start without it
$env:JWT_SECRET = "your-secret-here"

# Optional — defaults to C:\ProgramData\DLP
$env:DLP_DATA_PATH = "C:\ProgramData\DLP"

# Optional — defaults to http://127.0.0.1:8080
$env:DLP_SERVER_URL = "http://127.0.0.1:8080"
```

For development only, start the server with `--dev` to bypass the `JWT_SECRET` check (prints a warning):

```powershell
cd dlp-server
cargo run --release -- --dev
```

### 4. Start the components

```powershell
# Requires Administrator privileges
.\scripts\Manage-DlpComponents.ps1 -Action Start -Component Both
```

This starts `dlp-server` as a foreground process, waits for it to be ready, then installs and starts `dlp-agent` as a Windows Service.

**Component startup order (always):** server first, then agent. The agent requires the server to be reachable at `DLP_SERVER_URL` to register.

### 5. Connect with the admin CLI

```powershell
cd dlp-admin-cli
cargo run --release
```

Log in with the initial dlp-admin credentials set during first-run setup.

## First Run Checklist

- [ ] `cargo build --release` completes with no errors
- [ ] `JWT_SECRET` environment variable is set (production) or `--dev` flag used (development)
- [ ] `dlp-server` is running and listening on the configured port
- [ ] `dlp-agent` Windows Service is registered and running (`Get-Service DlpAgent`)
- [ ] `dlp-admin-cli` can connect to the server and authenticate

## Common Setup Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| Server refuses to start ("JWT_SECRET not set") | Production mode requires the env var | Set `JWT_SECRET` env var, or use `--dev` flag in development |
| Agent fails to register ("connection refused") | Server not yet running | Start server before agent: `Manage-DlpComponents.ps1 -Action Start -Component Both` |
| "Access is denied" when starting agent service | Not running as Administrator | Re-launch PowerShell as Administrator |
| MSI installer build fails | WiX v3 not installed | Install WiX v3.14.0+ from [wixtoolset.org](https://wixtoolset.org/releases/) |
| `cargo build` slow on first run | Fresh Rust compile | Normal — subsequent incremental builds are fast |

## Next Steps

- **DEVELOPMENT.md** — local build commands, code style, branch conventions
- **TESTING.md** — running and writing tests
- **CONFIGURATION.md** — full environment variable and config file reference
- **docs/OPERATIONAL.md** — production runbook, service management, log locations
- **docs/ARCHITECTURE.md** — system design, AD/LDAP integration, IPC protocol
