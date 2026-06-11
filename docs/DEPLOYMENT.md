<!-- generated-by: gsd-doc-writer -->

# Deployment

This document describes how to deploy the Enterprise DLP System in production environments.

## Deployment targets

The DLP system is designed for Windows enterprise environments. Two primary deployment methods are supported:

| Target | Method | Config files |
|--------|--------|-------------|
| **dlp-agent (endpoint)** | MSI installer via WiX v4+ | `installer/DLPAgent.wxs`, `installer/build.ps1` |
| **dlp-server (central)** | Standalone binary + process manager | Built from source via `cargo build --release -p dlp-server` |
| **dlp-admin-cli** | Bundled in MSI or built from source | Same as agent (MSI) or `cargo build --release -p dlp-admin-cli` |

The project does not use Docker, container orchestration, or cloud-native platforms. All components are native Windows binaries.

### MSI installer (dlp-agent)

The MSI installer (`installer/build.ps1`) produces a single `DLPAgent.msi` that installs:

| Path | Contents |
|------|---------|
| `C:\Program Files\DLP\` | `dlp-agent.exe`, `dlp-user-ui.exe`, `dlp-admin-cli.exe`, `dlp_hook_dll.dll`, `dlp_hook_dll_x86.dll` |
| `C:\Program Files\DLP\config\` | Agent configuration directory (empty on install) |
| `C:\Program Files\DLP\logs\` | Append-only audit event log directory |

The service is registered as `dlp-agent` with the Windows Service Control Manager (SCM) and starts automatically at boot under the `LocalSystem` account.

### dlp-server deployment

`dlp-server` runs as a regular foreground process (not a Windows Service). Deploy it using:

- A Windows service wrapper (e.g., `nssm` or custom wrapper)
- A scheduled task that restarts on failure
- Manual execution for development/testing

## Build pipeline

### CI/CD pipeline (GitHub Actions)

Three workflows are defined in `.github/workflows/`:

**Build (`build.yml`)**

Triggered on push to `master` and pull requests.

1. SonarQube static analysis scan
2. Install Rust stable toolchain with `i686-pc-windows-msvc` target
3. Cache `~/.cargo/registry`, `~/.cargo/git`, and `target/`
4. Build workspace with `cargo build --workspace` (`RUSTFLAGS: "-D warnings"`)
5. Build x86 hook DLL: `cargo build --target i686-pc-windows-msvc -p dlp-hook-dll`
6. Run clippy: `cargo clippy --workspace -- -D warnings`
7. Check formatting: `cargo fmt --check`
8. Run tests: `cargo test --workspace`

**Nightly (`nightly.yml`)**

Scheduled daily at 02:00 UTC, also dispatchable manually.

1. Build workspace in release mode to `target-release/`
2. Run clippy on release build
3. Run workspace tests against release binaries
4. Smoke test: verify binaries exist
5. Smoke test: start `dlp-server.exe`, verify `/health` returns `{"status":"ok"}`

**Release (`release.yml`)**

Triggered on push of tags matching `v*`.

1. Build workspace release binaries
2. Build x64 and x86 hook DLLs
3. Decode Authenticode signing certificate from `secrets.AUTHENTICODE_PFX`
4. Sign all binaries with `signtool` (DigiCert primary, Sectigo fallback)
5. Verify signatures with `signtool verify /pa`
6. Upload signed artifacts

### Local MSI build

From the `installer/` directory with Administrator privileges:

```powershell
# Full build (release binaries + MSI):
.\build.ps1

# Use pre-built binaries (skip cargo build):
.\build.ps1 -SkipRustBuild

# Debug build:
.\build.ps1 -Configuration debug
```

Prerequisites:

- Rust toolchain (stable)
- WiX v4+ (`dotnet tool install --global wix`)
- WiX extensions: `wix extension add WixToolset.Util.wixext`, `wix extension add WixToolset.UI.wixext`

Output: `installer/dist/DLPAgent.msi`

## Environment setup

### dlp-server required environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET` | **Yes** (production) | Secret key for JWT token signing. The server refuses to start without it unless `--dev` is passed. |

### dlp-agent required configuration

The agent requires a TOML config file at `C:\ProgramData\DLP\agent-config.toml`. The MSI does **not** bundle a default config. Create it post-install:

```toml
server_url = 'http://10.0.1.5:9090'
log_level = 'info'
```

See [CONFIGURATION.md](CONFIGURATION.md) for the full configuration reference.

### dlp-admin-cli first-run setup

After installing the agent MSI, use `dlp-admin-cli.exe` TUI **Set Agent Password** (or start `dlp-server --init-admin <password>` on the server) to set the dlp-admin password.

## Rollback procedure

### MSI rollback

To revert an agent installation:

```cmd
msiexec /x DLPAgent.msi /qn
```

Or via Service Control Manager:

```cmd
sc stop dlp-agent
sc delete dlp-agent
```

The MSI restores original `AppInit_DLLs` registry values from the backup key at `HKLM\SOFTWARE\DLP\Backup\AppInit_DLLs` on uninstall.

### dlp-server rollback

Since `dlp-server` is a standalone binary, rollback is performed by:

1. Stopping the running server process
2. Replacing the binary with the previous version
3. Restoring the previous SQLite database from backup (if schema changed)
4. Restarting the server

### Database rollback

The server uses SQLite with WAL mode (`PRAGMA journal_mode=WAL`). To roll back to a previous state, restore the `.db` file and its `-wal` / `-shm` companions from backup.

## Monitoring

### Structured logging

All binaries use `tracing` + `tracing-subscriber` with JSON output and environment-filter support:

| Binary | Log location | Configuration |
|--------|-------------|---------------|
| `dlp-agent` | `C:\ProgramData\DLP\logs\dlp-agent.log` (rolling) | `log_level` in TOML config or `RUST_LOG` env var |
| `dlp-server` | stdout/stderr | `--log-level` flag or `RUST_LOG` env var |
| `dlp-user-ui` | `C:\ProgramData\DLP\logs\dlp-user-ui.log` | `RUST_LOG` env var |
| `dlp-admin-cli` | stdout/stderr | `RUST_LOG` env var |

### Health check endpoint

`dlp-server` exposes a health check at `GET /health`:

```bash
curl http://127.0.0.1:9090/health
# Expected: {"status":"ok"}
```

### Service crash recovery

The MSI configures SCM failure actions for `dlp-agent`:

1. First failure: restart after 60 seconds
2. Second failure: restart after 60 seconds
3. Third failure: restart after 60 seconds
4. Subsequent failures: log event and leave service stopped

The failure counter resets after 24 hours of uptime.

### Audit logging

All policy enforcement events are written to `C:\ProgramData\DLP\logs\audit.jsonl` by the agent. The server stores audit events in SQLite and can forward them to:

- Splunk HEC
- Elasticsearch / ELK
- Syslog over TLS (RFC 5424)
- SMTP email alerts
- Webhooks

Configure these via the admin API or `dlp-admin-cli`. See [CONFIGURATION.md](CONFIGURATION.md) for details.

### No external APM integration

The project does not currently integrate with Sentry, Datadog, New Relic, or OpenTelemetry. Monitoring is based on structured logs, health checks, and the configured SIEM/syslog relays.

## Service management scripts

PowerShell scripts in `scripts/` assist with deployment operations:

| Script | Purpose |
|--------|---------|
| `scripts/Manage-DlpAgentService.ps1` | Install, start, stop, restart, or query the `dlp-agent` Windows Service |
| `scripts/Manage-DlpComponents.ps1` | Unified start/stop/status for both `dlp-server` (process) and `dlp-agent` (service) |
| `scripts/Uat-UsbBlock.ps1` | Real-hardware USB write-protection verification against a running dlp-server |

Example: install and start the agent service for development:

```powershell
.\scripts\Manage-DlpAgentService.ps1 -Action Install -ServerUrl "http://10.0.1.5:9090"
```

Example: start both server and agent:

```powershell
.\scripts\Manage-DlpComponents.ps1 -Action Start -Component Both
```

## Directory ACLs

The MSI applies the following NTFS permissions:

| Directory | ACL |
|-----------|-----|
| `C:\Program Files\DLP\` | `SYSTEM` + `Administrators`: Full; `Everyone`: Read |
| `C:\Program Files\DLP\config\` | `SYSTEM`: Full; `Administrators`: Full |
| `C:\Program Files\DLP\logs\` | `SYSTEM` + `Administrators`: Full; `Everyone`: Read + Execute |

## Code signing

Production deployments should sign all binaries with an Authenticode certificate before packaging. The release workflow demonstrates this with `signtool`:

```powershell
signtool sign /f cert.pfx /p $password `
  /tr http://timestamp.digicert.com /td sha256 /fd sha256 `
  target\release\dlp-agent.exe
```

<!-- VERIFY: The Authenticode certificate source and timestamp server URL are environment-specific and must be configured per-organization -->

## Deployment checklist

- [ ] Build release binaries (`cargo build --workspace --release`)
- [ ] Build x86 and x64 hook DLLs
- [ ] Sign all binaries with organizational Authenticode certificate
- [ ] Build MSI (`installer/build.ps1`)
- [ ] Deploy `dlp-server` to central host with `JWT_SECRET` set
- [ ] Initialize dlp-admin password (`--init-admin` or interactive prompt)
- [ ] Configure LDAP/AD connection via admin API
- [ ] Install agent MSI on endpoint machines
- [ ] Create `agent-config.toml` with correct `server_url`
- [ ] Verify agent service is running (`sc query dlp-agent`)
- [ ] Verify agent heartbeat in server admin API
- [ ] Configure SIEM relay, alerting, and syslog forwarding
- [ ] Run USB block UAT on representative endpoints (`scripts/Uat-UsbBlock.ps1`)
