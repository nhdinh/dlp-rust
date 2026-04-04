# Operational Runbook — DLP Rust Agent

**Document Version:** 1.0
**Date:** 2026-04-04
**Status:** Production
**Applies To:** DLP Agent v1.0 on Windows Server 2019+ / Windows 10/11 Enterprise

> See also: [SRS.md](SRS.md) for functional requirements, [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for security findings, [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) for architecture overview.

---

## 1. Installation

### 1.1 Prerequisites

| Component | Requirement |
|-----------|-------------|
| OS | Windows Server 2019 or later; Windows 10/11 Enterprise |
| .NET | .NET Framework 4.8 (for DPAPI / LDAPS password verification) |
| Network | LDAPS connectivity to at least one DC on port 636 |
| Policy Engine | `policy-engine` deployed and reachable at the configured URL |
| Firewall | Outbound TCP 8443 to Policy Engine; outbound TCP 636 to AD (LDAPS) |

### 1.2 MSI Installation

Install the MSI package on each managed endpoint:

```cmd
msiexec /i DLPAgent.msi
```

Or silently (for GPO/Intune deployment):

```cmd
msiexec /i DLPAgent.msi /qn
```

The service starts automatically after installation. Verify:

```cmd
sc query dlp-agent
```

Expected output:
```
SERVICE_NAME: dlp-agent
TYPE               : 10  WIN32_OWN_PROCESS
STATE              : 4   RUNNING
WIN32_EXIT_CODE    : 0   (0x0)
```

### 1.3 Per-Endpoint Configuration

Set the agent identifier **before or immediately after installation** via Group Policy environment variable or registry:

```cmd
:: Via environment variable (per-machine)
setx /M DLP_AGENT_ID "AGENT-FIN-HQ-001"
```

The agent reads `DLP_AGENT_ID` at startup. If unset, defaults to `AGENT-UNKNOWN` (service context) or `AGENT-CONSOLE` (console mode).

### 1.4 Uninstall

```cmd
:: Via MSI
msiexec /x DLPAgent.msi /qn

:: Or directly via SCM
sc stop dlp-agent
sc delete dlp-agent
```

---

## 2. Configuration Reference

### 2.1 Config File

The agent reads configuration from:

```
C:\ProgramData\DLP\agent-config.toml
```

If the file is missing or unparseable, the agent starts with defaults (watches all mounted drives, built-in exclusions only). No error is raised on a missing file.

**Schema:**

```toml
# Folders to monitor recursively.  Empty list = all drives A-Z.
# Use forward slashes or escaped backslashes.
monitored_paths = [
    'C:\Data\',
    'C:\Confidential\',
    'C:\Restricted\',
    'D:\Shares\',
]

# Additional folders to exclude (case-insensitive substring match).
# These are MERGED with the built-in exclusions below.
excluded_paths = [
    'C:\BuildOutput\',
]
```

### 2.2 Built-In Exclusions

The following paths are **always** excluded from monitoring, regardless of config:

| Path prefix (case-insensitive) | Reason |
|--------------------------------|--------|
| `C:\Windows\` | System directory |
| `C:\ProgramData\` | Application data |
| `C:\Program Files\` | Installed programs |
| `C:\Program Files (x86)\` | 32-bit programs |
| `C:\$Recycle.Bin\` | System recycle bin |
| `C:\System Volume Information\` | System restore |
| `%LOCALAPPDATA%\Temp\` | User temp |
| `%LOCALAPPDATA%\Microsoft\` | App caches |
| `%LOCALAPPDATA%\Packages\` | UWP app data |
| `%APPDATA%\Code\` | VS Code settings |
| `%APPDATA%\Microsoft\` | Office, Windows caches |

### 2.3 Policy Engine URL

The Policy Engine URL is compiled into the agent binary at build time. To override at runtime, set the `DLP_POLICY_ENGINE_URL` environment variable before starting the service:

```cmd
setx /M DLP_POLICY_ENGINE_URL "https://dlp-engine.corp.local:8443"
```

Default: `https://localhost:8443`

---

## 3. Service Management

### 3.1 SCM Commands

| Operation | Command |
|-----------|---------|
| Start | `sc start dlp-agent` |
| Stop | `sc stop dlp-agent` *(requires dlp-admin AD password — see §3.2)* |
| Query state | `sc query dlp-agent` |
| Pause | `sc pause dlp-agent` |
| Resume | `sc continue dlp-agent` |
| Uninstall | `sc delete dlp-agent` |

> **Note:** `sc stop` triggers a password-protected stop sequence. The dlp-admin must enter their AD credentials in the UI dialog that appears in the active console session. See §3.2.

### 3.2 Password-Protected Stop

To stop the service, a dlp-admin must authenticate via their Active Directory credentials:

1. An administrator runs `sc stop dlp-agent` from a session with a logged-in interactive user.
2. The service reports `STOP_PENDING` to the SCM with a 120-second wait hint.
3. A stop-password dialog appears in the active user session.
4. The admin enters their AD password and clicks **Confirm**.
5. The service validates the password via LDAPS bind to a domain controller.
6. On success: clean shutdown within 30 seconds.
7. On three consecutive failures: `EVENT_DLP_ADMIN_STOP_FAILED` is logged; the service reverts to `RUNNING`.

In **debug builds only**, the password challenge is bypassed — the service stops immediately.

### 3.3 Pause / Continue

Pausing the service suspends file interception. The UI remains responsive. Resume restarts interception.

```cmd
sc pause dlp-agent
:: ... perform maintenance ...
sc continue dlp-agent
```

### 3.4 Single-Instance Guarantee

The agent enforces a single running instance via the `Global\dlp-agent-instance` named mutex. A second start attempt exits cleanly without error. This prevents accidental double-start from startup scripts or Group Policy.

### 3.5 Console / Development Mode

For testing without Windows Service registration:

```cmd
cargo run -p dlp-agent --bin dlp-agent -- --console
```

The agent runs as a foreground process with full pipeline active. Press `Ctrl+C` to stop.

### 3.6 Crash Recovery

The MSI configures SCM failure actions:

| Failure | Action |
|---------|--------|
| 1st | Restart after 60 s |
| 2nd | Restart after 60 s |
| 3rd | Restart after 60 s |
| Subsequent | Log `EVENT_DLP_ADMIN_STOP_FAILED`; leave stopped |

If the service is stopped unexpectedly 3 times within 24 hours, it remains stopped until manually started. Check the Windows Application Event Log for `EVENT_DLP_ADMIN_STOP_FAILED`.

---

## 4. Monitoring and Health

### 4.1 Health Monitor

The agent runs a mutual health ping protocol with its UI subprocesses:

| Direction | Channel | Interval | Timeout |
|-----------|---------|----------|---------|
| Agent → UI | Pipe 2 (`HEALTH_PING`) | Every 5 s | 15 s → respawn UI |
| UI → Agent | Pipe 3 (`HEALTH_PONG`) | Every 5 s | 15 s → log warning |

If the file monitor, IPC servers, USB detector, or session monitor thread terminates unexpectedly, the health monitor logs an error and the SCM crash recovery takes over.

### 4.2 IPC Pipe Names

Allowlist these named pipes on host firewalls for intra-host communication only (they are not network-accessible by default):

| Pipe | Mode | Purpose |
|------|------|---------|
| `\\.\pipe\DLPCommand` | Message, duplex | Command/response (stop, override, clipboard) |
| `\\.\pipe\DLPEventAgent2UI` | Message, one-way | Agent → UI events (toasts, status, health) |
| `\\.\pipe\DLPEventUI2Agent` | Message, one-way | UI → Agent events (ready, closing, health pong) |

All three pipes require `SYSTEM` or `Administrators` access. No inbound firewall rules are needed.

### 4.3 What Unhealthy Looks Like

| Symptom | Likely Cause |
|---------|-------------|
| Service in `STOPPED` state, no crash log | Password-protected stop completed; expected |
| Service crashed repeatedly | Policy Engine unreachable + cache miss; check network |
| No audit events for any file operations | `agent-config.toml` has no `monitored_paths` or all paths excluded |
| UI not appearing in user session | `CreateProcessAsUser` failure; check user logon rights |
| `Pipe 2` errors in trace | UI process crashed; health monitor should have respawned |

---

## 5. Operational Logging

### 5.1 Tracing Logs (Structured)

The agent logs structured events via `tracing-subscriber`:

- **Output:** stdout / stderr (captured by Windows Service subsystem, visible in Event Viewer → Application log if wired, or in a log collector sidecar)
- **Default level:** `INFO`
- **Format:** structured JSON or human-readable with span close events and thread IDs

To increase verbosity to `DEBUG` for a running service:

> There is no runtime log level toggle. Rebuild with `RUST_LOG=debug` at compile time, or set the `RUST_LOG` environment variable before service start (requires service restart).

### 5.2 Audit Log

| Property | Value |
|----------|-------|
| Path | `C:\ProgramData\DLP\logs\audit.jsonl` |
| Format | One JSON object per line (JSONL) |
| Rotation | 50 MB per file; `audit.1.jsonl` … `audit.9.jsonl` |
| Rotation trigger | Every 100 emitted events |
| Rotation failure | Logged; audit continues; file operations are **not** blocked |

**Append-only guarantee:** The file handle is opened with `FILE_APPEND_DATA` only. The MSI ACL on `C:\ProgramData\DLP\logs\` prevents non-admin deletion. See §8.

**What is logged:**
- Every intercepted file operation (create, write, delete, move, read)
- USB mass storage connect/disconnect events
- SMB share connect/disconnect events
- Clipboard paste events (T2+ content only)
- Policy decisions (ALLOW, DENY, DENY_WITH_ALERT)
- Override requests and outcomes
- Service state transitions
- Offline/online transitions

**What is NOT logged:**
- File content or payloads
- Passwords, tokens, or session keys
- Classification metadata stored in NTFS xattrs (none used)

### 5.3 SIEM Relay (Phase 5)

In Phase 1–4, audit logs are written to the local JSONL file only. SIEM relay via `dlp-server` is planned for Phase 5. To prepare:

- Ship `C:\ProgramData\DLP\logs\` to your SIEM via existing log collector (Splunk Universal Forwarder, Elastic Agent, etc.)
- Each line is a JSON object conforming to F-AUD-02 schema (see `dlp-common/src/audit.rs`)

---

## 6. Offline Mode and Failover

### 6.1 How Offline Mode Activates

The agent maintains a heartbeat loop that probes the Policy Engine every **30 seconds**:

1. If the probe fails (network error, TLS error, 5xx HTTP response), the engine is marked **unreachable**.
2. A second consecutive failure triggers **offline mode**.
3. A transition audit event is emitted: `{ "event_type": "AGENT_OFFLINE" }`.

### 6.2 Fail-Closed Decision Table

When the Policy Engine is unreachable and the local cache has no decision for the requested resource:

| Classification | Decision | Rationale |
|---------------|---------|-----------|
| T1 (Public) | **ALLOW** | Lowest risk; false denials disruptive |
| T2 (Internal) | **ALLOW** | Moderate risk; false denials disruptive |
| T3 (Confidential) | **DENY** | Fail-closed; log the denial |
| T4 (Restricted) | **DENY** | Fail-closed; log the denial |

### 6.3 Cache Behaviour

- Cache TTL: 5 minutes per entry
- Cache key: SHA-256 of `(subject_sid + resource_path)`
- Cache miss during offline: apply fail-closed table above
- Cache eviction: LRU when cache reaches 10,000 entries

### 6.4 Heartbeat and Auto-Reconnect

When the Policy Engine becomes reachable again:
1. Next heartbeat probe succeeds.
2. Transition audit event emitted: `{ "event_type": "AGENT_ONLINE" }`.
3. Live ABAC evaluation resumes immediately.
4. Policy hot-reload: if `policies.json` changed on disk, engine picks it up within 5 seconds (no restart needed).

### 6.5 AD / LDAP Outage

AD group membership is cached with a 5-minute TTL. If AD is unreachable during a cache miss:
- Policy Engine denies requests that depend on AD group membership.
- The agent continues to enforce cached decisions.
- Once AD recovers, the AD client reconnects automatically.

---

## 7. Backup and Recovery

### 7.1 Audit Log Backup

Rotate and compress the log directory before `audit.9.jsonl` fills up disk:

```powershell
# Run as SYSTEM (via scheduled task with highest privileges)
$logDir = "C:\ProgramData\DLP\logs"
$stamp = Get-Date -Format "yyyy-MM-dd_HHmmss"

Compress-Archive -Path "$logDir\audit.*.jsonl" `
                 -DestinationPath "$logDir\audit-$stamp.zip" `
                 -Force

# Remove compressed originals after successful ship
Remove-Item "$logDir\audit.*.jsonl" -Force
```

> The most recent `audit.jsonl` (still being written) should **not** be compressed while open. Only rotate `audit.1.jsonl` through `audit.9.jsonl`.

### 7.2 Configuration Backup

Back up `C:\ProgramData\DLP\agent-config.toml` before any maintenance. There is no automated config backup.

### 7.3 Cache Persistence

The in-memory policy decision cache is **not persisted**. On service restart, the cache starts empty and fills as file operations are evaluated.

---

## 8. Upgrade Procedure

### 8.1 Manual Binary Update

1. Stop the service (password-protected stop as dlp-admin — see §3.2).
2. Replace `C:\Program Files\DLP\dlp-agent.exe` and `C:\Program Files\DLP\dlp-user-ui.exe`.
3. Start the service: `sc start dlp-agent`.

> The MSI upgrade path (`msiexec /i DLPAgent.msi`) handles this automatically and is the recommended approach.

### 8.2 Policy Hot-Reload

The Policy Engine watches `policies.json` on disk via the `notify` crate. Changes are validated and atomically swapped within **5 seconds** without restarting the engine or the agent.

To hot-reload policies:
1. Edit `policies.json` on the Policy Engine host.
2. Wait 5 seconds.
3. New policy takes effect on the next agent heartbeat.

### 8.3 Staging Deployment Checklist

Before deploying to production:

- [ ] Install on a single pilot endpoint; verify `sc query dlp-agent` shows `RUNNING`
- [ ] Confirm audit events appear in `C:\ProgramData\DLP\logs\audit.jsonl`
- [ ] Verify a T4 file write is blocked (denied and logged)
- [ ] Verify USB block works for a T3 file
- [ ] Confirm offline mode activates when Policy Engine is stopped
- [ ] Confirm offline mode clears when Policy Engine restarts
- [ ] Verify password-protected stop works with a real dlp-admin account
- [ ] Review audit log for false positives (adjust `excluded_paths` in config)

---

## 9. Directory Layout

| Path | Purpose | Managed By |
|------|---------|-----------|
| `C:\Program Files\DLP\` | Binaries | MSI |
| `C:\Program Files\DLP\dlp-agent.exe` | Service binary | MSI |
| `C:\Program Files\DLP\dlp-user-ui.exe` | UI subprocess | MSI |
| `C:\ProgramData\DLP\` | Runtime data | Agent at runtime |
| `C:\ProgramData\DLP\agent-config.toml` | Agent configuration | Ops |
| `C:\ProgramData\DLP\logs\` | Audit log directory | MSI ACLs; agent |
| `C:\ProgramData\DLP\logs\audit.jsonl` | Active audit log | Agent (append-only) |
| `C:\ProgramData\DLP\logs\audit.N.jsonl` | Rotated generations | Agent (1–9) |

---

## 10. Troubleshooting

### Service will not start

```cmd
:: Check SCM state
sc query dlp-agent

:: Check recent Windows Event Log errors
wevtutil qe Application /c:10 /f:text /q:"*[System[Provider[@Name='DLP-Agent']]]"
```

Common causes:
- Second instance blocked by `Global\dlp-agent-instance` mutex → stop the existing instance first
- `dlp-user-ui.exe` not found at `{exe_dir}\dlp-user-ui.exe` → set `DLP_UI_BINARY` env var

### No audit events appearing

1. Check `agent-config.toml` has valid `monitored_paths` or is empty (empty = all drives).
2. Check no configured path is covered by a built-in exclusion.
3. Confirm the file operations are happening on watched paths (e.g., write to `C:\Data\` not `C:\Windows\`).
4. Check tracing logs for `"could not watch path"` warnings.

### Password stop always fails

- Verify LDAPS (:636) is open from the endpoint to at least one DC.
- Verify the dlp-admin account is valid and not locked out.
- Check the Windows Event Log for `EVENT_DLP_ADMIN_STOP_FAILED` with the LDAPS error code.
- In a test environment without AD: use a debug build (password challenge bypassed).

### UI not appearing in user session

- The UI spawns into the **active console session** only. RDP sessions without console may not receive the UI.
- Check `session_monitor.rs` logs for `WTSEnumerateSessionsW` failures.
- Verify `CreateProcessAsUser` rights — the service account (LocalSystem) must have `SE_ASSIGNPRIMARYTOKEN_NAME` and `SE_INCREASE_QUOTA_NAME` privileges.

### Clipboard monitoring not working

- Clipboard hooks require an active UI in the session to process `WM_PASTE` messages.
- If the UI is not running in a session (e.g., locked screen), clipboard monitoring is inactive.

---

## 11. Security Operational Notes

### Process Hardening

The agent and UI processes are protected by a DACL that denies `PROCESS_TERMINATE`, `PROCESS_CREATE_THREAD`, `PROCESS_VM_OPERATION`, `PROCESS_VM_READ`, and `PROCESS_VM_WRITE` to `Authenticated Users`. Only `SYSTEM` and `Administrators` retain full access. This prevents standard users and non-dlp-admin administrators from killing the agent via Task Manager or `taskkill`.

To verify from a non-admin account:

```cmd
:: Should show Access Denied
handle.exe dlp-agent.exe
taskkill /IM dlp-agent.exe
```

### Immutable Audit Log

The audit log is append-only by design. The MSI sets `C:\ProgramData\DLP\logs\` ACLs to allow `SYSTEM` and `Administrators` full control, but no `DELETE` ACE for non-admin users. Do **not** modify these ACLs — removing them weakens the tamper-resistance of the audit trail.

### Override Justification Privacy Note

When a user requests an override, they type a justification into the block dialog. This free-text field is written to the audit log verbatim. If users may enter PII (SSN, credit card) into this field, consider adding a warning label or preprocessing the text before storage. This is a documented privacy risk — see `docs/SECURITY_AUDIT.md`.

---

## 12. Environment Variables

### Agent (dlp-agent)

| Variable | Default | Description |
|----------|---------|-------------|
| `DLP_AGENT_ID` | `AGENT-UNKNOWN` | Unique endpoint identifier in audit events |
| `DLP_UI_BINARY` | `{exe_dir}\dlp-user-ui.exe` | UI binary path override (dev only) |
| `DLP_LDAP_URL` | `ldaps://localhost:636` | AD/LDAPS server for password verification |
| `DLP_POLICY_ENGINE_URL` | `https://localhost:8443` | Policy Engine HTTPS endpoint (build-time default) |
| `RUST_LOG` | `info` | Tracing log level (`error`, `warn`, `info`, `debug`, `trace`) |
| `RUST_BACKTRACE` | `0` | Rust stack trace verbosity (`1` = full) |

### Policy Engine (policy-engine)

| Variable | Default | Source |
|----------|---------|--------|
| `BIND_ADDR` | `0.0.0.0:8443` | `policy-engine/src/main.rs` |
| `POLICY_FILE` | `./policies.json` | `policy-engine/src/main.rs` |
| `DLP_ENGINE_CERT_PATH` | `.env` (dotenvy) | Not an env var; loaded from `.env` |
| `DLP_ENGINE_KEY_PATH` | `.env` (dotenvy) | Not an env var; loaded from `.env` |
| `DLP_AD_BIND_PASSWORD` | `.env` (dotenvy) | AD service account password; loaded from `.env` |

> Never store credentials in environment variables or source code. Use `.env` files excluded from version control.
