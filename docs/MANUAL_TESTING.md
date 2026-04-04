# Manual Testing Guide -- Phase 1

**Date:** 2026-04-02
**Status:** Phase 1 complete (46/46 tasks, 118 tests)

This guide walks through building, running, and manually testing every
Phase 1 component on a Windows development machine.

---

## 1. Prerequisites

Assumes you have the following installed:

- Rust toolchain (stable) with `cargo` and `rustc`
- Windows 10 or later (for file system monitoring and service management)
- PowerShell (for service management and log parsing)
- `curl` (for API testing; included in Windows 10+)

---

## 2. Build

Build all workspace crates in release mode:

```cmd
cargo build --all --release
```

Output binaries:

| Binary        | Path                               |
| ------------- | ---------------------------------- |
| Policy Engine | `target\release\policy-engine.exe` |
| DLP Agent     | `target\release\dlp-agent.exe`     |

---

## 3. Start the Policy Engine

The engine listens on `http://127.0.0.1:8443` by default.

### Configuration (environment variables)

| Variable      | Default           | Description                                           |
| ------------- | ----------------- | ----------------------------------------------------- |
| `BIND_ADDR`   | `127.0.0.1:8443`  | Listen address and port                               |
| `POLICY_FILE` | `./policies.json` | Path to the policy JSON file                          |
| `RUST_LOG`    | `info`            | Log level (`trace`, `debug`, `info`, `warn`, `error`) |

Open **Terminal 1** and run:

```cmd
set BIND_ADDR=0.0.0.0:9000
set POLICY_FILE=C:\config\policies.json
set RUST_LOG=debug
cargo run -p policy-engine
```

### Verify the engine is running

```cmd
curl http://127.0.0.1:8443/health
```

Expected: HTTP 200 (empty body).

```cmd
curl http://127.0.0.1:8443/ready
```

Expected: HTTP 200 (policy store loaded).

---

## 4. Seed Policies

Check for the policies first.

```cmd
curl http://127.0.0.1:8443/policies
```

Expected: JSON array with three policy objects. If empty, use the REST API to add the
three standard ABAC rules from `docs/ABAC_POLICIES.md`.

### Rule 1: T4 Deny All

```cmd
curl -X POST http://127.0.0.1:8443/policies ^
  -H "Content-Type: application/json" ^
  -d "{\"id\":\"pol-001\",\"name\":\"T4 Deny All\",\"description\":\"Block all access to T4 Restricted resources\",\"priority\":1,\"conditions\":[{\"attribute\":\"classification\",\"op\":\"eq\",\"value\":\"T4\"}],\"action\":\"DENY\",\"enabled\":true,\"version\":1}"
```

### Rule 2: T3 Unmanaged Device Deny

```cmd
curl -X POST http://127.0.0.1:8443/policies ^
  -H "Content-Type: application/json" ^
  -d "{\"id\":\"pol-002\",\"name\":\"T3 Unmanaged Block\",\"description\":\"Block T3 from unmanaged devices\",\"priority\":2,\"conditions\":[{\"attribute\":\"classification\",\"op\":\"eq\",\"value\":\"T3\"},{\"attribute\":\"device_trust\",\"op\":\"eq\",\"value\":\"Unmanaged\"}],\"action\":\"DENY\",\"enabled\":true,\"version\":1}"
```

### Rule 3: T2 Allow with Logging

```cmd
curl -X POST http://127.0.0.1:8443/policies ^
  -H "Content-Type: application/json" ^
  -d "{\"id\":\"pol-003\",\"name\":\"T2 Allow with Log\",\"description\":\"Permit T2 access with audit logging\",\"priority\":3,\"conditions\":[{\"attribute\":\"classification\",\"op\":\"eq\",\"value\":\"T2\"}],\"action\":\"ALLOW_WITH_LOG\",\"enabled\":true,\"version\":1}"
```

### Verify policies loaded

```cmd
curl http://127.0.0.1:8443/policies
```

Expected: JSON array with three policy objects.

---

## 5. Test Policy Evaluation

### Test 1: T4 resource -- expect DENY

```cmd
curl -X POST http://127.0.0.1:8443/evaluate ^
  -H "Content-Type: application/json" ^
  -d "{\"subject\":{\"user_sid\":\"S-1-5-21-123\",\"user_name\":\"jsmith\",\"groups\":[],\"device_trust\":\"Managed\",\"network_location\":\"Corporate\"},\"resource\":{\"path\":\"C:\\\\Restricted\\\\secrets.xlsx\",\"classification\":\"T4\"},\"environment\":{\"timestamp\":\"2026-04-01T12:00:00Z\",\"session_id\":1,\"access_context\":\"local\"},\"action\":\"COPY\"}"
```

Expected response:

```json
{
  "decision": "DENY",
  "matched_policy_id": "pol-001",
  "reason": "Policy 'T4 Deny All' ..."
}
```

### Test 2: T2 resource -- expect ALLOW_WITH_LOG

```cmd
curl -X POST http://127.0.0.1:8443/evaluate ^
  -H "Content-Type: application/json" ^
  -d "{\"subject\":{\"user_sid\":\"S-1-5-21-123\",\"user_name\":\"jsmith\",\"groups\":[],\"device_trust\":\"Managed\",\"network_location\":\"Corporate\"},\"resource\":{\"path\":\"C:\\\\Data\\\\report.xlsx\",\"classification\":\"T2\"},\"environment\":{\"timestamp\":\"2026-04-01T12:00:00Z\",\"session_id\":1,\"access_context\":\"local\"},\"action\":\"WRITE\"}"
```

Expected: `"decision": "ALLOW_WITH_LOG"`, `"matched_policy_id": "pol-003"`.

### Test 3: T1 resource -- expect default DENY (no matching policy)

```cmd
curl -X POST http://127.0.0.1:8443/evaluate ^
  -H "Content-Type: application/json" ^
  -d "{\"subject\":{\"user_sid\":\"S-1-5-21-123\",\"user_name\":\"jsmith\",\"groups\":[],\"device_trust\":\"Managed\",\"network_location\":\"Corporate\"},\"resource\":{\"path\":\"C:\\\\Public\\\\readme.txt\",\"classification\":\"T1\"},\"environment\":{\"timestamp\":\"2026-04-01T12:00:00Z\",\"session_id\":1,\"access_context\":\"local\"},\"action\":\"READ\"}"
```

Expected: `"decision": "DENY"`, `"matched_policy_id": null` (no T1 rule loaded -- default-deny).

---

## 6. Policy CRUD Operations

### Update a policy

```cmd
curl -X PUT http://127.0.0.1:8443/policies/pol-003 ^
  -H "Content-Type: application/json" ^
  -d "{\"id\":\"pol-003\",\"name\":\"T2 Allow with Log (Updated)\",\"description\":\"Updated description\",\"priority\":3,\"conditions\":[{\"attribute\":\"classification\",\"op\":\"eq\",\"value\":\"T2\"}],\"action\":\"ALLOW_WITH_LOG\",\"enabled\":true,\"version\":1}"
```

Expected: HTTP 200 with the updated policy (version incremented by the store).

### Delete a policy

```cmd
curl -X DELETE http://127.0.0.1:8443/policies/pol-003
```

Expected: HTTP 204 No Content.

### Get a single policy

```cmd
curl http://127.0.0.1:8443/policies/pol-001
```

Expected: JSON object for `pol-001`.

---

## 7. Start the DLP Agent (Console Mode)

> **Administrator rights are optional.** The file monitor (`notify` crate) works
> in all sessions including non-elevated terminals. Admin rights are only
> required for Windows Service registration.

Open **Terminal 2** and run:

```cmd
# Using cargo (from the repo root):
cargo run -p dlp-agent --release -- --console
```

Or run the built binary directly:

```cmd
target\release\dlp-agent.exe --console
```

### Agent Configuration File

The agent reads `C:\ProgramData\DLP\agent-config.toml` at startup. If the file
is missing the agent uses defaults (all drives, built-in exclusions only).

```toml
# Directories to watch recursively.
# Empty or omitted = watch ALL mounted drives (A-Z).
monitored_paths = [
    'C:\Data\',
    'C:\Confidential\',
    'C:\Restricted\',
    'D:\Shares\',
]

# Additional exclusion prefixes (case-insensitive substring match).
# These are MERGED with the built-in exclusions, not replacing them.
# Built-in exclusions: C:\Windows, C:\ProgramData, C:\Program Files,
# C:\Program Files (x86), C:\$Recycle.Bin, System Volume Information,
# AppData\Local\Temp, AppData\Local\Microsoft, AppData\Local\Packages,
# AppData\Roaming\Code, AppData\Roaming\Microsoft.
excluded_paths = [
    'C:\BuildOutput\',
    'C:\Users\dev\node_modules\',
]
```

| Field | Default | Behavior |
| --- | --- | --- |
| `monitored_paths` | `[]` (empty) | Empty = watch all drives A-Z; non-empty = watch only listed paths |
| `excluded_paths` | `[]` (empty) | Merged with built-in exclusions (additive, never replaces) |

To apply changes, restart the agent (`Ctrl+C` in console mode, or `sc stop` + `sc start` for the service).
```

Console mode runs the agent in the foreground without registering as a
Windows Service. The full interception pipeline starts: file-system
monitoring (via the `notify` crate), Policy Engine client, and
audit log writer. Press `Ctrl+C` to stop.

> **Note:** The agent requires the Policy Engine to be running for online
> evaluation. If the engine is not reachable, the agent operates in offline
> mode with fail-closed semantics (DENY for T3/T4 on cache miss).

> **Console mode does not auto-spawn the UI.** The `dlp-user-ui` subprocess
> is only spawned automatically when the agent runs as a Windows Service
> (SYSTEM account). In console mode, to test the UI alongside the agent,
> start it manually in a separate terminal:
>
> ```cmd
> cargo run -p dlp-user-ui --release
> ```
>
> The UI will connect to the agent's named pipes and register its session.

---

## 8. View Audit Logs

The agent writes structured JSONL audit events to:

```text
C:\ProgramData\DLP\logs\audit.jsonl
```

### View the log

```cmd
type C:\ProgramData\DLP\logs\audit.jsonl
```

### Parse with PowerShell

```powershell
Get-Content C:\ProgramData\DLP\logs\audit.jsonl | ForEach-Object { $_ | ConvertFrom-Json }
```

### Log rotation

- Rotates at **50 MB** (configurable in code)
- Rotated files: `audit.1.jsonl`, `audit.2.jsonl`, ... up to `audit.9.jsonl`
- Oldest file is deleted when the limit is exceeded

---

## 9. Test Offline Fallback

1. With both the engine and agent running, send an evaluate request to
   confirm online operation.

2. **Stop the Policy Engine** (Ctrl+C in Terminal 1).

3. The agent detects the engine is unreachable and enters **offline mode**.
   Observe the log output:

   ```log
   WARN  Policy Engine unreachable -- entering offline mode
   ```

4. In offline mode:
   - **T3/T4 resources** with no cache entry are **DENIED** (fail-closed).
   - **T1/T2 resources** with no cache entry are **ALLOWED** (default-allow for non-sensitive).
   - Cached decisions continue to be served until TTL expires (default 60 s).

5. **Restart the Policy Engine**. The agent's heartbeat loop (30 s interval)
   detects the engine is back and transitions to online mode:

   ```log
   INFO  Policy Engine reachable -- resuming online mode
   ```

---

## 10. Trigger DLP Events

This section walks through triggering real events that the DLP Agent
detects. Ensure both the Policy Engine (section 3) and the Agent in
console mode (section 7) are running before you begin.

Open a **third terminal** for the commands below.

### 10.1 Setup: Create Test Directories

The agent classifies files by path prefix. Create the test directory
structure that matches the default sensitive-path table:

```cmd
mkdir C:\Restricted
mkdir C:\Confidential
mkdir C:\Data
mkdir C:\Public
```

| Directory          | Classification  | Sensitivity                 |
| ------------------ | --------------- | --------------------------- |
| `C:\Restricted\`   | T4 Restricted   | Highest -- fail-closed DENY |
| `C:\Confidential\` | T3 Confidential | High                        |
| `C:\Data\`         | T2 Internal     | Moderate                    |
| `C:\Public\`       | T1 Public       | Low                         |

### 10.2 File Operations (F-AGT-05)

The agent monitors file system events via the `notify` crate.
Perform these operations
and check the audit log after each one.

#### Create a file

```cmd
echo "Q4 Financial Results" > C:\Restricted\financials.txt
echo "Internal Memo" > C:\Data\memo.txt
echo "Public README" > C:\Public\readme.txt
```

Expected audit log: `ACCESS` events for each file, with
classification T4, T2, and T1 respectively.

#### Write / modify a file

```cmd
echo "Updated figures" >> C:\Restricted\financials.txt
```

Expected: `ACCESS` event for `C:\Restricted\financials.txt`,
classification T4.

#### Copy a file

```cmd
copy C:\Restricted\financials.txt C:\Restricted\financials_backup.txt
```

Expected: `ACCESS` events for the new file (copy triggers a create +
write sequence).

#### Rename / move a file

```cmd
ren C:\Data\memo.txt memo_archived.txt
move C:\Data\memo_archived.txt C:\Public\memo_archived.txt
```

Expected: `ACCESS` events for each operation. The rename stays in T2;
the move changes the path to T1 (`C:\Public\`).

#### Delete a file

```cmd
del C:\Public\readme.txt
```

Expected: `ACCESS` event with classification T1.

#### Verify in audit log

```powershell
Get-Content C:\ProgramData\DLP\logs\audit.jsonl |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Select-Object timestamp, event_type, resource_path, classification, decision |
  Format-Table
```

### 10.3 USB Mass Storage Detection (F-AGT-13)

#### Step 1: Insert a USB flash drive

Plug in a USB thumb drive. The agent scans drive types on arrival.

Expected agent log:

```log
INFO  USB mass storage arrived -- blocking writes  drive=E
```

(The drive letter depends on your system.)

#### Step 2: Copy a sensitive file to USB

```cmd
copy C:\Restricted\financials.txt E:\
```

Expected: Agent detects T4 write to a removable drive and **blocks** the
operation (or logs DENY if in audit-only mode).

#### Step 3: Copy a public file to USB

```cmd
copy C:\Public\readme.txt E:\
```

Expected: T1 write to USB is **allowed** (non-sensitive data).

#### Step 4: Remove the USB drive

Safely eject or pull the drive.

Expected agent log:

```log
INFO  USB mass storage removed  drive=E
```

#### Step 5: Verify audit events

```powershell
Get-Content C:\ProgramData\DLP\logs\audit.jsonl |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Where-Object { $_.resource_path -like "E:\*" } |
  Format-Table timestamp, resource_path, classification, decision
```

### 10.4 Network Share / SMB Detection (F-AGT-14)

The agent monitors outbound SMB connections against a server whitelist.
By default, no servers are whitelisted -- all T3/T4 SMB writes are blocked.

#### Test 1: Copy to a non-whitelisted share

```cmd
copy C:\Confidential\report.docx \\some-server\share\
```

Expected: T3 write to non-whitelisted server is **blocked**.

#### Test 2: Copy non-sensitive data to any share

```cmd
copy C:\Public\readme.txt \\some-server\share\
```

Expected: T1 data is **allowed** regardless of whitelist.

#### Test 3: Whitelisted server (if configured)

If the agent is configured with a whitelist entry for `fileserver01.corp.local`:

```cmd
copy C:\Restricted\financials.txt \\fileserver01.corp.local\approved-share\
```

Expected: T4 write to a whitelisted server is **allowed**.

> **Note:** In Phase 1, the whitelist is configured programmatically via
> `NetworkShareDetector::with_whitelist()`. Runtime configuration via
> config file is planned for Phase 2.

### 10.5 Clipboard Monitoring (F-AGT-17)

The agent classifies clipboard text when paste events are detected.
Use PowerShell to set clipboard content for repeatable testing.

#### Test 1: SSN pattern (T4)

```powershell
Set-Clipboard -Value "Employee SSN: 123-45-6789"
```

Then paste into any application (Notepad, Word, etc.).

Expected: Agent detects T4 content (SSN pattern `XXX-XX-XXXX`), emits
`ClipboardEvent` with `classification: T4`.

#### Test 2: Credit card number (T4)

```powershell
Set-Clipboard -Value "Card: 4111-1111-1111-1111"
```

Paste into any application.

Expected: T4 classification (credit card pattern detected).

#### Test 3: Confidential keyword (T3)

```powershell
Set-Clipboard -Value "This document is CONFIDENTIAL and must not be shared"
```

Paste into any application.

Expected: T3 classification (keyword "confidential" matched).

#### Test 4: Internal keyword (T2)

```powershell
Set-Clipboard -Value "FOR INTERNAL ONLY - do not distribute"
```

Expected: T2 classification.

#### Test 5: Benign text (T1 -- no event)

```powershell
Set-Clipboard -Value "Hello, world!"
```

Expected: T1 classification. **No clipboard event emitted** (T1 is
filtered out to reduce noise).

#### Verify clipboard events

```powershell
Get-Content C:\ProgramData\DLP\logs\audit.jsonl |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Where-Object { $_.resource_path -eq "clipboard" } |
  Format-Table timestamp, classification, decision
```

### 10.6 Verify Complete Audit Trail

After running all the tests above, the audit log should contain events
for every operation. Run this summary to confirm coverage:

```powershell
$events = Get-Content C:\ProgramData\DLP\logs\audit.jsonl |
  ForEach-Object { $_ | ConvertFrom-Json }

# Event count by type
$events | Group-Object event_type | Format-Table Count, Name

# Event count by classification
$events | Group-Object classification | Format-Table Count, Name

# Event count by decision
$events | Group-Object decision | Format-Table Count, Name
```

Expected output should show:

| Event Type | Expected                            |
| ---------- | ----------------------------------- |
| `ACCESS`   | File read/write operations          |
| `BLOCK`    | T3/T4 to USB or non-whitelisted SMB |

| Classification | Expected                                    |
| -------------- | ------------------------------------------- |
| T4             | Restricted directory + SSN/CC clipboard     |
| T3             | Confidential directory + keyword clipboard  |
| T2             | Data directory + internal keyword clipboard |
| T1             | Public directory (if logged)                |

### 10.8 Cleanup Test Files

```cmd
rd /s /q C:\Restricted
rd /s /q C:\Confidential
rd /s /q C:\Data
rd /s /q C:\Public
```

---

## 11. Windows Service (Full Deployment Mode)

> **No manual elevation needed** — the service runs as `LocalSystem` (SYSTEM),
> which has full administrator privileges. File-system interception works automatically
> via the `notify` crate.

The service is managed with the provided PowerShell script:

```powershell
# Full path to the management script (repo root):
.\scripts\Manage-DlpAgentService.ps1 -Action <action>
```

### Service Status

```powershell
.\scripts\Manage-DlpAgentService.ps1 -Action Status
```

Expected output:

```
Status : Running
```

### Install and Start

```powershell
# Run from an elevated terminal (Administrator):
.\scripts\Manage-DlpAgentService.ps1 -Action Install
```

This registers the service with SCM (as `LocalSystem`, auto-start) and starts it immediately.

### Verify dlp-user-ui is Running

When the agent runs as a Windows Service (SYSTEM account), it spawns one
`dlp-user-ui.exe` process per active interactive session. Verify both
processes are running:

```powershell
# Check that the agent service is running:
Get-Process dlp-agent -ErrorAction SilentlyContinue |
    Select-Object Id, ProcessName, SessionId | Format-Table

# Check that the UI subprocess was spawned in your session:
Get-Process dlp-user-ui -ErrorAction SilentlyContinue |
    Select-Object Id, ProcessName, SessionId | Format-Table
```

Expected:

| Process       | Session                  | Account               |
| ------------- | ------------------------ | --------------------- |
| `dlp-agent`   | 0 (SYSTEM)               | `NT AUTHORITY\SYSTEM` |
| `dlp-user-ui` | Your session (e.g. 1, 2) | Your AD user account  |

If `dlp-user-ui` is **not** running:

1. Check the agent log for spawn errors:
   ```powershell
   Get-WinEvent -FilterHashtable @{
       LogName='Application'; StartTime=(Get-Date).AddMinutes(-5)
   } | Where-Object { $_.Message -match 'ui_spawner|spawn' } |
       Select-Object TimeCreated, Message | Format-List
   ```
2. Verify the UI binary exists next to the agent binary:
   ```powershell
   $agentPath = (Get-Process dlp-agent).Path
   $uiPath = Join-Path (Split-Path $agentPath) "dlp-user-ui.exe"
   Test-Path $uiPath   # Should be True
   ```
3. Verify the `DLP_UI_BINARY` environment variable is set (optional
   override for development):
   ```powershell
   [System.Environment]::GetEnvironmentVariable("DLP_UI_BINARY", "Machine")
   ```

> **Note:** The UI is only spawned in interactive sessions (session ID > 0).
> Session 0 (SYSTEM services) never gets a UI instance. If you are
> connected via Remote Desktop, the agent spawns a UI in your RDP session.

### Verify System Tray Icon

Once `dlp-user-ui.exe` is running in your session, look for the DLP tray
icon (blue square) in the Windows notification area (system tray). Right-click
it to see the context menu:

- **Show Portal** -- opens the admin portal URL (Phase 5 target)
- **Agent Status: Running** -- read-only status label
- **Exit** -- closes the UI (agent will respawn it within 15 seconds)

### Password-Protected Stop

When `sc stop dlp-agent` is issued, the service reports `STOP_PENDING` to the SCM
with a 120-second wait hint, then sends a `PASSWORD_DIALOG` to the UI via Pipe 1.
The admin password dialog appears on the interactive desktop. Expected behavior:

1. `sc stop dlp-agent` returns immediately (no error) and `sc query` shows `STOP_PENDING`
2. The UI displays a password dialog
3. Correct password: service stops cleanly
4. Wrong password (x3) or Cancel: service reverts to `RUNNING` (`sc query` confirms)

### Force-Stop (when password dialog is stuck)

If no UI is connected, the password dialog cannot be shown. The service remains
in `STOP_PENDING` until the 120-second wait hint expires. Force-kill:

```powershell
sc stop dlp-agent
# Wait up to 120s — if still running:
Stop-Process -Name dlp-agent -Force
sc query dlp-agent  # Should show STOPPED
```

Then re-register and restart:

```powershell
.\scripts\Manage-DlpAgentService.ps1 -Action Register
.\scripts\Manage-DlpAgentService.ps1 -Action Start
```

### Uninstall

```powershell
.\scripts\Manage-DlpAgentService.ps1 -Action Uninstall
```

### Verify Audit Log from Service

The service writes to the same log file as console mode:

```powershell
Get-Content C:\ProgramData\DLP\logs\audit.jsonl -Tail 10 -Encoding UTF8 |
    ForEach-Object { $_ | ConvertFrom-Json } |
    Select-Object timestamp, event_type, resource_path, classification, decision |
    Format-Table
```

Service trace output goes to the **Windows Event Log** (not a text file).
View with Event Viewer or:

```powershell
# Requires admin to read Event Log:
Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=(Get-Date).AddHours(-1)} |
    Where-Object { $_.Message -match 'dlp|DLP' } |
    Select-Object TimeCreated, Message | Format-List
```

### Service Crash Recovery

The service is configured with SCM crash-recovery actions (restart after 60 s for
the first three crashes). If the service keeps crashing, check:

1. Windows Event Viewer → Windows Logs → Application for `Error` level events
2. SCM events: `sc query dlp-agent` → last exit code
3. Audit log: `C:\ProgramData\DLP\logs\audit.jsonl` for partial entries

> **Password-protected stop:** The agent prompts for the dlp-admin
> password before allowing a stop. Three failed attempts abort the stop
> and log `EVENT_DLP_ADMIN_STOP_FAILED`. To stop without the dialog,
> use `sc stop dlp-agent` from an elevated terminal — the dialog will
> appear on the interactive desktop if a UI is connected.

---

## 12. Run the Automated Test Suite

### Full workspace (138 tests)

```cmd
cargo test
```

### Policy Engine only (33 tests: 20 unit + 13 integration)

```cmd
cargo test -p policy-engine
```

### Policy Engine integration tests only (13 tests)

```cmd
cargo test -p policy-engine --test integration
```

### DLP Agent only (105 tests: 78 unit + 20 integration + 7 negative)

```cmd
cargo test -p dlp-agent
```

### DLP Agent integration tests only (20 tests)

```cmd
cargo test -p dlp-agent --test integration
```

### DLP Agent negative tests only (7 tests)

```cmd
cargo test -p dlp-agent --test negative
```

### Clippy (zero warnings required)

```cmd
cargo clippy --workspace -- -D warnings
```

---

## 13. Troubleshooting

### File monitor not receiving events

If file operations are not appearing in the audit log:

- Verify the agent is running (`tasklist | findstr dlp-agent`)
- Look for `watching path` in the agent's log output confirming paths are monitored
- Check `C:\ProgramData\DLP\agent-config.toml` -- if `monitored_paths` lists specific directories, only those are watched
- Check that the file is not matched by a built-in or custom exclusion in `excluded_paths`
- The `notify` crate polls every 500 ms -- events may take up to 1 second to appear
- Network shares require an explicit UNC path in `monitored_paths` (not watched by default)

### Policy Engine port already in use

```
Error: failed to bind
```

Another process is using port 8443. Either stop it or change the port:

```cmd
set BIND_ADDR=127.0.0.1:9443
```

### Audit log directory missing

The agent writes to `C:\ProgramData\DLP\logs\`. Create the directory manually:

```cmd
# Run as Administrator:
mkdir C:\ProgramData\DLP\logs
```

If the directory does not exist when the agent starts, the first run will create it automatically.

### Policy file not found

If `POLICY_FILE` points to a non-existent path and the parent directory
does not exist, the engine will fail to start. Ensure the parent directory
exists or use the default (`./policies.json` in the current directory).

### Verbose logging

Set `RUST_LOG` for detailed output:

```cmd
set RUST_LOG=debug
```

Per-crate filtering:

```cmd
set RUST_LOG=policy_engine=debug,dlp_agent=trace
```

### Agent cannot reach Policy Engine

- Verify the engine is running: `curl http://127.0.0.1:8443/health`
- Check that the engine URL in `engine_client.rs` matches the engine's bind address
  (default: `https://localhost:8443`). The URL scheme (`http://` vs `https://`) does not
  affect connectivity — the client always connects over plain TCP. Only the host and port
  must match the engine's `BIND_ADDR`.

---

## 14. Component Summary

| Component     | Binary                    | Default Address                       | Config                                 |
| ------------- | ------------------------- | ------------------------------------- | -------------------------------------- |
| Policy Engine | `policy-engine.exe`       | `127.0.0.1:8443`                      | `BIND_ADDR`, `POLICY_FILE`, `RUST_LOG` |
| DLP Agent     | `dlp-agent.exe --console` | N/A (local service)                   | `RUST_LOG`                             |
| DLP User UI   | `dlp-user-ui.exe`         | N/A (spawned by agent)                | `RUST_LOG`, `DLP_UI_BINARY`            |
| Audit Log     | N/A (file output)         | `C:\ProgramData\DLP\logs\audit.jsonl` | Hardcoded path (Phase 1)               |

---

## 15. Phase 1 Endpoint Reference

### Policy Engine

| Method   | Path                     | Description                           |
| -------- | ------------------------ | ------------------------------------- |
| `GET`    | `/health`                | Liveness probe (always 200)           |
| `GET`    | `/ready`                 | Readiness probe (200 if store loaded) |
| `POST`   | `/evaluate`              | ABAC policy evaluation                |
| `GET`    | `/policies`              | List all policies                     |
| `POST`   | `/policies`              | Create a policy (returns 201)         |
| `GET`    | `/policies/:id`          | Get a policy by ID                    |
| `PUT`    | `/policies/:id`          | Update a policy                       |
| `DELETE` | `/policies/:id`          | Delete a policy (returns 204)         |
| `GET`    | `/policies/:id/versions` | Get version history (stub)            |
