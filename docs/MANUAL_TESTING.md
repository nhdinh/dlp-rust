# Manual Testing Guide -- Phase 1

**Date:** 2026-04-01
**Status:** Phase 1 complete (46/46 tasks, 177 tests)

This guide walks through building, running, and manually testing every
Phase 1 component on a Windows development machine.

---

## 1. Prerequisites

| Requirement | Version | Check |
|-------------|---------|-------|
| Windows | 10 or 11 | `winver` |
| Rust toolchain | stable 1.75+ | `rustup show` |
| Git | any | `git --version` |
| curl (or Invoke-WebRequest) | any | Ships with Windows 10+ |
| Admin terminal | -- | Required only for Windows Service operations |

Clone the repository if you haven't already:

```cmd
git clone <repo-url> dlp-rust
cd dlp-rust
```

---

## 2. Build

Build all workspace crates in release mode:

```cmd
cargo build --release
```

Output binaries:

| Binary | Path |
|--------|------|
| Policy Engine | `target\release\policy-engine.exe` |
| DLP Agent | `target\release\dlp-agent.exe` |

To build a single crate:

```cmd
cargo build -p policy-engine --release
cargo build -p dlp-agent --release
```

---

## 3. Start the Policy Engine

Open **Terminal 1** and run:

```cmd
set RUST_LOG=info
cargo run -p policy-engine
```

The engine listens on `http://127.0.0.1:8443` by default.

### Configuration (environment variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `BIND_ADDR` | `127.0.0.1:8443` | Listen address and port |
| `POLICY_FILE` | `./policies.json` | Path to the policy JSON file |
| `RUST_LOG` | `info` | Log level (`trace`, `debug`, `info`, `warn`, `error`) |

Example with custom settings:

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

The engine starts with an empty policy set. Use the REST API to add the
three standard ABAC rules from `docs/ABAC_POLICIES.md`.

### Rule 1: T4 Deny All

```cmd
curl -X POST http://127.0.0.1:8443/policies ^
  -H "Content-Type: application/json" ^
  -d "{\"id\":\"pol-001\",\"name\":\"T4 Deny All\",\"description\":\"Block all access to T4 Restricted resources\",\"priority\":1,\"conditions\":[{\"Classification\":{\"op\":\"eq\",\"value\":\"T4\"}}],\"action\":\"DENY\",\"enabled\":true,\"version\":1}"
```

### Rule 2: T3 Unmanaged Device Deny

```cmd
curl -X POST http://127.0.0.1:8443/policies ^
  -H "Content-Type: application/json" ^
  -d "{\"id\":\"pol-002\",\"name\":\"T3 Unmanaged Block\",\"description\":\"Block T3 from unmanaged devices\",\"priority\":2,\"conditions\":[{\"Classification\":{\"op\":\"eq\",\"value\":\"T3\"}},{\"DeviceTrust\":{\"op\":\"eq\",\"value\":\"Unmanaged\"}}],\"action\":\"DENY\",\"enabled\":true,\"version\":1}"
```

### Rule 3: T2 Allow with Logging

```cmd
curl -X POST http://127.0.0.1:8443/policies ^
  -H "Content-Type: application/json" ^
  -d "{\"id\":\"pol-003\",\"name\":\"T2 Allow with Log\",\"description\":\"Permit T2 access with audit logging\",\"priority\":3,\"conditions\":[{\"Classification\":{\"op\":\"eq\",\"value\":\"T2\"}}],\"action\":\"ALLOW_WITH_LOG\",\"enabled\":true,\"version\":1}"
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
  -d "{\"subject\":{\"user_sid\":\"S-1-5-21-123\",\"user_name\":\"jsmith\",\"groups\":[],\"device_trust\":\"Managed\",\"network_location\":\"Corporate\"},\"resource\":{\"path\":\"C:\\\\Restricted\\\\secrets.xlsx\",\"classification\":\"T4\"},\"environment\":{\"timestamp\":\"2026-04-01T12:00:00Z\",\"session_id\":1,\"access_context\":\"Local\"},\"action\":\"COPY\"}"
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
  -d "{\"subject\":{\"user_sid\":\"S-1-5-21-123\",\"user_name\":\"jsmith\",\"groups\":[],\"device_trust\":\"Managed\",\"network_location\":\"Corporate\"},\"resource\":{\"path\":\"C:\\\\Data\\\\report.xlsx\",\"classification\":\"T2\"},\"environment\":{\"timestamp\":\"2026-04-01T12:00:00Z\",\"session_id\":1,\"access_context\":\"Local\"},\"action\":\"WRITE\"}"
```

Expected: `"decision": "ALLOW_WITH_LOG"`, `"matched_policy_id": "pol-003"`.

### Test 3: T1 resource -- expect default DENY (no matching policy)

```cmd
curl -X POST http://127.0.0.1:8443/evaluate ^
  -H "Content-Type: application/json" ^
  -d "{\"subject\":{\"user_sid\":\"S-1-5-21-123\",\"user_name\":\"jsmith\",\"groups\":[],\"device_trust\":\"Managed\",\"network_location\":\"Corporate\"},\"resource\":{\"path\":\"C:\\\\Public\\\\readme.txt\",\"classification\":\"T1\"},\"environment\":{\"timestamp\":\"2026-04-01T12:00:00Z\",\"session_id\":1,\"access_context\":\"Local\"},\"action\":\"READ\"}"
```

Expected: `"decision": "DENY"`, `"matched_policy_id": null` (no T1 rule loaded -- default-deny).

---

## 6. Policy CRUD Operations

### Update a policy

```cmd
curl -X PUT http://127.0.0.1:8443/policies/pol-003 ^
  -H "Content-Type: application/json" ^
  -d "{\"id\":\"pol-003\",\"name\":\"T2 Allow with Log (Updated)\",\"description\":\"Updated description\",\"priority\":3,\"conditions\":[{\"Classification\":{\"op\":\"eq\",\"value\":\"T2\"}}],\"action\":\"ALLOW_WITH_LOG\",\"enabled\":true,\"version\":1}"
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

Open **Terminal 2** and run:

```cmd
set RUST_LOG=info
cargo run -p dlp-agent -- --console
```

Console mode runs the agent in the foreground without registering as a
Windows Service. Press `Ctrl+C` to stop.

> **Note:** The agent requires the Policy Engine to be running for online
> evaluation. If the engine is not reachable, the agent operates in offline
> mode with fail-closed semantics (DENY for T3/T4 on cache miss).

---

## 8. View Audit Logs

The agent writes structured JSONL audit events to:

```
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

   ```
   WARN  Policy Engine unreachable -- entering offline mode
   ```

4. In offline mode:
   - **T3/T4 resources** with no cache entry are **DENIED** (fail-closed).
   - **T1/T2 resources** with no cache entry are **ALLOWED** (default-allow for non-sensitive).
   - Cached decisions continue to be served until TTL expires (default 60 s).

5. **Restart the Policy Engine**. The agent's heartbeat loop (30 s interval)
   detects the engine is back and transitions to online mode:

   ```
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

| Directory | Classification | Sensitivity |
|-----------|---------------|-------------|
| `C:\Restricted\` | T4 Restricted | Highest -- fail-closed DENY |
| `C:\Confidential\` | T3 Confidential | High |
| `C:\Data\` | T2 Internal | Moderate |
| `C:\Public\` | T1 Public | Low |

### 10.2 File Operations (F-AGT-05)

The agent monitors file system events via ETW. Perform these operations
and check the agent log after each one.

#### Create a file

```cmd
echo "Q4 Financial Results" > C:\Restricted\financials.txt
echo "Internal Memo" > C:\Data\memo.txt
echo "Public README" > C:\Public\readme.txt
```

Expected agent log: `FileAction::Created` for each file, with
classification T4, T2, and T1 respectively.

#### Write / modify a file

```cmd
echo "Updated figures" >> C:\Restricted\financials.txt
```

Expected: `FileAction::Written` with path `C:\Restricted\financials.txt`,
classification T4.

#### Copy a file

```cmd
copy C:\Restricted\financials.txt C:\Restricted\financials_backup.txt
```

Expected: `FileAction::Created` for the new file (copy triggers a create +
write sequence in ETW).

#### Rename / move a file

```cmd
ren C:\Data\memo.txt memo_archived.txt
move C:\Data\memo_archived.txt C:\Public\memo_archived.txt
```

Expected: `FileAction::Moved` for each operation. The rename stays in T2;
the move changes the path to T1 (`C:\Public\`).

#### Delete a file

```cmd
del C:\Public\readme.txt
```

Expected: `FileAction::Deleted` with classification T1.

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

```
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

```
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

### 10.6 ETW Bypass Detection (F-AGT-18)

The ETW bypass detector compares hook-intercepted operations against ETW
file-system events. If ETW reports an operation that the hooks did **not**
intercept, the agent logs `EVASION_SUSPECTED`.

#### How it works in Phase 1

In Phase 1, file interception uses ETW only (no API hooks yet). The
bypass detector's hook log is empty, so **every ETW event triggers an
evasion signal**. This is expected behavior -- it confirms the ETW
subscriber is receiving events and the correlation logic works.

In Phase 2, when API hooks are added, the bypass detector will only
fire for operations that bypass the hooks -- the intended production
behavior.

#### Trigger an evasion event

Any file operation in a monitored directory triggers an ETW event:

```cmd
echo "test" > C:\Data\etw_test.txt
```

Expected agent log:

```
WARN  EVASION_SUSPECTED: ETW event with no matching hook intercept
      path=C:\Data\etw_test.txt  process_id=<PID>  etw_operation=CreateFile
```

#### Verify in audit log

```powershell
Get-Content C:\ProgramData\DLP\logs\audit.jsonl |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Where-Object { $_.event_type -eq "EVASION_SUSPECTED" } |
  Format-Table timestamp, resource_path, action_attempted
```

### 10.7 Verify Complete Audit Trail

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

| Event Type | Expected |
|------------|----------|
| `ACCESS` | File read/write operations |
| `BLOCK` | T3/T4 to USB or non-whitelisted SMB |
| `EVASION_SUSPECTED` | ETW events without hook match (Phase 1) |

| Classification | Expected |
|---------------|----------|
| T4 | Restricted directory + SSN/CC clipboard |
| T3 | Confidential directory + keyword clipboard |
| T2 | Data directory + internal keyword clipboard |
| T1 | Public directory (if logged) |

### 10.8 Cleanup Test Files

```cmd
rd /s /q C:\Restricted
rd /s /q C:\Confidential
rd /s /q C:\Data
rd /s /q C:\Public
```

---

## 11. Windows Service Installation (Optional)

These steps require an **elevated (Administrator) terminal**.

### Install

```cmd
sc create dlp-agent type= own start= auto binpath= "C:\path\to\dlp-agent.exe"
```

### Start

```cmd
sc start dlp-agent
```

### Stop

```cmd
sc stop dlp-agent
```

> **Password-protected stop:** The agent prompts for the `dlp-admin` AD
> password before allowing a stop. Three failed attempts abort the stop
> and log `EVENT_DLP_ADMIN_STOP_FAILED`.

### Uninstall

```cmd
sc stop dlp-agent
sc delete dlp-agent
```

---

## 12. Run the Automated Test Suite

### Full workspace (177 tests)

```cmd
cargo test
```

### Policy Engine only (36 tests)

```cmd
cargo test -p policy-engine
```

### Policy Engine integration tests only (13 tests)

```cmd
cargo test -p policy-engine --test integration
```

### DLP Agent only (122 tests)

```cmd
cargo test -p dlp-agent
```

### DLP Agent integration tests only (23 tests)

```cmd
cargo test -p dlp-agent --test integration
```

### DLP Agent negative tests only (8 tests)

```cmd
cargo test -p dlp-agent --test negative
```

### Clippy (zero warnings required)

```cmd
cargo clippy --workspace -- -D warnings
```

---

## 13. Troubleshooting

### Port already in use

```
Error: failed to bind
```

Another process is using port 8443. Either stop it or change the port:

```cmd
set BIND_ADDR=127.0.0.1:9443
```

### Audit log directory permission denied

The agent writes to `C:\ProgramData\DLP\logs\`. If running in console mode
as a non-admin user, this directory may not be writable. Create it manually:

```cmd
mkdir C:\ProgramData\DLP\logs
```

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
- Check the `DEFAULT_ENGINE_URL` in `engine_client.rs` matches the engine's
  bind address (default: `https://localhost:8443`)
- For development without TLS, the engine client is constructed with
  `tls_verify=false`

---

## 14. Component Summary

| Component | Binary | Default Address | Config |
|-----------|--------|-----------------|--------|
| Policy Engine | `policy-engine.exe` | `127.0.0.1:8443` | `BIND_ADDR`, `POLICY_FILE`, `RUST_LOG` |
| DLP Agent | `dlp-agent.exe --console` | N/A (local service) | `RUST_LOG` |
| Audit Log | N/A (file output) | `C:\ProgramData\DLP\logs\audit.jsonl` | Hardcoded path (Phase 1) |

---

## 15. Phase 1 Endpoint Reference

### Policy Engine

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness probe (always 200) |
| `GET` | `/ready` | Readiness probe (200 if store loaded) |
| `POST` | `/evaluate` | ABAC policy evaluation |
| `GET` | `/policies` | List all policies |
| `POST` | `/policies` | Create a policy (returns 201) |
| `GET` | `/policies/:id` | Get a policy by ID |
| `PUT` | `/policies/:id` | Update a policy |
| `DELETE` | `/policies/:id` | Delete a policy (returns 204) |
| `GET` | `/policies/:id/versions` | Get version history (stub) |
