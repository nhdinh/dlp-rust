# DPAPI Master-Key Recovery Runbook

## Overview

This document covers recovery procedures when DPAPI unprotect fails on agent
restart, causing all encrypted secrets to become unreadable.

DPAPI (Data Protection API) binds encrypted keys to the Windows host via the
machine LSA secret. When a Windows host is reimaged, the profile is reset, or
the LSA secret rotates, `CryptUnprotectData` returns `NTE_BAD_KEY_STATE`
(0x8009000B). All secrets in `secret_kek_history` become unrecoverable without
intervention.

## Prerequisites

Before attempting recovery:

- Access to the DLP agent host with local administrator privileges.
- `DLP_KEK_SEED` environment variable value (for re-init flow) OR an offline
  backup of the `secret_kek_history` table (for restore flow).
- PowerShell 5.1 or later.
- dlp-admin-cli access (for verification steps).

## Understanding DPAPI Failure

DPAPI fails when the machine LSA secret changes:

- Windows reimage or profile reset generates a new LSA secret.
- `CryptUnprotectData` returns `NTE_BAD_KEY_STATE` (0x8009000B).
- All secrets in `secret_kek_history` become unrecoverable without
  intervention.
- The agent logs: "DPAPI unprotect failed -- secrets unavailable".

## Flow 1: Re-Init from Environment Variables

Use this flow when `DLP_KEK_SEED` is available.

### Step 1: Verify DPAPI failure

```powershell
$agentLog = Get-Content "C:\ProgramData\DLP\logs\dlp-agent.log" -Tail 50
if ($agentLog -match "DPAPI unprotect failed") {
    Write-Host "DPAPI failure confirmed -- proceeding with re-init"
}
```

### Step 2: Set the KEK seed environment variable

```powershell
[Environment]::SetEnvironmentVariable("DLP_KEK_SEED", "your-seed-value", "Machine")
```

### Step 3: Restart the DLP agent service

```powershell
Restart-Service dlp-agent
```

### Step 4: Verify recovery

```powershell
$newLog = Get-Content "C:\ProgramData\DLP\logs\dlp-agent.log" -Tail 20
if ($newLog -match "KEK re-initialized from environment seed") {
    Write-Host "Recovery successful"
}
```

### What happens during re-init

1. The agent detects `DLP_KEK_SEED` at startup.
2. Derives a new KEK from PBKDF2(seed, salt, iterations).
3. Inserts a new row into `secret_kek_history`.
4. Re-encrypts all secrets under the new KEK.
5. Logs success and clears the env var (optional security measure).

## Flow 2: Restore from Backup

Use this flow when `DLP_KEK_SEED` is NOT available.

### Step 1: Stop the DLP agent

```powershell
Stop-Service dlp-agent
```

### Step 2: Restore the secret_kek_history row from backup

```powershell
$backup = Get-Content "C:\DLP-Backups\secret_kek_history.json" | ConvertFrom-Json
$dbPath = "C:\ProgramData\DLP\dlp-server.db"
$conn = New-Object System.Data.SQLite.SQLiteConnection "Data Source=$dbPath"
$conn.Open()
$cmd = $conn.CreateCommand()
$cmd.CommandText = @"
    INSERT OR REPLACE INTO secret_kek_history
    (version, master_seed_dpapi, pbkdf2_salt, pbkdf2_iterations, created_at, retired_at)
    VALUES (@version, @seed, @salt, @iter, @created, NULL)
"@
$cmd.Parameters.AddWithValue("@version", $backup.version)
$cmd.Parameters.AddWithValue("@seed", [Convert]::FromBase64String($backup.master_seed_dpapi_b64))
$cmd.Parameters.AddWithValue("@salt", [Convert]::FromBase64String($backup.pbkdf2_salt_b64))
$cmd.Parameters.AddWithValue("@iter", $backup.pbkdf2_iterations)
$cmd.Parameters.AddWithValue("@created", $backup.created_at)
$cmd.ExecuteNonQuery()
$conn.Close()
```

### Step 3: Restart the agent

```powershell
Start-Service dlp-agent
```

### Step 4: Verify

```powershell
dlp-admin-cli secrets verify
```

### Backup format notes

- Backup format: JSON with base64-encoded BLOB fields.
- The restored KEK row must have `retired_at IS NULL` to be active.
- Agent loads the restored KEK on next startup.

## PowerShell Verification Snippets

### Verify KEK integrity (if registry backup exists)

```powershell
Test-Path "HKLM:\SOFTWARE\DLP\Backup"
```

### Check active KEK version

```powershell
$dbPath = "C:\ProgramData\DLP\dlp-server.db"
$conn = New-Object System.Data.SQLite.SQLiteConnection "Data Source=$dbPath"
$conn.Open()
$cmd = $conn.CreateCommand()
$cmd.CommandText = "SELECT version FROM secret_kek_history WHERE retired_at IS NULL"
$reader = $cmd.ExecuteReader()
while ($reader.Read()) {
    Write-Host "Active KEK version: $($reader.GetInt32(0))"
}
$conn.Close()
```

### Verify secret decryption

Attempt to read a known encrypted column (e.g., `smtp_password_encrypted`)
via dlp-admin-cli:

```powershell
dlp-admin-cli secrets verify --target smtp_password_encrypted
```

## UAT Checklist

### Positive cases

- [ ] Operator can identify DPAPI failure from agent logs.
- [ ] Operator can execute re-init-from-env-vars flow without manual SQL.
- [ ] Operator can execute restore-from-backup flow with provided PowerShell
      script.
- [ ] After recovery, agent successfully decrypts all secrets.
- [ ] After recovery, SIEM relay forwards events correctly.
- [ ] After recovery, admin API JWT authentication works.
- [ ] Documented PowerShell snippets execute without modification on Windows 11.

### Negative cases

- [ ] **Negative:** chmod/write/delete denied with agent stopped (DACL tripwire
      holds).
- [ ] **Negative:** `icacls /reset` on protected path is repaired by watcher
      within 60s.
- [ ] **Negative:** Staged removal creates no tamper alert.
- [ ] **Negative:** Expired staged removal (after GC) DOES create tamper alert
      on next ACL change.
- [ ] **Negative:** Oversized ACL (>60KB) rejected with clear error and audit
      event.
- [ ] **Negative:** Junction under protected tree is skipped and audited.

## Rollback Procedures

- If re-init fails, stop agent and restore from backup.
- If restore fails, contact support with agent logs and backup file.
- Never delete `secret_kek_history` rows unless explicitly instructed.

## References

- Phase 47 research:
  `.planning/phases/47-secrets-encryption-at-rest/47-RESEARCH.md`
- SecretCrypto module: `dlp-server/src/crypto/mod.rs`
- Agent DB path: `C:\ProgramData\DLP\agent.db`
- Server DB path: `C:\ProgramData\DLP\dlp-server.db`
- Service name: `dlp-agent`
- Env var: `DLP_KEK_SEED`
