# Phase 65: UAT — Service Stop Blocking Threads Fix

## Test Environment

- Windows 10/11 host with dlp-agent installed as service
- dlp-admin password configured
- UI binary (dlp-user-ui.exe) present

## Test Cases

### TC-01: Clean Stop with Correct Password
1. Ensure service is Running: `Get-Service dlp-agent`
2. Run: `sc stop dlp-agent`
3. Enter correct dlp-admin password in UI dialog
4. **Expected**: Service transitions to Stopped within 10 seconds
5. **Verify**: `Get-Process dlp-agent` returns no results

### TC-02: Stop with Wrong Password (3x)
1. Ensure service is Running
2. Run: `sc stop dlp-agent`
3. Enter wrong password 3 times
4. **Expected**: UI closes, service reverts to Running
5. **Verify**: `Get-Service dlp-agent` shows Status = Running

### TC-03: Stop with Cancel
1. Ensure service is Running
2. Run: `sc stop dlp-agent`
3. Click Cancel in UI dialog
4. **Expected**: Service reverts to Running
5. **Verify**: `Get-Service dlp-agent` shows Status = Running

### TC-04: Stop via PowerShell Script
1. Ensure service is Running
2. Run: `.\Manage-DlpAgentService.ps1 -Action Stop`
3. Enter correct password
4. **Expected**: Script reports "Service stopped successfully"
5. **Verify**: `Get-Service dlp-agent` shows Status = Stopped

### TC-05: PowerShell Script Detects StopPending
1. Start a stop: `sc stop dlp-agent`
2. While in StopPending, run: `.\Manage-DlpAgentService.ps1 -Action Stop`
3. **Expected**: Script detects StopPending and prints guidance instead of error

### TC-06: Restart After Stop
1. Stop service (TC-01)
2. Run: `sc start dlp-agent`
3. **Expected**: Service starts successfully
4. **Verify**: Chrome, IPC, health monitor, session monitor all functional

### TC-07: Multiple Stop/Start Cycles
1. Repeat TC-01 and TC-06 three times
2. **Expected**: Each cycle completes cleanly

### TC-08: Stop with No Active UI Session
1. Log off all interactive sessions (or run on headless server)
2. Run: `sc stop dlp-agent`
3. **Expected**: Stop times out after 120s, service reverts to Running
4. **Verify**: Service shows Running after timeout
