# S01: USB Enforcement Fix — PnP Disable Actually Works — UAT

**Milestone:** M008
**Written:** 2026-05-08T05:35:04.287Z

### UAT: USB Enforcement Fix

1. Plug a blocked USB device
2. Verify agent logs show resolved CM instance ID (not constructed VID/PID/serial)
3. Verify CM_Disable_DevNode succeeds
4. Verify file writes to the device fail with OS-level access denied
5. Verify audit event includes correct device identity fields
