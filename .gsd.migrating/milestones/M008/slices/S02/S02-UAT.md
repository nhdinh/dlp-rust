# S02: Mount-Time Blocking for Unregistered Disks — UAT

**Milestone:** M008
**Written:** 2026-05-08T05:35:04.288Z

### UAT: Mount-Time Blocking

1. Insert unregistered fixed disk (USB-bridged SATA/NVMe)
2. Verify disk does not appear in Explorer (no drive letter)
3. Verify I/O-time blocking still fires if mount-time block is bypassed
4. Verify audit event includes disk identity fields
