# S03: Grace Period / Quarantine for New Disk Arrivals — UAT

**Milestone:** M008
**Written:** 2026-05-08T05:35:04.288Z

### UAT: Grace Period

1. Set disk_grace_period_seconds = 300 in agent-config.toml
2. Insert unregistered disk
3. Verify drive letter appears and reads succeed
4. Verify writes are blocked with toast notification
5. Wait 5 minutes
6. Verify drive letter disappears (mount-time block engages)
