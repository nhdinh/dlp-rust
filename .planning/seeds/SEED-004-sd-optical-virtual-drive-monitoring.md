---
title: SD Card, Optical Drive, and Virtual Drive Monitoring
planted_date: 2026-05-06
trigger_condition: When network drive and cloud sync monitoring are deployed and stable
---

# SEED-004: SD Card, Optical Drive, and Virtual Drive Monitoring

## Description

Extend the dlp-agent's storage monitoring coverage to remaining logical/physical interfaces once the high-priority network and cloud paths are operational.

## Interfaces

### SD Cards / Card Readers
- Detect SD card insertions via USB mass storage or direct card reader interfaces
- Apply same ABAC policy framework: user role, time, data tier, device allowlist
- Block or alert based on policy evaluation

### Optical Drives (CD/DVD/Blu-ray)
- Detect disc insertions and burning operations
- Monitor write operations to optical media
- Note: diminishing threat surface on modern endpoints; may be lower priority

### Virtual Drives
- Detect virtual drive creation (Daemon Tools, VM disk mounts, ISO mounting via Windows Explorer)
- Monitor for sensitive data being copied to mounted virtual disk images
- Block or alert based on policy evaluation

## Trigger Condition

Activate this seed when:
1. Network drive monitoring (TODO) is deployed and metrics show stable enforcement
2. Cloud sync folder monitoring (TODO) is deployed and metrics show stable enforcement
3. Policy engine has proven it can handle multiple storage event types uniformly

## Estimated Effort

Medium — each interface requires its own detection mechanism, but the policy evaluation and enforcement pipeline will already be built.
