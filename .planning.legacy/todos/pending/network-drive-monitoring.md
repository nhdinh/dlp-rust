---
title: Implement Network Drive Mapping Monitoring with ABAC Enforcement
date: 2026-05-06
priority: 1
---

# Network Drive Mapping Monitoring

## Objective

Extend the dlp-agent to monitor for new network drive mappings and enforce DLP policies on them via the existing ABAC framework.

## Scope

- Detect new network drive mappings (e.g., `net use`, Explorer "Map Network Drive")
- Evaluate mapping against ABAC policy context:
  - User role / AD group membership
  - Time of day / endpoint location
  - Data classification tier being accessed
  - Destination server/path allowlist status
- Enforce: ALLOW, DENY, or DENY + ALERT based on policy result

## Acceptance Criteria

- [ ] Agent detects new network drive mappings in real-time (or near-real-time)
- [ ] Policy engine evaluates mapping against all four ABAC context signals
- [ ] Denied mappings are blocked before data transfer begins
- [ ] Allowed mappings to allowlisted destinations proceed without friction
- [ ] Audit log captures mapping event, policy decision, and outcome
- [ ] Works with both UNC paths (`\\server\share`) and mapped drive letters (`Z:`)

## Notes

- Consider WMI event subscription (`Win32_VolumeChangeEvent` with type 2 for network) or periodic polling of `Win32_LogicalDisk` where `DriveType = 4`
- May need to hook into `NetShareEnum` or filter at the filesystem filter driver level for deeper enforcement
- Coordinate with existing USB/fixed-disk monitoring to present unified "storage event" abstraction in policy engine
