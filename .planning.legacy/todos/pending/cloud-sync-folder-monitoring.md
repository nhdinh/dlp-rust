---
title: Implement Cloud Storage Sync Folder Monitoring with ABAC Enforcement
date: 2026-05-06
priority: 1
---

# Cloud Storage Sync Folder Monitoring

## Objective

Extend the dlp-agent to detect file writes to cloud storage sync folders and enforce DLP policies based on data classification and user context.

## Scope

- Monitor writes to known cloud sync folder paths:
  - OneDrive (`%USERPROFILE%\OneDrive`)
  - Google Drive (`%USERPROFILE%\Google Drive` or `%LOCALAPPDATA%\Google\DriveFS`)
  - Dropbox (`%USERPROFILE%\Dropbox`)
  - Other detected sync clients
- Evaluate write against ABAC policy context:
  - User role / AD group membership
  - Time of day / endpoint location
  - Data classification tier of file being written
  - Cloud service allowlist status
- Enforce: ALLOW, DENY, or DENY + ALERT

## Acceptance Criteria

- [ ] Agent detects file writes to cloud sync folders in real-time
- [ ] Policy engine evaluates write against all four ABAC context signals
- [ ] Denied writes are blocked before upload sync begins
- [ ] Allowed writes to sanctioned services proceed without friction
- [ ] Audit log captures sync event, policy decision, and outcome
- [ ] Handles both "personal" and "business" tiers of same service (e.g., OneDrive Personal vs OneDrive for Business)

## Notes

- Detection via filesystem minifilter on known sync paths, or by monitoring sync client processes
- Sync folders can be relocated by users — detection should not depend solely on default paths
- Consider monitoring sync client registry keys / config to discover actual sync root paths
- False positive risk: users legitimately sync T1/T2 files to corporate-managed cloud storage
