---
sliceId: S04
title: Disk enforcement
status: complete
completedAt: 2026-05-03
tasksCompleted: 3
---

# S04: Disk enforcement

## What was delivered

Runtime enforcement that blocks writes to unregistered disks. When a file operation targets an unregistered drive, the agent blocks the write and sends a user notification toast. Enforcement uses the disk allowlist from S03 and disk identity from S01 to make allow/deny decisions.

## Key files

- `dlp-agent/src/disk_enforcer.rs` — enforcement logic
- `dlp-agent/src/interception/file_monitor.rs` — file operation interception
- `dlp-agent/src/interception/policy_mapper.rs` — policy mapping for disk decisions

## Decisions made

- Disk enforcement block uses `continue` to skip ABAC (mirrors USB enforcement short-circuit)
- Toast format: '{model} ({drive_letter}:) - this disk is not registered' with optional drive letter
