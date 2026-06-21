---
status: in-progress
description: Verify that dlp-agent no longer spawns the dlp-user-ui process.
---

# Quick Check: dlp-user-ui not spawned by dlp-agent

## Goal
Confirm whether `dlp-agent` still spawns `dlp-user-ui` on service startup or session change.

## Method
1. Search `dlp-agent/src` for UI spawner code and call sites.
2. Trace the path from `service.rs` startup through `session_monitor.rs` to `ui_spawner.rs`.
3. Check for any conditional guards, feature flags, or recent commits that disable spawning.
4. Check tests for assertions that spawning is disabled.

## Expected Result
If the change was already made, `ui_spawner::init()` and `spawn_ui_in_session()` should have no active callers from `dlp-agent` startup/session logic.
