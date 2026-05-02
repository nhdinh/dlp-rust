---
phase: 34-bitlocker-verification
plan: "02"
subsystem: dlp-agent/config
tags: [config, agent, encryption, clamp, bitlocker, tdd]
completed: "2026-05-03"

dependency_graph:
  requires:
    - "34-01 (dlp-common DiskIdentity extension — zero file overlap, safe to parallelize)"
  provides:
    - "AgentConfig.encryption: EncryptionConfig with resolved_recheck_interval() accessor"
    - "ENCRYPTION_RECHECK_DEFAULT_SECS (21600), MIN_SECS (300), MAX_SECS (86400) constants"
  affects:
    - "34-04 (service wiring — calls agent_config.resolved_recheck_interval() at startup)"

tech_stack:
  added: []
  patterns:
    - "Option<T> substruct field with #[serde(default)] — absent TOML section yields Default::default()"
    - "resolved_X() accessor pattern — mirrors resolved_log_level(); applies clamping + warn! at use site"
    - "u64::clamp(min, max) for safe config value bounds — no panic, no crash, audit trail via warn!"

key_files:
  modified:
    - dlp-agent/src/config.rs

decisions:
  - "warn! on out-of-range fires at use site (resolved_recheck_interval call), not at TOML parse time — consistent with existing resolved_log_level pattern"
  - "Doc-comment example block at file top intentionally NOT extended — deferred to docs polish (out of task scope)"
  - "tracing::warn is already imported at line 53 (use tracing::{info, warn}) — no new import needed"
  - "Existing struct literal tests updated to include encryption: EncryptionConfig::default() (Rule 1 auto-fix for new required field)"

metrics:
  duration_mins: 15
  tasks_completed: 1
  files_modified: 1
---

# Phase 34 Plan 02: EncryptionConfig Substruct + Clamp Accessor Summary

`AgentConfig` gains `pub encryption: EncryptionConfig` with `resolved_recheck_interval() -> Duration` that clamps `[encryption].recheck_interval_secs` to `[300, 86400]` and emits `warn!` on out-of-range values without refusing to start.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 34-02-T1 (RED) | Failing tests for EncryptionConfig | 241bdb1 | dlp-agent/src/config.rs |
| 34-02-T1 (GREEN) | EncryptionConfig substruct + accessor | 0c6f8e6 | dlp-agent/src/config.rs |

## What Was Built

### Constants (dlp-agent/src/config.rs lines 60-68)

Three module-level `pub const` values:
- `ENCRYPTION_RECHECK_DEFAULT_SECS: u64 = 21_600` (6 hours)
- `ENCRYPTION_RECHECK_MIN_SECS: u64 = 300` (5 minutes)
- `ENCRYPTION_RECHECK_MAX_SECS: u64 = 86_400` (24 hours)

### EncryptionConfig struct (lines 82-91)

```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EncryptionConfig {
    #[serde(default)]
    pub recheck_interval_secs: Option<u64>,
}
```

- `Default` derived so `#[serde(default)]` at the field level on `AgentConfig` works when `[encryption]` section is absent.
- TOML round-trip: `[encryption]\nrecheck_interval_secs = 600\n` deserializes correctly.

### AgentConfig.encryption field (line 152)

```rust
#[serde(default)]
pub encryption: EncryptionConfig,
```

Inserted after `log_level` field, mirrors the existing `#[serde(default)]` style.

### resolved_recheck_interval() accessor (lines 312-338)

```rust
pub fn resolved_recheck_interval(&self) -> std::time::Duration {
    let raw = self.encryption.recheck_interval_secs
        .unwrap_or(ENCRYPTION_RECHECK_DEFAULT_SECS);
    let clamped = raw.clamp(ENCRYPTION_RECHECK_MIN_SECS, ENCRYPTION_RECHECK_MAX_SECS);
    if clamped != raw {
        warn!(
            requested = raw,
            applied = clamped,
            min = ENCRYPTION_RECHECK_MIN_SECS,
            max = ENCRYPTION_RECHECK_MAX_SECS,
            "encryption.recheck_interval_secs out of range -- clamped"
        );
    }
    std::time::Duration::from_secs(clamped)
}
```

**warn! message text:** `"encryption.recheck_interval_secs out of range -- clamped"` — contains `out of range` substring for SIEM rules (`LIKE '%out of range%'`). Plan 34-04 service wiring may assert against this text in integration scenarios.

## TDD Gate Compliance

- RED commit: `241bdb1` — `test(34-02): add failing tests for EncryptionConfig clamp accessor (RED)` — 6 tests that failed to compile (missing constants, struct, method)
- GREEN commit: `0c6f8e6` — `feat(34-02): add EncryptionConfig substruct + resolved_recheck_interval clamp accessor (GREEN)` — all 26 config tests pass

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Updated existing struct literal tests for new `encryption` field**
- **Found during:** Task 1 GREEN implementation
- **Issue:** `test_resolve_watch_paths_configured`, `test_agent_config_save_roundtrip`, and `test_agent_config_save_preserves_server_url` used exhaustive struct literal syntax and failed to compile after adding the `encryption` field to `AgentConfig`
- **Fix:** Added `encryption: EncryptionConfig::default()` to each affected struct literal in the test module
- **Files modified:** dlp-agent/src/config.rs (test module only)
- **Commit:** 0c6f8e6 (included in GREEN commit)

**2. [Rule 1 - Style] Applied rustfmt formatting to new test code**
- **Found during:** Task 1 GREEN verification (`cargo fmt --check`)
- **Issue:** Multi-line `format!` calls in `test_encryption_recheck_interval_boundary_values_pass_through` did not match rustfmt style
- **Fix:** Ran `cargo fmt -p dlp-agent -- dlp-agent/src/config.rs` to auto-format
- **Files modified:** dlp-agent/src/config.rs
- **Commit:** Included in GREEN commit (0c6f8e6)

None — plan executed exactly as designed with minor auto-fixes for compilation and formatting.

## Notes for Downstream Plans

- **Plan 34-04 (service wiring):** Call `agent_config.resolved_recheck_interval()` to get the `Duration` for the periodic re-check task. The method is on `AgentConfig` in `dlp-agent/src/config.rs`.
- **warn! text for integration assertions:** `"encryption.recheck_interval_secs out of range -- clamped"` — structured fields: `requested`, `applied`, `min`, `max`.
- **Doc-comment example block** (file-top `//!` block): Intentionally NOT extended with `[encryption]` example — deferred to docs polish, out of scope for this task to keep the diff focused.
- **tracing::warn** import: Already present at line 53 (`use tracing::{info, warn}`). No new imports added.

## Known Stubs

None. All constants, struct, and accessor are fully implemented and tested.

## Threat Flags

None. This plan adds a pure config parsing + clamping path. The threat T-34-05 (Tampering/DoS via config) is fully mitigated by the `clamp()` call and `warn!` audit trail. No new network endpoints, auth paths, or file access patterns introduced.

## Self-Check: PASSED

- dlp-agent/src/config.rs contains `pub struct EncryptionConfig`: FOUND (line 82)
- dlp-agent/src/config.rs contains `pub encryption: EncryptionConfig`: FOUND (line 152)
- dlp-agent/src/config.rs contains `pub fn resolved_recheck_interval`: FOUND (line 312)
- dlp-agent/src/config.rs contains `ENCRYPTION_RECHECK_DEFAULT_SECS: u64 = 21_600`: FOUND (line 60)
- dlp-agent/src/config.rs contains `ENCRYPTION_RECHECK_MIN_SECS: u64 = 300`: FOUND (line 64)
- dlp-agent/src/config.rs contains `ENCRYPTION_RECHECK_MAX_SECS: u64 = 86_400`: FOUND (line 68)
- dlp-agent/src/config.rs contains `.clamp(ENCRYPTION_RECHECK_MIN_SECS, ENCRYPTION_RECHECK_MAX_SECS)`: FOUND (line 323)
- dlp-agent/src/config.rs contains `out of range -- clamped`: FOUND (line 331)
- All 26 config tests pass (including 6 new + 20 existing)
- Commits 241bdb1 (RED) and 0c6f8e6 (GREEN): FOUND
