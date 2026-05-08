# S03: Disk Allowlist Persistence (Phase 35)

**Goal:** Agent persists disk allowlist and loads it across restarts.
**Demo:** Disk allowlist persisted to agent-config.toml and loaded across restarts.

## Must-Haves

- 1. Disk allowlist in [disk_allowlist] TOML section
- 2. Loaded into RwLock cache at startup
- 3. Instance ID is canonical key

## Proof Level

- This slice proves: tested

## Integration Closure

Provides in-memory cache for runtime enforcement in S04.

## Verification

- None — config persistence.

## Tasks

- [x] **T01: Disk allowlist persistence** `est:3h`
  Write enumerated disks to [disk_allowlist] section in agent-config.toml with device instance ID as canonical key. Load allowlist from TOML at startup into in-memory RwLock cache. Drive letter stored as informational metadata only.
  - Files: `dlp-agent/src/config.rs`, `dlp-agent/src/service.rs`
  - Verify: cargo test --package dlp-agent config::

## Files Likely Touched

- dlp-agent/src/config.rs
- dlp-agent/src/service.rs
