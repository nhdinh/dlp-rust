# Phase 45: Grace Period / Quarantine - Context

**Gathered:** 2026-05-08
**Status:** Ready for planning
**Mode:** Auto-generated (smart discuss — batch proposal accepted)

<domain>
## Phase Boundary

Goal: Configurable read-only window before hard block for new disk arrivals.

Requirement: DISK-07

Success criteria:
1. `agent-config.toml` accepts `disk_grace_period_seconds` (default 0 = immediate block)
2. During grace period, reads allowed, writes blocked with user notification
3. After grace period expires, mount-time block engages

This phase builds directly on Phase 44 (Mount-Time Blocking). Instead of immediately blocking unregistered disks at mount time, allow a configurable grace period where the disk is mounted read-only before the full block takes effect.

</domain>

<decisions>
## Implementation Decisions

### Grace Period Behavior
- Default `disk_grace_period_seconds = 0` means immediate block (backward compatible with Phase 44 behavior)
- During grace period: disk is mounted normally (drive letter assigned) but write operations are blocked via I/O-time blocking
- After grace period expires: mount-time block engages (drive letter removed, volume offlined)
- Grace period starts at disk arrival time (DBT_DEVICEARRIVAL)

### User Notification
- Toast notification via existing `dlp_common::notify::toast` when grace period starts
- Notification includes remaining time and policy explanation
- No notification needed when grace_period = 0 (immediate block)

### Configuration
- Add `disk_grace_period_seconds: u64` to `AgentConfig` struct
- Deserialize from `agent-config.toml` [disk] section
- Runtime reloadable via existing config pipeline

### Claude's Discretion
- Timer implementation: `tokio::time::sleep` or `std::thread::spawn` with channel notification
- Grace period tracking: per-disk HashMap<instance_id, Instant> in DiskEnumerator
- Write blocking during grace: reuse existing DiskEnforcer I/O-time blocking with a new `GracePeriod` trust tier variant

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- Phase 44 `block_disk_at_mount_time()` — called after grace period expires
- `DiskEnforcer::enforce()` — I/O-time blocking logic, can be extended for grace-period writes
- `AgentConfig` in `dlp-common/src/config.rs` — add new field here
- Toast notification system in `dlp-common/src/notify.rs`

### Established Patterns
- Config pipeline: TOML → AgentConfig → runtime reload via mpsc
- Trust tiers: ReadOnly, FullAccess, Blocked — add GracePeriod variant
- Disk arrival flow: `on_disk_arrival_inner` → allowlist check → drive_letter_map insert

### Integration Points
- `on_disk_arrival_inner` in `dlp-agent/src/detection/disk.rs` — insert grace period logic before/after allowlist check
- `DiskEnforcer` in `dlp-agent/src/disk_enforcer.rs` — extend enforce() for grace period writes
- Config loading in `dlp-agent/src/main.rs` or config module

</code_context>

<specifics>
## Specific Ideas

- When grace_period > 0, unregistered disks get drive letter and enter "quarantine" mode
- During quarantine: reads pass, writes fail with `ERROR_WRITE_PROTECT` or similar
- Timer thread watches grace period expiry and triggers `block_disk_at_mount_time()`
- Audit event `DiskQuarantineStarted` on arrival, `DiskQuarantineExpired` on expiry

</specifics>

<deferred>
## Deferred Ideas

- Per-device grace periods (different timeouts for different device types)
- Admin TUI to configure grace period globally
- Grace period extension/override via admin API

</deferred>
