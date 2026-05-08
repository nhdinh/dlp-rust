# S03: Grace Period / Quarantine for New Disk Arrivals

**Goal:** Configurable read-only window before hard block for new disk arrivals.
**Demo:** agent-config.toml accepts disk_grace_period_seconds (default 0 = immediate block). During grace period: reads allowed, writes blocked with toast. After expiry: full mount-time block engages.

## Must-Haves

- 1. disk_grace_period_seconds in agent-config.toml
- 2. During grace: reads allowed, writes blocked with toast
- 3. After expiry: full mount-time block

## Proof Level

- This slice proves: tested

## Integration Closure

Config field propagates server→agent→TOML. Agent evaluates grace period before mount-time block. Timer expiry triggers S02 blocking.

## Verification

- Config validation errors logged at agent startup; grace period state transitions traced.

## Tasks

- [x] **T01: Grace period implementation** `est:4h`
  Implement configurable grace period for new disk arrivals. Add disk_grace_period_seconds to agent-config.toml with validation. During grace period: allow reads, block writes with toast notification. On expiry: escalate to S02 mount-time block. Timer state machine with per-disk tracking.
  - Files: `dlp-agent/src/config.rs`, `dlp-agent/src/disk_enforcer.rs`, `dlp-agent/src/service.rs`
  - Verify: cargo test --package dlp-agent disk_enforcer::

## Files Likely Touched

- dlp-agent/src/config.rs
- dlp-agent/src/disk_enforcer.rs
- dlp-agent/src/service.rs
