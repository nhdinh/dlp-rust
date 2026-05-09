# S04: Operational Hardening Bundle (Phase 38.6)

**Goal:** Improve error handling, logging, telemetry, and shutdown behavior.
**Demo:** Disk enumeration handles IOCTL failures gracefully. USB enforcement emits structured traces. Agent config validates at load time. Service shutdown cancels in-flight tasks within 10s.

## Must-Haves

- 1. Disk IOCTL failures handled gracefully
- 2. USB structured tracing spans
- 3. Agent config validates ranges
- 4. Graceful shutdown within 10s

## Proof Level

- This slice proves: tested

## Integration Closure

Touches disk enumeration, USB enforcement, config loading, and service lifecycle.

## Verification

- Structured tracing spans for USB decisions. Config validation errors logged.

## Tasks

- [x] **T01: Operational hardening bundle** `est:4h`
  Add per-disk error handling in disk enumeration (continue on IOCTL failure). Add structured tracing::info! spans for all USB block/allow decisions. Add agent config TOML validation with descriptive errors. Implement graceful service shutdown: cancel in-flight tasks, flush audit buffer, restore DACLs, unregister notifications within 10s timeout.
  - Files: `dlp-agent/src/detection/disk.rs`, `dlp-agent/src/usb_enforcer.rs`, `dlp-agent/src/config.rs`, `dlp-agent/src/service.rs`
  - Verify: cargo test --package dlp-agent disk:: usb_enforcer:: config::

## Files Likely Touched

- dlp-agent/src/detection/disk.rs
- dlp-agent/src/usb_enforcer.rs
- dlp-agent/src/config.rs
- dlp-agent/src/service.rs
