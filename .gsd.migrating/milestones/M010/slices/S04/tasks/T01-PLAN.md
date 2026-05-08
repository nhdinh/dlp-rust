---
estimated_steps: 1
estimated_files: 4
skills_used: []
---

# T01: Operational hardening bundle

Add per-disk error handling in disk enumeration (continue on IOCTL failure). Add structured tracing::info! spans for all USB block/allow decisions. Add agent config TOML validation with descriptive errors. Implement graceful service shutdown: cancel in-flight tasks, flush audit buffer, restore DACLs, unregister notifications within 10s timeout.

## Inputs

- `Existing disk enumeration`
- `USB enforcement`
- `Service lifecycle`

## Expected Output

- `Disk enumeration error resilience`
- `USB structured traces`
- `Config validation`
- `Graceful shutdown`

## Verification

cargo test --package dlp-agent disk:: usb_enforcer:: config::
