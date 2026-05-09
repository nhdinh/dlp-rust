---
estimated_steps: 1
estimated_files: 2
skills_used: []
---

# T01: Disk allowlist persistence

Write enumerated disks to [disk_allowlist] section in agent-config.toml with device instance ID as canonical key. Load allowlist from TOML at startup into in-memory RwLock cache. Drive letter stored as informational metadata only.

## Inputs

- `Disk enumeration from S01`
- `TOML config patterns`

## Expected Output

- `AgentConfig disk_allowlist field`
- `TOML write on enumeration`
- `TOML read on startup`
- `Unit tests`

## Verification

cargo test --package dlp-agent config::
