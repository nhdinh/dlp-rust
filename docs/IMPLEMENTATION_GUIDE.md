# Implementation Guide (Rust)

## Architecture

- Policy Engine: Rust
- Agent: Rust (Windows API bindings)
- Logging: JSON → SIEM

## Crate Structure

- dlp-agent/
- dlp-ui/
- policy-engine/
- common-types/

## Key Libraries

- serde (serialization)
- windows-rs (WinAPI)

## Deployment Steps

1. Prepare AD
2. Configure NTFS
3. Deploy policy engine
4. Deploy agents
