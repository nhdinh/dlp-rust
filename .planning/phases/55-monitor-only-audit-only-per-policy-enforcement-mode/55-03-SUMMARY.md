# Plan 55-03 Summary: Wire Agent to Parse Enforcement Mode and Compute Effective Decisions

**Phase:** 55-monitor-only-audit-only-per-policy-enforcement-mode
**Plan:** 03 (Agent Integration)
**Status:** Complete
**Date:** 2026-05-29

---

## Objective

Wire the agent to parse enforcement mode config from TOML and server payload, compute effective mode in the hook IPC handler (file interception event loop), and emit enriched audit events with `policy_mode` and `would_have_denied`.

---

## Tasks Completed

### Task 1: Add EnforcementConfig to AgentConfig and extend server_client payload

**Commit:** `cf770d2`
**Files:** `dlp-agent/src/config.rs`, `dlp-agent/src/server_client.rs`

- Added `EnforcementConfig` struct with `pub global_mode: EnforcementMode` and Default = `PerPolicy`
- Added `#[serde(default)] pub enforcement: EnforcementConfig` to `AgentConfig`
- Added `#[serde(default = "default_global_enforcement_mode")] pub global_enforcement_mode: String` to `AgentConfigPayload`
- Added 5 unit tests:
  - `test_agent_config_enforcement_section_default` — no [enforcement] section defaults to PerPolicy
  - `test_agent_config_enforcement_section_parsed` — Audit mode parses correctly
  - `test_agent_config_enforcement_section_block` — Block mode parses correctly
  - `test_agent_config_enforcement_section_audit_and_block` — AuditAndBlock mode parses correctly
  - `test_agent_config_enforcement_toml_roundtrip` — save/load roundtrip preserves mode
- Added 2 server_client tests:
  - `test_agent_config_payload_global_enforcement_mode_default_when_missing` — defaults to "PerPolicy"
  - `test_agent_config_payload_global_enforcement_mode_roundtrip` — custom mode survives roundtrip
- Fixed all `EvaluateResponse` struct literals across agent crate for new `enforcement_mode` and `would_have_denied` fields

### Task 2: Apply global_enforcement_mode from server payload in service.rs config poll

**Commit:** `b5f88e6`
**Files:** `dlp-agent/src/service.rs`

- Added global_enforcement_mode parsing in `apply_payload_to_config()`:
  - Matches payload string against "Audit", "Block", "AuditAndBlock", "PerPolicy"
  - Invalid values default to Block (fail-safe)
  - Only logs and adds to changed_fields when the mode actually changes
- Added `tracing::info!` log when global mode changes (old_mode -> new_mode)
- Added 3 unit tests:
  - `test_apply_payload_updates_global_enforcement_mode` — payload "Audit" updates config
  - `test_apply_payload_global_enforcement_mode_no_change` — same mode does not appear in changed_fields
  - `test_apply_payload_global_enforcement_mode_invalid_defaults_block` — invalid mode safely defaults to Block

### Task 3: Compute effective mode in interception run_event_loop and emit enriched audit

**Commit:** `6951e32`
**Files:** `dlp-agent/src/interception/mod.rs`

- After receiving `EvaluateResponse`, compute effective mode:
  - Read `cfg.enforcement.global_mode` via `with_config` (default `Block` if config unavailable)
  - Call `dlp_common::abac::compute_effective_mode(global_mode, policy_mode)`
- Apply effective mode to determine final decision:
  - `Audit`: returns `Decision::ALLOW` to the physical operation regardless of server response
  - `Block` / `AuditAndBlock`: returns server response unchanged
- Enrich audit event:
  - `policy_mode` set to effective mode string via `with_policy_mode()`
  - `would_have_denied` set from server response via `with_would_have_denied()`
  - Event type reflects physical operation outcome (Access for Audit mode)
- Added 4 unit tests for `compute_effective_mode` behavior:
  - `test_compute_effective_mode_audit_overrides_block`
  - `test_compute_effective_mode_block_overrides_audit`
  - `test_compute_effective_mode_perpolicy_defersto_policy`
  - `test_compute_effective_mode_perpolicy_defersto_block`

---

## Verification Results

| Check | Command | Result |
|-------|---------|--------|
| dlp-agent lib tests | `cargo test -p dlp-agent --lib` | 703 passed, 0 failed |
| dlp-agent clippy | `cargo clippy -p dlp-agent -- -D warnings` | Clean |

---

## Key Design Decisions

1. **Fail-safe default:** When config is unavailable (race at startup), `with_config` returns `EnforcementMode::Block` — the safest choice.

2. **String wire format, typed internal:** The server payload sends `global_enforcement_mode` as a String for JSON compatibility, but the agent parses it into the typed `EnforcementMode` enum immediately upon application.

3. **Consistent computation:** The agent uses the same `compute_effective_mode` helper from `dlp-common` that the server uses, ensuring both sides agree on the effective mode.

4. **Audit event reflects physical outcome:** In Audit mode, the event type is `Access` (not Block) because the physical operation is allowed, while `would_have_denied` captures the policy intent.

---

## Artifacts Produced

- `dlp-agent/src/config.rs` — `EnforcementConfig` struct, `enforcement` field on `AgentConfig`
- `dlp-agent/src/server_client.rs` — `global_enforcement_mode` field on `AgentConfigPayload`
- `dlp-agent/src/service.rs` — `apply_payload_to_config` parses and applies global_enforcement_mode
- `dlp-agent/src/interception/mod.rs` — `run_event_loop` computes effective mode, returns ALLOW for Audit, enriches audit events

---

## Threat Model Disposition

| Threat ID | Status | Notes |
|-----------|--------|-------|
| T-55-07 | Mitigated | Config file is in ProgramData with restricted ACL; agent service runs as SYSTEM |
| T-55-08 | Mitigated | `would_have_denied` is set by `evaluate()` before network; local audit emitter persists to disk |
| T-55-09 | Accepted | `policy_mode` in audit event is part of audit trail by design; contains no PII |
