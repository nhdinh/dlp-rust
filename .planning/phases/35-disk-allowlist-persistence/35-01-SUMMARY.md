---
phase: 35-disk-allowlist-persistence
plan: "01"
subsystem: agent-config
tags: [config, agent, disk, allowlist, persistence, toml, serde]
dependency_graph:
  requires: []
  provides: [AgentConfig.disk_allowlist]
  affects: [dlp-agent/src/config.rs]
tech_stack:
  added: []
  patterns: [serde-default-field-addition, toml-array-of-tables]
key_files:
  created: []
  modified:
    - dlp-agent/src/config.rs
decisions:
  - "Import DiskIdentity via 'use dlp_common::DiskIdentity' (not inline qualified path) to match existing import style"
  - "Field placed between encryption and ldap_config matching Plan 34-02 ordering convention"
  - "toml 0.8 uses TOML literal strings (single-quoted) for backslash-containing strings; assertion uses single-backslash Rust literal not quadruple-backslash"
metrics:
  duration: 7m
  completed: "2026-05-03T15:03:04Z"
  tasks_completed: 1
  tasks_total: 1
---

# Phase 35 Plan 01: Add disk_allowlist Field to AgentConfig Summary

## One-Liner

Added `pub disk_allowlist: Vec<DiskIdentity>` field to `AgentConfig` with `#[serde(default)]` for backwards-compatible TOML persistence of the disk allowlist (DISK-03 / D-03 / D-08), with three new TOML roundtrip tests verifying backwards compat, `Option<char>` drive letter handling, and absence of `None` encryption fields in output.

## What Was Built

### Field Addition

`AgentConfig` in `dlp-agent/src/config.rs` gained one new field:

```rust
use dlp_common::DiskIdentity;   // added import line 52

// In AgentConfig struct, between `encryption` and `ldap_config`:
/// Disk allowlist persisted across agent restarts (Phase 35 / DISK-03 / D-03).
///
/// Loaded from `[[disk_allowlist]]` TOML array of tables. ...
#[serde(default)]
pub disk_allowlist: Vec<DiskIdentity>,
```

**Field placement:** Inserted between `pub encryption: EncryptionConfig` and `pub ldap_config: Option<...>`, following the same ordering convention established by Plan 34-02.

**Import style:** `use dlp_common::DiskIdentity;` (brought name into scope) rather than inline `dlp_common::DiskIdentity` path, matching the existing import style in the file.

### Test Struct Literal Fixes

Three existing tests that enumerate all fields in `AgentConfig {}` struct literals were updated to add `disk_allowlist: Vec::new()`:

1. `test_resolve_watch_paths_configured` (after `ldap_config: None`)
2. `test_agent_config_save_roundtrip` (after `ldap_config: None`, before `machine_name`)
3. `test_agent_config_save_preserves_server_url` (after `ldap_config: None`)

Tests using `..Default::default()` spread were NOT modified (they get `Vec::new()` automatically via the `Default` derive).

### Three New Tests

| Test | Validates |
|------|-----------|
| `test_disk_allowlist_backwards_compat` | TOML without `[[disk_allowlist]]` section yields `disk_allowlist.is_empty() == true` (D-08 backwards compat) |
| `test_disk_allowlist_toml_roundtrip` | Full `AgentConfig` with 2 `DiskIdentity` entries (one `drive_letter: Some('C')`, one `drive_letter: None`) saves and reloads preserving all fields including `Option<char>` (Pitfall 3 mitigated) |
| `test_disk_allowlist_omits_none_encryption_fields` | Serialized TOML does NOT contain `encryption_status`, `encryption_method`, or `encryption_checked_at` when all three are `None` (D-08 confirms `#[serde(skip_serializing_if = "Option::is_none")]` flows through `[[disk_allowlist]]`) |

## Test Results

```
cargo test -p dlp-agent --lib config 2>&1 | tail -5
test config::tests::test_agent_config_save_preserves_server_url ... ok
test server_client::tests::test_fetch_agent_config_unreachable ... ok

test result: ok. 32 passed; 0 failed; 0 ignored; 0 measured; 206 filtered out; finished in 2.05s
```

**Baseline for Plan 35-02:** 32 tests pass in `cargo test -p dlp-agent --lib config` (29 config module + 3 server_client module).

## Decisions Made

| Decision | Rationale |
|----------|-----------|
| Import via `use dlp_common::DiskIdentity;` at top | Matches existing import style; keeps field declaration on one line |
| Field between `encryption` and `ldap_config` | Follows Plan 34-02 ordering convention (encryption section just before network-facing config) |
| No changes to `save()` or `load()` | They already serialize/deserialize all `pub` fields; `#[serde(default)]` handles new field automatically |
| `disk_allowlist: Vec::new()` on 3 test literals | Only explicit struct literals need it; `..Default::default()` spreads already get Vec::new() for free |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed incorrect backslash escape assertion in plan's test code**
- **Found during:** GREEN phase (test_disk_allowlist_omits_none_encryption_fields failed)
- **Issue:** Plan specified assertion `serialized.contains("USB\\\\VID_1234&PID_5678\\\\001")` (Rust 4-backslash literal = 2 actual backslashes). However, the `toml` 0.8 crate serializes strings containing backslashes using TOML _literal strings_ (single-quoted), where backslashes are NOT escaped. The actual TOML output is `instance_id = 'USB\VID_1234&PID_5678\001'` — containing single backslashes.
- **Fix:** Changed assertion to `serialized.contains("USB\\VID_1234&PID_5678\\001")` (Rust 2-backslash literal = 1 actual backslash), with an explanatory comment about toml 0.8's TOML literal string behavior.
- **Files modified:** `dlp-agent/src/config.rs`
- **Commit:** ff25ea9

## Pitfall 3 Resolution (TOML char Roundtrip)

Assumption A1 from RESEARCH.md ("char serializes and deserializes correctly through toml 0.8 backend") was **verified**. The `test_disk_allowlist_toml_roundtrip` test confirms that `drive_letter: Some('C')` round-trips correctly through `save()` + `load()`. The toml 0.8 crate serializes `char` as a single-character string `"E"` (double-quoted basic string for ASCII drive letters without backslashes).

## Known Stubs

None. The plan has no stubs — it only adds a struct field and tests.

## Threat Flags

None. The `disk_allowlist` field itself introduces no new network endpoints or trust boundaries. The existing `AgentConfig::load()` fallback-to-default behavior (T-35-02 mitigation) already handles malformed TOML, and the new field inherits this behavior via `#[serde(default)]`.

## Self-Check: PASSED

- `dlp-agent/src/config.rs` exists with `pub disk_allowlist: Vec<DiskIdentity>` at line 168
- `dlp-agent/src/config.rs` contains `use dlp_common::DiskIdentity;` at line 52
- 3 struct literals have `disk_allowlist: Vec::new()` (grep count = 3)
- All 3 new tests exist and pass
- Commits d034b4c (RED) and ff25ea9 (GREEN) verified in git log
- `cargo test -p dlp-agent --lib config`: 32 passed, 0 failed
- `cargo build -p dlp-agent`: no warnings
- `cargo clippy -p dlp-agent -- -D warnings`: passes
- `cargo fmt --check -p dlp-agent`: passes

## TDD Gate Compliance

| Gate | Commit | Status |
|------|--------|--------|
| RED (test commit) | d034b4c | PASSED - 3 failing tests added before field existed |
| GREEN (feat commit) | ff25ea9 | PASSED - field + struct literal fixes made all tests pass |
| REFACTOR | N/A | No refactoring needed |
