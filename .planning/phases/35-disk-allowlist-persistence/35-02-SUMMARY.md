---
phase: 35-disk-allowlist-persistence
plan: "02"
subsystem: agent-disk
tags: [disk, allowlist, persistence, agent, parking_lot, toml, merge, service]
dependency_graph:
  requires: [AgentConfig.disk_allowlist, DiskEnumerator.instance_id_map]
  provides: [spawn_disk_enumeration_task-persistence, disk_config_arc-service-wiring]
  affects:
    - dlp-agent/src/detection/disk.rs
    - dlp-agent/src/service.rs
tech_stack:
  added: []
  patterns:
    - arc-rwlock-shared-config
    - lock-order-discipline
    - toml-merge-pre-load
    - non-fatal-persist
key_files:
  created: []
  modified:
    - dlp-agent/src/detection/disk.rs
    - dlp-agent/src/service.rs
    - dlp-agent/src/detection/encryption.rs
decisions:
  - "Pre-load block placed BEFORE retry loop (not inside it) so TOML entries are available from the first enumeration attempt onwards"
  - "toml_disks captured as Vec<DiskIdentity> clone before retry loop; borrow survives across async move without re-locking"
  - "Merge algorithm uses .iter().map(|d| (d.instance_id.clone(), d.clone())) on toml_disks (not .into_iter()) to allow toml_disks reuse in the pre-load block -- but pre-load is already done before the loop so .into_iter() would also be valid; .iter() is consistent with the plan code examples"
  - "config_path passed by .clone() at call site (not by move) -- config_path is only used at that one call site, so move would also work, but clone is defensive per existing audit_ctx.clone() convention on the line above"
  - "disk_config_arc inserted at line 552 (between config_arc at 541 and with_config at 595) -- safely within the Pitfall 2 window"
  - "encryption.rs had pre-existing rustfmt issues (trailing blank line, long chained method) fixed as part of cargo fmt run"
metrics:
  duration: 10m
  completed: "2026-05-03T15:12:55Z"
  tasks_completed: 1
  tasks_total: 1
---

# Phase 35 Plan 02: Wire Disk Allowlist Persistence Summary

## One-Liner

Wired `spawn_disk_enumeration_task` end-to-end with `Arc<parking_lot::RwLock<AgentConfig>>` + `PathBuf`, implementing TOML pre-load (D-11), live-wins merge (D-06/D-07), DiskEnumerator update with lock-order discipline (Pitfall 4), and non-fatal TOML persist; service.rs constructs `disk_config_arc` before `with_config` consumes `agent_config` (Pitfall 2).

## What Was Built

### disk.rs Changes

**Signature change:** `spawn_disk_enumeration_task` now accepts:
```rust
agent_config: Arc<parking_lot::RwLock<AgentConfig>>,
config_path: PathBuf,
```
replacing the `_agent_config_path: Option<String>` stub.

**TOML pre-load (D-11, D-12):** Before the retry loop, the task reads `agent_config.disk_allowlist` (read lock released immediately) and pre-populates `discovered_disks` and `instance_id_map` in the `DiskEnumerator`. `drive_letter_map` is intentionally NOT pre-populated to avoid routing I/O to phantom disconnected disks. `enumeration_complete` stays `false` (D-12 -- readiness requires live enumeration).

**Merge algorithm (D-06, D-07):** After successful live enumeration:
1. Build `HashMap<String, DiskIdentity>` from TOML entries (disconnected disks survive, D-06)
2. Overwrite with live entries by `instance_id` (live wins, D-07)
3. Collect + sort by `instance_id` ascending (deterministic TOML output)

**Lock-order discipline (Pitfall 4):** The DiskEnumerator update (all four write locks) is in one `if let` block. The `agent_config.write()` lock is acquired in a SEPARATE nested scope AFTER the `if let` block closes -- ensuring no simultaneous hold of both lock domains.

**Non-fatal persist:** `cfg.save(&config_path)` errors are logged via `tracing::error!` with `error = %e` and `path = %config_path.display()`. Enumeration succeeds regardless.

**Verified operation sequence inside the success arm:**
1. Pre-load TOML entries into DiskEnumerator (before retry loop)
2. `enumerate_fixed_disks()` succeeds
3. Mark boot disk
4. Merge TOML + live (pure computation, no locks)
5. Update DiskEnumerator (all four write locks, one scope)
6. Write `agent_config.disk_allowlist` + `cfg.save()` (separate scope)
7. `emit_disk_discovery` + `info!` + `return`

### service.rs Changes

**`disk_config_arc` insertion (line 552):** Inserted between `config_arc` (line 541) and `with_config(agent_config)` (line 595). The insertion window is 41 lines -- the Pitfall 2 risk (move-before-clone) is fully avoided.

**`config_path` binding (line 553):** `PathBuf::from(AgentConfig::effective_config_path())` constructed at the same point.

**Call site update (lines 643-647):** Replaced `None` argument with `Arc::clone(&disk_config_arc)` and `config_path.clone()`.

### Five New Unit Tests

| Test | Validates |
|------|-----------|
| `test_pre_load_populates_instance_map` | Pre-load fills `instance_id_map` + `discovered_disks`; `is_ready()` stays false (D-11, D-12) |
| `test_merge_live_wins_over_toml` | Same `instance_id`: live `drive_letter` + `is_boot_disk` override TOML values (D-07) |
| `test_merge_disconnected_disk_retained` | TOML-only disk absent from live scan survives with original values (D-06) |
| `test_merge_sorts_by_instance_id` | Out-of-order TOML input yields alphabetically sorted output |
| `test_persist_save_failure_is_non_fatal` | Save to nonexistent path returns `Err`; in-memory `disk_allowlist` is updated regardless |

## Test Results

```
cargo test -p dlp-agent --lib 2>&1 | tail -5
test server_client::tests::test_fetch_device_registry_unreachable_server ... ok
test server_client::tests::test_fetch_managed_origins_unreachable_server ... ok

test result: ok. 243 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.04s
```

**Baseline for Phase 36:** 243 tests pass (238 pre-existing + 5 new Phase 35 tests).

## Decisions Made

| Decision | Rationale |
|----------|-----------|
| Pre-load before retry loop, not inside it | TOML entries are available from attempt 1; re-populating on each retry would re-clear live updates from a partial success |
| `config_path.clone()` at call site | Matches `audit_ctx.clone()` convention; defensive in case future code adds a second use after this call |
| `disk_config_arc` and `config_arc` remain independent bindings | Per CONTEXT.md D-04 and RESEARCH.md Open Question 1: they serve disjoint subsystems (disk_allowlist vs heartbeat/paths); unification is a future maintenance concern |
| `encryption.rs` reformatted in same commit | `cargo fmt --check` requires the whole crate to be clean; the pre-existing issues were unrelated to disk.rs but blocking the format gate |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Pre-existing rustfmt failures in encryption.rs**
- **Found during:** `cargo fmt --check -p dlp-agent` verification step
- **Issue:** `dlp-agent/src/detection/encryption.rs` had two pre-existing formatting issues (trailing blank line between impl block and static; long chained method call over 100 chars) that caused `cargo fmt --check` to fail, blocking the acceptance criteria gate
- **Fix:** Applied `cargo fmt -p dlp-agent` which fixed both issues in `encryption.rs` along with the new code in `disk.rs`
- **Files modified:** `dlp-agent/src/detection/encryption.rs`
- **Commit:** Included in e7f2919 (same commit as the main implementation)

## Phase 36 Entry Condition

`DiskEnumerator.disk_for_instance_id(id)` returns:
- `Some(disk)` for **live disks** after successful enumeration (via merge + DiskEnumerator update step)
- `Some(disk)` for **disconnected-allowlisted disks** (TOML entry not present in live scan -- retained by merge D-06)
- `None` only for disks that never appeared in TOML or any live scan

`DiskEnumerator.is_ready()` returns `true` only after `enumeration_complete` is set in the DiskEnumerator update block (Step 3), which only executes on a successful live enumeration call. Pre-load alone does NOT set the readiness flag (D-12).

Phase 36 enforcement can safely use `disk_for_instance_id` as the authoritative allowlist read path (D-10, D-13).

## Known Stubs

None. The persistence loop is fully wired: pre-load, merge, update, and save are all implemented.

## Threat Flags

None. No new network endpoints or trust boundaries introduced. The STRIDE threats T-35-04 through T-35-07 documented in the plan are handled as specified (T-35-04 and T-35-05 via algorithm properties; T-35-06 and T-35-07 accepted per analysis).

## Self-Check: PASSED

- `dlp-agent/src/detection/disk.rs` contains `agent_config: Arc<parking_lot::RwLock<AgentConfig>>` -- verified
- `dlp-agent/src/detection/disk.rs` contains `config_path: PathBuf` -- verified
- `dlp-agent/src/detection/disk.rs` contains `use crate::config::AgentConfig;` -- verified
- `dlp-agent/src/detection/disk.rs` contains `use std::path::PathBuf;` -- verified
- `dlp-agent/src/detection/disk.rs` contains `pre-loaded disk allowlist from TOML` -- verified
- `dlp-agent/src/detection/disk.rs` contains `Merge live disks with TOML snapshot` -- verified
- `dlp-agent/src/detection/disk.rs` contains `failed to persist disk allowlist to TOML` -- verified
- `dlp-agent/src/detection/disk.rs` contains `updated_list.sort_by(|a, b| a.instance_id.cmp(&b.instance_id))` -- verified
- All 5 new test functions present -- verified
- `dlp-agent/src/service.rs` contains `let disk_config_arc = Arc::new(parking_lot::RwLock::new(agent_config.clone()));` -- verified
- `dlp-agent/src/service.rs` contains `let config_path = std::path::PathBuf::from(crate::config::AgentConfig::effective_config_path());` -- verified
- `dlp-agent/src/service.rs` contains `Arc::clone(&disk_config_arc)` -- verified
- No `_agent_config_path` references remain (grep returns 0 matches) -- verified
- No `spawn_disk_enumeration_task(...None` pattern remains -- verified
- `instance_map.insert` appears 4 times (pre-load x1, post-merge x1, test body x2) -- verified
- `cargo build -p dlp-agent`: no warnings -- verified
- `cargo test -p dlp-agent --lib -- detection::disk`: all 5 new tests + pre-existing pass -- verified
- `cargo test -p dlp-agent --lib`: 243 passed, 0 failed -- verified
- `cargo clippy -p dlp-agent -- -D warnings`: exits 0 -- verified
- `cargo fmt --check -p dlp-agent`: exits 0 -- verified
- No new `.unwrap()` outside `#[cfg(test)]` blocks -- verified (save uses `if let Err`)
- Commit e7f2919 verified in git log -- verified
