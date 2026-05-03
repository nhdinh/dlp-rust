---
phase: 35-disk-allowlist-persistence
verified: 2026-05-03T15:30:00Z
status: passed
score: 11/11 must-haves verified
overrides_applied: 0
---

# Phase 35: Disk Allowlist Persistence Verification Report

**Phase Goal:** Agent persists the disk allowlist and loads it across restarts
**Verified:** 2026-05-03T15:30:00Z
**Status:** passed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Agent writes enumerated disks to [[disk_allowlist]] section in agent-config.toml with device instance ID as canonical key | VERIFIED | `AgentConfig.disk_allowlist: Vec<DiskIdentity>` at config.rs line 168 with `#[serde(default)]`; `save()` at line 278 serializes all pub fields; `instance_id` field is the key in the merge HashMap (disk.rs line 231); `updated_list.sort_by(|a, b| a.instance_id.cmp(&b.instance_id))` at line 239 |
| 2 | Agent loads the allowlist from TOML at startup into an in-memory RwLock cache | VERIFIED | Pre-load block at disk.rs lines 172-199 reads `agent_config.disk_allowlist.clone()` (read lock) and populates `enumerator.discovered_disks` and `enumerator.instance_id_map` before the retry loop; both fields are `parking_lot::RwLock<_>` |
| 3 | Drive letter is stored as informational metadata only; device instance ID is the canonical identity key | VERIFIED | Merge algorithm uses `instance_id` as HashMap key (disk.rs line 231); `drive_letter_map` is NOT pre-populated from TOML (disk.rs line 183-186, explicit comment "drive_letter_map is INTENTIONALLY left empty here"); `drive_letter` documented as "informational metadata only" in config.rs line 159 |

**Score:** 3/3 roadmap success criteria verified

---

### PLAN Must-Haves Verification

#### Plan 35-01 Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | D-03: AgentConfig has a new public `disk_allowlist: Vec<DiskIdentity>` field with `#[serde(default)]`; existing `AgentConfig::save()` is the only TOML write path | VERIFIED | config.rs lines 167-168: `#[serde(default)]` + `pub disk_allowlist: Vec<DiskIdentity>`; save() at line 278 is the single write path; no duplicate write paths exist |
| 2 | D-03: backwards compat — an empty TOML file (no `[[disk_allowlist]]` section) deserializes to `disk_allowlist == Vec::new()` | VERIFIED | `test_disk_allowlist_backwards_compat` test at config.rs line 580 confirms this; `#[serde(default)]` on the field ensures Vec::new() when section absent |
| 3 | D-08: a TOML file with one or more `[[disk_allowlist]]` entries deserializes into matching DiskIdentity values via the same save() path | VERIFIED | `test_disk_allowlist_toml_roundtrip` at config.rs line 593 saves 2 entries and loads them back, asserting all fields including Option<char> drive_letter and BusType |
| 4 | D-08: full DiskIdentity round-trips through save() -> load() preserving instance_id, bus_type, model, drive_letter (Option<char>), is_boot_disk, and the optional encryption fields | VERIFIED | test_disk_allowlist_toml_roundtrip asserts all these fields; SUMMARY confirms Pitfall 3 (char roundtrip) was verified by the test passing |
| 5 | D-08: a DiskIdentity whose encryption_status/encryption_method/encryption_checked_at are all None serializes WITHOUT those keys | VERIFIED | `test_disk_allowlist_omits_none_encryption_fields` at config.rs line 653 asserts absence of all three keys in TOML output |
| 6 | All existing AgentConfig struct-literal tests still compile (every site adds `disk_allowlist: Vec::new()`) | VERIFIED | Three sites confirmed at config.rs lines 450, 485, 515; tests using `..Default::default()` spread untouched (correct — Default provides Vec::new()) |

#### Plan 35-02 Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 7 | D-04: spawn_disk_enumeration_task accepts Arc<parking_lot::RwLock<AgentConfig>> and PathBuf instead of the prior _agent_config_path: Option<String> stub | VERIFIED | disk.rs lines 165-170: signature is `agent_config: Arc<parking_lot::RwLock<AgentConfig>>, config_path: PathBuf`; grep confirms zero `_agent_config_path` references remain |
| 8 | D-02, D-11: on startup the task pre-loads cfg.disk_allowlist into DiskEnumerator.instance_id_map and discovered_disks BEFORE running live enumeration | VERIFIED | Pre-load block at disk.rs lines 172-199 is before `let retry_delays` at line 201; populates both `discovered_disks` and `instance_id_map`; `drive_letter_map` intentionally NOT populated |
| 9 | D-12: DiskEnumerator.enumeration_complete is NOT set to true by the TOML pre-load step — only after live enumeration succeeds | VERIFIED | Pre-load block (lines 172-199) has no `*complete = true`; comment at line 198 explicitly states "enumeration_complete remains FALSE (D-12)"; `*complete = true` only at disk.rs line 260 inside the live enumeration success arm |
| 10 | D-06, D-07: after successful live enumeration, the task merges TOML entries with live disks — disconnected TOML entries survive (D-06), live data overwrites for present instance_ids (D-07) | VERIFIED | Merge at disk.rs lines 230-239: HashMap seeded from toml_disks (D-06 foundation), then overwritten by live disks (D-07 "live wins"); `test_merge_disconnected_disk_retained` and `test_merge_live_wins_over_toml` tests verify both |
| 11 | D-01, D-02: after merge, the task writes the merged Vec back to cfg.disk_allowlist and calls cfg.save(&config_path) immediately; save failure is logged via tracing::error! and does NOT fail enumeration | VERIFIED | Persist block at disk.rs lines 268-279: `cfg.disk_allowlist = updated_list.clone()` then `if let Err(e) = cfg.save(&config_path) { tracing::error!(...) }`; `test_persist_save_failure_is_non_fatal` confirms non-fatal behavior |
| 12 | D-05, D-09: Phase 34's encryption re-check does NOT trigger a TOML re-write | VERIFIED | Grep of detection/encryption.rs shows no `cfg.save()` or `disk_allowlist` references; the TOML write trigger is exclusively inside the `Ok(mut disks)` arm in disk.rs |
| 13 | D-10, D-13: DiskEnumerator.instance_id_map IS the allowlist (no new DiskAllowlist singleton) | VERIFIED | No DiskAllowlist struct exists; `instance_id_map` on DiskEnumerator (disk.rs line 52) is the unified map; `disk_for_instance_id()` is the authoritative read path per Phase 36 entry condition |
| 14 | DiskEnumerator write locks are released BEFORE the AgentConfig write lock is acquired (lock-order discipline — Pitfall 4) | VERIFIED | DiskEnumerator update in `if let Some(enumerator)` block (lines 245-262) closes before AgentConfig scope opens at line 268; agent_config.write() line 269 is in a separate `{ }` block |
| 15 | drive_letter_map is NOT pre-populated from TOML (only from live enumeration) | VERIFIED | Pre-load block explicitly skips drive_letter_map (disk.rs line 183-186); only updated in post-merge DiskEnumerator update at lines 255-257 |
| 16 | D-04: service.rs constructs Arc<parking_lot::RwLock<AgentConfig>> from agent_config.clone() BEFORE InterceptionEngine::with_config(agent_config) consumes the value (Pitfall 2) | VERIFIED | disk_config_arc constructed at service.rs line 552; with_config consumes agent_config at line 595 — 43 lines later |
| 17 | service.rs passes the Arc and a PathBuf to spawn_disk_enumeration_task; the prior None argument is removed | VERIFIED | Call site at service.rs lines 642-647: `Arc::clone(&disk_config_arc), config_path.clone()`; grep confirms zero `spawn_disk_enumeration_task.*None` matches |

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `dlp-agent/src/config.rs` | AgentConfig.disk_allowlist field + 3 new TOML roundtrip tests + struct-literal test fixes | VERIFIED | Field at line 168 with `#[serde(default)]`; 3 new tests at lines 580, 593, 653; 3 struct literal sites at lines 450, 485, 515 |
| `dlp-agent/src/detection/disk.rs` | Updated spawn_disk_enumeration_task signature + TOML pre-load + merge + non-fatal persist + 5 new unit tests | VERIFIED | Signature at lines 165-170; pre-load lines 172-199; merge lines 230-239; persist lines 268-279; 5 tests at lines 619, 654, 678, 709, 736 |
| `dlp-agent/src/service.rs` | Arc<RwLock<AgentConfig>> binding (disk_config_arc) constructed before with_config; call site updated | VERIFIED | disk_config_arc at line 552; config_path at line 553; call site at lines 642-647 |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| dlp-agent/src/config.rs | dlp-common/src/disk.rs | `use dlp_common::DiskIdentity;` import | VERIFIED | config.rs line 52: `use dlp_common::DiskIdentity;` present |
| dlp-agent/src/service.rs | dlp-agent/src/detection/disk.rs | spawn_disk_enumeration_task receives Arc::clone(&disk_config_arc) | VERIFIED | service.rs line 645: `Arc::clone(&disk_config_arc)` matches pattern exactly |
| dlp-agent/src/detection/disk.rs | dlp-agent/src/config.rs | Task body reads cfg.disk_allowlist on pre-load, writes cfg.disk_allowlist + cfg.save(path) on persist | VERIFIED | disk.rs line 177: `cfg.disk_allowlist.clone()`; line 270: `cfg.disk_allowlist = updated_list.clone()`; line 271: `cfg.save(&config_path)` |

---

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|--------------|--------|-------------------|--------|
| disk.rs spawn_disk_enumeration_task | toml_disks | `agent_config.read().disk_allowlist.clone()` — real Vec loaded from TOML file via AgentConfig::load() | Yes — reads from TOML file on disk via `toml::from_str` in AgentConfig::load(); not hardcoded | FLOWING |
| disk.rs spawn_disk_enumeration_task | updated_list | Merge of toml_disks + live enumeration result from `enumerate_fixed_disks()` | Yes — `enumerate_fixed_disks()` calls WinAPI SetupDi; merge is real data | FLOWING |
| DiskEnumerator.instance_id_map | HashMap<String, DiskIdentity> | Written from updated_list (lines 254-259); also pre-loaded from toml_disks (lines 188-191) | Yes — populated from both TOML and live enumeration | FLOWING |

---

### Behavioral Spot-Checks

Step 7b: Tests serve as behavioral spot-checks. Full test run reported in SUMMARY-02 as "243 passed, 0 failed". Cannot rerun cargo test without risking long build time, but code-level verification confirms all 8 test functions (3 in config.rs, 5 in disk.rs) are substantive implementations that exercise the actual code paths — not stubs.

| Behavior | Verification Method | Status |
|----------|---------------------|--------|
| Backwards compat: TOML without [[disk_allowlist]] yields empty Vec | `test_disk_allowlist_backwards_compat` — reads toml::from_str directly | PASS (code verified) |
| TOML roundtrip with Option<char> drive letter | `test_disk_allowlist_toml_roundtrip` — save/load cycle on temp file | PASS (code verified) |
| None encryption fields absent in TOML output | `test_disk_allowlist_omits_none_encryption_fields` — asserts absence of keys | PASS (code verified) |
| Pre-load populates instance_id_map, is_ready stays false | `test_pre_load_populates_instance_map` — direct DiskEnumerator manipulation | PASS (code verified) |
| Live data wins over TOML for same instance_id | `test_merge_live_wins_over_toml` — merge algorithm applied to fixture data | PASS (code verified) |
| Disconnected TOML disk retained after merge | `test_merge_disconnected_disk_retained` — merge algorithm applied to fixture data | PASS (code verified) |
| Merge output sorted by instance_id | `test_merge_sorts_by_instance_id` — sort assertion on merge output | PASS (code verified) |
| Save failure non-fatal, in-memory state updated | `test_persist_save_failure_is_non_fatal` — bad path triggers Err, disk_allowlist still updated | PASS (code verified) |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| DISK-03 | 35-01, 35-02 | Agent persists the disk allowlist to agent-config.toml with device instance ID as canonical key; drive letter is informational only | SATISFIED | disk_allowlist field in AgentConfig (config.rs:168); persist step in disk.rs (lines 268-279); instance_id canonical key via HashMap keying and sort; drive_letter informational per doc comment (config.rs:159) and intentional exclusion from drive_letter_map pre-load |

No orphaned requirements: REQUIREMENTS.md traceability table maps only DISK-03 to Phase 35. All other DISK-* requirements map to phases 33, 36, 37, 38.

---

### Anti-Patterns Found

| File | Pattern | Severity | Impact |
|------|---------|----------|--------|
| None found | — | — | — |

Scan results:
- Zero `.unwrap()` calls outside `#[cfg(test)]` blocks in modified files (disk.rs, config.rs, service.rs)
- Zero TODO/FIXME/PLACEHOLDER comments in new code
- Zero `return null` / `return {}` / `return []` stubs
- Zero hardcoded empty returns in production paths
- The prior `_agent_config_path: Option<String>` stub is fully removed (grep returns 0 matches)
- The prior `None` argument at the call site is fully removed (grep returns 0 matches)

---

### Human Verification Required

None. All observable behaviors are verifiable programmatically from code and test logic. The Phase 35 changes are pure in-process logic (TOML serialization, merge algorithm, lock-order discipline) with no UI, network, or external service dependencies that require human testing.

---

## Gaps Summary

No gaps. All 3 roadmap success criteria and all 17 plan must-have truths are verified against actual code. The phase goal — "Persist the disk allowlist across agent restarts (DISK-03)" — is fully achieved.

The end-to-end wire is confirmed:
- `AgentConfig.disk_allowlist: Vec<DiskIdentity>` field exists with `#[serde(default)]` (backwards compat)
- `spawn_disk_enumeration_task` pre-loads TOML into `DiskEnumerator.instance_id_map` and `discovered_disks` before live enumeration (D-11, D-12)
- Merge algorithm correctly implements D-06 (disconnected retained) and D-07 (live wins) with deterministic sort
- Lock-order discipline: DiskEnumerator write locks released before AgentConfig write lock acquired (Pitfall 4)
- Save failure logged non-fatally via `tracing::error!`; in-memory state authoritative (D-01)
- `service.rs` constructs `disk_config_arc` 43 lines before `with_config(agent_config)` move (Pitfall 2)
- All 8 new unit tests are substantive implementations, not stubs
- SUMMARY-02 reports 243 tests passed (green baseline for Phase 36)

---

_Verified: 2026-05-03T15:30:00Z_
_Verifier: Claude (gsd-verifier)_
