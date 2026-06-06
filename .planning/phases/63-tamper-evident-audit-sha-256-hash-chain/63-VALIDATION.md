---
phase: 63
slug: tamper-evident-audit-sha-256-hash-chain
status: verified
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-06
updated: 2026-06-06
---

# Phase 63 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in test (`#[test]`) + doc-tests |
| **Config file** | Cargo.toml (workspace) |
| **Quick run command** | `cargo test -p dlp-common -p dlp-agent -p dlp-server --lib -- <filter>` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~90 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p <crate> --lib` for affected crate
- **After every plan wave:** Run `cargo test -p dlp-common -p dlp-agent -p dlp-server --lib`
- **Before `/gsd:verify-work`:** Full suite `cargo test --workspace` must be green
- **Max feedback latency:** ~90 seconds

---

## Per-Task Verification Map

### Plan 63-01: Server-Side Hash Chain Persistence

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 63-01-01 | 01 | 1 | audit_events prev_hash column | T-63-01 | Nullable TEXT column exists in schema | unit | `cargo test -p dlp-server --lib db::tests::test_tables_created` | built-in | green |
| 63-01-01 | 01 | 1 | audit_events chain_hash column | T-63-01 | Nullable TEXT column exists in schema | unit | `cargo test -p dlp-server --lib db::tests::test_tables_created` | built-in | green |
| 63-01-01 | 01 | 1 | Idempotent migration | T-63-03 | `run_alter` swallows duplicate-column errors | unit | `cargo test -p dlp-server --lib db::tests::test_idempotent_init` | built-in | green |
| 63-01-02 | 01 | 1 | idx_audit_events_agent_chain partial index | T-63-03b | Partial index on `(agent_id, id) WHERE chain_hash IS NOT NULL` | unit | `cargo test -p dlp-server --lib db::tests::test_audit_events_indexes_exist` | built-in | green |
| 63-01-02 | 01 | 1 | idx_audit_events_agent_latest index | T-63-03b | Index on `(agent_id, id DESC)` | unit | `cargo test -p dlp-server --lib db::tests::test_audit_events_indexes_exist` | built-in | green |
| 63-01-02 | 01 | 1 | AuditEventRow hash fields | T-63-01 | `prev_hash` and `chain_hash` as `Option<String>` | unit | `cargo test -p dlp-server --lib audit_store::tests::test_store_events_sync_admin_action` | built-in | green |
| 63-01-02 | 01 | 1 | insert_batch 16-param SQL | T-63-01 | Includes prev_hash and chain_hash bindings | unit | `cargo test -p dlp-server --lib audit_store::tests::test_ingest_verifies_valid_chain` | built-in | green |
| 63-01-03 | 01 | 1 | get_last_chain_hash | T-63-01 | Returns latest chain_hash per agent | unit | `cargo test -p dlp-server --lib db::repositories::audit_events::tests::test_get_last_chain_hash_returns_latest_hash` | built-in | green |
| 63-01-03 | 01 | 1 | get_last_chain_hash unknown agent | T-63-01 | Returns None for unknown agent_id | unit | `cargo test -p dlp-server --lib db::repositories::audit_events::tests::test_get_last_chain_hash_returns_none_for_unknown_agent` | built-in | green |
| 63-01-03 | 01 | 1 | get_chain_breaks | T-63-01 | Detects prev_hash mismatches via LAG window | unit | `cargo test -p dlp-server --lib db::repositories::audit_events::tests::test_get_chain_breaks_detects_mismatch` | built-in | green |
| 63-01-03 | 01 | 1 | get_chain_breaks pagination | T-63-03b | Respects since_id + limit | unit | `cargo test -p dlp-server --lib db::repositories::audit_events::tests::test_get_chain_breaks_respects_pagination` | built-in | green |
| 63-01-03 | 01 | 1 | is_valid_hash_format | T-63-01 | Validates 64 ASCII hex characters | unit | `cargo test -p dlp-server --lib db::repositories::audit_events::tests::test_is_valid_hash_format_accepts_and_rejects` | built-in | green |

### Plan 63-02: SHA-256 Hash Chain for Audit Emitter

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 63-02-01 | 02 | 2 | genesis_hash() | T-63-04 | Deterministic 64-char hex constant | unit | `cargo test -p dlp-agent --lib audit_emitter::tests::test_genesis_hash_is_deterministic` | built-in | green |
| 63-02-01 | 02 | 2 | genesis_hash() | T-63-04 | Doc-test verifies SHA-256("DLP-AUDIT-CHAIN-v1-GENESIS") | doc-test | `cargo test -p dlp-common --doc` | built-in | green |
| 63-02-01 | 02 | 2 | compute_chain_hash() | T-63-04 | SHA256(prev_hash \|\| canonical_json) | unit | `cargo test -p dlp-agent --lib audit_emitter::tests::test_chain_hash_computation` | built-in | green |
| 63-02-01 | 02 | 2 | compute_chain_hash() | T-63-04 | Doc-test verifies hash computation | doc-test | `cargo test -p dlp-common --doc` | built-in | green |
| 63-02-01 | 02 | 2 | canonical_json_for_hash() | T-63-04 | Excludes prev_hash/chain_hash, deterministic | doc-test | `cargo test -p dlp-common --doc` | built-in | green |
| 63-02-01 | 02 | 2 | emit() includes hash fields | T-63-04 | First event chains from genesis | unit | `cargo test -p dlp-agent --lib audit_emitter::tests::test_emit_includes_hash_fields` | built-in | green |
| 63-02-02 | 02 | 2 | Chain continuity | T-63-04 | Each prev_hash matches previous chain_hash | unit | `cargo test -p dlp-agent --lib audit_emitter::tests::test_chain_continuity_across_multiple_emits` | built-in | green |
| 63-02-02 | 02 | 2 | Concurrent emit safety | T-63-05 | Mutex serializes hash compute + write + flush | unit | `cargo test -p dlp-agent --lib audit_emitter::tests::test_concurrent_emit_maintains_order` | built-in | green |
| 63-02-03 | 02 | 2 | JSONL tail recovery | T-63-04 | Recovers last chain_hash from JSONL tail | unit | `cargo test -p dlp-agent --lib audit_emitter::tests::test_restart_recovers_last_hash` | built-in | green |
| 63-02-03 | 02 | 2 | Truncated line handling | T-63-05 | Skips unparseable last line, uses prior valid | unit | `cargo test -p dlp-agent --lib audit_emitter::tests::test_recovery_handles_truncated_last_line` | built-in | green |

### Plan 63-03: Server-Side Chain Verification

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 63-03-01 | 03 | 3 | store_events_sync maps hash fields | T-63-01 | prev_hash/chain_hash mapped into AuditEventRow | unit | `cargo test -p dlp-server --lib audit_store::tests::test_ingest_verifies_valid_chain` | built-in | green |
| 63-03-02 | 03 | 3 | ingest_events integrity check | T-63-07 | Recomputes hash, compares to claimed chain_hash | unit | `cargo test -p dlp-server --lib audit_store::tests::test_ingest_verifies_valid_chain` | built-in | green |
| 63-03-02 | 03 | 3 | ingest_events continuity check | T-63-08 | prev_hash matches last stored chain_hash per agent | unit | `cargo test -p dlp-server --lib audit_store::tests::test_ingest_detects_broken_chain` | built-in | green |
| 63-03-02 | 03 | 3 | Legacy event skip | T-63-07 | Events without hash fields skip verification | unit | `cargo test -p dlp-server --lib audit_store::tests::test_ingest_skips_verification_for_legacy_events` | built-in | green |
| 63-03-02 | 03 | 3 | Chain break alert | T-63-07 | Synthetic ChainBreakDetected persisted + alerted | unit | `cargo test -p dlp-server --lib audit_store::tests::test_ingest_triggers_alert_on_chain_break` | built-in | green |
| 63-03-02 | 03 | 3 | Alert deduplication | T-63-09b | One alert per (agent_id, reason) per batch | unit | `cargo test -p dlp-server --lib audit_store::tests::test_ingest_deduplicates_chain_break_alerts` | built-in | green |
| 63-03-02 | 03 | 3 | Out-of-order sorting | T-63-08 | Batch sorted by (agent_id, timestamp) before verify | unit | `cargo test -p dlp-server --lib audit_store::tests::test_ingest_out_of_order_events_sorted_correctly` | built-in | green |
| 63-03-02 | 03 | 3 | Hash computation error handling | T-63-09 | Returns Result; flagged as HashComputationFailed | unit | `cargo test -p dlp-server --lib audit_store::tests::test_ingest_detects_broken_chain` | built-in | green |

### Plan 63-04: Integrity Endpoint

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 63-04-01 | 04 | 4 | GET /admin/audit/integrity | T-63-11 | Returns AuditIntegrityResponse with counts | unit | `cargo test -p dlp-server --lib admin_api::tests::test_integrity_endpoint_reports_valid_chain` | built-in | green |
| 63-04-01 | 04 | 4 | integrity_ok true | T-63-11 | No breaks → integrity_ok is true | unit | `cargo test -p dlp-server --lib admin_api::tests::test_integrity_endpoint_reports_valid_chain` | built-in | green |
| 63-04-01 | 04 | 4 | integrity_ok false | T-63-13 | Breaks detected → integrity_ok false + details | unit | `cargo test -p dlp-server --lib admin_api::tests::test_integrity_endpoint_reports_broken_chain` | built-in | green |
| 63-04-01 | 04 | 4 | Legacy events ignored | T-63-13 | Events without chain_hash excluded from report | unit | `cargo test -p dlp-server --lib admin_api::tests::test_integrity_endpoint_ignores_legacy_events` | built-in | green |
| 63-04-01 | 04 | 4 | Pagination limits | T-63-12 | Default 10k, max 100k enforced | unit | `cargo test -p dlp-server --lib admin_api::tests::test_integrity_endpoint_respects_pagination` | built-in | green |
| 63-04-01 | 04 | 4 | JWT protection | T-63-11 | Route under admin router with require_auth | unit | `cargo test -p dlp-server --lib admin_api::tests::test_integrity_endpoint_reports_valid_chain` | built-in | green |
| 63-04-01 | 04 | 4 | spawn_blocking | T-63-12 | Handler offloads to spawn_blocking | unit | `cargo test -p dlp-server --lib admin_api::tests::test_integrity_endpoint_reports_valid_chain` | built-in | green |

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. No Wave 0 setup needed.

- `dlp-common`: Doc-tests for `genesis_hash`, `compute_chain_hash`, `canonical_json_for_hash`
- `dlp-agent`: 7 unit tests in `audit_emitter.rs` covering hash chain + recovery + concurrency
- `dlp-server`: 15 unit tests across `audit_events.rs`, `audit_store.rs`, `admin_api.rs`

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| None | — | — | All behaviors have automated verification |

---

## Validation Audit Trail

| Audit Date | Gaps Found | Resolved | Escalated | Run By |
|------------|------------|----------|-----------|--------|
| 2026-06-06 | 0 | 0 | 0 | gsd-validate-phase |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 90s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** verified 2026-06-06
