---
phase: 47
slug: secrets-encryption-at-rest
status: complete
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-13
---

# Phase 47 — Validation Strategy

> Nyquist validation contract for Phase 47 (Secrets Encryption at Rest / HARD-01).
> Reconstructed from `47-PLAN.md` and `47-SUMMARY.md` because no prior
> `47-VALIDATION.md` existed.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Cargo test (built-in Rust test harness) |
| **Config file** | `dlp-server/Cargo.toml`, `dlp-admin-cli/Cargo.toml` |
| **Quick run command** | `cargo test -p dlp-server crypto:: db::repositories::secret_kek db::repositories::jwt_secret db::repositories::system_kv secrets_migration::tests admin_auth::tests::resolve_jwt` |
| **Full suite command** | `cargo test -p dlp-server` |
| **Estimated runtime** | ~90 seconds (integration tests exercise real DPAPI + file-backed SQLite) |

---

## Sampling Rate

- **After every task commit:** Run the relevant module/unit test command from the Per-Task Verification Map.
- **After every plan wave:** Run `cargo test -p dlp-server` (full unit + integration suite).
- **Before `/gsd-verify-work`:** Full suite must be green on a Windows host (DPAPI-gated tests are `#![cfg(windows)]`).
- **Max feedback latency:** ~90 seconds for full suite.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 47-01-01 | 01 | 1 | HARD-01 | T-47-01 / T-47-03 | AES-256-GCM round-trip recovers plaintext exactly | unit | `cargo test -p dlp-server crypto::tests::round_trip_recovers_plaintext_exactly` | yes | green |
| 47-01-02 | 01 | 1 | HARD-01 | T-47-02 | Column-binding AAD prevents cross-column replay | unit | `cargo test -p dlp-server crypto::tests::aad_mismatch_returns_auth_tag_mismatch` | yes | green |
| 47-01-03 | 01 | 1 | HARD-01 | T-47-05 | Unknown envelope version byte rejected | unit | `cargo test -p dlp-server crypto::tests::unknown_version_byte_yields_unsupported_version_error` | yes | green |
| 47-01-04 | 01 | 1 | HARD-01 | T-47-01 | DPAPI protect/unprotect round-trip (Windows) | unit | `cargo test -p dlp-server crypto::tests::dpapi_round_trip_recovers_plaintext` | yes | green |
| 47-01-05 | 01 | 1 | HARD-01 | T-47-12 | PBKDF2-HMAC-SHA256 known-answer + separation | unit | `cargo test -p dlp-server crypto::tests::pbkdf2_known_answer_rfc7914_passwd_salt_1iter crypto::tests::pbkdf2_inputs_separation` | yes | green |
| 47-01-06 | 01 | 1 | HARD-01 | T-47-03 | Envelope format: 29-byte overhead, version+nonce+ct layout | unit | `cargo test -p dlp-server crypto::tests::envelope_overhead_is_29_bytes crypto::tests::envelope_serialize_layout_is_version_nonce_ciphertext` | yes | green |
| 47-01-07 | 01 | 1 | HARD-01 | T-47-04 | SecretCrypto Debug redacts KEK bytes | unit | `cargo test -p dlp-server crypto::tests::debug_does_not_leak_kek_bytes` | yes | green |
| 47-02-01 | 02 | 2 | HARD-01 | — | `secret_kek_history` table created idempotently | unit | `cargo test -p dlp-server db::repositories::secret_kek::tests::table_exists_after_new_pool` | yes | green |
| 47-02-02 | 02 | 2 | HARD-01 | — | Repository CRUD + retire idempotency + duplicate-version rejection | unit | `cargo test -p dlp-server db::repositories::secret_kek::tests` | yes | green |
| 47-02-03 | 02 | 2 | HARD-01 | — | Pre-Phase-47 DB upgrade path creates table and preserves data | unit | `cargo test -p dlp-server db::repositories::secret_kek::tests::migration_creates_table_on_pre_phase47_db` | yes | green |
| 47-03-01 | 03 | 2 | HARD-01 | — | `secrets_jwt` schema matches plan (CHECK id=1, columns) | unit | `cargo test -p dlp-server db::repositories::jwt_secret::tests::schema_columns_match_plan` | yes | green |
| 47-03-02 | 03 | 2 | HARD-01 | — | `secrets_jwt` single-row invariant enforced | unit | `cargo test -p dlp-server db::repositories::jwt_secret::tests::check_constraint_rejects_non_one_id` | yes | green |
| 47-03-03 | 03 | 2 | HARD-01 | — | Encrypted column trios added idempotently to pre-Phase-47 schema | unit | `cargo test -p dlp-server db::tests::test_migration_add_secret_encrypted_columns` | yes | green |
| 47-04-01 | 04 | 3 | HARD-01 | T-47-02 / T-47-03 | `siem_config` encrypted column round-trip | unit | `cargo test -p dlp-server db::repositories::siem_config::tests::update_then_get_round_trips_both_secrets` | yes | green |
| 47-04-02 | 04 | 3 | HARD-01 | T-47-03 | `siem_config` tampered nonce yields decrypt error | unit | `cargo test -p dlp-server db::repositories::siem_config::tests::tamper_with_nonce_yields_decrypt_error` | yes | green |
| 47-04-03 | 04 | 3 | HARD-01 | T-47-02 | `alert_router_config` cross-column replay rejected by AAD | unit | `cargo test -p dlp-server db::repositories::alert_router_config::tests::cross_column_replay_rejected_by_aad` | yes | green |
| 47-04-04 | 04 | 3 | HARD-01 | T-47-10 | `alert_router_config` mask round-trip preserved | unit | `cargo test -p dlp-server db::repositories::alert_router_config::tests::mask_round_trip_preserves_existing_secret` | yes | green |
| 47-04-05 | 04 | 3 | HARD-01 | T-47-04 | `alert_router_config` Debug redacts secrets | unit | `cargo test -p dlp-server db::repositories::alert_router_config::tests::secret_debug_redacts` | yes | green |
| 47-05-01 | 05 | 3 | HARD-01 | — | JWT env-var migrates into encrypted DB row once | unit | `cargo test -p dlp-server admin_auth::tests::resolve_jwt_with_crypto_migrates_env_var_into_db` | yes | green |
| 47-05-02 | 05 | 3 | HARD-01 | — | JWT DB row wins over env-var on subsequent starts | unit | `cargo test -p dlp-server admin_auth::tests::resolve_jwt_with_crypto_prefers_db_over_env_var` | yes | green |
| 47-05-03 | 05 | 3 | HARD-01 | — | Dev-mode fallback does not write DB; production without env fails | unit | `cargo test -p dlp-server admin_auth::tests::resolve_jwt_with_crypto_dev_mode_fallback_does_not_write_db admin_auth::tests::resolve_jwt_with_crypto_production_without_env_returns_error` | yes | green |
| 47-05-04 | 05 | 3 | HARD-01 | — | LDAP explicit-bind round-trip; passwordless default | unit | `cargo test -p dlp-server db::repositories::ldap_config::tests` | yes | green |
| 47-06-01 | 06 | 4 | HARD-01 | T-47-01 | Migration encrypts seeded cleartext and drops columns | unit | `cargo test -p dlp-server secrets_migration::tests::seeded_cleartext_encrypts_and_drops_columns` | yes | green |
| 47-06-02 | 06 | 4 | HARD-01 | T-47-08 | Migration is idempotent on already-migrated DB | unit | `cargo test -p dlp-server secrets_migration::tests::idempotent_second_run_reports_zero_work` | yes | green |
| 47-06-03 | 06 | 4 | HARD-01 | T-47-08 | Migration is atomic across a table boundary | unit | `cargo test -p dlp-server secrets_migration::tests::migration_is_atomic_across_a_table_boundary` | yes | green |
| 47-06-04 | 06 | 4 | HARD-01 | — | JWT no-env + no-DB is a no-op | unit | `cargo test -p dlp-server secrets_migration::tests::jwt_no_env_no_db_is_a_noop` | yes | green |
| 47-07-01 | 07 | 4 | HARD-01 | T-47-10 | Admin API mask round-trip preserves existing SMTP password | integration | `cargo test -p dlp-server --test secrets_encryption_integration test_admin_api_mask_round_trip_preserves_existing` | yes | green |
| 47-08-01 | 08 | 5 | HARD-01 | T-47-09 | Rotation refuses without maintenance mode when force=false | unit | `cargo test -p dlp-server secrets_migration::tests::rotate_kek_requires_maintenance_mode_when_force_false` | yes | green |
| 47-08-02 | 08 | 5 | HARD-01 | T-47-09 | Rotation re-encrypts all targets and retires old KEK | unit | `cargo test -p dlp-server secrets_migration::tests::rotate_kek_test_inject_reencrypts_all_targets_and_retires_v1` | yes | green |
| 47-08-03 | 08 | 5 | HARD-01 | T-47-09 | Rotation skips targets with no populated rows but still retires | unit | `cargo test -p dlp-server secrets_migration::tests::rotate_kek_skips_targets_with_no_populated_rows` | yes | green |
| 47-08-04 | 08 | 5 | HARD-01 | T-47-09 | Same-version rotation is rejected | unit | `cargo test -p dlp-server secrets_migration::tests::rotate_kek_same_version_rejected` | yes | green |
| 47-08-05 | 08 | 5 | HARD-01 | — | `system_kv` maintenance_mode toggle works | unit | `cargo test -p dlp-server db::repositories::system_kv::tests` | yes | green |
| 47-08-06 | 08 | 5 | HARD-01 | — | `dlp-admin-cli rotate-secrets` builds | build | `cargo build -p dlp-admin-cli` | yes | green |
| 47-09-01 | 09 | 3 | HARD-01 | T-47-04 | SecretString Debug redaction in `alert_router_config` | unit | `cargo test -p dlp-server db::repositories::alert_router_config::tests::secret_debug_redacts` | yes | green |
| 47-10-01 | 10 | 5 | HARD-01 | T-47-09 | Full KEK rotation cycle + forensic decrypt + tampering | integration | `cargo test -p dlp-server --test secrets_rotation_integration` | yes | green |
| 47-11-01 | 11 | 5 | HARD-01 | T-47-01 / T-47-08 | Pre-Phase-47 fixture DB migration drops cleartext columns | integration | `cargo test -p dlp-server --test secrets_migration_integration` | yes | green |
| 47-11-02 | 11 | 5 | HARD-01 | T-47-01 | Admin API e2e round-trip + DB-level encrypted-blob check | integration | `cargo test -p dlp-server --test secrets_encryption_integration` | yes | green |
| 47-11-03 | 11 | 5 | HARD-01 | T-47-04 | No cleartext secret in tracing or `audit_events` TEXT columns | integration | `cargo test -p dlp-server --test secrets_log_scan_integration` | yes | green |

*Status: green = verified passing on 2026-06-13*

---

## Wave 0 Requirements

- [x] Existing Cargo test infrastructure covers all phase requirements.
- [x] No new test framework needed.
- [x] No watch-mode flags used.

*"Existing infrastructure covers all phase requirements."*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| None | — | — | — |

*All phase behaviors have automated verification. DPAPI recovery runbook is intentionally Phase 52 scope (CONTEXT D-Q4); Phase 47 only fail-fasts on DPAPI errors, and that path is covered by `load_active_or_bootstrap` startup wiring in `main.rs` plus integration tests on Windows CI.*

---

## Validation Audit 2026-06-13

| Metric | Count |
|--------|-------|
| Gaps found | 0 |
| Resolved | 0 |
| Escalated | 0 |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or build verification
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 120s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-06-13
