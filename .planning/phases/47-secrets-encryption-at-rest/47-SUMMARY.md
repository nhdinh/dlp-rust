---
phase: 47
phase_name: Secrets Encryption at Rest
milestone: v1.0.0
milestone_name: Enterprise Hardening & Scale
status: complete
completed: 2026-05-11
requirements: [HARD-01]
tags: [security, crypto, secrets, dpapi, aes-gcm, kek-rotation]
key_files:
  added:
    - dlp-server/src/crypto/mod.rs
    - dlp-server/src/crypto/dpapi.rs
    - dlp-server/src/crypto/envelope.rs
    - dlp-server/src/crypto/error.rs
    - dlp-server/src/crypto/kdf.rs
    - dlp-server/src/secrets_migration.rs
    - dlp-server/src/db/repositories/secret_kek.rs
    - dlp-server/src/db/repositories/jwt_secret.rs
    - dlp-server/src/db/repositories/system_kv.rs
    - dlp-server/tests/secrets_rotation_integration.rs
    - dlp-server/tests/secrets_migration_integration.rs
    - dlp-server/tests/secrets_encryption_integration.rs
    - dlp-server/tests/secrets_log_scan_integration.rs
  modified:
    - dlp-server/src/admin_api.rs
    - dlp-server/src/admin_auth.rs
    - dlp-server/src/alert_router.rs
    - dlp-server/src/db/mod.rs
    - dlp-server/src/db/repositories/mod.rs
    - dlp-server/src/db/repositories/alert_router_config.rs
    - dlp-server/src/db/repositories/siem_config.rs
    - dlp-server/src/db/repositories/ldap_config.rs
    - dlp-server/src/lib.rs
    - dlp-server/src/main.rs
    - dlp-server/src/siem_connector.rs
    - dlp-admin-cli/src/client.rs
    - dlp-admin-cli/src/main.rs
key_decisions:
  - Use AES-256-GCM with per-row 96-bit random nonce + (table,column) AAD
  - DPAPI-machine-scope (CRYPTPROTECT_LOCAL_MACHINE) protects the master seed
  - PBKDF2-HMAC-SHA256 with 600 000 iterations (OWASP 2026) derives the KEK
  - Cleartext columns are dropped in the SAME transaction as the encrypt pass (CONTEXT D-Q6)
  - Rotation is admin-CLI only (no HTTP-only path), gated by `system_kv.maintenance_mode`
  - Retired KEK rows are RETAINED in `secret_kek_history` for delayed-rollback forensic decrypt
metrics:
  total_tasks: 11
  total_commits: 13
  test_count_before: 293
  test_count_after_lib: 313
  integration_test_files: 4
  integration_test_count: 9
---

# Phase 47: Secrets Encryption at Rest — Summary

End-to-end encryption-at-rest layer for every secret in operator SQLite, machine-bound to the originating Windows host via DPAPI. HARD-01 is closed.

## One-Liner

AES-256-GCM envelope encryption for every operator-DB secret column, machine-bound via DPAPI + PBKDF2 (600 000 iter), with atomic cleartext-drop migration, admin-CLI KEK rotation, and a permanent log-scan acceptance test.

## What Shipped

**Wave 1 — Crypto core (Task 47-01)** — `dlp-server/src/crypto/`:

- `SecretCrypto` AES-256-GCM wrapper with `encrypt`/`decrypt`/`from_kek`/`load_active`/`load_active_or_bootstrap`/`create_new_version`/`load_by_version`.
- `Envelope` on-disk format (version byte + 12-byte nonce + ciphertext+tag).
- `aad_for(table, column)` binds every ciphertext to its column identity.
- DPAPI `protect`/`unprotect` Windows FFI with machine-scope binding.
- PBKDF2 KDF (600 000 iterations, 16-byte salt).

**Wave 2 — Storage layer (Tasks 47-02, 47-03)**:

- `secret_kek_history` table + `SecretKekRepository` (storage-only — no crypto coupling).
- `secrets_jwt` table (single-row, `CHECK id = 1`) for the JWT signing secret.
- `*_encrypted` / `*_nonce` / `*_version` column trios on `alert_router_config`, `siem_config`, `ldap_config` via idempotent `run_alter` migrations.

**Wave 3 — Encrypted repositories + SecretString boundary (Tasks 47-04, 47-05, 47-09)**:

- `SiemConfigRepository`, `AlertRouterConfigRepository`, `LdapConfigRepository`, `jwt_secret` repository return `SecretString` from every read path.
- `expose_secret()` quarantined to send paths (SMTP via lettre, LDAP bind, JWT sign/verify).
- Per-repo policy comment forbids naked-`String` secret fields.

**Wave 4 — Migration + AppState + mask-round-trip (Tasks 47-06, 47-07)**:

- `secrets_migration::migrate_secrets_to_encrypted` performs the one-shot atomic upgrade: encrypt-and-verify pass, NULL the cleartext, `ALTER TABLE ... DROP COLUMN` — all inside one transaction per `(table, column)` pair (SQLite 3.35+ DROP COLUMN guarantee).
- `Arc<SecretCrypto>` wired through `AppState`; `SiemConnector::new` and `AlertRouter::new` consume it.
- `admin_auth::resolve_jwt_secret(pool, crypto, dev_mode)` migrates env-var → DB row on first call, then ignores the env-var.
- `PRAGMA secure_delete = ON` enabled at pool init so freed pages are zero-overwritten.
- `ALERT_SECRET_MASK` round-trip regression-tested for both SMTP and SIEM endpoints.

**Wave 5 — Rotation + acceptance tests (Tasks 47-08, 47-10, 47-11)**:

- `dlp-admin-cli rotate-secrets [--force-while-running]` + `dlp-admin-cli maintenance enter|exit` subcommands.
- `POST /admin/secrets/rotate`, `POST /admin/maintenance/enter`, `POST /admin/maintenance/exit` admin-auth-gated endpoints.
- `secrets_migration::rotate_kek(pool, current, force) -> RotationReport` performs per-table re-encrypt under a fresh KEK, then retires the old version in `secret_kek_history`.
- `system_kv` table + repository hosts the `maintenance_mode` boolean gate.
- `SecretCrypto::load_by_version(conn, v)` enables forensic decrypt of pre-rotation envelopes after the rotation cycle completes.
- Four integration test files (9 tests) cover: full rotation cycle with tampering + forensic decrypt; pre-Phase-47 → migrated DB acceptance + JWT env→DB; admin-API e2e round-trip; permanent log-scan + audit-events cleartext-leak scan.

## Success Criteria Trace

| Criterion | Description | Closed by |
|-----------|-------------|-----------|
| #1 | New rows encrypt on write; reads decrypt transparently | Tasks 47-01 (crypto), 47-04 (encrypted repos), 47-05 (LDAP), 47-11 (`secrets_encryption_integration.rs`) |
| #2 | Migration upgrades existing rows; JWT env-var migrates to DB on first start | Tasks 47-03 (schema), 47-05 (JWT repo), 47-06 (`migrate_secrets_to_encrypted`), 47-11 (`secrets_migration_integration.rs`) |
| #3 (amended) | Cleartext column is transient (intra-migration only); no cleartext persists after migration commit | Tasks 47-06 (DROP COLUMN in-commit), 47-11 (PRAGMA `table_info` assertion in `test_migration_drops_cleartext_columns_in_same_commit`) |
| #4 | Rotation procedure exercised in a test | Tasks 47-08 (CLI + endpoint + `rotate_kek`), 47-10 (`secrets_rotation_integration.rs` — full cycle with forensic decrypt) |
| #5 | No cleartext secret appears in any log line | Tasks 47-09 (SecretString boundary + Debug-redaction policy), 47-11 (`secrets_log_scan_integration.rs` — in-memory tracing buffer + dynamic audit_events TEXT-column scan) |

## Locked Decisions — How They Landed

| Decision | Resolution in Code |
|----------|--------------------|
| **D-Q1** — Scope: encrypt all four secret types (SMTP, webhook, SIEM tokens, JWT, optional LDAP bind) | Schema columns added (Task 47-03); migration covers all four MIGRATION_TARGETS plus the JWT special case (Task 47-06). |
| **D-Q2** — KDF: PBKDF2-HMAC-SHA256, 600 000 iter | `crypto::kdf::derive_kek` + `PBKDF2_DEFAULT_ITERATIONS = 600_000`. Iteration count is persisted per-row in `secret_kek_history.pbkdf2_iterations` so a future bump can coexist with older KEKs. |
| **D-Q3** — AES-256-GCM with per-row 96-bit random nonce + `(table, column)` AAD | `SecretCrypto::encrypt` draws nonce from `OsRng`; `aad_for(table, column)` produces `b"dlp:secret:<table>:<column>"`. Cross-column ciphertext replay fails with `CryptoError::AuthTagMismatch`. |
| **D-Q4** — DPAPI recovery is Phase 52 documentation, NOT Phase 47 code | Phase 47 fails fast on DPAPI unprotect failure (surfaced from `SecretCrypto::load_active_or_bootstrap` via `anyhow::Error` to `main.rs`). See "Phase 52 Handoff" below. |
| **D-Q5** — Rotation via admin CLI only | `dlp-admin-cli rotate-secrets` subcommand (Task 47-08). The HTTP endpoint is mTLS+admin-auth-gated and only the CLI calls it. Maintenance-mode gate forces explicit operator opt-in (or `--force-while-running`). |
| **D-Q6** — Cleartext columns dropped in same release (no persistent backup column) | `migrate_one_column` runs encrypt-and-verify, NULL of cleartext, and `ALTER TABLE ... DROP COLUMN` inside a single transaction. `test_migration_drops_cleartext_columns_in_same_commit` (Task 47-11) asserts via `PRAGMA table_info` that the cleartext column is physically gone after migration. |

## Test Counts

- **Pre-phase baseline (Wave 0):** 293 `dlp-server` library tests.
- **Post-Wave 5:** 313 `dlp-server` library tests + 9 new integration tests:
  - `secrets_rotation_integration.rs` — 1 test (full cycle + forensic decrypt + tampering)
  - `secrets_migration_integration.rs` — 4 tests (cleartext drop, JWT env→DB, idempotency, no-env-no-DB no-op)
  - `secrets_encryption_integration.rs` — 3 tests (alert-config round-trip, mask preservation, SIEM tokens round-trip)
  - `secrets_log_scan_integration.rs` — 1 test (in-memory tracing + audit_events TEXT-column scan)
- **Per-wave breakdown:**
  - Wave 1: +crypto module tests (envelope, AAD round-trip, encrypt/decrypt parity, AES-GCM tampering rejection).
  - Wave 2: +`secret_kek_history` repository tests (insert/get_active/retire/list/migration).
  - Wave 3: +mask round-trip and SecretString-Debug-redact tests for each encrypted repo.
  - Wave 4: +migration tests in `secrets_migration::tests` (empty DB, seeded cleartext, idempotency, JWT env→DB).
  - Wave 5: +5 unit-level rotation tests in `secrets_migration::tests` (maintenance gate, re-encrypt all targets + retire v1, force bypass, skip-empty-targets, same-version rejection), +4 `system_kv` repository tests, +9 integration tests listed above.

## Deviations from Plan

1. **Transitional `*_with_crypto` method duality (Wave 3, retired in Wave 4).** Wave 3 (Tasks 47-04 / 47-05) introduced `get_with_crypto`/`update_with_crypto` parallel methods rather than rewriting the existing `get`/`update` signatures in-place. Rationale: AppState integration was deferred to Wave 4 (Task 47-06), so a same-commit in-place rewrite of `get`/`update` would have required `main.rs` to ship `Arc<SecretCrypto>` in `AppState` simultaneously. The duality kept Wave 3 narrowly scoped; Wave 4's Task 47-06 retired the duality by renaming `*_with_crypto` back to the canonical names once `AppState` carried the crypto handle. Documented in the wave-4 STATE note.

2. **`SecretCrypto.kek` type — `Zeroizing<[u8; 32]>` instead of `SecretBox<[u8; 32]>`.** The original `<interfaces>` block in 47-PLAN.md specified `secrecy::SecretBox<[u8; 32]>`, but `secrecy 0.8` requires `Box<S>: Zeroize`, and `zeroize 1.8` only implements `Zeroize for Box<[T]>` (slice form), not `Box<[T; N]>` (sized array form). `Zeroizing<[u8; 32]>` provides equivalent on-drop zeroisation without the type-system tax. Documented in the doc comment on `SecretCrypto`.

3. **Wave 5 added a `#[cfg(test)] rotate_kek_test_inject` seam.** The production `rotate_kek` calls `SecretCrypto::create_new_version`, which is DPAPI-gated and only compiles on Windows. To keep the unit-test suite usable on non-Windows dev machines, Wave 5 added a `rotate_kek_test_inject(pool, current, new_crypto)` seam that bypasses DPAPI by accepting a pre-built `SecretCrypto`. Integration tests (Tasks 47-10 / 47-11) still exercise the full DPAPI path on Windows runners via `#![cfg(windows)]` file-level gating.

4. **`maintenance_mode` flag — generic `system_kv` table instead of a dedicated single-row table.** Plan-check N5 called for an explicit boolean flag to gate the rotation endpoint. We introduced `system_kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)` rather than a dedicated `maintenance_state` table, because any future ad-hoc operator toggle (e.g. read-only mode, ingestion pause) can piggyback on the same table without growing the schema. The `system_kv` repository centralises the boolean encoding (`"1"` / `"0"`) so future flags stay consistent.

## Auth / Operational Gates Observed

- **DPAPI bootstrap.** `SecretCrypto::load_active_or_bootstrap` is called at server start (`main.rs`). On a fresh install it inserts `secret_kek_history` v1 + a DPAPI-wrapped 32-byte CSPRNG seed. On subsequent starts it re-derives the KEK from the DPAPI-wrapped seed. Failure (e.g. wrong machine, profile rebuild, security tool intervention) surfaces as a startup `Err` to `main.rs` and exits non-zero. Per CONTEXT D-Q4, recovery is operational documentation in Phase 52.
- **Rotation maintenance gate.** `rotate_kek(force=false)` refuses unless `system_kv.maintenance_mode = "1"` — operator must explicitly `dlp-admin-cli maintenance enter` first. `--force-while-running` bypasses the gate. No timing-based / heuristic gate (e.g. "last heartbeat < 60s") was introduced — the deterministic boolean cannot race with normal agent polling cycles.

## Phase 52 Handoff — DPAPI Recovery Runbook

**Out of scope for Phase 47 (per CONTEXT D-Q4).** Phase 52 must produce an operational runbook covering at least the following scenarios where Phase 47's fail-fast guarantee bites:

1. **VM reimage / OS reinstall.** DPAPI machine scope is bound to the OS installation. A reimage destroys the machine secret; existing `secret_kek_history.master_seed_dpapi` blobs become permanently unrecoverable.
2. **Profile rebuild.** Same outcome at the user-profile level if the service ever switches off the SYSTEM account.
3. **Security-tool intervention.** Some EDR / DLP products encrypt or block DPAPI; the service starts and fails at `dpapi_unprotect`. The runbook should enumerate known-bad products and remediation steps.
4. **Migration off a host.** No "export the KEK to a portable file" path exists in Phase 47 by design (D-Q3 + D-Q4 trust model). Phase 52 should document the recovery procedure: re-bootstrap on the new host (creates a fresh KEK v1), then re-enter every operator secret (SMTP password, SIEM tokens, etc.) through the admin TUI. The prior secrets cannot be recovered without DPAPI.

**Artifacts Phase 52 inherits:**

- `secret_kek_history` table — source of truth for the protected master seed. Phase 52's runbook MUST document offline backup of this table BEFORE any high-risk operation. Backups must be encrypted at rest by the operator (out-of-DLP) because the DPAPI-wrapped blob alone is not portable.
- `system_kv.maintenance_mode` — the operator-facing toggle that lets Phase 52's recovery flow guarantee no in-flight rotation collides with the recovery procedure.
- `SecretCrypto::load_by_version(conn, v)` — the API Phase 52's "validate the backup decrypts before reimage" check-script will call.

## Out-of-Scope Items Observed

- **31 pre-existing clippy errors** in `dlp-server/src/db/repositories/device_registry.rs`, `disk_registry.rs`, and `managed_origins.rs`. These predate Phase 47 (count unchanged across Waves 1-5 and confirmed against `cargo clippy -p dlp-server --tests`). Flag for a dedicated cleanup phase or roll into Phase 48 (admin_api refactor) cleanup.
- **`dlp-hook-dll` clippy warnings.** Pre-existing; out of scope per CLAUDE.md §9.16.
- **`dlp-admin-cli/src/screens/render.rs`** has a pre-existing rustfmt diff (import order, line break) unrelated to this phase. Left untouched.

## HARD-01 Status

**CLOSED.** Every secret column in operator SQLite is AES-256-GCM ciphertext after migration (`test_admin_api_round_trip_smtp_password`, `test_admin_api_siem_tokens_round_trip`). Cleartext columns are dropped in-commit (`test_migration_drops_cleartext_columns_in_same_commit`). JWT env→DB migration works (`test_jwt_env_var_migrates_to_db_on_first_call_only`). Rotation is exercised end-to-end with forensic decrypt of retired KEK envelopes (`full_rotation_cycle_preserves_every_secret_and_retires_v1`). The log-scan test (`test_no_cleartext_secret_appears_in_tracing_or_audit_log`) asserts permanent absence of cleartext in both tracing output and `audit_events` TEXT columns — any future regression in logging hygiene fails CI.

## Commits

| Wave | Task | Commit | Purpose |
|------|------|--------|---------|
| 1 | 47-01 | `1cdcb48` | Crypto core (AES-256-GCM, DPAPI, KDF, envelope, AAD). |
| 2 | 47-02 | `a62c735` | `secret_kek_history` schema + storage-only repository. |
| 2 | 47-03 | `3c44265` | `secrets_jwt` table + `*_encrypted` trios on existing secret tables. |
| 2 | (state) | `d963645` | Wave 2 STATE.md update. |
| 3 | 47-04, 47-05, 47-09 | (Waves 3 commits — see git log) | Encrypted repository readers/writers, SecretString boundary, logging-hygiene audit. |
| 4 | 47-06 | `765e875` | One-shot atomic migration + `AppState.crypto` wiring + DROP COLUMN in-commit. |
| 4 | 47-07 | `b86a962` | SIEM-side ALERT_SECRET_MASK round-trip regression test. |
| 4 | (state) | `dc13f25` | Wave 4 STATE.md update (paused before Wave 5). |
| 5 | 47-08 | `7846671` | Admin-CLI `rotate-secrets` + server endpoint + maintenance-mode flag. |
| 5 | 47-10 | `5a0619f` | Full-cycle KEK rotation integration test with forensic decrypt. |
| 5 | 47-11 | `e6e4aa4` | Migration + e2e + log-scan integration tests (HARD-01 acceptance). |

## Self-Check: PASSED

- All Wave 5 commits exist in `git log --oneline --all`.
- All success criteria mapped to closing tests.
- HARD-01 closed.
- Phase 52 handoff documented above.
