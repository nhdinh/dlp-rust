---
phase: 47-secrets-encryption-at-rest
plan: 47
type: execute
wave: 1
depends_on: []
requirements: [HARD-01]
autonomous: true
files_modified:
  # Wave 1 — Crypto core
  - dlp-server/Cargo.toml
  - dlp-server/src/lib.rs
  - dlp-server/src/crypto/mod.rs
  - dlp-server/src/crypto/dpapi.rs
  - dlp-server/src/crypto/kdf.rs
  - dlp-server/src/crypto/envelope.rs
  - dlp-server/src/crypto/error.rs
  - dlp-server/src/crypto/tests.rs
  # Wave 2 — Schema + KEK lifecycle
  - dlp-server/src/db/mod.rs
  - dlp-server/src/db/repositories/secret_kek.rs
  - dlp-server/src/db/repositories/mod.rs
  # Wave 3 — Loader integration + JWT/LDAP schema
  - dlp-server/src/db/repositories/siem_config.rs
  - dlp-server/src/db/repositories/alert_router_config.rs
  - dlp-server/src/db/repositories/jwt_secret.rs
  - dlp-server/src/db/repositories/ldap_config.rs
  - dlp-server/src/admin_auth.rs
  - dlp-server/src/admin_api.rs
  - dlp-common/src/ad_client.rs
  # Wave 4 — One-shot data migration + bootstrap wiring
  - dlp-server/src/main.rs
  - dlp-server/src/secrets_migration.rs
  # Wave 5 — Rotation CLI + integration tests
  - dlp-admin-cli/src/main.rs
  - dlp-admin-cli/src/client.rs
  - dlp-server/src/admin_api.rs
  - dlp-server/tests/secrets_encryption_integration.rs
  - dlp-server/tests/secrets_rotation_integration.rs
  - dlp-server/tests/secrets_log_scan_integration.rs
  - dlp-server/tests/secrets_migration_integration.rs

must_haves:
  truths:
    - "SMTP password, SIEM tokens, JWT signing key, and LDAP bind password are stored only as AES-256-GCM ciphertext in SQLite after migration."
    - "Existing cleartext rows are encrypted in place; the cleartext column is dropped in the same release."
    - "JWT_SECRET env-var is migrated into an encrypted DB row on first post-deploy startup and is no longer required thereafter."
    - "Service operator can invoke `dlp-admin-cli rotate-secrets` to re-key all encrypted columns in one atomic operation."
    - "No fixture secret value appears in any tracing log line or audit_events row, asserted by a CI integration test."
    - "Admin API mask round-trip (ALERT_SECRET_MASK) preserves the existing TOCTOU-safe pattern when reading and writing encrypted columns."
  artifacts:
    - path: dlp-server/src/crypto/mod.rs
      provides: "SecretCrypto facade — encrypt(plaintext,aad) / decrypt(envelope,aad)"
    - path: dlp-server/src/crypto/dpapi.rs
      provides: "DPAPI wrap/unwrap with CRYPTPROTECT_LOCAL_MACHINE"
    - path: dlp-server/src/crypto/kdf.rs
      provides: "PBKDF2-HMAC-SHA256 600k → 32-byte KEK"
    - path: dlp-server/src/crypto/envelope.rs
      provides: "Versioned ciphertext envelope: [version][nonce(12)][gcm_ct+tag]"
    - path: dlp-server/src/db/repositories/secret_kek.rs
      provides: "secret_kek_history repository — KEK seed lifecycle + rotation"
    - path: dlp-server/src/secrets_migration.rs
      provides: "One-shot atomic cleartext-to-encrypted migration; idempotent re-runnable"
    - path: dlp-server/tests/secrets_encryption_integration.rs
      provides: "End-to-end round-trip via admin API"
    - path: dlp-server/tests/secrets_rotation_integration.rs
      provides: "Full key-rotation cycle test (success criterion #4)"
    - path: dlp-server/tests/secrets_log_scan_integration.rs
      provides: "Audit-log + tracing-buffer scan asserting no cleartext (success criterion #5)"
    - path: dlp-server/tests/secrets_migration_integration.rs
      provides: "Pre-Phase-47 fixture DB → migrate → assert cleartext columns dropped"
  key_links:
    - from: "dlp-server/src/db/repositories/alert_router_config.rs"
      to: "dlp-server/src/crypto/mod.rs::SecretCrypto"
      via: "decrypt() in get_secrets(), encrypt() in update()"
      pattern: "SecretCrypto::(encrypt|decrypt)"
    - from: "dlp-server/src/admin_auth.rs"
      to: "dlp-server/src/db/repositories/jwt_secret.rs"
      via: "DB-encrypted row preferred, env-var fallback with deprecation warn"
      pattern: "jwt_secret::load_or_migrate_from_env"
    - from: "dlp-admin-cli/src/main.rs"
      to: "POST /admin/secrets/rotate"
      via: "rotate-secrets subcommand"
      pattern: "rotate-secrets"
    - from: "dlp-server/src/main.rs"
      to: "dlp-server/src/secrets_migration.rs::migrate_secrets_to_encrypted"
      via: "called after new_pool(), before serve()"
      pattern: "migrate_secrets_to_encrypted"
---

# Phase 47 Plan — Secrets Encryption at Rest

<objective>
Encrypt all four enterprise secret types in the operator SQLite database (SMTP password, SIEM webhook/API tokens, JWT signing key, LDAP bind password) using PBKDF2-HMAC-SHA256 (600k iterations) for KEK derivation from a DPAPI-protected machine secret, then AES-256-GCM with per-row 96-bit nonces and column-binding AAD for the column ciphertext envelope. Migrate cleartext columns to encrypted form atomically and drop the cleartext column in the same release. Migrate JWT from env-var to DB on first startup post-deployment. Add schema for LDAP optional explicit-bind credentials. Expose `dlp-admin-cli rotate-secrets` for documented, test-exercised key rotation. Guarantee no cleartext secret appears in any log line via CI scan.

Purpose: Closes HARD-01 — the highest-severity hardening debt from PROJECT.md. Removes the cleartext secret risk from the SQLite file (offline file-theft + backup-leak attack class), aligns with NIST/FIPS posture, and prepares the codebase for SonarQube's "hardcoded credential" detector (HARD-08).

Output: A `dlp-server/src/crypto/` module, four encrypted SQLite columns (SMTP password, SIEM splunk_token + elk_api_key, webhook_secret) plus two new encrypted tables (`secrets_jwt`, `secrets_ldap_bind`), an idempotent migration function, an admin CLI rotation command, and four integration tests proving round-trip, migration, rotation, and log hygiene.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/phases/47-secrets-encryption-at-rest/47-CONTEXT.md
@.planning/phases/47-secrets-encryption-at-rest/47-RESEARCH.md
@.planning/codebase/STACK.md
@.planning/codebase/STRUCTURE.md
@.planning/codebase/CONVENTIONS.md
@.planning/codebase/TESTING.md

# Critical reference points — read before touching the corresponding modules
@dlp-server/src/db/mod.rs           # Lines 1-100 init pattern; 271-423 migrations; 731-802 test template
@dlp-server/src/admin_api.rs        # Lines 1300-1416 ALERT_SECRET_MASK round-trip — DO NOT BREAK
@dlp-server/src/admin_auth.rs       # Lines 60-99 current JWT_SECRET env-var loading site
@dlp-agent/src/password_stop.rs     # Lines 750-781 CryptUnprotectData reference (user-scope today)
@dlp-user-ui/src/dialogs/stop_password.rs  # Lines 239-265 CryptProtectData reference (user-scope today)
@dlp-common/src/ad_client.rs        # Line 376 simple_bind passwordless SSPI site

<interfaces>
<!-- Cryptographic API surface — every task in this plan implements against or consumes these contracts.
     Executors should NOT re-explore the codebase to discover these: they are normative for Phase 47. -->

From dlp-server/src/crypto/mod.rs (to be created by Task 47-01):
```rust
// New module surface
pub use dpapi::{MachineSecret, dpapi_protect, dpapi_unprotect};
pub use kdf::derive_kek;                                      // PBKDF2-HMAC-SHA256, 600k iterations
pub use envelope::{Envelope, ENVELOPE_VERSION_V1};            // [version][nonce(12)][ct+tag]
pub use error::CryptoError;

/// Per-secret AAD: binds ciphertext to its table+column to prevent cross-column replay.
pub fn aad_for(table: &str, column: &str) -> Vec<u8>; // b"dlp:secret:" || table || b":" || column

pub struct SecretCrypto {
    kek: secrecy::SecretBox<[u8; 32]>,
    version: u8,
}

impl SecretCrypto {
    /// Bootstrap from secret_kek_history active row. Reads master_seed_dpapi,
    /// unprotects via DPAPI (CRYPTPROTECT_LOCAL_MACHINE), derives KEK via PBKDF2.
    pub fn load_active(conn: &rusqlite::Connection) -> Result<Self, CryptoError>;

    /// Generate fresh seed + salt, DPAPI-protect, insert as new active version.
    pub fn create_new_version(conn: &mut rusqlite::Connection) -> Result<Self, CryptoError>;

    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Envelope, CryptoError>;
    pub fn decrypt(&self, env: &Envelope, aad: &[u8]) -> Result<secrecy::SecretString, CryptoError>;
}
```

From dlp-server/src/db/repositories/secret_kek.rs (to be created by Task 47-02):
```rust
pub struct SecretKekRecord {
    pub version: u8,
    pub master_seed_dpapi: Vec<u8>,   // DPAPI-protected, machine-scope
    pub pbkdf2_salt: [u8; 16],
    pub pbkdf2_iterations: u32,        // 600_000 default
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub retired_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub fn get_active(conn: &rusqlite::Connection) -> Result<Option<SecretKekRecord>, rusqlite::Error>;
pub fn get_by_version(conn: &rusqlite::Connection, version: u8) -> Result<Option<SecretKekRecord>, rusqlite::Error>;
pub fn insert_new(conn: &rusqlite::Connection, rec: &SecretKekRecord) -> Result<(), rusqlite::Error>;
pub fn retire(conn: &rusqlite::Connection, version: u8, retired_at: chrono::DateTime<chrono::Utc>) -> Result<(), rusqlite::Error>;
```

From dlp-server/src/secrets_migration.rs (to be created by Task 47-04):
```rust
/// Idempotent. Safe to re-run on every startup. Encrypts any row where
/// `*_encrypted IS NULL AND <cleartext> != ''`, verifies decrypt round-trip,
/// NULLs the cleartext column, and after all rows processed drops the cleartext
/// column via ALTER TABLE. JWT special case: migrates env-var to DB row.
pub fn migrate_secrets_to_encrypted(
    pool: &crate::db::Pool,
    crypto: &crate::crypto::SecretCrypto,
    jwt_env_fallback: Option<&str>,
) -> anyhow::Result<MigrationReport>;

pub struct MigrationReport {
    pub rows_encrypted: u32,
    pub jwt_migrated_from_env: bool,
    pub cleartext_columns_dropped: Vec<String>,
}
```

From dlp-server/src/admin_api.rs (ALERT_SECRET_MASK pattern at lines 1300-1416 — preserved invariant):
- GET decrypts `*_encrypted` blob → masks the field to ALERT_SECRET_MASK sentinel in response JSON.
- PUT: if incoming field == ALERT_SECRET_MASK, repository's get_secrets() reads + decrypts the existing
  ciphertext within the same transaction (TOCTOU-safe) and re-encrypts unchanged plaintext into the new row.
- This invariant is the most likely place to break — every read/write path through these repositories
  MUST go through SecretCrypto and MUST preserve the mask sentinel semantics.

From dlp-admin-cli (Task 47-08):
```
dlp-admin-cli rotate-secrets [--force-while-running]
```
- Connects to running server via existing admin client; requires admin auth (existing JWT flow).
- POSTs to new endpoint `POST /admin/secrets/rotate` (admin-auth-gated, rate-limited).
- Server-side: refuses unless service is in `maintenance` flag or `--force-while-running` was sent.
</interfaces>
</context>

## Phase Goal

Encrypt every secret column in operator SQLite using DPAPI-bound, PBKDF2-derived AES-256-GCM with column-binding AAD. Migrate cleartext atomically; drop cleartext column same-release. Migrate JWT env-var to DB. Provide exercised rotation via admin CLI. Prove no cleartext leaks into logs.

## Success Criteria (with CONTEXT amendments)

1. **New rows write encrypted ciphertext; reads transparently decrypt.** [maps to Tasks 47-01, 47-04, 47-05]
2. **Migration successfully upgrades existing cleartext rows in place; JWT migrates from env-var to DB on first startup post-deployment.** [maps to Tasks 47-03, 47-06]
3. ~~Backup column allows rollback within one release window~~ → **Amended per CONTEXT D-Q6: transient in-migration `*_legacy` column only; no persisted cleartext after migration commit.** [maps to Task 47-06]
4. **Key rotation procedure documented and exercised via `dlp-admin-cli rotate-secrets`; an integration test executes the full rotation cycle.** [maps to Tasks 47-08, 47-10]
5. **No cleartext secret appears in any log line (verified by automated audit-log scan in CI).** [maps to Tasks 47-07, 47-11]

## Wave Structure

| Wave | Tasks | Parallel? | Rationale |
|------|-------|-----------|-----------|
| 1 | 47-01 (crypto core) | sequential prerequisite | Every later task depends on the `SecretCrypto` API surface |
| 2 | 47-02 (schema + KEK repo), 47-03 (JWT/LDAP schema additions) | parallel — disjoint files | Both add tables; neither touches the other's tables |
| 3 | 47-04 (siem_config + alert_router_config loaders), 47-05 (jwt_secret + ldap_bind loaders), 47-09 (logging hygiene + SecretString wrapping) | parallel — disjoint repositories; logging audit reads only | Different repositories; logging task only reads/audits, doesn't conflict |
| 4 | 47-06 (one-shot migration), 47-07 (admin_api mask round-trip verification) | sequential (07 verifies 04+05+06) | Migration depends on loaders being encryption-aware |
| 5 | 47-08 (CLI rotate-secrets + server endpoint), 47-10 (rotation integration test), 47-11 (log-scan + migration + e2e integration tests) | parallel after server endpoint exists | Tests are independent files |

Estimated context per task: ~30-50% (heavy crypto + schema work). Eleven tasks total; this plan deliberately exceeds the 2-3-task target because the work is one indivisible HARD-01 deliverable — every task is on the critical path for a single requirement. Splitting into multiple plan files would multiply the frontmatter boilerplate without gaining parallelism beyond what waves already give.

## Tasks

<tasks>

<task type="auto" tdd="true">
  <name>Task 47-01: Crypto primitives module (DPAPI + PBKDF2 + AES-GCM envelope)</name>
  <files>
    dlp-server/Cargo.toml,
    dlp-server/src/lib.rs,
    dlp-server/src/crypto/mod.rs,
    dlp-server/src/crypto/dpapi.rs,
    dlp-server/src/crypto/kdf.rs,
    dlp-server/src/crypto/envelope.rs,
    dlp-server/src/crypto/error.rs,
    dlp-server/src/crypto/tests.rs
  </files>
  <behavior>
    - Round-trip: `encrypt(pt, aad) → decrypt(env, aad)` recovers original plaintext exactly.
    - Nonce uniqueness: 1000 sequential encrypts produce 1000 distinct 12-byte nonces (assert HashSet size == 1000).
    - AAD mismatch: encrypting with `aad_for("table_a", "col_x")` and decrypting with `aad_for("table_b", "col_x")` returns `CryptoError::AuthTagMismatch`.
    - Version byte: envelope decode of unknown leading byte returns `CryptoError::UnsupportedVersion(byte)` (forward-compat).
    - DPAPI round-trip (gated `#[cfg(windows)]`): `dpapi_protect(b"hello") → dpapi_unprotect(...) == b"hello"`.
    - PBKDF2 known-answer test: with fixed salt, fixed input, 600k iterations, derives the expected 32-byte output (use one RFC 6070 vector adapted to SHA-256).
    - Envelope binary format: `[version_u8][nonce(12)][ciphertext+gcm_tag]`. Total overhead = 29 bytes vs plaintext.
  </behavior>
  <action>
    Add to `dlp-server/Cargo.toml` (per D-Q2/D-Q3, MSRV-1.75-compatible versions verified by 47-RESEARCH §A.3):
      aes-gcm = { version = "0.10.3", features = ["std", "zeroize"] }
      pbkdf2  = { version = "0.12.2", default-features = false, features = ["hmac"] }
      hmac    = "0.12.1"
      sha2    = "0.10.8"
      zeroize = { version = "1.8.2", features = ["derive"] }
    Add `Win32_Security_Cryptography` to the existing `windows = "0.58"` feature list (current features at Cargo.toml lines 86-90).
    Justification line per new crate (in Cargo.toml comment): "Phase 47 HARD-01 — encryption at rest. All pinned to MSRV ≤ 1.60 to respect project MSRV 1.75 floor (47-RESEARCH §A.3)."

    Create `dlp-server/src/crypto/mod.rs` exporting the public API listed in the `<interfaces>` block above. Register `pub mod crypto;` in `dlp-server/src/lib.rs`.

    `crypto/dpapi.rs`: model on `dlp-agent/src/password_stop.rs:760-781` but add the `CRYPTPROTECT_LOCAL_MACHINE` flag (0x4) to the `dwflags` parameter of `CryptProtectData` per D-Q1 scope and 47-RESEARCH §B.1. The unprotect side does not need the flag. Use the same `CRYPT_INTEGER_BLOB` / `LocalFree(HLOCAL)` cleanup pattern as the reference implementation; copy SAFETY comments verbatim. Surface failures as `CryptoError::DpapiUnprotectFailed { source }` — never panic, never log the plaintext on failure.

    `crypto/kdf.rs`: thin wrapper around `pbkdf2::pbkdf2_hmac::<sha2::Sha256>`. Signature `derive_kek(seed: &[u8], salt: &[u8; 16], iterations: u32) -> [u8; 32]`. Wrap the output in `secrecy::SecretBox<[u8; 32]>` for the public-facing `SecretCrypto.kek` field; zeroize on drop via `zeroize::Zeroizing`.

    `crypto/envelope.rs`: `ENVELOPE_VERSION_V1: u8 = 1`. `Envelope::serialize() -> Vec<u8>` writes `[version, nonce(12), ciphertext_with_tag]`. `Envelope::deserialize(blob: &[u8])` parses the same; rejects blob shorter than 13 bytes with `CryptoError::InvalidEnvelope`. The format is the on-disk BLOB written to `*_encrypted` columns.

    `SecretCrypto::encrypt` builds the `Aes256Gcm` cipher from the KEK, draws a 96-bit nonce from `OsRng`, calls `cipher.encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad })`, and returns an `Envelope`. The cipher is dropped (zeroized via the `zeroize` feature) after each call to keep the KEK in memory only when held by `Self`.

    `SecretCrypto::decrypt` rejects unknown version bytes early, then performs the inverse. Returned plaintext is wrapped in `secrecy::SecretString` (or `SecretBox<Vec<u8>>` for binary).

    `crypto/error.rs`: `#[derive(thiserror::Error, Debug)] enum CryptoError { DpapiProtectFailed, DpapiUnprotectFailed, KdfFailed, EncryptFailed, AuthTagMismatch, UnsupportedVersion(u8), InvalidEnvelope, KekNotLoaded }`. NEVER include plaintext or KEK bytes in the Display impl.

    `crypto/tests.rs` (or inline `#[cfg(test)] mod tests`): write all the failing tests in the `<behavior>` block FIRST (RED), then implement (GREEN). Gate DPAPI tests with `#[cfg(windows)]` to keep the rest portable.

    DO NOT touch any DB code, any repository, or `admin_api.rs` in this task. This is the pure crypto layer.
  </action>
  <verify>
    <automated>cargo test -p dlp-server --lib crypto:: -- --nocapture &amp;&amp; cargo clippy -p dlp-server -- -D warnings</automated>
  </verify>
  <done>
    All behavior tests pass. `SecretCrypto::encrypt`/`decrypt` is callable from outside the module. `dlp-server` builds with no new warnings. No new crates added beyond those listed in the action. Cargo.toml justification comment present.
  </done>
</task>

<task type="auto" tdd="true">
  <name>Task 47-02: secret_kek_history schema + repository</name>
  <files>
    dlp-server/src/db/mod.rs,
    dlp-server/src/db/repositories/secret_kek.rs,
    dlp-server/src/db/repositories/mod.rs
  </files>
  <behavior>
    - `init_tables()` creates `secret_kek_history` when absent; idempotent re-run is a no-op.
    - `get_active()` returns the row with `retired_at IS NULL` and highest version, or `None` on first-ever start.
    - `get_by_version(v)` returns the matching row including retired ones (needed for decrypt-only after rotation).
    - `insert_new()` rejects duplicate version (UNIQUE PRIMARY KEY).
    - `retire(v, ts)` sets `retired_at` and is idempotent (re-applying same ts is a no-op).
  </behavior>
  <action>
    Add to `init_tables()` in `dlp-server/src/db/mod.rs` (using `CREATE TABLE IF NOT EXISTS` per the existing pattern at lines 64-264):

    ```sql
    CREATE TABLE IF NOT EXISTS secret_kek_history (
        version             INTEGER PRIMARY KEY,
        master_seed_dpapi   BLOB NOT NULL,
        pbkdf2_salt         BLOB NOT NULL,
        pbkdf2_iterations   INTEGER NOT NULL DEFAULT 600000,
        created_at          TEXT NOT NULL,
        retired_at          TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_secret_kek_active
        ON secret_kek_history(version DESC) WHERE retired_at IS NULL;
    ```

    Create `dlp-server/src/db/repositories/secret_kek.rs` implementing the surface defined in the `<interfaces>` block. Use `rusqlite::params!` for binding, return `rusqlite::Error` (consistent with sibling repositories). Convert the chrono timestamps via the standard `to_rfc3339()` / `parse::<DateTime<Utc>>()` pattern used by sibling repos (e.g., `siem_config.rs`).

    Register the module in `dlp-server/src/db/repositories/mod.rs` (`pub mod secret_kek;`).

    Add a colocated `#[cfg(test)] mod tests` at the bottom of the new repository file. Tests open `new_pool(":memory:")`, exercise insert → get_active → retire → get_by_version. Model the migration test on `test_migration_add_mode_column` (db/mod.rs:731-802) — verify the table exists after `new_pool()` and re-running `init_tables` is a no-op.
  </action>
  <verify>
    <automated>cargo test -p dlp-server db::repositories::secret_kek -- --nocapture</automated>
  </verify>
  <done>
    Table created idempotently. Repository CRUD covered by unit tests. No clippy warnings. Sibling repository pattern preserved (no new error types, no new dependencies).
  </done>
</task>

<task type="auto" tdd="true">
  <name>Task 47-03: Schema additions — JWT + LDAP encrypted columns + per-table encrypted columns on existing secret tables</name>
  <files>
    dlp-server/src/db/mod.rs,
    dlp-server/src/db/repositories/jwt_secret.rs,
    dlp-server/src/db/repositories/mod.rs
  </files>
  <behavior>
    - `secrets_jwt` table exists after `new_pool()`; holds at most one active row (CHECK id=1).
    - `secrets_jwt` columns: `secret_encrypted BLOB`, `secret_nonce BLOB`, `secret_version INTEGER`, `created_at TEXT`, `rotated_at TEXT`.
    - `alert_router_config.smtp_password_encrypted BLOB`, `smtp_password_nonce BLOB`, `smtp_password_version INTEGER` columns added (idempotent ALTER per db/mod.rs:271-423 pattern).
    - `alert_router_config.webhook_secret_encrypted` (same three-column shape) added.
    - `siem_config.splunk_token_encrypted` (same shape) and `siem_config.elk_api_key_encrypted` (same shape) added.
    - `ldap_config.bind_password_encrypted` (same shape) plus a new `bind_dn TEXT` column. SSPI passwordless bind (per CONTEXT D-Q1) remains the default; explicit bind is opt-in by setting bind_dn + bind_password.
    - Re-running migrations is a no-op (duplicate column errors swallowed per existing pattern).
    - `jwt_secret` repository surface: `get()`, `upsert_encrypted(envelope, version)`.
  </behavior>
  <action>
    In `dlp-server/src/db/mod.rs::init_tables()`, add the new `secrets_jwt` table with the CHECK constraint inlined in the DDL (resolves plan-check N6):

    ```sql
    CREATE TABLE IF NOT EXISTS secrets_jwt (
        id                INTEGER PRIMARY KEY CHECK (id = 1),
        secret_encrypted  BLOB    NOT NULL,
        secret_nonce      BLOB    NOT NULL,
        secret_version    INTEGER NOT NULL,
        created_at        TEXT    NOT NULL,
        rotated_at        TEXT
    );
    ```

    The `CHECK (id = 1)` guarantees at most one active row; subsequent inserts with id=1 are rejected by SQLite. Rotations UPDATE the single row in place, bumping `secret_version` and `rotated_at`.

    In `dlp-server/src/db/mod.rs::run_migrations()`, add one `run_alter()` call per new column, following the exact idempotent-swallow pattern at lines 271-423. For each table, add three columns: `<col>_encrypted BLOB`, `<col>_nonce BLOB`, `<col>_version INTEGER`. List of altered columns:
      - `alert_router_config.smtp_password` → 3 new columns
      - `alert_router_config.webhook_secret` → 3 new columns
      - `siem_config.splunk_token` → 3 new columns
      - `siem_config.elk_api_key` → 3 new columns
      - `ldap_config.bind_password` → 3 new columns + 1 column `bind_dn TEXT`

    NOTE: We are NOT yet dropping the cleartext columns in this task. That happens at the migration commit (Task 47-06) per CONTEXT D-Q6. This task only adds the encrypted-side columns.

    Create `dlp-server/src/db/repositories/jwt_secret.rs` with `get()` returning `Option<(Envelope, u8 /* kek version */)>` and `upsert_encrypted(envelope, kek_version, now)` performing INSERT OR REPLACE on `id=1`. Register in `repositories/mod.rs`.

    Add a new test in `db/mod.rs` named `test_migration_add_secret_encrypted_columns()` modeled on `test_migration_add_mode_column` (lines 731-802):
      1. Stand up a pre-Phase-47 schema with the four cleartext tables (without encrypted columns) and seed one row each.
      2. Open via `new_pool()`.
      3. Use `PRAGMA table_info(<tbl>)` to assert each new column exists.
      4. Verify the pre-existing cleartext rows still read correctly.
      5. Re-run `run_migrations` and confirm no error (duplicate-column swallow works).
  </action>
  <verify>
    <automated>cargo test -p dlp-server test_migration_add_secret_encrypted_columns -- --nocapture &amp;&amp; cargo test -p dlp-server db::repositories::jwt_secret -- --nocapture</automated>
  </verify>
  <done>
    All schema additions land idempotently. The new test passes. Existing migration test (`test_migration_add_mode_column`) still passes. No clippy warnings.
  </done>
</task>

<task type="auto" tdd="true">
  <name>Task 47-04: Loader integration — siem_config + alert_router_config encrypted read/write</name>
  <files>
    dlp-server/src/db/repositories/siem_config.rs,
    dlp-server/src/db/repositories/alert_router_config.rs
  </files>
  <behavior>
    - `get()` on each repository: if `<col>_encrypted` IS NOT NULL, decrypt via `SecretCrypto::decrypt` with the column-bound AAD; else fall back to reading the legacy cleartext column (only relevant during the migration window inside Task 47-06).
    - `update()`: encrypts the new plaintext via `SecretCrypto::encrypt`, writes `<col>_encrypted`, `<col>_nonce`, `<col>_version`, and (transitionally) NULLs the cleartext column.
    - `get_secrets()` (the TOCTOU-safe read at alert_router_config.rs:137 area) reads the encrypted columns and returns `SecretString`. Caller in admin_api.rs:1300-1416 receives the decrypted value within the same transaction — preserving the existing mask round-trip.
    - AAD per column matches `crypto::aad_for(table, column)`: `b"dlp:secret:alert_router_config:smtp_password"`, etc.
    - Decryption failure on a non-NULL `*_encrypted` column returns a typed error (`AppError::Internal("decrypt failed for {table}.{col}")`) and does NOT silently fall back to cleartext.
  </behavior>
  <action>
    Thread `Arc<SecretCrypto>` through `AppState` (see Task 47-06 for the bootstrap wiring; the repository functions take it as a parameter for testability). The signature pattern matches existing repositories that take `&Connection`; add a second parameter `crypto: &SecretCrypto`.

    `dlp-server/src/db/repositories/siem_config.rs`:
      - In `get()`, decrypt `splunk_token_encrypted` (AAD `aad_for("siem_config", "splunk_token")`) and `elk_api_key_encrypted` (AAD `aad_for("siem_config", "elk_api_key")`) when non-NULL. Return as `secrecy::SecretString`.
      - In `update()`, encrypt the incoming plaintexts before write. Write the envelope blob, the nonce, the version byte. NULL the legacy `splunk_token` / `elk_api_key` columns in the SAME UPDATE statement.

    `dlp-server/src/db/repositories/alert_router_config.rs`:
      - Same pattern for `smtp_password` and `webhook_secret`.
      - `get_secrets()` (the TOCTOU-safe reader) MUST decrypt within the same transaction it reads from. Preserve the existing transaction boundary; do NOT introduce an Arc<Mutex> or async hop. If the existing function isn't transactional, lift it into a `UnitOfWork::run` call as the sibling repositories do.

    Preserve `ALERT_SECRET_MASK` semantics: when admin_api receives the mask sentinel on PUT, it calls `get_secrets()` to recover the existing plaintext, then re-encrypts and writes via `update()`. This means `update()` MUST be safe to call with an unchanged plaintext (idempotent at the application layer; produces a new ciphertext blob because of fresh nonce, which is fine).

    Add a `secrecy::ExposeSecret` import where needed for the existing live use of `SecretString` in `alert_router.rs:28-202` (47-RESEARCH §D.2). DO NOT log `expose_secret()` output — that's Task 47-09's audit target.

    Unit tests (colocated `#[cfg(test)]`):
      - `update()` then `get()` round-trip recovers original plaintext.
      - Tampering with `*_nonce` on disk produces `AuthTagMismatch`.
      - Mask-round-trip simulation: PUT plaintext A → PUT mask sentinel → confirm `get()` still returns A.
  </action>
  <verify>
    <automated>cargo test -p dlp-server db::repositories::siem_config -- --nocapture &amp;&amp; cargo test -p dlp-server db::repositories::alert_router_config -- --nocapture</automated>
  </verify>
  <done>
    All four secret columns round-trip through encryption. Mask round-trip preserved. No clippy warnings. No new dependencies.
  </done>
</task>

<task type="auto" tdd="true">
  <name>Task 47-05: Loader integration — JWT secret + LDAP bind credentials</name>
  <files>
    dlp-server/src/db/repositories/jwt_secret.rs,
    dlp-server/src/db/repositories/ldap_config.rs,
    dlp-server/src/admin_auth.rs,
    dlp-common/src/ad_client.rs
  </files>
  <behavior>
    - `admin_auth::resolve_jwt_secret(pool, crypto, dev_mode)` (new signature) prefers the DB-encrypted row; falls back to env var with a one-time `tracing::warn!` deprecation message; in dev mode, falls back to DEV_JWT_SECRET as today.
    - `ldap_config` repository exposes `get_bind_credentials()` returning `Option<(bind_dn: String, bind_password: SecretString)>`. None when SSPI passwordless mode is configured (the default).
    - `ad_client::ldap_bind()` (or equivalent at line 376) accepts an optional explicit-bind credential; falls back to `simple_bind(machine_account_dn, "")` when None.
    - JWT migration: if env var is set AND `secrets_jwt` row is absent, the loader generates an encrypted row from the env-var value and logs `tracing::warn!("JWT_SECRET env-var migrated into encrypted DB row; the env var is no longer required and will be ignored on future startups");`.
    - After migration, env-var presence does NOT cause an error; it is silently ignored (per CONTEXT — emit a one-shot deprecation warn on the first startup that detects this state).
  </behavior>
  <action>
    `dlp-server/src/admin_auth.rs`:
      - Refactor `resolve_jwt_secret` (currently at lines 65-92) to accept `&Pool` and `&SecretCrypto`. Preserve the existing dev-mode fallback path.
      - New control flow: (1) try `jwt_secret::get(conn)`; if Some, decrypt and return. (2) If None and env-var is set, encrypt + insert into `secrets_jwt` via `upsert_encrypted`, log the deprecation warn, return the plaintext. (3) If None and env-var absent and not dev-mode, return the existing typed error string.
      - The existing `JWT_SECRET: OnceLock<String>` static (line 98) is kept; populate it from the resolved value.

    `dlp-server/src/db/repositories/ldap_config.rs`:
      - Add `bind_dn: Option<String>` and `bind_password: Option<SecretString>` to the `LdapConfig` struct.
      - In `get()`, decrypt the `bind_password_encrypted` blob if present using AAD `aad_for("ldap_config", "bind_password")`.
      - Add `get_bind_credentials()` helper returning `Option<(String, SecretString)>` — None when either field is null/empty.

    `dlp-common/src/ad_client.rs`:
      - At the LDAP bind call site (line ~376, `simple_bind(&machine_account_dn, "")`), accept an optional `bind_credentials: Option<(String, SecretString)>` parameter on the function that invokes the bind. When Some, call `simple_bind(&bind_dn, password.expose_secret())`. When None, preserve the existing passwordless behavior.
      - Update all call sites in `dlp-server/` that invoke this function to thread the optional credentials from the ldap_config repository.
      - The wider AD client refactor (changing the public signature) cascades through any callers in dlp-server; update them mechanically.

    Unit tests (colocated):
      - JWT loader: empty DB + env-var set → after call, DB has encrypted row, env-var no longer required on second call.
      - JWT loader: empty DB + no env-var + dev mode → returns DEV_JWT_SECRET, does NOT write to DB.
      - JWT loader: empty DB + no env-var + production → returns the existing typed error string.
      - LDAP loader: bind_password column NULL → `get_bind_credentials()` returns None.
      - LDAP loader: bind_password populated + bind_dn populated → returns Some with decrypted SecretString.
  </action>
  <verify>
    <automated>cargo test -p dlp-server admin_auth::tests::resolve_jwt -- --nocapture &amp;&amp; cargo test -p dlp-server db::repositories::ldap_config -- --nocapture &amp;&amp; cargo test -p dlp-common ad_client -- --nocapture</automated>
  </verify>
  <done>
    JWT secret survives a server restart by being read from the encrypted DB row, not the env-var. LDAP supports both passwordless SSPI (unchanged default) and explicit-bind (new opt-in). All call sites compile and pass clippy.
  </done>
</task>

<task type="auto">
  <name>Task 47-06: One-shot atomic data migration (cleartext → encrypted, transient _legacy column, drop in-commit)</name>
  <files>
    dlp-server/src/secrets_migration.rs,
    dlp-server/src/lib.rs,
    dlp-server/src/main.rs,
    dlp-server/src/db/mod.rs
  </files>
  <behavior>
    - Idempotent: re-runnable on every startup. No-op when all cleartext columns have already been migrated and dropped.
    - For each `<table>.<col>` in the migration set: open a write transaction; for each row where `<col>_encrypted IS NULL AND <col> != ''`: encrypt, write encrypted+nonce+version, immediately re-read and decrypt to verify (read-after-write check); on verification failure, abort the transaction and return an error.
    - Within the same transaction, NULL the cleartext column for every successfully-encrypted row.
    - After all rows in a table are encrypted (or the table is already empty of cleartext), `ALTER TABLE <table> DROP COLUMN <col>` to remove the cleartext column. This commits in the same transaction as the encryption pass — no persisted cleartext after the commit (per CONTEXT D-Q6).
    - JWT special case: if `JWT_SECRET` env-var is set AND `secrets_jwt` is empty, migrate per Task 47-05 logic; this task wires the call site into the bootstrap sequence.
    - Bootstrap order in `main.rs`: (1) `new_pool()`; (2) `SecretCrypto::load_active(conn)` (creating a new v1 KEK on a fresh install); (3) `migrate_secrets_to_encrypted(&pool, &crypto, env::var("JWT_SECRET").ok().as_deref())`; (4) construct AppState with `Arc<SecretCrypto>`; (5) serve.
    - First-run KEK generation: when `secret_kek_history` is empty, generate 32 random bytes via `OsRng`, DPAPI-protect with `CRYPTPROTECT_LOCAL_MACHINE`, generate a fresh 16-byte salt, INSERT as `version = 1`.
    - SQLite `DROP COLUMN` support: requires SQLite >= 3.35 (released 2021-03). `rusqlite 0.39` with bundled SQLite is well past this — verify the bundled feature is enabled, and add a one-line `// SQLite 3.35+ required for DROP COLUMN` comment at the call site.
  </behavior>
  <action>
    Create `dlp-server/src/secrets_migration.rs` per the `<interfaces>` surface. Internal layout:
      ```rust
      const MIGRATION_TARGETS: &[(&str, &str)] = &[
          ("alert_router_config", "smtp_password"),
          ("alert_router_config", "webhook_secret"),
          ("siem_config", "splunk_token"),
          ("siem_config", "elk_api_key"),
          // ldap_config.bind_password is opt-in — skip if column is empty
      ];
      ```

    For each target:
      1. Within `UnitOfWork::run`, SELECT the primary key + cleartext + encrypted-state for all rows.
      2. For each row needing encryption: derive AAD via `crypto::aad_for(table, col)`, encrypt, prepare UPDATE.
      3. Apply UPDATE: set `<col>_encrypted = ?, <col>_nonce = ?, <col>_version = ?, <col> = NULL`.
      4. Read back and decrypt to verify; on mismatch, return Err — the transaction rolls back.
      5. After all rows for the table: `ALTER TABLE <table> DROP COLUMN <col>` (within the same transaction).
      6. Commit.

    JWT branch: if `secrets_jwt` is empty and `jwt_env_fallback` is Some, encrypt the env-var value via `SecretCrypto::encrypt` with AAD `aad_for("secrets_jwt", "secret")`, INSERT into `secrets_jwt`, mark `MigrationReport.jwt_migrated_from_env = true`. Log `tracing::warn!("JWT secret migrated from env-var into encrypted DB row")`.

    Idempotency contract: when the cleartext column has already been dropped, the SELECT step uses a `PRAGMA table_info` check first; if the column is absent, the migration for that target is a no-op.

    Wire into `dlp-server/src/main.rs`: after `let pool = new_pool(...)?`, call `let crypto = Arc::new(crypto::SecretCrypto::load_active_or_bootstrap(&pool)?); let report = secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, std::env::var("JWT_SECRET").ok().as_deref())?; tracing::info!(rows_encrypted = report.rows_encrypted, jwt_migrated = report.jwt_migrated_from_env, dropped = ?report.cleartext_columns_dropped, "secrets migration complete");`.

    Failure modes:
      - DPAPI unprotect fails on startup → return Err from `load_active_or_bootstrap`; main.rs surfaces it as a hard startup error per CONTEXT D-Q4 (no automatic recovery).
      - Encryption verify-decrypt fails mid-row → transaction rolls back; next startup retries.
      - Crash mid-write → WAL recovery rolls back; next startup retries.
  </action>
  <verify>
    <automated>cargo test -p dlp-server secrets_migration -- --nocapture &amp;&amp; cargo build -p dlp-server</automated>
  </verify>
  <done>
    Server starts on a fresh DB and produces a v1 KEK. Server starts on a DB with cleartext secrets and migrates them — cleartext columns are dropped in the same release. Server starts on an already-migrated DB and reports `rows_encrypted = 0, cleartext_columns_dropped = []`. JWT env-var migration logs the deprecation warn exactly once.
  </done>
</task>

<task type="auto">
  <name>Task 47-07: Preserve ALERT_SECRET_MASK round-trip through encrypted columns (admin_api.rs verification)</name>
  <files>
    dlp-server/src/admin_api.rs
  </files>
  <behavior>
    - GET `/admin/alert-config` returns the SMTP password as the ALERT_SECRET_MASK sentinel (never the decrypted plaintext) when the row has an encrypted password.
    - PUT `/admin/alert-config` with `smtp_password == ALERT_SECRET_MASK` does NOT overwrite the existing encrypted blob; reads the existing plaintext via `get_secrets()` within the same transaction; re-encrypts and writes unchanged plaintext.
    - PUT with a new plaintext (not the mask) replaces the encrypted blob.
    - Same invariants hold for SIEM tokens (`splunk_token`, `elk_api_key`) and LDAP `bind_password`.
  </behavior>
  <action>
    Read the existing mask round-trip code at admin_api.rs:1300-1416 (referenced in 47-RESEARCH §G.2). Confirm that after Task 47-04 lands, the function still:
      1. Calls `get_secrets()` within the PUT transaction — this is now an encrypted-column read.
      2. Compares incoming field == ALERT_SECRET_MASK.
      3. Substitutes the existing decrypted plaintext when mask is received.
      4. Calls `update()` — which now encrypts on the way down.

    Add an integration-style unit test colocated in admin_api.rs (or in `tests/secrets_encryption_integration.rs` per Task 47-11) that walks:
      - POST `/admin/alert-config` with `smtp_password = "fixture-password-XYZ"` → expect 200.
      - GET → expect `smtp_password == ALERT_SECRET_MASK` (not the plaintext).
      - PUT `/admin/alert-config` with `smtp_password = ALERT_SECRET_MASK` (other fields changed) → expect 200, expect the underlying encrypted blob unchanged in size structure (the test won't read the blob — it tests by GET → assert mask, then bounces the server, and reads back via internal API).
      - Restart pool (simulating a server bounce); GET → still returns mask; internal `get_secrets()` decrypts to `"fixture-password-XYZ"`.

    DO NOT introduce any new public API. This task is verification + a targeted regression test. If the mask round-trip is silently broken by Task 47-04, this task is the firewall.
  </action>
  <verify>
    <automated>cargo test -p dlp-server admin_api::tests::alert_secret_mask -- --nocapture</automated>
  </verify>
  <done>
    The mask round-trip test passes. No behavior change to existing API consumers (admin TUI, scripted operators).
  </done>
</task>

<task type="auto">
  <name>Task 47-08: Admin CLI rotate-secrets command + server-side rotation endpoint</name>
  <files>
    dlp-admin-cli/src/main.rs,
    dlp-admin-cli/src/client.rs,
    dlp-server/src/admin_api.rs,
    dlp-server/src/secrets_migration.rs
  </files>
  <behavior>
    - `dlp-admin-cli rotate-secrets` (new subcommand) requires admin auth (existing flow); POSTs to `/admin/secrets/rotate`; prints a summary report on success.
    - Server endpoint `POST /admin/secrets/rotate` (admin-auth + rate-limit per existing middleware): generates a new KEK version (Task 47-02 repository), re-encrypts every `*_encrypted` column with the new KEK, retires the old KEK row.
    - Rotation is wrapped in a single `UnitOfWork::run` per table; failure rolls back; the old KEK remains active.
    - `--force-while-running` flag (CLI side): default behavior refuses if the server has agents currently polling. With the flag, rotates anyway. Server-side mirror: a `maintenance_lock` row in a small KV table (or reuse an existing flag); endpoint refuses unless the lock is set or `force=true` is in the JSON body.
    - Recommended pattern (justified): single-column overwrite WITHIN one transaction per table. The transient `*_pending` column approach is rejected — it doubles the schema churn and the WAL already provides crash-atomicity. Stamping the new version byte in the envelope is the operative idempotency marker.
  </behavior>
  <action>
    Server side (`dlp-server/src/admin_api.rs`):
      - Add `POST /admin/secrets/rotate` to the admin route composition. Handler validates admin JWT, parses optional `{"force": bool}` JSON body, calls `secrets_migration::rotate_kek(&pool, &crypto, force)`.

    Server side (`dlp-server/src/secrets_migration.rs`):
      - Add `pub fn rotate_kek(pool: &Pool, current: &SecretCrypto, force: bool) -> anyhow::Result<RotationReport>`.
      - Algorithm:
        1. If `force == false` and the explicit maintenance-mode KV row is absent, return `Err(RotationError::ServiceNotInMaintenance)`. The maintenance-mode mechanism (resolves plan-check N5):
           - Add a `system_kv` row keyed `"maintenance_mode"` with value `"1"`/`"0"` (boolean as TEXT) — created by migration if absent, default `"0"`.
           - New admin CLI sub-commands: `dlp-admin-cli maintenance enter` (writes `"1"`) and `dlp-admin-cli maintenance exit` (writes `"0"`). Operator runs `enter` before rotation, `exit` after.
           - `--force-while-running` bypasses the check (still requires explicit flag, no implicit fallback).
           - This is a deterministic boolean instead of the heuristic `last_heartbeat < 60s` check (which would race with normal agent polling cycles).
        2. Generate new KEK via `SecretCrypto::create_new_version(&mut conn)` — this is the same path Task 47-01/47-02 expose. Inserts a new `secret_kek_history` row.
        3. For each `(table, col)` in MIGRATION_TARGETS plus `("secrets_jwt", "secret")` and (if populated) `("ldap_config", "bind_password")`:
           - `UnitOfWork::run`: SELECT all rows with `<col>_encrypted IS NOT NULL`; for each: decrypt with the CURRENT (old) KEK using AAD `aad_for(table, col)`; re-encrypt with the NEW KEK using the same AAD; UPDATE the row with the new envelope. Commit.
        4. After all tables succeed: `secret_kek::retire(old_version, now)`. The new KEK is now the active version.
        5. Return `RotationReport { old_version, new_version, rows_reencrypted, tables_rotated }`.

    CLI side (`dlp-admin-cli/src/main.rs`):
      - Add `Commands::RotateSecrets { force_while_running: bool }` to the existing subcommand enum (or equivalent at the same architectural layer).
      - Dispatch to a new `rotate_secrets(client, force)` function in `client.rs` that calls `POST /admin/secrets/rotate`.
      - On success, print: `"Rotated KEK from v{old} to v{new} — {rows} secrets re-encrypted across {tables} tables. Old key retired and retained in secret_kek_history for delayed-rollback decrypts."`.

    Integration test wiring: Task 47-10 will exercise the full rotation cycle end-to-end.
  </action>
  <verify>
    <automated>cargo test -p dlp-server secrets_migration::tests::rotate -- --nocapture &amp;&amp; cargo build -p dlp-admin-cli</automated>
  </verify>
  <done>
    `dlp-admin-cli rotate-secrets` builds and runs against a live server. Server endpoint is admin-auth-gated. Old KEK rows are retained (not deleted) so historical envelopes remain decryptable in case of bug discovery.
  </done>
</task>

<task type="auto">
  <name>Task 47-09: Logging hygiene — wrap secrets in SecretString and audit tracing call sites</name>
  <files>
    dlp-server/src/db/repositories/siem_config.rs,
    dlp-server/src/db/repositories/alert_router_config.rs,
    dlp-server/src/db/repositories/jwt_secret.rs,
    dlp-server/src/db/repositories/ldap_config.rs,
    dlp-server/src/admin_auth.rs,
    dlp-server/src/alert_router.rs,
    dlp-server/src/siem_connector.rs
  </files>
  <behavior>
    - Every in-memory secret returned from a repository is a `secrecy::SecretString` (or `SecretBox<Vec<u8>>` for raw bytes). No `pub` fields hold a `String` plaintext.
    - No `tracing::(info|debug|warn|error)!` call site in `dlp-server/` logs a struct that contains a secret as a `Display` or `Debug` field except through `SecretString`'s redacting Debug impl.
    - The audit_events table never persists a secret value (a search for any fixture-secret string in any column returns zero rows after a representative flow).
    - The repository layer NEVER calls `expose_secret()` to log. The single legitimate call site for `expose_secret()` is the SMTP send path (lettre call), the LDAP bind path (`ad_client::ldap_bind`), and the JWT sign/verify path (`jsonwebtoken`).
  </behavior>
  <action>
    Confirm `secrecy = 0.8` is already a workspace dependency (47-RESEARCH §D.2). No new crate needed.

    Audit (read-only pass):
      - Run `grep -nE 'tracing::(info|debug|warn|error)!' dlp-server/src/ | grep -iE '(secret|password|token|api_key|jwt|webhook)'` — record each hit.
      - For each hit, verify the formatted value is either a `SecretString` (Debug-redacted) or an opaque field. Any naked plaintext string field flagged as secret-adjacent must be wrapped or removed.
      - Specifically scrutinize: `alert_router.rs` (47-RESEARCH §D.2 already wraps `smtp_password` in `SecretString`), `admin_auth.rs:325` ("admin password changed" — confirmed not logging the value), `siem_connector.rs` (does it log webhook headers?).

    Refactor: change repository return types so secrets are always `SecretString` from the boundary:
      - `siem_config::get()` returns `SiemConfig { splunk_token: Option<SecretString>, elk_api_key: Option<SecretString>, ... }`.
      - `alert_router_config::get()` returns `AlertRouterConfig { smtp_password: Option<SecretString>, webhook_secret: Option<SecretString>, ... }`.
      - `jwt_secret::get()` returns `Option<SecretString>`.
      - `ldap_config::get_bind_credentials()` returns `Option<(String, SecretString)>` (already done in Task 47-05).
      - Update `alert_router.rs`, `siem_connector.rs`, `admin_auth.rs` to consume the new shapes. They should already be `SecretString`-aware per 47-RESEARCH §D.2.

    Add a `#[derive(Debug)]`-free policy comment at the top of each touched repository: `// Secret-bearing structs use SecretString to ensure Debug redacts. Do not add naked-String secret fields.`

    Add a unit test in `dlp-server/src/db/repositories/alert_router_config.rs` colocated `#[cfg(test)] mod tests`:
      - Construct an `AlertRouterConfig` with a known fixture password.
      - Format with `{:?}` — assert the output does NOT contain the fixture password (it should show `Secret([REDACTED ...])`).
  </action>
  <verify>
    <automated>cargo test -p dlp-server tests::secret_debug_redacts -- --nocapture &amp;&amp; cargo clippy -p dlp-server -- -D warnings</automated>
  </verify>
  <done>
    No `tracing::*` call site logs a secret value. Every secret-bearing repository return type is SecretString-wrapped. The Debug-redaction unit test passes. The CI-level log scan is Task 47-11's job.
  </done>
</task>

<task type="auto">
  <name>Task 47-10: Rotation integration test — full cycle (success criterion #4)</name>
  <files>
    dlp-server/tests/secrets_rotation_integration.rs
  </files>
  <behavior>
    - Fresh DB → bootstrap creates KEK v1 → write fixture secrets (smtp_password, splunk_token, elk_api_key, webhook_secret, secrets_jwt.secret) via the encrypted repositories.
    - Read back: all values decrypt to fixture plaintexts via KEK v1.
    - Call `rotate_kek(force=true)` → produces KEK v2; all encrypted blobs are re-encrypted with v2; v1 is marked retired.
    - Read back: values still decrypt (now via KEK v2).
    - Tampering check: hand-craft a row with version byte = 99 (no such KEK); read returns `CryptoError::UnsupportedVersion(99)`.
    - Old-KEK forensic decrypt: load `SecretCrypto::load_by_version(conn, 1)`, manually decrypt a hand-saved v1 envelope from before rotation, and confirm the plaintext recovers — proving v1 is retained, not deleted (operational guarantee from Task 47-08).
  </behavior>
  <action>
    Model on existing integration test patterns in `dlp-server/tests/` (47-RESEARCH §F.4: `ldap_config_api.rs`, `admin_audit_integration.rs`, etc.).

    Use `tempfile::NamedTempFile` for the SQLite file (NOT `:memory:` — rotation involves opening multiple connections from a pool, and `:memory:` is per-connection unless `cache=shared` is configured; the file-based path matches production semantics).

    Test layout:
      1. Create temp file → `new_pool(path)` → `SecretCrypto::load_active_or_bootstrap(&pool)` (creates v1).
      2. Save a hand-crafted v1 envelope as `let v1_envelope_for_forensic_test = ...;` for the later step.
      3. Run `migrate_secrets_to_encrypted` on a seeded DB containing fixture cleartext (the test sets up the pre-Phase-47 schema, seeds, then calls migrate).
      4. Assert read-back via repository `get()` returns fixture plaintexts.
      5. Call `rotate_kek(&pool, &crypto, /*force=*/true)`.
      6. Assert `secret_kek_history` has v1 retired, v2 active.
      7. Re-construct `SecretCrypto::load_active(&conn)` (now v2) and assert all repository `get()` calls still return fixture plaintexts.
      8. Forensic decrypt: `SecretCrypto::load_by_version(&conn, 1)` → decrypt the saved v1 envelope → assert the plaintext matches.

    Skip DPAPI gating: use `#[cfg(windows)]` on the test, OR factor the test so non-Windows builds use a stub `MachineSecret` that returns a fixed 32-byte seed (preferred — keeps the test runnable on CI dev machines for crypto correctness checks; the actual DPAPI call is exercised by the Windows-flavored CI runner per Phase 50 infrastructure).
  </action>
  <verify>
    <automated>cargo test -p dlp-server --test secrets_rotation_integration -- --nocapture</automated>
  </verify>
  <done>
    Full rotation cycle runs end-to-end. v1 → v2 transition does not lose any secret. v1 envelopes remain decryptable post-rotation via `load_by_version`. Test runs on both Windows CI and developer machine.
  </done>
</task>

<task type="auto">
  <name>Task 47-11: Migration + log-scan + e2e admin-API integration tests (success criteria #2, #3, #5)</name>
  <files>
    dlp-server/tests/secrets_encryption_integration.rs,
    dlp-server/tests/secrets_log_scan_integration.rs,
    dlp-server/tests/secrets_migration_integration.rs
  </files>
  <behavior>
    - **secrets_migration_integration.rs**: Pre-Phase-47 schema fixture DB (created by hand-writing the v0.9.0 schema via `rusqlite::Connection::open`) is seeded with one cleartext row per secret column. Open via `new_pool()` → migration runs. Post-condition: every `<col>` cleartext column is absent (PRAGMA table_info), every `<col>_encrypted` is non-NULL, repository `get()` returns the fixture plaintext via decryption. **Asserts CONTEXT D-Q6**: no cleartext column persists after migration commit.
    - **secrets_encryption_integration.rs**: full HTTP round-trip — admin auth → POST `/admin/alert-config` with fixture password → GET returns mask → DB-level verification: `SELECT smtp_password_encrypted FROM alert_router_config` returns non-empty BLOB; `SELECT smtp_password FROM alert_router_config` errors (column gone). Same for SIEM tokens.
    - **secrets_log_scan_integration.rs** (success criterion #5): spin up the server with a `tracing` subscriber that writes to an in-memory buffer (use `tracing_subscriber::fmt::layer().with_writer(make_writer)` per the existing test patterns). Issue: admin login → POST a fixture secret containing a high-entropy magic string (`SECRET-MAGIC-XYZ-{random 32 hex chars}`) → trigger a config-save, a config-read, a JWT issue, a representative SIEM webhook fire (mocked), and a server restart cycle. After all flows: `assert!(!log_buffer.contains(&magic_secret));` AND `let audit_rows = read all audit_events.* TEXT columns; assert no row contains magic_secret;`.
    - **JWT env-var migration test** (in secrets_migration_integration.rs): env-var set, DB empty → migration creates encrypted row → second `resolve_jwt_secret` call returns the value from DB (env-var no longer required); also assert the deprecation warn appears in the tracing buffer exactly once.
  </behavior>
  <action>
    Create three integration test files matching the existing pattern in `dlp-server/tests/`:

    `tests/secrets_migration_integration.rs`:
      - Helper `setup_pre_phase47_fixture(path: &Path)` creates an old-schema DB by hand (CREATE TABLE alert_router_config WITHOUT the encrypted columns, etc.) and seeds known cleartext.
      - Test `test_migration_drops_cleartext_columns_in_same_commit`: runs migration; uses `PRAGMA table_info` to confirm cleartext columns are GONE (not just NULL); uses repository `get()` to confirm plaintexts round-trip via decryption.
      - Test `test_jwt_env_var_migrates_to_db_on_first_start`: sets `JWT_SECRET=fixture-jwt-magic-...`; spins up server; calls `resolve_jwt_secret` once; asserts DB has the encrypted row; clears env-var; spins up server again; asserts `resolve_jwt_secret` succeeds from DB without the env-var; asserts the tracing buffer shows the deprecation warn from the first start.
      - Test `test_migration_idempotent`: runs migration twice on an already-migrated DB; second run produces `MigrationReport { rows_encrypted: 0, jwt_migrated_from_env: false, cleartext_columns_dropped: [] }`.

    `tests/secrets_encryption_integration.rs`:
      - Helper `start_test_server(pool, crypto)` constructs the AppState and returns a `TestServer` (or `axum::Router` via `tower::ServiceExt`).
      - Test `test_admin_api_round_trip_smtp_password`: admin login → POST alert-config with fixture password → GET returns mask → direct SQLite query confirms encrypted blob is populated and cleartext column is absent.
      - Test `test_admin_api_mask_round_trip_preserves_existing`: POST password A → GET returns mask → PUT with mask in password field, other fields changed → GET decrypts internal `get_secrets()` to A (verifies the TOCTOU-safe round-trip from Task 47-07).
      - Test `test_admin_api_siem_tokens_round_trip`: same shape for splunk_token + elk_api_key.

    `tests/secrets_log_scan_integration.rs`:
      - Use `tracing_subscriber::fmt::layer().with_writer(buffer_writer)` to capture all tracing output.
      - Helper `random_magic_secret() -> String` returns a 64-char hex string from `OsRng`.
      - Test `test_no_cleartext_secret_appears_in_tracing_or_audit_log`:
        - Generate magic secret.
        - Start server, admin login, POST alert-config with magic as smtp_password.
        - Trigger flows: GET, config-save, server restart, GET again.
        - Assert: `!buffer.to_string().contains(&magic)`.
        - Query: `SELECT *.text_columns FROM audit_events` → for each row, for each TEXT column, assert no value contains `magic`.

    Filename grep gate hygiene (per planner-antipatterns): when computing the audit-log scan in CI, filter to actual log lines, not comments. The captured buffer is the running output — no comment-filter risk.
  </action>
  <verify>
    <automated>cargo test -p dlp-server --test secrets_migration_integration -- --nocapture &amp;&amp; cargo test -p dlp-server --test secrets_encryption_integration -- --nocapture &amp;&amp; cargo test -p dlp-server --test secrets_log_scan_integration -- --nocapture</automated>
  </verify>
  <done>
    All three integration test files compile and pass. Success criteria #2, #3 (amended), and #5 are demonstrably satisfied. The log-scan test is wired into the existing CI workflow (no special invocation needed — `cargo test` runs all integration tests).
  </done>
</task>

</tasks>

<threat_model>

## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Offline file system → SQLite file | Attacker exfiltrates the SQLite file (backup theft, disk image, malicious-admin copy). DPAPI machine-scope binding ensures the file alone is useless on a different host. |
| Local admin on box → SYSTEM-service memory | Local admin can read DPAPI-decrypted bytes from SYSTEM-process memory via debugger; out of scope for HARD-01 (file-at-rest threat only, per CONTEXT). |
| Operator → admin API (rotate-secrets endpoint) | Admin authentication + rate limit; same trust as policy CRUD. |
| Operator → admin CLI (rotate-secrets command) | Same trust as the API it calls. |
| Server process → DPAPI/LSA | Trusted OS service. Failure surfaces as a hard startup error per CONTEXT D-Q4. |
| `tracing` subscriber → log sinks | Logs may reach SIEM, file, stderr; secrets must be redacted before this boundary. |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-47-01 | Information Disclosure | SQLite file at rest (backup, theft) | mitigate | AES-256-GCM with DPAPI-bound KEK; cleartext columns dropped in-migration. Task 47-06. |
| T-47-02 | Information Disclosure | Ciphertext substitution across columns | mitigate | Column-binding AAD (`b"dlp:secret:" || table || b":" || col`); GCM auth-tag rejects on AAD mismatch. Tested in Task 47-01. |
| T-47-03 | Tampering | Bit-flip on ciphertext blob | mitigate | AES-GCM tag detects any modification; decrypt returns `AuthTagMismatch`. Tested in Task 47-04 + 47-10. |
| T-47-04 | Information Disclosure | Cleartext secret leaks into tracing/audit logs | mitigate | All secret-bearing types use `secrecy::SecretString` (Debug-redacting). CI log-scan test asserts zero leakage. Tasks 47-09 + 47-11. |
| T-47-05 | Spoofing / Forgery | Attacker forges ciphertext for unknown KEK version | mitigate | Envelope version byte rejected with `UnsupportedVersion(byte)`. Tested in Task 47-01. |
| T-47-06 | Denial of Service | DPAPI master-key loss makes secrets unrecoverable | accept | Per CONTEXT D-Q4, recovery is Phase 52 documentation. Phase 47 fails-fast with a clear startup error. |
| T-47-07 | Elevation of Privilege | Local admin recovers KEK from SYSTEM process memory | accept | Out of scope per CONTEXT (file-at-rest threat model). HSM/CNG isolation is deferred to a future milestone. |
| T-47-08 | Information Disclosure | Old cleartext recoverable from freed SQLite pages | mitigate (partial) | After cleartext column DROP, run `VACUUM` (Task 47-06 follow-up) to release pages. Note: full forensic-grade erasure requires `PRAGMA secure_delete = ON` from pool init — add to Task 47-06's PRAGMA list. |
| T-47-09 | Tampering | Rotation interrupted mid-cycle leaves mixed-KEK state | mitigate | Per-table `UnitOfWork::run` transactions; WAL crash-atomicity; old KEK retained until last UPDATE commits. Task 47-08. |
| T-47-10 | Information Disclosure | Mask-round-trip bug overwrites stored secret with mask sentinel | mitigate | Preserve existing ALERT_SECRET_MASK pattern through encryption layer; targeted regression test. Task 47-07. |
| T-47-11 | Information Disclosure | JWT env-var lingers in deployment harness after DB migration | mitigate | One-shot deprecation warn on first start that detects this state; documentation handoff to Phase 52. Task 47-05 + 47-11. |
| T-47-12 | Denial of Service | KDF iteration count high (600k) blocks startup | accept | ~150 ms one-time cost on server start per 47-RESEARCH §A.2; below operational threshold. |

</threat_model>

## Cross-Task Verification — Success Criteria Trace

| Success Criterion | Status | Tasks That Satisfy |
|-------------------|--------|---------------------|
| #1 New rows encrypt; reads decrypt transparently | Covered | 47-01 (crypto core), 47-04 (loaders), 47-05 (JWT/LDAP loaders), 47-11 (e2e test) |
| #2 Migration upgrades existing rows; JWT env→DB on first start | Covered | 47-03 (schema), 47-05 (JWT loader logic), 47-06 (one-shot migration), 47-11 (migration test + JWT test) |
| #3 (amended) Transient-only legacy column; no cleartext after commit | Covered | 47-06 (DROP COLUMN in same commit), 47-11 (`PRAGMA table_info` assertion that cleartext columns are absent) |
| #4 Rotation procedure documented + exercised | Covered | 47-08 (CLI + endpoint), 47-10 (full-cycle integration test) |
| #5 No cleartext secret in any log line | Covered | 47-09 (SecretString wrapping + audit), 47-11 (log-scan integration test) |

Every locked CONTEXT decision maps to at least one task:
- D-Q1 (scope EXPAND: 4 secret types) → Tasks 47-03, 47-05, 47-06
- D-Q2 (PBKDF2-HMAC-SHA256 600k) → Task 47-01
- D-Q3 (AES-256-GCM with AAD) → Task 47-01, 47-04
- D-Q4 (DPAPI recovery → Phase 52) → Task 47-06 fails-fast; no recovery code in Phase 47
- D-Q5 (rotation via admin CLI only) → Task 47-08
- D-Q6 (same-release cleartext drop) → Task 47-06, asserted by Task 47-11

## Test Strategy Summary

| Test Type | Where | Coverage |
|-----------|-------|----------|
| Unit — crypto round-trip, nonce uniqueness, AAD mismatch, version byte | Task 47-01 (colocated `crypto/tests.rs`) | Crypto core correctness |
| Unit — secret_kek_history CRUD | Task 47-02 (colocated) | Repository correctness |
| Unit — schema migration idempotency (new test `test_migration_add_secret_encrypted_columns`) | Task 47-03 (`db/mod.rs`) | Schema additions don't break upgrades |
| Unit — encrypted-column repository round-trip + mask round-trip | Task 47-04 + 47-05 (colocated) | Loader correctness |
| Unit — SecretString Debug redaction | Task 47-09 (colocated) | Compile-time guarantee |
| Integration — admin API mask round-trip | Task 47-07 (`admin_api.rs` tests) | TOCTOU-safe mask preservation |
| Integration — pre-Phase-47 fixture → migrate → assert clean | Task 47-11 (`secrets_migration_integration.rs`) | Success criterion #2, #3 |
| Integration — JWT env-var → DB migration | Task 47-11 (`secrets_migration_integration.rs`) | Success criterion #2 (JWT special case) |
| Integration — full rotation cycle including old-KEK forensic decrypt | Task 47-10 (`secrets_rotation_integration.rs`) | Success criterion #4 |
| Integration — admin API e2e round-trip + DB-level encrypted-blob check | Task 47-11 (`secrets_encryption_integration.rs`) | Success criterion #1 |
| Integration (CI) — log scan + audit_events scan asserts no cleartext | Task 47-11 (`secrets_log_scan_integration.rs`) | Success criterion #5 |

## Open Risks / Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| **DPAPI master-key loss** (VM reimage, profile corruption, security-tool intervention) | HIGH | Fail-fast on startup with a clear error message identifying the missing master key. Recovery runbook is Phase 52 territory (HARD-06) per CONTEXT D-Q4. No automatic recovery in Phase 47. |
| **Migration crash mid-write** | MEDIUM | SQLite WAL provides crash-atomicity; the transaction either lands fully or rolls back. Idempotent re-run on next startup picks up where it left off (`WHERE *_encrypted IS NULL`). DROP COLUMN is the last statement in the transaction — if it didn't commit, the cleartext column still exists and the next startup retries. |
| **Key-rotation atomicity across tables** | MEDIUM | Each table's re-encryption runs in its own `UnitOfWork::run`. If table N succeeds and table N+1 fails, the old KEK is retained (not retired) until the very last step. Read paths consult `secret_kek_history` to resolve version bytes; mixed-version state is decryptable end-to-end during partial rotation. |
| **MSRV bump** | LOW | All chosen crate versions explicitly verified MSRV-compatible with Rust 1.75 in 47-RESEARCH §A.3 (`aes-gcm 0.10.3` MSRV 1.56, `pbkdf2 0.12.2` MSRV 1.60, `sha2 0.10.8` MSRV unstated but pre-0.11, `hmac 0.12.1` pre-0.11, `zeroize 1.8.2` MSRV 1.60). Explicitly do NOT bump to `pbkdf2 0.13.0` or `sha2 0.11.0` or `aes-gcm 0.11.0-rc.x` — those require Rust 1.85. |
| **Windows API gotcha — windows-rs 0.58 vs 0.62** | LOW | dlp-server pins 0.58 (47-RESEARCH §B.2). The DPAPI surface is identical across both versions. Only addition needed is `Win32_Security_Cryptography` to the existing feature list. No version bump in this phase. |
| **ALERT_SECRET_MASK round-trip silently broken** | MEDIUM | Task 47-07 is a dedicated regression test for this. If broken, Task 47-04's mask-round-trip unit test in alert_router_config.rs fails first; if that passes but admin API doesn't, Task 47-11's integration test catches it. |
| **CRYPTPROTECT_LOCAL_MACHINE flag forgotten** | MEDIUM | Hardcoded in `crypto/dpapi.rs::dpapi_protect`. Task 47-01's behavior tests cover both protect and unprotect paths; the `#[cfg(windows)]`-gated integration test on a Windows CI runner exercises the SCM-launched service context per 47-RESEARCH §G.1 (Phase 50 infrastructure handoff). |
| **PRAGMA secure_delete not enabled** | LOW | Add `PRAGMA secure_delete = ON;` to `new_pool`'s init batch (db/mod.rs:51) in Task 47-06 alongside the WAL pragma. Past cleartext on free pages becomes recoverable only via forensic tools post-VACUUM; this PRAGMA closes that. |
| **Logging hygiene regression after this phase** | MEDIUM | Task 47-11's CI log-scan integration test is permanent — any future code that logs a secret will fail CI. Document the pattern in `docs/SECURITY_ARCHITECTURE.md` (Phase 52). |

<verification>
- `cargo test -p dlp-server` — all unit + integration tests pass
- `cargo test -p dlp-common` — ad_client tests pass (updated for explicit-bind support)
- `cargo test -p dlp-admin-cli` — rotate-secrets command builds and basic CLI tests pass
- `cargo clippy --workspace -- -D warnings` — zero warnings
- `cargo fmt --check` — formatting clean
- Manual: spin up a fresh server, observe v1 KEK creation; spin up against a pre-Phase-47 DB, observe migration logs; run `dlp-admin-cli rotate-secrets`; restart server, observe v2 active.
</verification>

<success_criteria>
All five amended success criteria from CONTEXT.md satisfied (see Cross-Task Verification table). Phase 47 closes HARD-01.
- Every secret column in operator SQLite is AES-256-GCM ciphertext after migration.
- Migration is atomic, idempotent, and same-release (no persisted cleartext after commit).
- JWT moves from env-var to DB on first start; env-var becomes optional.
- LDAP gains opt-in explicit-bind support; SSPI passwordless remains the default.
- `dlp-admin-cli rotate-secrets` re-keys every encrypted column in one operation, exercised end-to-end by an integration test.
- CI log-scan asserts zero cleartext leakage into tracing or audit_events.
</success_criteria>

<output>
After completion, create `.planning/phases/47-secrets-encryption-at-rest/47-SUMMARY.md` describing the shipped artifacts, decisions made during execution, any deviations from this plan, and pointers for Phase 52 (DPAPI recovery runbook handoff).
</output>
