# Phase 47 Research — Secrets Encryption at Rest

**Researched:** 2026-05-11
**Domain:** Cryptography, Windows DPAPI, SQLite migrations, secret-handling in a Rust workspace
**Confidence:** HIGH for crypto/Windows surface; MEDIUM for codebase-internal migration tactics
**Requirement:** HARD-01

---

## Executive Summary

- **Recommended stack:** RustCrypto `aes-gcm 0.10.3` + `pbkdf2 0.12.2` + `hmac 0.12.1` + `sha2 0.10.8` + `zeroize 1.8.2`. All versions are MSRV ≤ 1.60, well below the project's declared 1.75 floor. `zeroize 1.8.2` and `subtle 2.6.1` are already in the dependency tree transitively, so they're effectively free additions. Use the **windows-rs** crate (already in `dlp-server` at 0.58, in `dlp-agent` at 0.62) for DPAPI bindings — `CryptProtectData` / `CryptUnprotectData` are battle-tested in this repo already (`dlp-agent/src/password_stop.rs` line 45, `dlp-user-ui/src/dialogs/stop_password.rs` line 250). [VERIFIED: `cargo info`, `cargo tree -p dlp-server`]

- **The "secrets" target list, verified against the actual schema, is narrower than the roadmap implies.** Currently cleartext in SQLite: `siem_config.splunk_token`, `siem_config.elk_api_key`, `alert_router_config.smtp_password`, `alert_router_config.webhook_secret` ([VERIFIED: `dlp-server/src/db/mod.rs:161-188`]). **JWT signing key is loaded from env var only** ([VERIFIED: `dlp-server/src/admin_auth.rs:75`]) — it is never written to SQLite, so HARD-01's "JWT signing key" target needs explicit clarification (see Open Question 1). **LDAP bind credentials are not in SQLite either** — current LDAP code uses passwordless SSPI machine-account bind ([VERIFIED: `dlp-common/src/ad_client.rs:376` — `simple_bind(&machine_account_dn, "")`]). HARD-01 mentions "LDAP bind credentials" as a future-looking target; the phase will need to either descope or add the column.

- **Crypto envelope recommendation:** AES-256-GCM with a 96-bit nonce per ciphertext, key versioning prefix, and an explicit AAD binding the column to the row (so a ciphertext extracted from `alert_router_config.smtp_password` cannot be replayed into `siem_config.splunk_token`). Wrap the data-encryption-key (DEK) inside the DB header row using a key-encryption-key (KEK) derived by PBKDF2-HMAC-SHA256 (600,000 iterations per OWASP 2024 guidance) from a DPAPI-protected machine-bound master secret. Per-cipher version byte enables rotation without dual-decryption logic. [CITED: OWASP Password Storage Cheat Sheet 2024]

- **PBKDF2 vs Argon2id flag for the planner:** The roadmap mandates PBKDF2. For *this specific use case* — deriving from a 32-byte machine-random secret with > 256 bits of entropy, not a user password — the choice between PBKDF2 and Argon2id is largely cosmetic: both KDFs add negligible value when the input is already high-entropy. PBKDF2 is the right call for FIPS-140 compliance pathways and ecosystem alignment with NIST. Argon2id is more defensible against future GPU attacks if the master secret entropy is ever weakened. The roadmap's PBKDF2 choice is fine. [CITED: OWASP Password Storage Cheat Sheet 2024 — "PBKDF2 is recommended by NIST and has FIPS-140 validated implementations"]

- **Critical risks:** (a) DPAPI master keys can be lost on profile corruption or VM reimage — without a recovery path, the SQLite secrets become unrecoverable; (b) the existing `ALERT_SECRET_MASK` round-trip in `admin_api.rs:1300-1416` MUST be preserved through the encryption layer or admin updates will silently overwrite secrets with the mask string; (c) the agent service runs as **SYSTEM (LocalSystem)**, not LOCAL_SERVICE or NETWORK_SERVICE — DPAPI behavior with `CRYPTPROTECT_LOCAL_MACHINE` for SYSTEM is correct but the LSA-protected master key path differs from user accounts and must be tested under SCM, not under interactive user.

---

## A. Crypto Primitives

### A.1 PBKDF2 vs Argon2id

**Roadmap decision:** PBKDF2.

**Analysis:**

| Aspect | PBKDF2-HMAC-SHA256 | Argon2id |
|--------|--------------------|----------|
| FIPS-140 validated | Yes [CITED: OWASP] | No |
| NIST SP 800-132 conformant | Yes | No |
| GPU/ASIC resistance | Weak (CPU-only) | Strong (memory-hard) |
| Memory cost | Negligible | 19-46 MiB recommended |
| Rust crate maturity | `pbkdf2` 0.13/0.12 (RustCrypto) | `argon2` 0.5.3 (RustCrypto) |
| Suitable for high-entropy input | Yes — iteration count irrelevant | Yes — overkill |

**Verdict:** **Accept the roadmap's PBKDF2 choice.** The input to the KDF is a DPAPI-protected machine secret (effectively 256+ bits of entropy). The KDF's job here is not stretching a weak password — it's deriving a stable AES key from a master seed plus a salt. Either KDF achieves that. PBKDF2 also aligns with the existing security architecture's NIST/FIPS posture (`docs/SECURITY_ARCHITECTURE.md` referenced FIPS-friendly choices).

If the planner wants to revisit this, surfaced as **Open Question 2** below.

[ASSUMED] — but well-supported by the OWASP/NIST citations: the iteration count's defensive value approaches zero when the input is already high-entropy random bytes. Tagging as assumed because no specific paper is being cited.

### A.2 PBKDF2 Parameters (OWASP 2024)

[CITED: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html]

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Hash function | HMAC-SHA-256 | NIST-recommended; FIPS-validated path |
| Iterations | **600,000** | OWASP 2024 minimum for SHA-256 |
| Salt length | **16 bytes (128 bit)** | Industry standard; NIST SP 800-132 §5.1 minimum |
| Output (derived KEK) length | **32 bytes (256 bit)** | Matches AES-256-GCM key size |

Note: 600,000 iterations on this input is theatrical (input is already high-entropy). It costs ~150 ms one-time on startup and is paid back in compliance documentation. Do not lower it; it does not measurably affect runtime.

### A.3 Recommended Rust Crates

| Crate | Version | Status | Why |
|-------|---------|--------|-----|
| `pbkdf2` | `0.12.2` | stable, MSRV 1.60 | RustCrypto-maintained, FIPS-aligned, used by major projects. Do NOT use 0.13.0 — MSRV 1.85 conflicts with project's stated 1.75 MSRV. [VERIFIED: `cargo info pbkdf2@0.12.2`] |
| `hmac` | `0.12.1` | stable, MSRV unknown | Required by pbkdf2. RustCrypto-maintained. [VERIFIED: `cargo info hmac`] |
| `sha2` | `0.10.8` | stable | RustCrypto. Do NOT use 0.11.0 — MSRV 1.85. [VERIFIED: `cargo info sha2@0.10.8`] |
| `aes-gcm` | `0.10.3` | stable, MSRV 1.56 | RustCrypto AEAD. NCC Group audited. Do NOT use 0.11.0-rc.x — pre-release with MSRV 1.85. [VERIFIED: `cargo info aes-gcm@0.10.3`] |
| `zeroize` | `1.8.2` | stable, MSRV 1.60 | Already in dependency tree via existing crates. Memory hygiene for KEK/DEK in RAM. [VERIFIED: `cargo tree -p dlp-server` shows `zeroize v1.8.2`] |
| `subtle` | `2.6.1` | stable | Already in dependency tree. Use `subtle::ConstantTimeEq` only if comparing MAC/tag values manually — `aes-gcm` does this internally. [VERIFIED: `cargo tree -p dlp-server`] |
| `rand` | already in tree as v0.8.x via `uuid`, or use OsRng from aes-gcm `getrandom` feature | — | For nonce generation. `Aes256Gcm::generate_nonce(&mut OsRng)` is the idiomatic call. [CITED: docs.rs/aes-gcm] |

**Installation (additions to `dlp-server/Cargo.toml`):**
```toml
# Crypto for HARD-01 (Phase 47)
aes-gcm = { version = "0.10.3", features = ["std", "zeroize"] }
pbkdf2 = { version = "0.12.2", default-features = false, features = ["hmac"] }
hmac = "0.12.1"
sha2 = "0.10.8"
zeroize = { version = "1.8.2", features = ["derive"] }
```

`zeroize` is already in the workspace via the `secrecy` crate transitively. Use the workspace dependency if a new workspace-level entry is added.

**Alternatives Considered:**

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `aes-gcm` | `chacha20poly1305` | Faster in pure software (~4 GB/s vs ~1.8 GB/s on CPUs without AES-NI), 192-bit XChaCha20 nonces are simpler to randomly generate. Tradeoff: Windows endpoints almost universally have AES-NI (post-2010 Intel/AMD CPUs), so AES-GCM is faster there (~6.4 GB/s). And SQLite secrets are tiny — performance is irrelevant. Pick AES-GCM for FIPS alignment. [CITED: https://blog.vitalvas.com/post/2025/06/01/xchacha20-poly1305-vs-aes/] |
| RustCrypto AES-GCM | `ring` | `ring` has stricter FIPS positioning but pulls in larger build (BoringSSL). RustCrypto is leaner and the workspace already commits to RustCrypto (pulled via `chacha20`, `subtle`, `zeroize`). Stick with RustCrypto. |
| PBKDF2 | Argon2id (`argon2 0.5.3`) | See A.1 — surface as planner decision, but PBKDF2 is fine. |

### A.4 Code Pattern (verified against docs.rs/aes-gcm)

```rust
// Source: https://docs.rs/aes-gcm/0.10.3/aes_gcm/
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use rand::rngs::OsRng;
use rand::RngCore;

// KEY: 32 bytes derived via PBKDF2 from DPAPI-protected master secret + salt.
let cipher = Aes256Gcm::new_from_slice(&kek)
    .expect("KEK must be exactly 32 bytes");

// NONCE: 96-bit random; MUST be unique per ciphertext under this key.
let mut nonce_bytes = [0u8; 12];
OsRng.fill_bytes(&mut nonce_bytes);
let nonce = Nonce::from_slice(&nonce_bytes);

// AAD binds ciphertext to its location — prevents copy-paste between columns.
let aad = b"alert_router_config:smtp_password:v1";
let ciphertext = cipher
    .encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
    .map_err(|_| AppError::Internal("encrypt failed".into()))?;

// Envelope: [version:u8 (1 byte)][nonce (12)][ciphertext+tag]
// Total overhead: 1 + 12 + 16 = 29 bytes vs plaintext length.
```

---

## B. Windows DPAPI Binding

### B.1 DPAPI Scope — `CRYPTPROTECT_LOCAL_MACHINE`

**Recommendation:** Use `CryptProtectData` with the `CRYPTPROTECT_LOCAL_MACHINE` flag (value `0x4`).

**Why this scope:**
- `dlp-server` runs (in production deployments) as a Windows Service under LocalSystem or a managed service account. The encryption must survive reboots and remain decryptable by the service process, not bound to any user logon.
- `CRYPTPROTECT_LOCAL_MACHINE` binds the data to the *machine* (DPAPI_SYSTEM LSA secret), not to a user profile. Any process on the machine can decrypt — but the SQLite file itself is ACL-restricted to SYSTEM (`docs/SECURITY_AUDIT.md`), so the file system is the access boundary, not DPAPI.
- Without this flag, DPAPI defaults to user-scoped encryption — the service's profile (`C:\Windows\System32\config\systemprofile`) would hold the master key, and decryption would fail if the service is later run under a different account.

[CITED: https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata]

**Threat model when `CRYPTPROTECT_LOCAL_MACHINE` is set:**
- Encryption no longer protects against a local admin on the same machine — they can decrypt via any process. NTFS ACL on the SQLite file is the only remaining barrier on-box.
- Protects against: offline file-system theft, SQLite file copied to another machine, attackers without admin on the box.
- Does NOT protect against: SYSTEM-level malware, local admin with code-execution.

This is acceptable for HARD-01's stated goal: prevent secret leak via file copy or backup. The SQLite file ACL handles the on-box admin case.

### B.2 windows-rs Module Path

**`dlp-server` currently pins `windows = 0.58`** ([VERIFIED: `dlp-server/Cargo.toml:86`]). **`dlp-agent` pins `windows = 0.62`** ([VERIFIED: `dlp-agent/src/password_stop.rs:43-49`]). Both 0.58 and 0.62 expose the DPAPI surface at the **same** module path:

```rust
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE,
};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
```

**Required feature flag for `windows` crate:** Add `Win32_Security_Cryptography` to the windows feature list in `dlp-server/Cargo.toml`. Currently dlp-server includes `Win32_Foundation`, `Win32_Security`, `Win32_System_Registry` ([VERIFIED: `dlp-server/Cargo.toml:86-90`]).

[VERIFIED: https://docs.rs/windows-sys/latest/windows_sys/Win32/Security/Cryptography/fn.CryptProtectData.html]

**Function signature (windows-rs 0.58/0.62):**
```rust
unsafe fn CryptProtectData(
    pdatain: *const CRYPT_INTEGER_BLOB,
    szdatadescr: PCWSTR,
    poptionalentropy: Option<*const CRYPT_INTEGER_BLOB>,
    pvreserved: Option<*const c_void>,
    ppromptstruct: Option<*const CRYPTPROTECT_PROMPTSTRUCT>,
    dwflags: u32,
    pdataout: *mut CRYPT_INTEGER_BLOB,
) -> windows::core::Result<()>
```

**The agent already has working unwrap code at `dlp-agent/src/password_stop.rs:760-781`.** The protect side exists at `dlp-user-ui/src/dialogs/stop_password.rs:239-265`. The Phase 47 work can be **directly modelled on these two functions**, just adding the `CRYPTPROTECT_LOCAL_MACHINE` flag (currently neither call site sets it because they're user-scoped over a pipe).

### B.3 Failure Modes & Recovery

[CITED: https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi-backup-keys-on-ad-domain-controllers]

| Failure | Cause | Recovery |
|---------|-------|----------|
| `ERROR_FILE_NOT_FOUND` on unprotect | Master key file missing — fresh OS install or profile reset | None automatic; phase must surface a clear startup error and require operator to re-enter all secrets via admin CLI |
| `NTE_BAD_KEY` / `NTE_BAD_KEY_STATE` | Master key encrypted with old DPAPI_SYSTEM LSA secret no longer accessible | Same — re-entry only |
| Decryption returns garbage / GCM tag mismatch | DB file copied from another machine | Same — re-entry only |

**Implications for the migration plan:**
- The backup column (cleartext copy) for "one release" is the rollback path if encryption is broken at deploy time, not the recovery path if DPAPI is broken.
- For DPAPI-loss scenarios there is no recovery — the planner needs an operator runbook (Phase 52 territory) describing how to re-enter every secret if the master key is lost. **Surface as Open Question 4.**

### B.4 Alternative — Windows CNG (BCrypt + Microsoft Software Key Storage Provider)

[CITED: https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval]

CNG offers a more modern API surface (`NCryptOpenKey`, `BCryptKeyDerivation`) with key isolation inside the LSA — even SYSTEM cannot extract the raw key bytes.

**Tradeoffs:**
- Pro: Stronger isolation; keys cannot be exfiltrated even by SYSTEM-level malware on the same box.
- Pro: Supports key versioning and rotation at the OS level.
- Con: Substantially more complex than DPAPI. Each operation is a `NCryptOpenKey` + `NCryptDecrypt` round-trip through LSA.
- Con: No existing code path in the workspace; whereas DPAPI is already used in two crates.
- Con: Schannel/CAPI compatibility quirks across Windows versions.

**Recommendation:** Stay with DPAPI for v1.0.0. CNG is a future-hardening target if a security audit later flags DPAPI as insufficient. Document as a deferred improvement.

---

## C. SQLite Migration Pattern

### C.1 Existing Migration Infrastructure

[VERIFIED: `dlp-server/src/db/mod.rs:271-423`]

- Migration runner is `run_migrations()` called by `new_pool()` after `init_tables()` (line 55).
- Each migration is a `run_alter()` call that swallows "duplicate column name" errors, making them idempotent.
- There is **no version tracking** — re-running migrations is idempotent by error-swallowing only.
- There is **no down-migration** support — rollback is via the backup column (HARD-01's explicit pattern).
- Existing migration test pattern is at `dlp-server/src/db/mod.rs:731-802` — `test_migration_add_mode_column()` is the model: spin up an old-schema DB in a temp file, open via `new_pool()`, assert the new column exists and existing rows pick up defaults.

The Phase 47 migration must follow this established pattern. Do not introduce `rusqlite_migration` or any external migration crate — it would conflict with the idempotent-error-swallow pattern already in place.

### C.2 Schema Changes

Four config tables hold cleartext secrets today. The migration must add one encrypted column per existing cleartext column, plus retain the cleartext for one release window:

| Table | Cleartext Column (existing) | New Encrypted Column | New Backup Column (rollback) | One-release retirement |
|-------|------------------------------|----------------------|------------------------------|------------------------|
| `siem_config` | `splunk_token` | `splunk_token_enc BLOB` | Keep `splunk_token` as-is | drop after v1.1.0 |
| `siem_config` | `elk_api_key` | `elk_api_key_enc BLOB` | Keep `elk_api_key` as-is | drop after v1.1.0 |
| `alert_router_config` | `smtp_password` | `smtp_password_enc BLOB` | Keep `smtp_password` as-is | drop after v1.1.0 |
| `alert_router_config` | `webhook_secret` | `webhook_secret_enc BLOB` | Keep `webhook_secret` as-is | drop after v1.1.0 |

Additionally, a new key-management table is needed:

```sql
CREATE TABLE IF NOT EXISTS secret_kek (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    -- DPAPI-protected (CRYPTPROTECT_LOCAL_MACHINE) blob of the master KDF seed.
    -- 32 bytes of random pre-DPAPI; variable size post-DPAPI (typically 200-300 bytes).
    master_seed_dpapi BLOB NOT NULL,
    -- Salt for PBKDF2 — 16 bytes, generated once at first run.
    pbkdf2_salt BLOB NOT NULL,
    -- Iteration count — currently 600000 per OWASP 2024.
    pbkdf2_iterations INTEGER NOT NULL DEFAULT 600000,
    -- Version byte used as envelope prefix; supports rotation.
    key_version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    rotated_at TEXT
);
```

Seeded with `INSERT OR IGNORE` at first startup with a freshly-generated random seed.

### C.3 Migration Sequence (Behavior-Preserving)

1. `init_tables()` adds `secret_kek` table with `CREATE TABLE IF NOT EXISTS` — idempotent on existing installs.
2. `run_migrations()` adds the four `*_enc BLOB` columns via `run_alter()` calls following the exact pattern at lines 272-406 (idempotent duplicate-column swallow).
3. **One-shot data migration** (new function `migrate_secrets_to_encrypted()`):
   - Acquire SYSTEM-level DPAPI key — generate `master_seed_dpapi` + `pbkdf2_salt` if `secret_kek` row is empty.
   - For each row in each table where `*_enc IS NULL AND <cleartext> != ''`:
     - Derive KEK via PBKDF2.
     - Encrypt cleartext with AES-256-GCM using per-row random nonce and AAD = `"table:column:v1"`.
     - Write to `*_enc` column.
     - **Do NOT clear the cleartext column** — that's the rollback path.
   - Idempotent: re-running checks `*_enc IS NULL`.
4. **Read path** in `get()` methods of the four repositories: prefer `*_enc` if non-NULL, fall back to cleartext. Decrypt transparently. Mask in API responses as today.
5. **Write path** in `update()` methods: encrypt before writing to `*_enc`, also write the same plaintext to the legacy column (dual-write for one release).
6. **Retirement migration** (v1.1.0 — out of scope for Phase 47): drop the cleartext columns, simplify read path.

### C.4 Rollback Mechanics

If decryption fails at runtime (key lost, tag mismatch):
- Log at WARN with the table+column (not the value).
- Fall back to the cleartext column if non-empty.
- Return a typed error if the cleartext is also empty.

If a deployment must be rolled back to pre-Phase 47:
- The cleartext columns still contain the original values (kept for one release).
- The pre-Phase 47 code reads those columns directly, ignoring the `*_enc` columns it doesn't know about.
- SQLite ignores unknown columns during ALTER-TABLE-added column reads — schema is forward-compatible.

### C.5 Migration Failure Recovery (Atomicity)

The data migration loop must:
- Wrap each table's migration in a `UnitOfWork` transaction (matching the existing pattern in `unit_of_work.rs`).
- Inside the transaction: read all rows, encrypt in memory, batch UPDATE.
- Commit only after all rows succeed.
- If any row fails (e.g., process crashes mid-write), the next startup's `migrate_secrets_to_encrypted()` runs again and resumes from `WHERE *_enc IS NULL`.

Power-loss safety is provided by SQLite WAL journal mode (already enabled at `dlp-server/src/db/mod.rs:51`).

---

## D. Logging Hygiene

### D.1 Existing Risk Surface

[VERIFIED via `Grep` of `tracing::(info|warn|error|debug)!` against `secret|password|token|api_key` patterns in `dlp-server/src/`]

- The only existing `tracing` call referencing a secret-adjacent term is `dlp-server/src/admin_auth.rs:325` ("admin password changed") — but the password value is not logged. No leakage today.
- `dlp-server/src/admin_api.rs` masks secrets in API responses via `ALERT_SECRET_MASK` (lines 1300-1416) — this pattern MUST be preserved through the encryption layer.

### D.2 `secrecy` Crate — Already in Use

[VERIFIED: `dlp-server/src/alert_router.rs:28-202`] — `SecretString` already wraps `smtp_password` in the live `AlertRouter` struct. The encrypted-at-rest secrets should be wrapped in `SecretString` (or `SecretVec<u8>` for raw bytes) at every layer between decryption and use, matching the existing pattern.

`secrecy = 0.8` is already a workspace dependency ([VERIFIED: `Cargo.toml:26`]).

### D.3 Audit-Log Scan Test (Success Criterion 5)

Pattern for the required test:

```rust
#[tokio::test]
async fn no_cleartext_secret_appears_in_logs() {
    // 1. Set tracing subscriber to write into an in-memory buffer.
    // 2. Spin up a fresh server with :memory: DB.
    // 3. Generate a high-entropy magic-string secret (e.g., random 32-byte hex).
    // 4. POST /admin/alert-config with that secret as smtp_password.
    // 5. Trigger a representative flow: GET, restart, GET again.
    // 6. Convert the tracing buffer to string.
    // 7. assert!(!buffer.contains(&magic_secret));
    // 8. Also scan the audit_events table for the magic string.
}
```

The phase plan should include this test in the verification step. It also exercises rotation by varying the secret across the flow.

---

## E. Key Rotation

### E.1 Rotation Strategy — Versioned Envelope

Each ciphertext starts with a 1-byte `key_version`. The `secret_kek` table tracks the current version. Multiple master seeds can coexist:

```
Envelope format (binary BLOB):
[u8  key_version]   // 1 byte — selects which master seed in secret_kek_history
[u8  alg_version]   // 1 byte — 1 = AES-256-GCM-PBKDF2-HMAC-SHA256-600000
[u8; 12 nonce]      // 12 bytes — random per ciphertext
[var ciphertext]    // plaintext.len() + 16 (GCM tag)
```

For multi-version rotation support, the `secret_kek` schema needs to evolve to `secret_kek_history` (a table, not a row):

```sql
CREATE TABLE IF NOT EXISTS secret_kek_history (
    version INTEGER PRIMARY KEY,
    master_seed_dpapi BLOB NOT NULL,
    pbkdf2_salt BLOB NOT NULL,
    pbkdf2_iterations INTEGER NOT NULL DEFAULT 600000,
    created_at TEXT NOT NULL,
    retired_at TEXT  -- non-NULL when version is no longer the active write key
);
```

The reader resolves `key_version` to the row in `secret_kek_history`. The writer always uses the row with `retired_at IS NULL` and the highest version.

### E.2 Rotation Procedure

1. Generate a new `master_seed_dpapi` + `pbkdf2_salt`, INSERT a new row with `version = max(version)+1`.
2. Mark the previous row `retired_at = NOW`.
3. Re-encrypt all secrets: for each `*_enc` column, decrypt with the old key, re-encrypt with the new key. Run in a transaction per table.
4. Old keys are kept in `secret_kek_history` indefinitely to support delayed-rollback scenarios (decrypt-only). Operator can purge by setting retention policy.

### E.3 Rotation Test (Success Criterion 4)

```rust
#[test]
fn test_key_rotation_exercise() {
    // 1. Fresh in-memory DB; migrate secrets; write a known plaintext.
    // 2. Read back — assert decryption returns the plaintext.
    // 3. Call rotate_kek() — generates v2.
    // 4. Read back — still decrypts (using v1 envelope, v1 still in history).
    // 5. Call reencrypt_all_secrets() — rewrites with v2.
    // 6. Read back — decrypts via v2.
    // 7. Mark v1 retired_at. Verify writes go to v2.
}
```

### E.4 DPAPI Re-Key Implications

If the OS rotates the DPAPI_SYSTEM LSA master key (Windows does this every ~3 months automatically), the `master_seed_dpapi` BLOB stored in `secret_kek_history` becomes unreadable. **In practice this does not happen** — DPAPI keeps old master keys forever (`C:\Windows\System32\Microsoft\Protect\S-1-5-18\User`, per Microsoft docs). But planning should call this out: if the operator manually invalidates DPAPI (rare, but possible via security tool intervention), all encrypted secrets become unrecoverable.

[CITED: https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi-backup-keys-on-ad-domain-controllers]

---

## F. Codebase Integration

### F.1 Affected Modules

| File | Why | Estimated change |
|------|-----|------------------|
| `dlp-server/Cargo.toml` | Add crypto deps; add `Win32_Security_Cryptography` to windows feature list | +6 lines |
| `dlp-server/src/db/mod.rs:64-264` | Add `secret_kek_history` table to `init_tables()`; add 4 `ALTER TABLE` migrations for `*_enc` columns to `run_migrations()` | +30 lines |
| `dlp-server/src/db/mod.rs` (new test) | Add `test_migration_add_secret_enc_columns()` modelled on `test_migration_add_mode_column()` at line 731 | +60 lines |
| `dlp-server/src/db/repositories/siem_config.rs` | Update `get()` / `update()` to handle `*_enc` columns; decrypt on read, encrypt on write | ~+40 lines |
| `dlp-server/src/db/repositories/alert_router_config.rs` | Same — but harder because `get_secrets()` at line 137 is a separate read path that bypasses normal read; must also use the encrypted path | ~+50 lines |
| `dlp-server/src/db/repositories/secret_kek.rs` (new) | Repository for the new `secret_kek_history` table | ~+100 lines |
| `dlp-server/src/crypto.rs` (new) | Core: DPAPI wrap/unwrap, PBKDF2 KDF, AES-GCM encrypt/decrypt, envelope serialization, key lifecycle, rotation | ~+300 lines |
| `dlp-server/src/lib.rs` | Add `pub mod crypto;` and possibly initialize the KEK at startup; thread the KEK handle through `AppState` | ~+15 lines |
| `dlp-server/src/main.rs:78-228` | Call `crypto::initialize()` after pool creation; run `migrate_secrets_to_encrypted()` on first start | ~+20 lines |
| `dlp-server/src/admin_api.rs:1300-1416` | Verify `ALERT_SECRET_MASK` flow still works through the encrypted column path (no behavior change but careful review) | ~0 lines, test additions |
| `dlp-server/tests/secrets_encryption_integration.rs` (new) | New integration test file: end-to-end secret round-trip, migration test, rotation test, log-scrub test | ~+200 lines |

### F.2 JWT Secret Question (Open Question 1)

The roadmap lists "JWT signing key" as a HARD-01 target. But:
- `dlp-server/src/admin_auth.rs:75` reads it from env var only.
- It is **never stored in SQLite today**.
- The existing security model relies on environment variable injection by the deployment harness (operator-controlled).

If the phase is to encrypt it at rest in SQLite, the architecture changes substantially:
- Need to add it to the schema.
- Need to handle the "first run, no JWT secret yet" case — currently env var is required at startup.
- Need to migrate existing deployments off env var.

**Surface to planner — see Open Question 1.**

### F.3 LDAP Bind Credentials (Open Question 3)

The roadmap lists "LDAP bind credentials" as a HARD-01 target. But:
- `dlp-common/src/ad_client.rs:376` uses `simple_bind(&machine_account_dn, "")` — passwordless machine-account bind via SSPI/Kerberos.
- There is no `bind_dn` / `bind_password` field in `ldap_config` ([VERIFIED: `dlp-server/src/db/repositories/ldap_config.rs:16-29`]).

If the phase is to add an explicit bind credential, that's a schema addition plus an `ad_client.rs` code change — substantial scope beyond "encrypt existing fields." **Surface to planner — see Open Question 3.**

### F.4 Test Strategy

[VERIFIED: `dlp-server/tests/` directory]

Existing integration test pattern in `dlp-server/tests/`:
- `ldap_config_api.rs`, `admin_audit_integration.rs`, `managed_origins_integration.rs`, `device_registry_integration.rs`, `mode_end_to_end.rs`.
- Pattern: spin up an `axum` app with `:memory:` SQLite, drive HTTP requests, assert state.

Phase 47 tests should follow this pattern in a new file `dlp-server/tests/secrets_encryption_integration.rs`. Three scenarios:
1. **Round-trip:** POST secret via admin API; restart pool; GET back (decrypted, masked); assert mask sentinel.
2. **Migration:** Stand up a pre-Phase-47 schema in a temp file, seed with cleartext, open via new `new_pool()`, assert `*_enc` is populated.
3. **Rotation:** Set up v1 KEK, write secret, rotate to v2, re-encrypt-all, decrypt with v2.

Use `tempfile::NamedTempFile` for the migration test exactly as `test_migration_add_mode_column` does at `db/mod.rs:736`.

---

## G. Pitfalls & Gotchas

### G.1 SYSTEM-Service DPAPI Gotchas

[CITED: https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi-backup-keys-on-ad-domain-controllers]

- The service profile path for LocalSystem is `C:\Windows\System32\config\systemprofile`. DPAPI master keys for SYSTEM live under `S-1-5-18\User\` — not the normal user profile path.
- **Testing this in a unit test under interactive user is misleading** — under interactive user, the master key is in `%APPDATA%\Microsoft\Protect\<SID>`. Behavior under SCM-launched service is different.
- Integration test recommendation: run the encrypt/decrypt smoke test under both interactive context (developer machine, dev mode) and SCM-launched service (CI Windows runner). Phase 50 (HARD-04) is doing the SCM-launch infrastructure; reuse that.

### G.2 ALERT_SECRET_MASK Round-Trip

[VERIFIED: `dlp-server/src/admin_api.rs:1300-1416`]

The existing admin API masks secrets on GET and accepts the mask sentinel on PUT to mean "keep existing." This pattern **must be preserved end-to-end**:
1. GET decrypts the `*_enc` blob, masks to sentinel before serializing the response.
2. PUT receives the mask sentinel, calls `get_secrets()` to read the existing decrypted value, then re-encrypts and writes.

`get_secrets()` at `alert_router_config.rs:137-143` currently reads cleartext from the transaction. After Phase 47, it must read from `*_enc` and decrypt — this is the critical TOCTOU-safe read path.

### G.3 Constant-Time Comparison

Not directly relevant — AES-GCM's authentication tag check is done internally by the `aes-gcm` crate using constant-time `subtle::ConstantTimeEq`. **Do not roll your own MAC verification.** The only attacker-input-vs-secret comparison in the existing codebase is bcrypt verification (admin_auth.rs:149) which is already constant-time via the `bcrypt` crate.

### G.4 Migration Failure Recovery

- WAL mode is already enabled, so a power-loss mid-migration leaves the DB in a consistent state (either all updates in the transaction landed, or none did).
- The cleartext columns are not cleared, so a botched encryption migration leaves the system in a fully-readable cleartext state — bad for security posture, good for recoverability.
- Idempotent restart: `WHERE *_enc IS NULL AND <cleartext> != ''` is the migration filter; once a row is migrated, it's skipped.

### G.5 Key in Memory — `zeroize`

- The KEK (32 bytes) and individual plaintext secrets must be zeroized after use.
- `zeroize 1.8.2` is already in the transitive deps; use `#[derive(Zeroize, ZeroizeOnDrop)]` on the master-key struct.
- The `aes-gcm` crate, when built with `--features zeroize`, automatically zeroizes the internal key when the cipher is dropped.
- `secrecy::SecretString` does NOT zeroize automatically in 0.8.x — it merely prevents accidental Debug logging. Pair with `zeroize` for the actual memory hygiene.

### G.6 dlp-server `windows = 0.58` vs dlp-agent `windows = 0.62`

Two different versions of `windows` in the workspace. The DPAPI module path is the same in both, but if the planner decides to bump dlp-server to 0.62 for consistency, that's a separate refactor (unrelated breaking changes in 0.59-0.62 affect other Win32 surfaces like Registry). **Recommendation:** Keep dlp-server on 0.58 for this phase; just add the `Win32_Security_Cryptography` feature flag. Bumping is HARD-02 / future-phase work.

### G.7 PRAGMA `secure_delete` for SQLite

After the cleartext columns are retired (v1.1.0 follow-on), the SQLite file should be VACUUMed to actually release the freed pages. Until that happens, the old cleartext is still recoverable from unused database pages via forensic tools. Consider enabling `PRAGMA secure_delete = ON;` at pool init (`db/mod.rs:51`) to make this future cleanup more effective.

---

## Open Questions

1. **JWT signing key — descope or expand?** The roadmap lists "JWT signing key" as a target. Currently it's env-only and never in SQLite. Options:
   - (a) **Descope:** clarify HARD-01 success criteria to cover only the four SQLite secrets currently cleartext (splunk_token, elk_api_key, smtp_password, webhook_secret).
   - (b) **Expand:** add JWT secret to a new SQLite table, encrypted at rest, with migration from env var. Substantially larger phase scope.
   - **Recommendation: (a) descope** — env vars are already at-rest-protected by the deployment harness; bringing JWT into SQLite adds attack surface (admin API can now read/write the JWT secret) for marginal gain.

2. **PBKDF2 vs Argon2id (re-confirm).** Roadmap says PBKDF2; analysis above supports the choice. Planner can confirm PBKDF2 or surface to user; either is defensible.

3. **LDAP bind credentials — descope or add schema?** Currently the code uses passwordless machine-account bind. Options:
   - (a) **Descope:** explicit bind credentials are out of scope until LDAP bind via username/password is itself a requirement.
   - (b) **Add bind fields:** schema additions to `ldap_config` plus `ad_client.rs` rewrite. Substantially larger phase scope.
   - **Recommendation: (a) descope** — and surface as a future enhancement.

4. **DPAPI master-key loss recovery — operator-facing runbook?** Phase 47 implements the encryption; Phase 52 (HARD-06) covers ops runbooks. Either phase 47 includes a brief recovery doc or phase 52 picks it up. **Planner should pick one.**

5. **Rotation schedule and trigger.** The phase must "exercise" rotation in a test. Must rotation be exposed as an admin API endpoint, an admin CLI command, both, or just an internal mechanism the test exercises directly? Roadmap is silent. **Recommendation: admin CLI command (`dlp-admin-cli rotate-secret-key`), no HTTP API in v1.0** — minimizes attack surface.

6. **Cleartext column retirement timing.** Roadmap says "backup column retained for one release." Specifically: kept through v1.0.0, dropped at v1.1.0? Or kept through some other release? **Recommendation: drop at v1.0.1 if no rollback was needed, otherwise v1.1.0.** Planner should pick.

---

## Recommended Plan Outline

Suggested task ordering (dependency-first). The planner will refine.

1. **T01 — Crypto primitives module (`dlp-server/src/crypto.rs`).** Add deps to Cargo.toml. Implement DPAPI wrap/unwrap, PBKDF2 KDF, AES-GCM envelope (encrypt/decrypt), key generation, and unit tests for round-trip + AAD tampering rejection + nonce uniqueness. Pure crypto, no DB.
2. **T02 — Schema migration + secret_kek_history repository.** Add `secret_kek_history` to `init_tables()`. Add 4 ALTER TABLE migrations for `*_enc` columns. Create `db/repositories/secret_kek.rs`. Unit tests modelled on `test_migration_add_mode_column`.
3. **T03 — KEK lifecycle.** On first server start: generate master seed, DPAPI-wrap, store in `secret_kek_history`. Thread the unwrap-on-startup result through `AppState`. Idempotent: subsequent starts read existing.
4. **T04 — Encrypted-field read/write path.** Modify the 4 repositories (siem_config, alert_router_config) to decrypt `*_enc` on get, encrypt + dual-write on update. Preserve `get_secrets()` TOCTOU pattern.
5. **T05 — One-shot data migration.** New function `migrate_secrets_to_encrypted()` called on startup after pool init. Idempotent. Logs at INFO when work is done, at DEBUG when no work needed.
6. **T06 — Admin CLI rotate command + rotation logic.** `dlp-admin-cli rotate-secret-key` calls an internal trait method on the server-side crypto module. Rotates KEK, re-encrypts all secrets. Integration test verifies the full cycle.
7. **T07 — End-to-end integration tests (`tests/secrets_encryption_integration.rs`).** Round-trip via admin API, migration test, rotation test, log-scrub test (asserts no secret appears in tracing buffer or audit_events).
8. **T08 — Documentation + retirement plan.** Brief operator note in `docs/SECURITY_ARCHITECTURE.md` describing the new at-rest model + the v1.0.x → v1.1.0 retirement of cleartext columns. Operator runbook for "DPAPI master key lost" (handoff to Phase 52 if preferred).

---

## Sources

### Primary (HIGH confidence)
- `dlp-server/src/db/mod.rs` (full schema + migration patterns) [VERIFIED in-tree]
- `dlp-server/src/db/repositories/{siem_config,alert_router_config,ldap_config,credentials}.rs` [VERIFIED in-tree]
- `dlp-server/src/admin_auth.rs:75` (JWT secret env-only) [VERIFIED in-tree]
- `dlp-server/src/admin_api.rs:1300-1416` (ALERT_SECRET_MASK pattern) [VERIFIED in-tree]
- `dlp-common/src/ad_client.rs:376` (LDAP passwordless bind) [VERIFIED in-tree]
- `dlp-agent/src/password_stop.rs:760-781` (`CryptUnprotectData` reference impl) [VERIFIED in-tree]
- `dlp-user-ui/src/dialogs/stop_password.rs:239-265` (`CryptProtectData` reference impl) [VERIFIED in-tree]
- `dlp-server/Cargo.toml` (windows 0.58 + features) [VERIFIED in-tree]
- `Cargo.toml` (workspace deps including `secrecy 0.8`) [VERIFIED in-tree]
- `cargo info` / `cargo search` / `cargo tree` outputs against live crates.io index 2026-05-11 [VERIFIED]
- https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata (CryptProtectData reference, last updated 2025-11-13) [CITED]
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html (PBKDF2 600k iterations recommendation) [CITED]
- https://docs.rs/aes-gcm/0.10.3/aes_gcm/ (AES-GCM Rust API + AAD payload pattern) [CITED]

### Secondary (MEDIUM confidence)
- https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi-backup-keys-on-ad-domain-controllers (key rotation behavior) [CITED]
- https://blog.vitalvas.com/post/2025/06/01/xchacha20-poly1305-vs-aes/ (AES-GCM vs ChaCha20 performance) [CITED]
- https://docs.rs/windows-sys/latest/windows_sys/Win32/Security/Cryptography/fn.CryptProtectData.html (windows-rs function signature) [CITED]

### Tertiary (LOW — informational only, not load-bearing)
- https://www.sygnia.co/blog/the-downfall-of-dpapis-top-secret-weapon/ (DPAPI threat-model commentary)
- https://tierzerosecurity.co.nz/2024/01/22/data-protection-windows-api.html (offensive-side DPAPI context)

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | KDF iteration count adds negligible defense when input is high-entropy random bytes | A.1, A.2 | Low — even if wrong, 600k iterations still passes OWASP and works correctly; the claim is only used to justify ignoring "do you need Argon2id" |
| A2 | The four SQLite secret columns enumerated in C.2 are exhaustive | C.2 | Medium — if there's another secret-bearing column missed by `Grep`, Phase 47 misses it. Phase plan should include an explicit re-scan task. |
| A3 | The DPAPI master key on a SYSTEM-launched service is stable across reboots without further intervention | B.3 | Medium — verified by Microsoft docs but not exercised in CI yet (until Phase 50 runs SCM-launched services). Recommend smoke test on a real Windows host before declaring HARD-01 complete. |
| A4 | `cargo search`/`cargo info` results on 2026-05-11 reflect current crates.io state | A.3 | Low — directly queries live registry index |

---

## Confidence Breakdown

| Area | Level | Reason |
|------|-------|--------|
| Crypto crate selection (versions + MSRV) | HIGH | Live `cargo info` + matched against MSRV stated in README |
| Windows DPAPI surface | HIGH | Two working reference implementations already in the repo + Microsoft Learn docs verified |
| SQLite migration pattern | HIGH | `test_migration_add_mode_column` is a working in-tree model |
| Secret column inventory | MEDIUM | Grep-confirmed but A2 risk remains |
| OWASP iteration count | HIGH | Direct OWASP cheat sheet citation |
| Rotation mechanics | MEDIUM | Pattern is industry-standard but no existing in-tree code path |
| JWT/LDAP target descope | MEDIUM | Code-confirmed but user may have intended different scope |

**Research date:** 2026-05-11
**Valid until:** 2026-06-11 (30 days for stable crates; refresh sooner if RustCrypto releases 0.11/0.13 stable)
