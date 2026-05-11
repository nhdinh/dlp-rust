# Phase 47: Secrets Encryption at Rest — Context

**Gathered:** 2026-05-11
**Status:** Ready for planning
**Source:** Post-research user decisions on open questions from `47-RESEARCH.md`

<domain>

## Phase Boundary

Implement end-to-end secret encryption for the operator SQLite database. All four secret types in ROADMAP scope are in scope, even those that currently live outside the database — Phase 47 also brings them into the encrypted schema:

- **SMTP credentials** (already in DB cleartext) — encrypt in place
- **SIEM webhook tokens** (already in DB cleartext) — encrypt in place
- **JWT signing key** (currently env-var only) — add to DB schema, migrate from env-var, encrypt
- **LDAP bind credentials** (currently SSPI passwordless) — add schema rows for the optional explicit-bind path, encrypt

Cleartext columns are dropped in the **same release (v1.0.0)** — no persisted backup column. A transient `*_legacy` column is allowed *during* the migration step (write encrypted, verify decrypt, then atomic drop) but must not survive past the migration commit.

</domain>

<decisions>

## Locked Decisions (from researcher's open questions, resolved by user)

### Q1 — Scope: EXPAND
Add JWT + LDAP schema rows. Encrypt all 4 secret types. JWT migrates from env-var to DB column. LDAP gains optional explicit-bind credential storage (SSPI remains the default; explicit bind is a configuration alternative).

### Q2 — Key Derivation: PBKDF2-HMAC-SHA256
Per ROADMAP. 600,000 iterations (OWASP 2026 guidance). Crate: `pbkdf2 0.12.2` (MSRV 1.75-compatible). The high-entropy machine-bound DPAPI secret is the KDF input — adequate for non-password-derived keys.

### Q3 — Symmetric Cipher: AES-256-GCM
Authenticated encryption with associated data (AAD). Crate: `aes-gcm 0.10.3` (MSRV-compatible). 96-bit random nonce per row stored alongside the ciphertext; AAD binds ciphertext to the row's table+column identity to prevent ciphertext substitution attacks across columns.

### Q4 — DPAPI Recovery Runbook: Phase 52 (Operational Documentation)
The DPAPI-master-key-loss recovery procedure is operational documentation, not Phase 47 code. Phase 47 must fail-fast with a clear error message if DPAPI unprotect fails; Phase 52 documents recovery (re-init from env vars, restore-from-backup, etc.).

### Q5 — Rotation Interface: Admin CLI only
`dlp-admin-cli rotate-secrets` command. Service must be stopped or in maintenance mode (explicit lock). No HTTP endpoint — smaller attack surface, matches the operational shape of other admin maintenance commands. Required to satisfy ROADMAP success criterion #4 ("rotation procedure documented and exercised in a test").

### Q6 — Cleartext Column Lifecycle: Same release (v1.0.0)
No persisted backup column. The migration is atomic-per-table:

1. Add `<secret>_encrypted BLOB` and `<secret>_nonce BLOB` columns.
2. For each cleartext row: derive KEK via DPAPI unprotect → PBKDF2; encrypt cleartext into the new columns; verify by re-reading and decrypting.
3. NULL the cleartext column in the same UPDATE.
4. After all rows processed: `ALTER TABLE` to drop the cleartext column.
5. Commit.

This **modifies ROADMAP success criterion #3** ("backup column allows rollback within one release window") — the backup column is transient (intra-migration only), not persistent. Document this scope shift in REQUIREMENTS.md HARD-01 once the phase is complete.

</decisions>

<canonical_refs>

## Canonical References

Downstream agents MUST read these before planning or implementing.

### Project planning
- `.planning/ROADMAP.md` — Phase 47 goal + 5 success criteria (criterion #3 amended above)
- `.planning/REQUIREMENTS.md` — HARD-01 description
- `.planning/PROJECT.md` — overall architecture, decisions, gotchas

### Phase artifacts
- `.planning/phases/47-secrets-encryption-at-rest/47-RESEARCH.md` — full research (crate versions, DPAPI bindings, codebase locations, pitfalls)

### Codebase reference
- `.planning/codebase/STACK.md` — current crate dependencies (windows 0.58, rusqlite 0.32, r2d2 0.8)
- `.planning/codebase/CONCERNS.md` — JWT fallback tech debt, unsafe code

### Existing DPAPI usage (battle-tested templates to extend)
- `dlp-agent/src/password_stop.rs:760-781` — `CryptUnprotectData` reference
- `dlp-user-ui/src/dialogs/stop_password.rs:239-265` — `CryptProtectData` reference
- *Phase 47 extension:* both use user-scope DPAPI; Phase 47 requires `CRYPTPROTECT_LOCAL_MACHINE` flag for service-running-as-SYSTEM recovery across reboots.

### Existing migration pattern (template)
- `db/mod.rs:731-802` — `test_migration_add_mode_column` — idempotent ALTER TABLE pattern with duplicate-column-error swallow

### Existing TOCTOU-safe secret round-trip (must preserve through encryption layer)
- `admin_api.rs:1300-1416` — `ALERT_SECRET_MASK` + `get_secrets()` round-trip pattern

</canonical_refs>

<specifics>

## Specific Ideas

### Migration ordering
1. Add schema columns for JWT + LDAP (new) and `*_encrypted`/`*_nonce` for SMTP + SIEM (existing tables).
2. Run encryption migration per existing-cleartext column (SMTP, SIEM).
3. Migrate JWT_SECRET env-var to encrypted DB row on first startup post-deployment; emit deprecation warning if env-var still present after migration.
4. LDAP bind creds: optional — only populated when operator explicitly switches from SSPI to explicit-bind via admin CLI.

### Logging hygiene
- Audit every `tracing::` call site in `dlp-server/` that today logs config struct contents.
- Introduce `secrecy::SecretString` (or equivalent) for in-memory handling; rely on its `Debug` impl to redact in tracing output.
- Add a CI test that scans logs from a representative startup+config-save flow for the literal secret values used by the fixture.

### Key rotation
- Versioned ciphertext envelope: `version || nonce || ciphertext_tag` so a future re-key can identify rows pending re-encryption.
- Rotation command writes new-key-encrypted rows; old-key decryption remains available until the rotation completes; cutover commits the new key as primary.

### Test surface
- Unit: round-trip encrypt/decrypt with known KEK; nonce uniqueness; AAD-mismatch detection.
- Integration: migration on a fixture DB; rotation end-to-end; log-scan assertion that no secret literal appears in tracing output.

</specifics>

<deferred>

## Deferred Ideas

- **HSM / TPM key isolation** — outside HARD-01 scope. Could be a future v1.x milestone.
- **DPAPI key recovery runbook** — moves to Phase 52 (HARD-06 Operational Documentation).
- **Migration from explicit-bind back to SSPI for LDAP** — not in scope; admin can null the fields manually.
- **Backup/restore tooling for the encryption envelope** — Phase 52 or later.

</deferred>

---

*Phase: 47-secrets-encryption-at-rest*
*Context gathered: 2026-05-11 from researcher findings + user decisions on 6 open questions*
