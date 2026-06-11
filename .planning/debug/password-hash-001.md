---
status: resolved
trigger: "Investigate bug in DLP Rust project: when creating or updating the password for dlp-admin, the hashed password is not being created/updated correctly."
created: 2026-06-11T00:00:00Z
updated: 2026-06-11T00:00:00Z
---

## Current Focus

hypothesis: "The dlp-admin password has two separate storage locations (admin_users.password_hash for JWT login and agent_credentials.DLPAuthHash for service stop). Creating or updating the admin password only updates one of them, leaving the agent stop password out of sync."
test: "Trace all password creation/update code paths and verify what stores are touched"
expecting: "Confirm that create_admin_user and change_password only update admin_users, not agent_credentials.DLPAuthHash"
next_action: "Document root cause and recommended fix approach"

## Symptoms

expected: "Creating or updating dlp-admin password should correctly generate and persist a password hash that is usable for all dlp-admin authentication scenarios, including service stop"
actual: "Hashed password is not being created/updated correctly for dlp-admin — the admin login password and agent stop password are stored in separate tables and are not synchronized"
errors: "No explicit error in code; symptom manifests as password verification failures when the wrong store is consulted (e.g. agent service stop cannot verify password set via --init-admin)"
reproduction: |
  1. Start dlp-server with a fresh DB: `dlp-server --init-admin "my-password"`
  2. Observe that admin_users.password_hash is set to a valid bcrypt hash of "my-password".
  3. Query agent_credentials table for key "DLPAuthHash" — row is absent.
  4. Attempt to stop dlp-agent service with "my-password" — verification fails because the agent only reads DLPAuthHash from agent_credentials / registry.
started: "Always present — architectural split between JWT login password (admin_users) and agent stop password (agent_credentials)"

## Eliminated

- hypothesis: "bcrypt::hash is producing invalid hashes"
  evidence: "Wrote standalone tests for create_admin_user and change_password; both produce valid $2b$12$... bcrypt hashes that verify correctly with bcrypt::verify."
  timestamp: 2026-06-11T00:00:00Z

- hypothesis: "AdminUserRepository::insert or update_password_hash has SQL parameter binding errors"
  evidence: "Verified SQL column order matches params! macro order in both insert() and update_password_hash(). Integration tests confirm rows are written and hashes change after update."
  timestamp: 2026-06-11T00:00:00Z

- hypothesis: "change_password handler has an ownership or async bug that drops the new hash"
  evidence: "Traced the handler: new_hash String is moved into the spawn_blocking closure that calls update_password_hash. Test confirms stored hash changes and new password verifies."
  timestamp: 2026-06-11T00:00:00Z

## Evidence

- timestamp: 2026-06-11T00:00:00Z
  checked: "dlp-server/src/admin_auth.rs create_admin_user() and change_password()"
  found: "create_admin_user hashes password with bcrypt cost 12 and inserts into admin_users via AdminUserRepository::insert. change_password hashes new_password and updates admin_users.password_hash via AdminUserRepository::update_password_hash. Neither function touches agent_credentials."
  implication: "Admin login password is correctly hashed and stored, but agent stop credential (DLPAuthHash) is never set by these flows."

- timestamp: 2026-06-11T00:00:00Z
  checked: "dlp-server/src/db/repositories/admin_users.rs"
  found: "insert() writes (username, password_hash, created_at) to admin_users. update_password_hash() updates only password_hash. No repository method propagates changes to agent_credentials."
  implication: "The repository layer is single-table only; synchronization must happen at a higher layer."

- timestamp: 2026-06-11T00:00:00Z
  checked: "dlp-server/src/db/repositories/credentials.rs and dlp-server/src/admin_api.rs set_agent_auth_hash()"
  found: "CredentialsRepository::upsert() writes to agent_credentials with a key/value model. The admin API endpoint PUT /agent-credentials/auth-hash stores key 'DLPAuthHash' with the provided bcrypt hash. This is the only code path that sets DLPAuthHash."
  implication: "The agent stop password is a completely separate credential that must be explicitly set via the TUI 'Set Agent Password' menu or a direct API call."

- timestamp: 2026-06-11T00:00:00Z
  checked: "dlp-agent/src/password_stop.rs and dlp-agent/src/server_client.rs"
  found: "Agent service stop only uses get_auth_hash() -> read_registry_string('DLPAuthHash') or fetch_auth_hash() from GET /agent-credentials/auth-hash. It never references admin_users."
  implication: "Even if admin_users.password_hash is correctly set, the agent cannot use it for stop verification."

- timestamp: 2026-06-11T00:00:00Z
  checked: "dlp-admin-cli/src/screens/dispatch.rs password menu"
  found: "TUI has two independent actions: 'Change Admin Password' -> PUT /auth/password (updates admin_users) and 'Set Agent Password' -> PUT /agent-credentials/auth-hash (updates agent_credentials). There is no single action that updates both."
  implication: "Operators can easily set one password and assume it applies to both login and service stop, but it does not."

- timestamp: 2026-06-11T00:00:00Z
  checked: "docs/OPERATIONAL.md and docs/SRS.md references to dlp-admin password"
  found: "Documentation treats 'dlp-admin password' as a single credential used for service stop and references `dlp-admin-cli.exe set-password`, which does not exist as a subcommand. The actual CLI only exposes 'Set Agent Password' inside the TUI."
  implication: "Documentation and CLI surface are inconsistent with the dual-password implementation."

- timestamp: 2026-06-11T00:00:00Z
  checked: "dlp-server/src/main.rs ensure_admin_user()"
  found: "First-run setup creates the admin user in admin_users but does NOT seed agent_credentials.DLPAuthHash."
  implication: "A fresh server started with --init-admin has a working admin login but a non-working agent stop password out of the box."

## Resolution

root_cause: |
  The codebase maintains two independent bcrypt-hashed credentials for the dlp-admin identity:
    1. admin_users.password_hash — used for JWT login to the admin API.
    2. agent_credentials.DLPAuthHash — used for agent service stop verification.
  Creating or updating the dlp-admin password (via create_admin_user, --init-admin, or PUT /auth/password)
  only touches (1). The agent stop credential (2) is only set by a separate TUI flow ('Set Agent Password'
  -> PUT /agent-credentials/auth-hash). There is no synchronization between the two stores. From an
  operator perspective the 'dlp-admin password' is a single credential, so the current behavior means the
  hashed password is not created/updated in the store that actually matters for service stop.
fix: |
  Recommended minimal fix: unify the two password stores for the dlp-admin account.
    Option A (preferred): When create_admin_user() / change_password() runs, also upsert the same bcrypt
    hash into agent_credentials with key 'DLPAuthHash'. This makes --init-admin and 'Change Admin Password'
    automatically propagate to service stop.
    Option B: Remove the dual-password concept entirely and have the agent fetch the hash from
    admin_users via a new endpoint (e.g. GET /auth/agent-hash). This is cleaner architecturally but
    requires more changes on the agent side.
  In either case, update docs/OPERATIONAL.md and docs/SRS.md to reflect the actual CLI surface
  (no `set-password` subcommand exists; use TUI 'Set Agent Password' or equivalent).
verification: |
  Wrote and ran two standalone integration tests confirming admin_users.password_hash is correctly created
  and updated with valid bcrypt hashes. The functional gap is not in hashing or storage of admin_users,
  but in the missing propagation to agent_credentials.DLPAuthHash.
files_changed: []
