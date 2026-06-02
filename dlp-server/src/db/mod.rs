//! SQLite database initialization and shared connection pool.
//!
//! Uses `r2d2`/`r2d2_sqlite` for multi-connection pooling. All axum
//! handlers should wrap DB calls in `tokio::task::spawn_blocking` to
//! avoid blocking the async reactor.

pub mod repositories;
pub mod unit_of_work;

pub use unit_of_work::UnitOfWork;

use anyhow::Context;
use r2d2::Pool as R2d2Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection as SqliteConn;

/// Pool type alias — wraps `SqliteConnectionManager`.
pub type Pool = R2d2Pool<SqliteConnectionManager>;

/// A checked-out connection from the pool. Automatically returns to
/// the pool when dropped.
pub type Connection = r2d2::PooledConnection<SqliteConnectionManager>;

/// Creates a connection pool for the given SQLite database path and
/// initializes all required tables.
///
/// # Arguments
///
/// * `path` - Filesystem path or `:memory:` URI for the SQLite database.
///
/// # Errors
///
/// Returns an error if the pool cannot be built or table creation fails.
pub fn new_pool(path: &str) -> anyhow::Result<Pool> {
    // Enable foreign-key enforcement on every checked-out connection.
    // SQLite does NOT enforce FK constraints unless `PRAGMA foreign_keys = ON`
    // is set per connection — the setting is not persisted at the file level.
    let mgr = SqliteConnectionManager::file(path)
        .with_init(|conn| conn.execute_batch("PRAGMA foreign_keys = ON;"));
    let pool = R2d2Pool::builder()
        .max_size(5)
        .build(mgr)
        .context("failed to build connection pool")?;

    // Initialize tables using the first connection from the pool.
    // SQLite sets WAL journal mode at the file level on first open,
    // so subsequent connections to the same file inherit that mode.
    let conn = pool
        .get()
        .context("failed to acquire connection for init")?;
    // WAL gives crash-atomic writes (used by the secrets migration's
    // single-transaction encrypt+DROP-COLUMN flow). `secure_delete = ON`
    // (Phase 47 Task 47-06) zeroises freed SQLite pages on overwrite/
    // VACUUM, blocking post-deletion forensic recovery of the cleartext
    // bytes that the secrets migration removes from disk. The PRAGMA is
    // file-level (persisted in the DB header), so it remains active
    // across re-opens; we still set it here so a fresh install picks it
    // up at create time. See 47-PLAN.md §"PRAGMA secure_delete not
    // enabled" risk register.
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA secure_delete = ON;")
        .context("failed to enable WAL + secure_delete pragmas")?;

    init_tables(&conn)?;
    run_migrations(&conn)?;
    Ok(pool)
}

/// Creates all application tables if they do not already exist.
///
/// # Errors
///
/// Returns an error if any `CREATE TABLE` statement fails.
fn init_tables(conn: &SqliteConn) -> anyhow::Result<()> {
    conn.execute_batch(
        "
            CREATE TABLE IF NOT EXISTS agents (
                agent_id       TEXT PRIMARY KEY,
                hostname       TEXT NOT NULL,
                ip             TEXT NOT NULL,
                os_version     TEXT NOT NULL,
                agent_version  TEXT NOT NULL,
                last_heartbeat TEXT NOT NULL,
                status         TEXT NOT NULL DEFAULT 'online',
                registered_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp        TEXT NOT NULL,
                event_type       TEXT NOT NULL,
                user_sid         TEXT NOT NULL,
                user_name        TEXT NOT NULL,
                resource_path    TEXT NOT NULL,
                classification   TEXT NOT NULL,
                action_attempted TEXT NOT NULL,
                decision         TEXT NOT NULL,
                policy_id        TEXT,
                policy_name      TEXT,
                agent_id         TEXT NOT NULL,
                session_id       INTEGER NOT NULL,
                access_context   TEXT NOT NULL DEFAULT 'local',
                correlation_id   TEXT UNIQUE,
                content_sha256   TEXT
            );

            CREATE TABLE IF NOT EXISTS exceptions (
                id               TEXT PRIMARY KEY,
                policy_id        TEXT NOT NULL,
                user_sid         TEXT NOT NULL,
                approver         TEXT NOT NULL,
                justification    TEXT NOT NULL,
                duration_seconds INTEGER NOT NULL,
                granted_at       TEXT NOT NULL,
                expires_at       TEXT NOT NULL
            );

            -- user_sid: added via Phase 9 ALTER TABLE migration below.
            -- NOTE: This column is added by the ALTER TABLE statement that runs after
            -- CREATE TABLE. On fresh databases (first run) CREATE TABLE includes user_sid
            -- directly. On existing databases (re-run), ALTER TABLE adds it if missing.
            -- The IF NOT EXISTS guard on ALTER TABLE makes this block idempotent.
            CREATE TABLE IF NOT EXISTS admin_users (
                username      TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                user_sid      TEXT NULL,
                created_at    TEXT NOT NULL
            );


            CREATE TABLE IF NOT EXISTS agent_credentials (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS policies (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                description TEXT,
                priority    INTEGER NOT NULL,
                conditions  TEXT NOT NULL,
                action      TEXT NOT NULL,
                enabled     INTEGER NOT NULL DEFAULT 1,
                mode        TEXT NOT NULL DEFAULT 'ALL',
                version     INTEGER NOT NULL DEFAULT 1,
                updated_at  TEXT NOT NULL
            );

            -- device_registry: USB device trust assignments managed by dlp-admin.
            -- trust_tier CHECK constraint enforces only valid tier values at the DB layer.
            -- UNIQUE(vid, pid, serial, owner_sid) allows multiple per-user entries for the
            -- same physical device. Machine-wide uniqueness (NULL owner_sid) is enforced
            -- by a coalesce-based unique index (Phase 38.4, D-02).
            CREATE TABLE IF NOT EXISTS device_registry (
                id          TEXT PRIMARY KEY,
                vid         TEXT NOT NULL,
                pid         TEXT NOT NULL,
                serial      TEXT NOT NULL,
                owner_sid   TEXT,
                owner_user  TEXT,
                description TEXT NOT NULL DEFAULT '',
                trust_tier  TEXT NOT NULL CHECK(trust_tier IN ('blocked', 'read_only', 'full_access')),
                created_at  TEXT NOT NULL
            );
            -- Unique index using COALESCE to treat NULL owner_sid as empty string,
            -- enforcing at most one machine-wide entry per (vid, pid, serial).
            -- Per-user entries have distinct owner_sid values so they coexist.
            CREATE UNIQUE INDEX IF NOT EXISTS idx_device_registry_unique
                ON device_registry(vid, pid, serial, COALESCE(owner_sid, ''));

            CREATE TABLE IF NOT EXISTS siem_config (
                id              INTEGER PRIMARY KEY CHECK (id = 1),
                splunk_url      TEXT NOT NULL DEFAULT '',
                splunk_token    TEXT NOT NULL DEFAULT '',
                splunk_enabled  INTEGER NOT NULL DEFAULT 0,
                elk_url         TEXT NOT NULL DEFAULT '',
                elk_index       TEXT NOT NULL DEFAULT '',
                elk_api_key     TEXT NOT NULL DEFAULT '',
                elk_enabled     INTEGER NOT NULL DEFAULT 0,
                updated_at      TEXT NOT NULL DEFAULT ''
            );
            INSERT OR IGNORE INTO siem_config (id) VALUES (1);

            CREATE TABLE IF NOT EXISTS alert_router_config (
                id                INTEGER PRIMARY KEY CHECK (id = 1),
                smtp_host         TEXT NOT NULL DEFAULT '',
                smtp_port         INTEGER NOT NULL DEFAULT 587,
                smtp_username     TEXT NOT NULL DEFAULT '',
                smtp_password     TEXT NOT NULL DEFAULT '',
                smtp_from         TEXT NOT NULL DEFAULT '',
                smtp_to           TEXT NOT NULL DEFAULT '',
                smtp_enabled      INTEGER NOT NULL DEFAULT 0,
                webhook_url       TEXT NOT NULL DEFAULT '',
                webhook_secret    TEXT NOT NULL DEFAULT '',
                webhook_enabled   INTEGER NOT NULL DEFAULT 0,
                updated_at        TEXT NOT NULL DEFAULT ''
            );
            INSERT OR IGNORE INTO alert_router_config (id) VALUES (1);

            -- ldap_config: Active Directory connection configuration (Phase 7).
            -- Single-row table enforced via CHECK (id = 1), seeded below.
            -- vpn_subnets is a comma-separated list of CIDR ranges.
            CREATE TABLE IF NOT EXISTS ldap_config (
                id               INTEGER PRIMARY KEY CHECK (id = 1),
                ldap_url         TEXT NOT NULL DEFAULT 'ldaps://dc.corp.internal:636',
                base_dn          TEXT NOT NULL DEFAULT '',
                require_tls      INTEGER NOT NULL DEFAULT 1,
                cache_ttl_secs   INTEGER NOT NULL DEFAULT 300,
                vpn_subnets      TEXT NOT NULL DEFAULT '',
                updated_at       TEXT NOT NULL DEFAULT ''
            );
            INSERT OR IGNORE INTO ldap_config (id) VALUES (1);

            -- global_agent_config: single-row default applied to all agents unless overridden.
            -- Uses CHECK (id = 1) to enforce exactly one row, seeded below.
            -- monitored_paths is stored as a JSON text array.
            -- NOTE: agent_config_overrides has a FK to agents(agent_id) ON DELETE CASCADE,
            -- but rusqlite does NOT enforce FK constraints unless PRAGMA foreign_keys = ON
            -- is set per connection. The cascade is a safety net, not a correctness invariant.
            CREATE TABLE IF NOT EXISTS global_agent_config (
                id                      INTEGER PRIMARY KEY CHECK (id = 1),
                monitored_paths         TEXT NOT NULL DEFAULT '[]',
                excluded_paths          TEXT NOT NULL DEFAULT '[]',
                heartbeat_interval_secs INTEGER NOT NULL DEFAULT 30,
                offline_cache_enabled   INTEGER NOT NULL DEFAULT 1,
                updated_at              TEXT NOT NULL DEFAULT ''
            );
            INSERT OR IGNORE INTO global_agent_config (id) VALUES (1);

            CREATE TABLE IF NOT EXISTS agent_config_overrides (
                agent_id                TEXT PRIMARY KEY
                                        REFERENCES agents(agent_id) ON DELETE CASCADE,
                monitored_paths         TEXT NOT NULL DEFAULT '[]',
                excluded_paths          TEXT NOT NULL DEFAULT '[]',
                heartbeat_interval_secs INTEGER NOT NULL DEFAULT 30,
                offline_cache_enabled   INTEGER NOT NULL DEFAULT 1,
                updated_at              TEXT NOT NULL DEFAULT ''
            );

            -- managed_origins: URL-pattern strings trusted by the Chrome Enterprise
            -- Connector (Phase 29) and managed via the admin TUI (Phase 28).
            -- UNIQUE constraint on `origin` prevents duplicate URL patterns.
            CREATE TABLE IF NOT EXISTS managed_origins (
                id     TEXT PRIMARY KEY,
                origin TEXT NOT NULL UNIQUE
            );

            -- disk_registry: server-side disk allowlist managed by dlp-admin (Phase 37, ADMIN-01).
            -- Entries are scoped per (agent_id, instance_id) pair -- a disk allowed on
            -- machine-A is NOT allowed on machine-B (physical relocation attack prevention, D-01).
            -- UNIQUE(agent_id, instance_id) enforces one allowlist entry per machine-disk pair (D-04).
            -- encryption_status CHECK constraint enforces only canonical serde names (D-11).
            -- Values match EncryptionStatus snake_case serialisation:
            --   Encrypted->encrypted, Suspended->suspended, Unencrypted->unencrypted
            -- Deployments that stored fully_encrypted/partially_encrypted must
            -- drop + recreate disk_registry before upgrading.
            CREATE TABLE IF NOT EXISTS disk_registry (
                id                 TEXT PRIMARY KEY,
                agent_id           TEXT NOT NULL,
                instance_id        TEXT NOT NULL,
                bus_type           TEXT NOT NULL,
                encryption_status  TEXT NOT NULL
                                   CHECK(encryption_status IN
                                         ('encrypted', 'suspended',
                                          'unencrypted', 'unknown')),
                model              TEXT NOT NULL DEFAULT '',
                registered_at      TEXT NOT NULL,
                UNIQUE(agent_id, instance_id)
            );

            -- Phase 47 (HARD-01): KEK version history for secret encryption at rest.
            -- One row per Key-Encryption-Key generation. `master_seed_dpapi` is the
            -- 32-byte high-entropy seed wrapped with DPAPI machine-scope
            -- (CRYPTPROTECT_LOCAL_MACHINE); PBKDF2 over (seed, salt, iterations)
            -- yields the actual AES-256-GCM KEK. `retired_at IS NULL` identifies
            -- the active KEK; retired rows are retained so post-rotation rows
            -- encrypted under an older KEK can still be decrypted for verification
            -- or rollback within the retention window. The partial index makes
            -- the highest-active-version lookup an O(1) tree probe.
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

            -- Phase 47 (Task 47-03): JWT signing secret encrypted at rest.
            -- Single-row table (CHECK id = 1) holds the active JWT secret
            -- envelope. Rotations UPDATE the row in place, bumping
            -- `secret_version` (the KEK version the envelope was wrapped under)
            -- and stamping `rotated_at`. The CHECK constraint rejects any
            -- INSERT with id != 1, so the single-row invariant cannot drift
            -- (resolves plan-check N6).
            --
            -- Column shape:
            --   secret_encrypted -- AES-GCM ciphertext+tag (no version prefix;
            --                       version is a separate column).
            --   secret_nonce     -- 12-byte AES-GCM nonce (NONCE_LEN).
            --   secret_version   -- KEK version stamped by SecretCrypto::encrypt,
            --                       used to look up the right KEK row in
            --                       secret_kek_history at decrypt time.
            CREATE TABLE IF NOT EXISTS secrets_jwt (
                id                INTEGER PRIMARY KEY CHECK (id = 1),
                secret_encrypted  BLOB    NOT NULL,
                secret_nonce      BLOB    NOT NULL,
                secret_version    INTEGER NOT NULL,
                created_at        TEXT    NOT NULL,
                rotated_at        TEXT
            );

            -- Phase 47 (Task 47-08): system-wide key/value store for
            -- transient operational flags (e.g. `maintenance_mode`).
            -- Deliberately schema-less: any future single-row toggle can
            -- piggyback rather than growing yet another single-row table.
            -- Both key and value are TEXT (booleans are encoded as the
            -- single-character strings \"0\" / \"1\" so they survive a
            -- round-trip through sqlite_dump | jq | etc.).
            CREATE TABLE IF NOT EXISTS system_kv (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            INSERT OR IGNORE INTO system_kv (key, value) VALUES ('maintenance_mode', '0');

            -- Phase 59: Label Service table for pilot data classification.
            -- Stores file/folder/archive labels with tier, state, and inheritance.
            -- CHECK constraints enforce valid tier and label_state values.
            -- parent_label_id is self-referencing FK for folder inheritance.
            CREATE TABLE IF NOT EXISTS labels (
                id                  TEXT PRIMARY KEY,
                path                TEXT NOT NULL,
                object_type         TEXT NOT NULL CHECK(object_type IN ('file', 'folder', 'archive')),
                tier                TEXT NOT NULL CHECK(tier IN ('T1', 'T2', 'T3', 'T4', 'Unclassified-Blocked')),
                label_state         TEXT NOT NULL CHECK(label_state IN ('temporary', 'confirmed', 'rejected', 'expired')),
                owner_sid           TEXT,
                parent_label_id     TEXT REFERENCES labels(id) ON DELETE SET NULL,
                acl_snapshot_id     TEXT,
                hash                TEXT,
                scanner_confidence  REAL,
                department          TEXT,
                created_at          TEXT NOT NULL,
                updated_at          TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_labels_path ON labels(path);
            CREATE INDEX IF NOT EXISTS idx_labels_tier ON labels(tier);
            CREATE INDEX IF NOT EXISTS idx_labels_state ON labels(label_state);
            CREATE INDEX IF NOT EXISTS idx_labels_owner ON labels(owner_sid);
            CREATE INDEX IF NOT EXISTS idx_labels_parent ON labels(parent_label_id);
            CREATE INDEX IF NOT EXISTS idx_labels_department ON labels(department);

            -- Phase 61: Approval Workflow Engine table.
            -- Stores approval requests and grants for T3 Data Owner and
            -- T4 Board digital-signature workflows.
            --
            -- data_object_id is a SOFT reference to labels(id) -- not enforced
            -- at DB level so path-based approvals work during pilot phase.
            CREATE TABLE IF NOT EXISTS approvals (
                id               TEXT PRIMARY KEY,
                requester_sid    TEXT NOT NULL,
                approver_sid     TEXT,
                data_object_id   TEXT NOT NULL,
                allowed_action   TEXT NOT NULL,
                destination_scope TEXT,
                valid_from       TEXT,
                valid_until      TEXT,
                signature        TEXT,
                status           TEXT NOT NULL
                                 CHECK(status IN ('pending', 'approved', 'rejected', 'revoked', 'expired')),
                justification    TEXT NOT NULL DEFAULT '',
                created_at       TEXT NOT NULL,
                updated_at       TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
            CREATE INDEX IF NOT EXISTS idx_approvals_requester ON approvals(requester_sid);
            CREATE INDEX IF NOT EXISTS idx_approvals_object ON approvals(data_object_id);
            CREATE INDEX IF NOT EXISTS idx_approvals_valid_until ON approvals(valid_until);
            CREATE INDEX IF NOT EXISTS idx_approvals_created_at ON approvals(created_at);

            -- Phase 62: Syslog Forwarder configuration (RFC 5424 + encrypted offline queue).
            -- Single-row config table enforced via CHECK (id = 1), seeded below.
            -- facility_code 20 = LOCAL4 (default per D-04). Range 16-23 (LOCAL0-LOCAL7).
            -- protocol is 'tls' only in Phase 62 (TCP without TLS and UDP deferred).
            -- queue_policy values: 'fifo_tail_drop', 'fifo_head_drop', 'ring_buffer' (per D-08).
            -- severity_alert = 3 (ERROR), severity_block = 4 (WARNING), severity_audit = 6 (INFO) per D-03.
            CREATE TABLE IF NOT EXISTS syslog_config (
                id                     INTEGER PRIMARY KEY CHECK (id = 1),
                host                   TEXT NOT NULL DEFAULT '',
                port                   INTEGER NOT NULL DEFAULT 514,
                enabled                INTEGER NOT NULL DEFAULT 0,
                protocol               TEXT NOT NULL DEFAULT 'tls',
                facility_code          INTEGER NOT NULL DEFAULT 20,
                format                 TEXT NOT NULL DEFAULT 'json',
                batching_enabled       INTEGER NOT NULL DEFAULT 1,
                severity_alert         INTEGER NOT NULL DEFAULT 3,
                severity_block         INTEGER NOT NULL DEFAULT 4,
                severity_audit         INTEGER NOT NULL DEFAULT 6,
                queue_policy           TEXT NOT NULL DEFAULT 'fifo_tail_drop',
                queue_max_size         INTEGER NOT NULL DEFAULT 100000,
                tls_min_version        TEXT NOT NULL DEFAULT '1.2',
                updated_at             TEXT NOT NULL DEFAULT ''
            );
            INSERT OR IGNORE INTO syslog_config (id) VALUES (1);

            -- Phase 62: Syslog offline queue for failed forward retry.
            -- event_json_encrypted + event_json_nonce store the KEK-encrypted envelope (per D-07, R-62-01).
            -- retry_count, last_error, next_attempt_at support time-based retry scheduling (per R-62-07).
            -- Index on created_at for efficient FIFO drain (Pitfall 5 in RESEARCH.md).
            -- Index on next_attempt_at for time-based scheduling (per R-62-08).
            CREATE TABLE IF NOT EXISTS syslog_queue (
                id                     INTEGER PRIMARY KEY AUTOINCREMENT,
                event_json_encrypted   BLOB NOT NULL,
                event_json_nonce       BLOB NOT NULL,
                created_at             INTEGER NOT NULL,
                retry_count            INTEGER NOT NULL DEFAULT 0,
                last_error             TEXT NOT NULL DEFAULT '',
                next_attempt_at        TEXT NOT NULL DEFAULT '',
                leased_until           TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_syslog_queue_created_at ON syslog_queue(created_at);
            CREATE INDEX IF NOT EXISTS idx_syslog_queue_next_attempt_at ON syslog_queue(next_attempt_at);
            CREATE INDEX IF NOT EXISTS idx_syslog_queue_leased_until ON syslog_queue(leased_until);

            -- Phase 49: Server-side allowlist entries for universal injection protection.
            -- match_type CHECK constraint enforces only canonical match types.
            -- category CHECK constraint enforces only canonical category values.
            -- priority is an integer for deterministic ordering (lower = higher priority).
            -- enabled is a boolean stored as INTEGER (0/1).
            -- version is bumped on every update for optimistic concurrency.
            CREATE TABLE IF NOT EXISTS allowlist_entries (
                id          TEXT PRIMARY KEY,
                match_type  TEXT NOT NULL CHECK(match_type IN ('exact_path', 'path_glob', 'path_prefix', 'cert_subject', 'cert_thumbprint')),
                value       TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                category    TEXT NOT NULL CHECK(category IN ('self', 'avedr', 'system_critical', 'operator_defined')),
                priority    INTEGER NOT NULL DEFAULT 100,
                enabled     INTEGER NOT NULL DEFAULT 1,
                version     INTEGER NOT NULL DEFAULT 1,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_allowlist_category ON allowlist_entries(category);
            CREATE INDEX IF NOT EXISTS idx_allowlist_enabled ON allowlist_entries(enabled);
            CREATE INDEX IF NOT EXISTS idx_allowlist_version ON allowlist_entries(version);

            -- Phase 49: Audit log for allowlist entry mutations.
            -- Tracks create, update, delete, enable, disable actions.
            -- old_value and new_value store JSON snapshots of the entry state.
            -- entry_id FK references allowlist_entries(id) with CASCADE delete.
            CREATE TABLE IF NOT EXISTS allowlist_audit_log (
                id          TEXT PRIMARY KEY,
                entry_id    TEXT NOT NULL,
                action      TEXT NOT NULL CHECK(action IN ('create', 'update', 'delete', 'enable', 'disable')),
                actor       TEXT NOT NULL,
                old_value   TEXT,
                new_value   TEXT,
                timestamp   TEXT NOT NULL,
                FOREIGN KEY (entry_id) REFERENCES allowlist_entries(id)
            );
            CREATE INDEX IF NOT EXISTS idx_allowlist_audit_entry ON allowlist_audit_log(entry_id);

            -- Phase 52 (Task 52-03): Protected paths registry for DACL tripwire.
            -- Stores the single source of truth for which paths receive tripwire
            -- protection. Paths may be auto-populated from confirmed T3/T4 labels
            -- or manually added by dlp-admin.
            --
            -- CHECK constraints enforce valid source and tier values.
            -- UNIQUE on path prevents duplicate entries.
            -- label_id is a soft FK to labels(id) with ON DELETE SET NULL.
            CREATE TABLE IF NOT EXISTS protected_paths (
                id          TEXT PRIMARY KEY,
                path        TEXT NOT NULL UNIQUE,
                source      TEXT NOT NULL CHECK(source IN ('auto', 'manual')),
                is_override INTEGER NOT NULL DEFAULT 0,
                tier        TEXT NOT NULL CHECK(tier IN ('T3', 'T4')),
                label_id    TEXT REFERENCES labels(id) ON DELETE SET NULL,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_protected_paths_path ON protected_paths(path);
            CREATE INDEX IF NOT EXISTS idx_protected_paths_source ON protected_paths(source);
            CREATE INDEX IF NOT EXISTS idx_protected_paths_tier ON protected_paths(tier);
            CREATE INDEX IF NOT EXISTS idx_protected_paths_label ON protected_paths(label_id);

            -- Phase 52 (Task 52-03): Canonical ACE snapshots per protected path.
            -- Each protected path may have one canonical ACE row storing the
            -- baseline SDDL string for tripwire comparison.
            -- ON DELETE CASCADE removes the ACE when the parent path is deleted.
            CREATE TABLE IF NOT EXISTS protected_path_aces (
                id                TEXT PRIMARY KEY,
                protected_path_id TEXT NOT NULL UNIQUE REFERENCES protected_paths(id) ON DELETE CASCADE,
                sddl              TEXT NOT NULL,
                created_at        TEXT NOT NULL,
                updated_at        TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_protected_path_aces_path ON protected_path_aces(protected_path_id);

            -- Phase 53: Bypass alerts table for ETW Kernel-File bypass correlator.
            -- Stores bypass alerts from agents with deduplication, severity, and ack tracking.
            CREATE TABLE IF NOT EXISTS bypass_alerts (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id            TEXT NOT NULL,
                pid                 INTEGER NOT NULL,
                image_path          TEXT NOT NULL,
                image_sha256        TEXT NULL,
                file_path           TEXT NOT NULL,
                operation           TEXT NOT NULL,
                file_object         INTEGER NOT NULL DEFAULT 0,
                qpc_timestamp       INTEGER NOT NULL,
                created_at          TEXT NOT NULL,
                severity            TEXT NOT NULL CHECK(severity IN ('info', 'warn', 'crit')),
                ack_by              TEXT NULL REFERENCES admin_users(username),
                ack_at              TEXT NULL,
                correlation_reason  TEXT NOT NULL CHECK(correlation_reason IN ('no_hook_journal', 'op_mismatch', 'hook_overwritten')),
                batch_id            TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_bypass_alerts_agent ON bypass_alerts(agent_id);
            CREATE INDEX IF NOT EXISTS idx_bypass_alerts_severity ON bypass_alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_bypass_alerts_created_at ON bypass_alerts(created_at);
            CREATE INDEX IF NOT EXISTS idx_bypass_alerts_ack ON bypass_alerts(ack_by, ack_at);
            CREATE INDEX IF NOT EXISTS idx_bypass_alerts_pid ON bypass_alerts(pid);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_bypass_alerts_dedup ON bypass_alerts(agent_id, pid, qpc_timestamp, file_path);
        ",
    )
    .context("failed to initialize database tables")?;

    Ok(())
}

/// Runs database migrations for existing installations.
///
/// Each migration is idempotent — safe to call on every startup. Duplicate-column
/// errors from `ALTER TABLE` are swallowed; all other errors are propagated.
pub fn run_migrations(conn: &SqliteConn) -> anyhow::Result<()> {
    run_alter(
        conn,
        "ALTER TABLE policies ADD COLUMN mode TEXT NOT NULL DEFAULT 'ALL'",
        "mode",
        "policies",
    )?;
    run_alter(
        conn,
        "ALTER TABLE global_agent_config ADD COLUMN excluded_paths TEXT NOT NULL DEFAULT '[]'",
        "excluded_paths",
        "global_agent_config",
    )?;
    run_alter(
        conn,
        "ALTER TABLE agent_config_overrides ADD COLUMN excluded_paths TEXT NOT NULL DEFAULT '[]'",
        "excluded_paths",
        "agent_config_overrides",
    )?;
    // Phase 38.4: per-user device registry columns.
    run_alter(
        conn,
        "ALTER TABLE device_registry ADD COLUMN owner_sid TEXT",
        "owner_sid",
        "device_registry",
    )?;
    run_alter(
        conn,
        "ALTER TABLE device_registry ADD COLUMN owner_user TEXT",
        "owner_user",
        "device_registry",
    )?;

    // Phase 43: USB enforcement config columns.
    run_alter(
        conn,
        "ALTER TABLE global_agent_config ADD COLUMN usb_blocked_failure_mode TEXT NOT NULL DEFAULT 'Warning only'",
        "usb_blocked_failure_mode",
        "global_agent_config",
    )?;
    run_alter(
        conn,
        "ALTER TABLE global_agent_config ADD COLUMN usb_startup_resolution_mode TEXT NOT NULL DEFAULT 'VID/PID/serial fallback'",
        "usb_startup_resolution_mode",
        "global_agent_config",
    )?;
    run_alter(
        conn,
        "ALTER TABLE global_agent_config ADD COLUMN usb_none_serial_policy TEXT NOT NULL DEFAULT 'Always Blocked'",
        "usb_none_serial_policy",
        "global_agent_config",
    )?;

    // Phase 43: USB enforcement config columns for per-agent overrides.
    run_alter(
        conn,
        "ALTER TABLE agent_config_overrides ADD COLUMN usb_blocked_failure_mode TEXT NOT NULL DEFAULT 'Warning only'",
        "usb_blocked_failure_mode",
        "agent_config_overrides",
    )?;
    run_alter(
        conn,
        "ALTER TABLE agent_config_overrides ADD COLUMN usb_startup_resolution_mode TEXT NOT NULL DEFAULT 'VID/PID/serial fallback'",
        "usb_startup_resolution_mode",
        "agent_config_overrides",
    )?;
    run_alter(
        conn,
        "ALTER TABLE agent_config_overrides ADD COLUMN usb_none_serial_policy TEXT NOT NULL DEFAULT 'Always Blocked'",
        "usb_none_serial_policy",
        "agent_config_overrides",
    )?;

    // M017: Cloud hook and print interception config columns.
    run_alter(
        conn,
        "ALTER TABLE global_agent_config ADD COLUMN cloud_hook_enabled INTEGER NOT NULL DEFAULT 0",
        "cloud_hook_enabled",
        "global_agent_config",
    )?;
    run_alter(
        conn,
        "ALTER TABLE global_agent_config ADD COLUMN print_enabled INTEGER NOT NULL DEFAULT 0",
        "print_enabled",
        "global_agent_config",
    )?;
    run_alter(
        conn,
        "ALTER TABLE global_agent_config ADD COLUMN print_xps_timeout_ms INTEGER NOT NULL DEFAULT 5000",
        "print_xps_timeout_ms",
        "global_agent_config",
    )?;
    run_alter(
        conn,
        "ALTER TABLE global_agent_config ADD COLUMN print_unclassifiable_action TEXT NOT NULL DEFAULT 'Block'",
        "print_unclassifiable_action",
        "global_agent_config",
    )?;
    run_alter(
        conn,
        "ALTER TABLE global_agent_config ADD COLUMN print_max_pages INTEGER NOT NULL DEFAULT 100",
        "print_max_pages",
        "global_agent_config",
    )?;

    // M017: Cloud hook and print interception config columns for per-agent overrides.
    run_alter(
        conn,
        "ALTER TABLE agent_config_overrides ADD COLUMN cloud_hook_enabled INTEGER NOT NULL DEFAULT 0",
        "cloud_hook_enabled",
        "agent_config_overrides",
    )?;
    run_alter(
        conn,
        "ALTER TABLE agent_config_overrides ADD COLUMN print_enabled INTEGER NOT NULL DEFAULT 0",
        "print_enabled",
        "agent_config_overrides",
    )?;
    run_alter(
        conn,
        "ALTER TABLE agent_config_overrides ADD COLUMN print_xps_timeout_ms INTEGER NOT NULL DEFAULT 5000",
        "print_xps_timeout_ms",
        "agent_config_overrides",
    )?;
    run_alter(
        conn,
        "ALTER TABLE agent_config_overrides ADD COLUMN print_unclassifiable_action TEXT NOT NULL DEFAULT 'Block'",
        "print_unclassifiable_action",
        "agent_config_overrides",
    )?;
    run_alter(
        conn,
        "ALTER TABLE agent_config_overrides ADD COLUMN print_max_pages INTEGER NOT NULL DEFAULT 100",
        "print_max_pages",
        "agent_config_overrides",
    )?;

    // Phase 47 (Task 47-03): encrypted-secret column trios on existing
    // cleartext-secret tables. Each `<col>` gains three siblings:
    //   <col>_encrypted BLOB     -- AES-GCM ciphertext + 16-byte GCM tag.
    //   <col>_nonce     BLOB     -- 12-byte AES-GCM nonce per envelope.
    //   <col>_version   INTEGER  -- KEK version stamped at encrypt time.
    //
    // The legacy cleartext column is RETAINED in this task. Task 47-06
    // performs the one-shot atomic migration (encrypt + verify-decrypt +
    // NULL the cleartext + DROP COLUMN in a single transaction).
    //
    // BLOB columns are nullable (no NOT NULL) so the migration window can
    // mark "not yet encrypted" with NULL; INTEGER `_version` is nullable
    // for the same reason -- a row with NULL `_version` has not been
    // encrypted yet under the current schema.

    // alert_router_config.smtp_password
    run_alter(
        conn,
        "ALTER TABLE alert_router_config ADD COLUMN smtp_password_encrypted BLOB",
        "smtp_password_encrypted",
        "alert_router_config",
    )?;
    run_alter(
        conn,
        "ALTER TABLE alert_router_config ADD COLUMN smtp_password_nonce BLOB",
        "smtp_password_nonce",
        "alert_router_config",
    )?;
    run_alter(
        conn,
        "ALTER TABLE alert_router_config ADD COLUMN smtp_password_version INTEGER",
        "smtp_password_version",
        "alert_router_config",
    )?;

    // alert_router_config.webhook_secret
    run_alter(
        conn,
        "ALTER TABLE alert_router_config ADD COLUMN webhook_secret_encrypted BLOB",
        "webhook_secret_encrypted",
        "alert_router_config",
    )?;
    run_alter(
        conn,
        "ALTER TABLE alert_router_config ADD COLUMN webhook_secret_nonce BLOB",
        "webhook_secret_nonce",
        "alert_router_config",
    )?;
    run_alter(
        conn,
        "ALTER TABLE alert_router_config ADD COLUMN webhook_secret_version INTEGER",
        "webhook_secret_version",
        "alert_router_config",
    )?;

    // siem_config.splunk_token
    run_alter(
        conn,
        "ALTER TABLE siem_config ADD COLUMN splunk_token_encrypted BLOB",
        "splunk_token_encrypted",
        "siem_config",
    )?;
    run_alter(
        conn,
        "ALTER TABLE siem_config ADD COLUMN splunk_token_nonce BLOB",
        "splunk_token_nonce",
        "siem_config",
    )?;
    run_alter(
        conn,
        "ALTER TABLE siem_config ADD COLUMN splunk_token_version INTEGER",
        "splunk_token_version",
        "siem_config",
    )?;

    // siem_config.elk_api_key
    run_alter(
        conn,
        "ALTER TABLE siem_config ADD COLUMN elk_api_key_encrypted BLOB",
        "elk_api_key_encrypted",
        "siem_config",
    )?;
    run_alter(
        conn,
        "ALTER TABLE siem_config ADD COLUMN elk_api_key_nonce BLOB",
        "elk_api_key_nonce",
        "siem_config",
    )?;
    run_alter(
        conn,
        "ALTER TABLE siem_config ADD COLUMN elk_api_key_version INTEGER",
        "elk_api_key_version",
        "siem_config",
    )?;

    // ldap_config: new bind_dn column plus bind_password encrypted trio.
    // SSPI passwordless bind remains the default (per CONTEXT D-Q1);
    // explicit-bind is opt-in by populating bind_dn + bind_password.
    run_alter(
        conn,
        "ALTER TABLE ldap_config ADD COLUMN bind_dn TEXT",
        "bind_dn",
        "ldap_config",
    )?;
    run_alter(
        conn,
        "ALTER TABLE ldap_config ADD COLUMN bind_password_encrypted BLOB",
        "bind_password_encrypted",
        "ldap_config",
    )?;
    run_alter(
        conn,
        "ALTER TABLE ldap_config ADD COLUMN bind_password_nonce BLOB",
        "bind_password_nonce",
        "ldap_config",
    )?;
    run_alter(
        conn,
        "ALTER TABLE ldap_config ADD COLUMN bind_password_version INTEGER",
        "bind_password_version",
        "ldap_config",
    )?;

    // Phase 60: scanner_confidence and department columns for labels table.
    run_alter(
        conn,
        "ALTER TABLE labels ADD COLUMN scanner_confidence REAL",
        "scanner_confidence",
        "labels",
    )?;
    run_alter(
        conn,
        "ALTER TABLE labels ADD COLUMN department TEXT",
        "department",
        "labels",
    )?;

    // Phase 55: enforcement_mode column on policies table.
    run_alter(
        conn,
        "ALTER TABLE policies ADD COLUMN enforcement_mode TEXT NOT NULL DEFAULT 'Block' CHECK(enforcement_mode IN ('Audit', 'Block', 'AuditAndBlock'))",
        "enforcement_mode",
        "policies",
    )?;

    // Phase 55: global_enforcement_mode system_kv entry (default PerPolicy).
    conn.execute(
        "INSERT OR IGNORE INTO system_kv (key, value) VALUES ('global_enforcement_mode', 'PerPolicy')",
        [],
    )
    .context("seed global_enforcement_mode system_kv")?;

    // Phase 58-04: content_sha256 column for audit event evidence hashing.
    run_alter(
        conn,
        "ALTER TABLE audit_events ADD COLUMN content_sha256 TEXT",
        "content_sha256",
        "audit_events",
    )?;

    Ok(())
}

/// Executes a single `ALTER TABLE` statement, ignoring duplicate-column errors.
fn run_alter(conn: &SqliteConn, sql: &str, column: &str, table: &str) -> anyhow::Result<()> {
    match conn.execute(sql, []) {
        Ok(_) => Ok(()),
        Err(e)
            if e.to_string()
                .contains(&format!("duplicate column name: {column}")) =>
        {
            Ok(())
        }
        Err(e) => Err(e).context(format!("running migration: add {column} column to {table}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_pool_in_memory() {
        let pool = new_pool(":memory:");
        assert!(pool.is_ok(), "should create pool for in-memory database");
    }

    #[test]
    fn test_tables_created() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let tables: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master \
                 WHERE type='table' ORDER BY name",
            )
            .expect("prepare")
            .query_map([], |row| row.get(0))
            .expect("query")
            .filter_map(|r| r.ok())
            .collect();

        assert!(tables.contains(&"agents".to_string()));
        assert!(tables.contains(&"audit_events".to_string()));
        assert!(tables.contains(&"exceptions".to_string()));
        assert!(tables.contains(&"admin_users".to_string()));
        assert!(tables.contains(&"agent_credentials".to_string()));
        assert!(tables.contains(&"siem_config".to_string()));
        assert!(tables.contains(&"alert_router_config".to_string()));
        assert!(tables.contains(&"ldap_config".to_string()));
        assert!(tables.contains(&"global_agent_config".to_string()));
        assert!(tables.contains(&"agent_config_overrides".to_string()));
        assert!(
            tables.contains(&"protected_paths".to_string()),
            "protected_paths table must exist after init"
        );
        assert!(
            tables.contains(&"protected_path_aces".to_string()),
            "protected_path_aces table must exist after init"
        );

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM siem_config", [], |r| r.get(0))
            .expect("count siem_config rows");
        assert_eq!(count, 1, "siem_config should have exactly one seed row");
    }

    #[test]
    fn test_global_agent_config_seed_row() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let (monitored_paths, heartbeat_interval_secs, offline_cache_enabled): (String, i64, i64) =
            conn.query_row(
                "SELECT monitored_paths, heartbeat_interval_secs, offline_cache_enabled \
                 FROM global_agent_config WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("seed row must exist");

        assert_eq!(
            monitored_paths, "[]",
            "default monitored_paths must be empty JSON array"
        );
        assert_eq!(
            heartbeat_interval_secs, 30,
            "default heartbeat_interval_secs must be 30"
        );
        assert_eq!(
            offline_cache_enabled, 1,
            "default offline_cache_enabled must be 1 (true)"
        );
    }

    #[test]
    fn test_idempotent_init() {
        let pool = new_pool(":memory:").expect("first open");
        let conn = pool.get().expect("acquire connection");
        let result =
            conn.execute_batch("CREATE TABLE IF NOT EXISTS agents (agent_id TEXT PRIMARY KEY);");
        assert!(result.is_ok(), "re-init should be idempotent");
    }

    #[test]
    fn test_alert_router_config_seed_row() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let tables: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master \
                 WHERE type='table' AND name='alert_router_config'",
            )
            .expect("prepare")
            .query_map([], |row| row.get(0))
            .expect("query")
            .filter_map(|r| r.ok())
            .collect();
        assert!(
            tables.contains(&"alert_router_config".to_string()),
            "alert_router_config table must exist after init"
        );

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM alert_router_config", [], |r| r.get(0))
            .expect("count alert_router_config rows");
        assert_eq!(
            count, 1,
            "alert_router_config must have exactly one seed row"
        );

        let (smtp_enabled, webhook_enabled): (i64, i64) = conn
            .query_row(
                "SELECT smtp_enabled, webhook_enabled FROM alert_router_config WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("read seed row");
        assert_eq!(smtp_enabled, 0, "smtp_enabled default must be 0");
        assert_eq!(webhook_enabled, 0, "webhook_enabled default must be 0");
    }

    #[test]
    fn test_ldap_config_seed_row() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let tables: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master \
                 WHERE type='table' AND name='ldap_config'",
            )
            .expect("prepare")
            .query_map([], |row| row.get(0))
            .expect("query")
            .filter_map(|r| r.ok())
            .collect();
        assert!(
            tables.contains(&"ldap_config".to_string()),
            "ldap_config table must exist after init"
        );

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM ldap_config", [], |r| r.get(0))
            .expect("count ldap_config rows");
        assert_eq!(count, 1, "ldap_config must have exactly one seed row");

        let (ldap_url, base_dn, require_tls, cache_ttl_secs): (String, String, i64, i64) = conn
            .query_row(
                "SELECT ldap_url, base_dn, require_tls, cache_ttl_secs \
                 FROM ldap_config WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .expect("read seed row");
        assert_eq!(ldap_url, "ldaps://dc.corp.internal:636", "default ldap_url");
        assert_eq!(require_tls, 1, "require_tls default must be 1");
        assert_eq!(cache_ttl_secs, 300, "cache_ttl_secs default must be 300");
        assert_eq!(base_dn, "", "default base_dn must be empty string");
    }

    #[test]
    fn test_device_registry_table_exists() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='device_registry'",
                [],
                |r| r.get(0),
            )
            .expect("query sqlite_master");
        assert_eq!(count, 1, "device_registry table must exist after init");
    }

    #[test]
    fn test_device_registry_columns() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(device_registry)")
            .expect("prepare pragma")
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query pragma")
            .filter_map(Result::ok)
            .collect();

        for col in &[
            "id",
            "vid",
            "pid",
            "serial",
            "owner_sid",
            "owner_user",
            "description",
            "trust_tier",
            "created_at",
        ] {
            assert!(
                columns.contains(&col.to_string()),
                "device_registry must have column '{col}'; found {columns:?}"
            );
        }
    }

    #[test]
    fn test_device_registry_check_constraint() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        // 'bad_tier' is not in ('blocked', 'read_only', 'full_access') — must fail.
        let result = conn.execute(
            "INSERT INTO device_registry (id, vid, pid, serial, description, trust_tier, created_at) \
             VALUES ('id1', 'v', 'p', 's', '', 'bad_tier', '2026-01-01')",
            [],
        );
        assert!(
            result.is_err(),
            "invalid trust_tier must be rejected by CHECK constraint"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("CHECK constraint failed"),
            "error must mention CHECK constraint; got: {err_msg}"
        );
    }

    #[test]
    fn test_device_registry_unique_constraint() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        conn.execute(
            "INSERT INTO device_registry (id, vid, pid, serial, description, trust_tier, created_at) \
             VALUES ('id1', '0951', '1666', 'SN001', '', 'blocked', '2026-01-01')",
            [],
        )
        .expect("first insert must succeed");

        let result = conn.execute(
            "INSERT INTO device_registry (id, vid, pid, serial, owner_sid, owner_user, description, trust_tier, created_at) \
             VALUES ('id2', '0951', '1666', 'SN001', NULL, NULL, '', 'read_only', '2026-01-02')",
            [],
        );
        assert!(
            result.is_err(),
            "duplicate (vid, pid, serial) with NULL owner_sid must fail UNIQUE constraint"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("UNIQUE constraint failed"),
            "error must mention UNIQUE constraint; got: {err_msg}"
        );
    }

    #[test]
    fn test_device_registry_per_user_unique_constraint() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        // Machine-wide entry (NULL owner_sid) succeeds.
        conn.execute(
            "INSERT INTO device_registry (id, vid, pid, serial, owner_sid, owner_user, description, trust_tier, created_at) \
             VALUES ('id1', '0951', '1666', 'SN001', NULL, NULL, '', 'blocked', '2026-01-01')",
            [],
        )
        .expect("machine-wide insert must succeed");

        // Per-user entry for same device with different SID succeeds (different UNIQUE key).
        conn.execute(
            "INSERT INTO device_registry (id, vid, pid, serial, owner_sid, owner_user, description, trust_tier, created_at) \
             VALUES ('id2', '0951', '1666', 'SN001', 'S-1-5-21-1', 'alice', '', 'read_only', '2026-01-02')",
            [],
        )
        .expect("per-user insert with different SID must succeed");

        // Duplicate per-user SID for same device fails.
        let result = conn.execute(
            "INSERT INTO device_registry (id, vid, pid, serial, owner_sid, owner_user, description, trust_tier, created_at) \
             VALUES ('id3', '0951', '1666', 'SN001', 'S-1-5-21-1', 'alice2', '', 'full_access', '2026-01-03')",
            [],
        );
        assert!(
            result.is_err(),
            "duplicate (vid, pid, serial, owner_sid) must fail UNIQUE constraint"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("UNIQUE constraint failed"),
            "error must mention UNIQUE constraint; got: {err_msg}"
        );

        // Different SID for same device succeeds.
        conn.execute(
            "INSERT INTO device_registry (id, vid, pid, serial, owner_sid, owner_user, description, trust_tier, created_at) \
             VALUES ('id4', '0951', '1666', 'SN001', 'S-1-5-21-2', 'bob', '', 'full_access', '2026-01-04')",
            [],
        )
        .expect("per-user insert with different SID must succeed");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM device_registry", [], |r| r.get(0))
            .expect("count rows");
        assert_eq!(count, 3, "expected 3 rows: 1 machine-wide + 2 per-user");
    }

    #[test]
    fn test_migration_add_mode_column() {
        // Simulates the v0.4.0 → v0.5.0 upgrade path: an existing DB without
        // the `mode` column gets it added by `run_migrations` (called inside
        // `new_pool`), and pre-existing rows pick up the SQL DEFAULT 'ALL'.
        // Idempotency: re-running run_migrations is a no-op.
        let tmp = tempfile::NamedTempFile::new().expect("create temp db file");
        let path = tmp.path().to_str().expect("temp path utf8");

        // Step 1: stand up the v0.4.0 schema directly (no `mode` column) and
        // seed one row.
        {
            let conn = rusqlite::Connection::open(path).expect("open temp db");
            conn.execute_batch(
                "CREATE TABLE policies (
                    id          TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    description TEXT,
                    priority    INTEGER NOT NULL,
                    conditions  TEXT NOT NULL,
                    action      TEXT NOT NULL,
                    enabled     INTEGER NOT NULL DEFAULT 1,
                    version     INTEGER NOT NULL DEFAULT 1,
                    updated_at  TEXT NOT NULL
                );
                INSERT INTO policies
                    (id, name, priority, conditions, action, enabled, version, updated_at)
                VALUES
                    ('existing-policy', 'existing', 1, '[]', 'Allow', 1, 1, '2026-01-01T00:00:00Z');",
            )
            .expect("create v0.4.0 schema");
        }

        // Step 2: open via new_pool — triggers init_tables (no-op, IF NOT EXISTS)
        // followed by run_migrations (adds the column).
        let pool = new_pool(path).expect("open pool with migrations");
        let conn = pool.get().expect("acquire connection");

        // Step 3: confirm the `mode` column now exists.
        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(policies)")
            .expect("prepare pragma")
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query pragma")
            .filter_map(Result::ok)
            .collect();
        assert!(
            columns.contains(&"mode".to_string()),
            "mode column must exist after migration; saw {columns:?}"
        );

        // Step 4: pre-existing row picks up SQL DEFAULT 'ALL'.
        let mode: String = conn
            .query_row(
                "SELECT mode FROM policies WHERE id = 'existing-policy'",
                [],
                |r| r.get(0),
            )
            .expect("read mode column from pre-existing row");
        assert_eq!(mode, "ALL", "pre-existing rows must default to 'ALL' mode");

        // Step 5: idempotency — re-running migrations must not error.
        run_migrations(&conn).expect("second run must not error");

        let mode2: String = conn
            .query_row(
                "SELECT mode FROM policies WHERE id = 'existing-policy'",
                [],
                |r| r.get(0),
            )
            .expect("re-read mode column");
        assert_eq!(mode2, "ALL", "mode must persist after re-run");
    }

    #[test]
    fn test_disk_registry_table_exists() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='disk_registry'",
                [],
                |r| r.get(0),
            )
            .expect("query sqlite_master");
        assert_eq!(count, 1, "disk_registry table must exist after init");
    }

    #[test]
    fn test_disk_registry_columns() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(disk_registry)")
            .expect("prepare pragma")
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query pragma")
            .filter_map(Result::ok)
            .collect();

        for col in &[
            "id",
            "agent_id",
            "instance_id",
            "bus_type",
            "encryption_status",
            "model",
            "registered_at",
        ] {
            assert!(
                columns.contains(&col.to_string()),
                "disk_registry must have column '{col}'; found {columns:?}"
            );
        }
    }

    #[test]
    fn test_disk_registry_check_constraint() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        // 'bad_value' is not in the allowed set — must fail the CHECK constraint.
        let result = conn.execute(
            "INSERT INTO disk_registry \
             (id, agent_id, instance_id, bus_type, encryption_status, model, registered_at) \
             VALUES ('id1', 'agent-A', 'disk-1', 'usb', 'bad_value', '', '2026-01-01T00:00:00Z')",
            [],
        );
        assert!(
            result.is_err(),
            "invalid encryption_status must be rejected by CHECK constraint"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("CHECK constraint failed"),
            "error must mention CHECK constraint; got: {err_msg}"
        );
    }

    #[test]
    fn test_disk_registry_unique_constraint() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        conn.execute(
            "INSERT INTO disk_registry \
             (id, agent_id, instance_id, bus_type, encryption_status, model, registered_at) \
             VALUES ('id1', 'agent-A', 'disk-1', 'usb', 'unencrypted', '', '2026-01-01T00:00:00Z')",
            [],
        )
        .expect("first insert must succeed");

        let result = conn.execute(
            "INSERT INTO disk_registry \
             (id, agent_id, instance_id, bus_type, encryption_status, model, registered_at) \
             VALUES ('id2', 'agent-A', 'disk-1', 'usb', 'encrypted', '', '2026-01-02T00:00:00Z')",
            [],
        );
        assert!(
            result.is_err(),
            "duplicate (agent_id, instance_id) must fail UNIQUE constraint"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("UNIQUE constraint failed"),
            "error must mention UNIQUE constraint; got: {err_msg}"
        );
    }

    #[test]
    fn test_disk_registry_accepts_all_four_statuses() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        // Each of the four allowed encryption_status values (canonical serde names) must succeed.
        for (i, status) in ["encrypted", "suspended", "unencrypted", "unknown"]
            .iter()
            .enumerate()
        {
            conn.execute(
                "INSERT INTO disk_registry \
                 (id, agent_id, instance_id, bus_type, encryption_status, model, registered_at) \
                 VALUES (?1, 'agent-A', ?2, 'usb', ?3, '', '2026-01-01T00:00:00Z')",
                rusqlite::params![format!("id{i}"), format!("disk-{i}"), status,],
            )
            .unwrap_or_else(|e| {
                panic!("INSERT with encryption_status='{status}' must succeed; got: {e}");
            });
        }

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM disk_registry", [], |r| r.get(0))
            .expect("count rows");
        assert_eq!(
            count, 4,
            "all four valid statuses must insert without error"
        );
    }

    #[test]
    fn test_global_agent_config_usb_columns() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        // Verify columns exist in global_agent_config.
        let global_cols: Vec<String> = conn
            .prepare("PRAGMA table_info(global_agent_config)")
            .expect("prepare pragma")
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query pragma")
            .filter_map(Result::ok)
            .collect();
        for col in &[
            "usb_blocked_failure_mode",
            "usb_startup_resolution_mode",
            "usb_none_serial_policy",
        ] {
            assert!(
                global_cols.contains(&col.to_string()),
                "global_agent_config must have column '{col}'; found {global_cols:?}"
            );
        }

        // Verify columns exist in agent_config_overrides.
        let override_cols: Vec<String> = conn
            .prepare("PRAGMA table_info(agent_config_overrides)")
            .expect("prepare pragma")
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query pragma")
            .filter_map(Result::ok)
            .collect();
        for col in &[
            "usb_blocked_failure_mode",
            "usb_startup_resolution_mode",
            "usb_none_serial_policy",
        ] {
            assert!(
                override_cols.contains(&col.to_string()),
                "agent_config_overrides must have column '{col}'; found {override_cols:?}"
            );
        }

        // Verify seed row defaults in global_agent_config.
        let (failure_mode, resolution_mode, none_policy): (String, String, String) = conn
            .query_row(
                "SELECT usb_blocked_failure_mode, usb_startup_resolution_mode, \
                 usb_none_serial_policy \
                 FROM global_agent_config WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("seed row must exist");
        assert_eq!(failure_mode, "Warning only");
        assert_eq!(resolution_mode, "VID/PID/serial fallback");
        assert_eq!(none_policy, "Always Blocked");
    }

    /// Phase 47 Task 47-03: simulates the pre-Phase-47 -> Phase-47 upgrade for
    /// every encrypted-column trio added by `run_migrations`. Models this on
    /// `test_migration_add_mode_column` (lines 751-822):
    ///
    /// 1. Stand up a pre-Phase-47 schema containing the four cleartext-secret
    ///    tables WITHOUT any encrypted columns. Seed one row per single-row
    ///    config table so the pre-existing data is observable post-migration.
    /// 2. Open via `new_pool` -- triggers `init_tables` (creates the new
    ///    `secrets_jwt` table) followed by `run_migrations` (adds the
    ///    encrypted column trios + ldap bind_dn).
    /// 3. Assert each new column exists via `PRAGMA table_info`.
    /// 4. Verify the pre-existing cleartext rows still read correctly --
    ///    migrations are additive in Task 47-03 (the destructive cleartext
    ///    drop happens in Task 47-06).
    /// 5. Re-run `run_migrations` directly to prove duplicate-column-error
    ///    swallowing renders the migration idempotent.
    #[test]
    fn test_migration_add_secret_encrypted_columns() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db file");
        let path = tmp.path().to_str().expect("temp path utf8");

        // Step 1: stand up the pre-Phase-47 schema directly. These DDLs
        // mirror the cleartext-only column layout as of Phase 46.
        {
            let conn = rusqlite::Connection::open(path).expect("open temp db");
            conn.execute_batch(
                "CREATE TABLE alert_router_config (
                    id              INTEGER PRIMARY KEY CHECK (id = 1),
                    smtp_host       TEXT NOT NULL DEFAULT '',
                    smtp_port       INTEGER NOT NULL DEFAULT 587,
                    smtp_username   TEXT NOT NULL DEFAULT '',
                    smtp_password   TEXT NOT NULL DEFAULT '',
                    smtp_from       TEXT NOT NULL DEFAULT '',
                    smtp_to         TEXT NOT NULL DEFAULT '',
                    smtp_enabled    INTEGER NOT NULL DEFAULT 0,
                    webhook_url     TEXT NOT NULL DEFAULT '',
                    webhook_secret  TEXT NOT NULL DEFAULT '',
                    webhook_enabled INTEGER NOT NULL DEFAULT 0,
                    updated_at      TEXT NOT NULL DEFAULT ''
                );
                INSERT INTO alert_router_config
                    (id, smtp_password, webhook_secret)
                VALUES (1, 'legacy-smtp-pwd', 'legacy-webhook-secret');

                CREATE TABLE siem_config (
                    id              INTEGER PRIMARY KEY CHECK (id = 1),
                    splunk_url      TEXT NOT NULL DEFAULT '',
                    splunk_token    TEXT NOT NULL DEFAULT '',
                    splunk_enabled  INTEGER NOT NULL DEFAULT 0,
                    elk_url         TEXT NOT NULL DEFAULT '',
                    elk_index       TEXT NOT NULL DEFAULT '',
                    elk_api_key     TEXT NOT NULL DEFAULT '',
                    elk_enabled     INTEGER NOT NULL DEFAULT 0,
                    updated_at      TEXT NOT NULL DEFAULT ''
                );
                INSERT INTO siem_config
                    (id, splunk_token, elk_api_key)
                VALUES (1, 'legacy-splunk-token', 'legacy-elk-key');

                CREATE TABLE ldap_config (
                    id              INTEGER PRIMARY KEY CHECK (id = 1),
                    ldap_url        TEXT NOT NULL DEFAULT 'ldaps://dc.corp.internal:636',
                    base_dn         TEXT NOT NULL DEFAULT '',
                    require_tls     INTEGER NOT NULL DEFAULT 1,
                    cache_ttl_secs  INTEGER NOT NULL DEFAULT 300,
                    vpn_subnets     TEXT NOT NULL DEFAULT '',
                    updated_at      TEXT NOT NULL DEFAULT ''
                );
                INSERT INTO ldap_config (id) VALUES (1);",
            )
            .expect("create pre-Phase-47 schema");
        }

        // Step 2: opening via new_pool runs init_tables + run_migrations.
        let pool = new_pool(path).expect("open pool with migrations");
        let conn = pool.get().expect("acquire connection");

        // Step 3: assert every new column landed.
        //
        // Helper: returns the set of column names for a table.
        fn cols(c: &rusqlite::Connection, table: &str) -> Vec<String> {
            c.prepare(&format!("PRAGMA table_info({table})"))
                .expect("prepare pragma")
                .query_map([], |row| row.get::<_, String>(1))
                .expect("query pragma")
                .filter_map(Result::ok)
                .collect()
        }

        let alert_cols = cols(&conn, "alert_router_config");
        for col in &[
            "smtp_password_encrypted",
            "smtp_password_nonce",
            "smtp_password_version",
            "webhook_secret_encrypted",
            "webhook_secret_nonce",
            "webhook_secret_version",
        ] {
            assert!(
                alert_cols.contains(&col.to_string()),
                "alert_router_config must have column '{col}'; found {alert_cols:?}"
            );
        }

        let siem_cols = cols(&conn, "siem_config");
        for col in &[
            "splunk_token_encrypted",
            "splunk_token_nonce",
            "splunk_token_version",
            "elk_api_key_encrypted",
            "elk_api_key_nonce",
            "elk_api_key_version",
        ] {
            assert!(
                siem_cols.contains(&col.to_string()),
                "siem_config must have column '{col}'; found {siem_cols:?}"
            );
        }

        let ldap_cols = cols(&conn, "ldap_config");
        for col in &[
            "bind_dn",
            "bind_password_encrypted",
            "bind_password_nonce",
            "bind_password_version",
        ] {
            assert!(
                ldap_cols.contains(&col.to_string()),
                "ldap_config must have column '{col}'; found {ldap_cols:?}"
            );
        }

        // The new secrets_jwt table also exists (created by init_tables, not
        // by an ALTER -- the table is brand new in Phase 47).
        let jwt_table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type='table' AND name='secrets_jwt'",
                [],
                |r| r.get(0),
            )
            .expect("count secrets_jwt");
        assert_eq!(
            jwt_table_count, 1,
            "secrets_jwt table must exist after Phase 47 migration"
        );

        // Step 4: pre-existing cleartext rows survived the additive migration.
        // The migration window keeps cleartext alongside the empty new columns
        // until Task 47-06 performs the destructive drop.
        let (legacy_smtp, legacy_webhook): (String, String) = conn
            .query_row(
                "SELECT smtp_password, webhook_secret FROM alert_router_config WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("read alert_router_config row");
        assert_eq!(legacy_smtp, "legacy-smtp-pwd");
        assert_eq!(legacy_webhook, "legacy-webhook-secret");

        let (legacy_splunk, legacy_elk): (String, String) = conn
            .query_row(
                "SELECT splunk_token, elk_api_key FROM siem_config WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("read siem_config row");
        assert_eq!(legacy_splunk, "legacy-splunk-token");
        assert_eq!(legacy_elk, "legacy-elk-key");

        // The newly-added BLOB / INTEGER columns are NULL for pre-existing
        // rows (no DEFAULT was applied -- ALTER TABLE ... ADD COLUMN <BLOB>
        // leaves existing rows with NULL).
        let smtp_enc: Option<Vec<u8>> = conn
            .query_row(
                "SELECT smtp_password_encrypted FROM alert_router_config WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .expect("read smtp_password_encrypted");
        assert!(
            smtp_enc.is_none(),
            "newly-added encrypted column must be NULL for pre-existing row"
        );

        // Step 5: idempotency -- re-running migrations must be a no-op.
        run_migrations(&conn).expect("second run must not error");
        run_migrations(&conn).expect("third run must not error either");

        // Data is still intact after the redundant migration passes.
        let still_smtp: String = conn
            .query_row(
                "SELECT smtp_password FROM alert_router_config WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .expect("re-read smtp_password");
        assert_eq!(still_smtp, "legacy-smtp-pwd");
    }

    // Phase 62 Task 1: syslog_config and syslog_queue table tests.

    #[test]
    fn test_syslog_config_table_exists() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='syslog_config'",
                [],
                |r| r.get(0),
            )
            .expect("query sqlite_master");
        assert_eq!(count, 1, "syslog_config table must exist after init");
    }

    #[test]
    fn test_syslog_queue_table_exists() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='syslog_queue'",
                [],
                |r| r.get(0),
            )
            .expect("query sqlite_master");
        assert_eq!(count, 1, "syslog_queue table must exist after init");
    }

    #[test]
    fn test_syslog_config_seed_row() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM syslog_config", [], |r| r.get(0))
            .expect("count syslog_config rows");
        assert_eq!(count, 1, "syslog_config must have exactly one seed row");

        let (
            host,
            port,
            enabled,
            protocol,
            facility_code,
            format,
            batching_enabled,
            severity_alert,
            severity_block,
            severity_audit,
            queue_policy,
            queue_max_size,
            tls_min_version,
        ): (
            String,
            i64,
            i64,
            String,
            i64,
            String,
            i64,
            i64,
            i64,
            i64,
            String,
            i64,
            String,
        ) = conn
            .query_row(
                "SELECT host, port, enabled, protocol, facility_code, format, \
                 batching_enabled, severity_alert, severity_block, severity_audit, \
                 queue_policy, queue_max_size, tls_min_version \
                 FROM syslog_config WHERE id = 1",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                        r.get(10)?,
                        r.get(11)?,
                        r.get(12)?,
                    ))
                },
            )
            .expect("read seed row");

        assert_eq!(host, "", "default host must be empty");
        assert_eq!(port, 514, "default port must be 514");
        assert_eq!(enabled, 0, "default enabled must be 0 (disabled)");
        assert_eq!(protocol, "tls", "default protocol must be tls");
        assert_eq!(
            facility_code, 20,
            "default facility_code must be 20 (LOCAL4)"
        );
        assert_eq!(format, "json", "default format must be json");
        assert_eq!(batching_enabled, 1, "default batching_enabled must be 1");
        assert_eq!(
            severity_alert, 3,
            "default severity_alert must be 3 (ERROR)"
        );
        assert_eq!(
            severity_block, 4,
            "default severity_block must be 4 (WARNING)"
        );
        assert_eq!(severity_audit, 6, "default severity_audit must be 6 (INFO)");
        assert_eq!(
            queue_policy, "fifo_tail_drop",
            "default queue_policy must be fifo_tail_drop"
        );
        assert_eq!(
            queue_max_size, 100000,
            "default queue_max_size must be 100000"
        );
        assert_eq!(
            tls_min_version, "1.2",
            "default tls_min_version must be 1.2"
        );
    }

    #[test]
    fn test_syslog_queue_columns() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(syslog_queue)")
            .expect("prepare pragma")
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query pragma")
            .filter_map(Result::ok)
            .collect();

        for col in &[
            "id",
            "event_json_encrypted",
            "event_json_nonce",
            "created_at",
            "retry_count",
            "last_error",
            "next_attempt_at",
            "leased_until",
        ] {
            assert!(
                columns.contains(&col.to_string()),
                "syslog_queue must have column '{col}'; found {columns:?}"
            );
        }
    }

    #[test]
    fn test_syslog_queue_indexes_exist() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let indexes: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='syslog_queue'",
            )
            .expect("prepare")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query")
            .filter_map(Result::ok)
            .collect();

        assert!(
            indexes.contains(&"idx_syslog_queue_created_at".to_string()),
            "idx_syslog_queue_created_at must exist; found {indexes:?}"
        );
        assert!(
            indexes.contains(&"idx_syslog_queue_next_attempt_at".to_string()),
            "idx_syslog_queue_next_attempt_at must exist; found {indexes:?}"
        );
        assert!(
            indexes.contains(&"idx_syslog_queue_leased_until".to_string()),
            "idx_syslog_queue_leased_until must exist; found {indexes:?}"
        );
    }

    #[test]
    fn test_syslog_queue_accepts_insert() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        conn.execute(
            "INSERT INTO syslog_queue (event_json_encrypted, event_json_nonce, created_at) \
             VALUES (?1, ?2, ?3)",
            rusqlite::params![vec![0u8; 32], vec![0u8; 12], 1716268800i64,],
        )
        .expect("insert into syslog_queue must succeed");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM syslog_queue", [], |r| r.get(0))
            .expect("count rows");
        assert_eq!(count, 1, "syslog_queue must have one row after insert");

        let (retry_count, last_error, next_attempt_at): (i64, String, String) = conn
            .query_row(
                "SELECT retry_count, last_error, next_attempt_at FROM syslog_queue WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("read defaults");
        assert_eq!(retry_count, 0, "default retry_count must be 0");
        assert_eq!(last_error, "", "default last_error must be empty");
        assert_eq!(next_attempt_at, "", "default next_attempt_at must be empty");
    }

    // Phase 53: bypass_alerts table schema validation tests.

    #[test]
    fn test_bypass_alerts_table_exists() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='bypass_alerts'",
                [],
                |r| r.get(0),
            )
            .expect("query sqlite_master");
        assert_eq!(count, 1, "bypass_alerts table must exist after init");
    }

    #[test]
    fn test_bypass_alerts_indexes_exist() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let indexes: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='bypass_alerts'",
            )
            .expect("prepare")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query")
            .filter_map(Result::ok)
            .collect();

        let expected = [
            "idx_bypass_alerts_agent",
            "idx_bypass_alerts_severity",
            "idx_bypass_alerts_created_at",
            "idx_bypass_alerts_ack",
            "idx_bypass_alerts_pid",
            "idx_bypass_alerts_dedup",
        ];
        for idx in &expected {
            assert!(
                indexes.contains(&idx.to_string()),
                "index '{idx}' must exist on bypass_alerts table; found {indexes:?}"
            );
        }
    }

    #[test]
    fn test_bypass_alerts_dedup_unique_constraint() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        conn.execute(
            "INSERT INTO bypass_alerts \
             (agent_id, pid, image_path, file_path, operation, qpc_timestamp, created_at, severity, correlation_reason) \
             VALUES ('agent-1', 1234, 'C:\\app.exe', 'C:\\file.txt', 'Create', 1000, '2026-01-01T00:00:00Z', 'crit', 'no_hook_journal')",
            [],
        )
        .expect("first insert must succeed");

        let result = conn.execute(
            "INSERT INTO bypass_alerts \
             (agent_id, pid, image_path, file_path, operation, qpc_timestamp, created_at, severity, correlation_reason) \
             VALUES ('agent-1', 1234, 'C:\\app.exe', 'C:\\file.txt', 'Create', 1000, '2026-01-01T00:00:00Z', 'crit', 'no_hook_journal')",
            [],
        );
        assert!(
            result.is_err(),
            "duplicate (agent_id, pid, qpc_timestamp, file_path) must fail UNIQUE constraint"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("UNIQUE constraint failed"),
            "error must mention UNIQUE constraint; got: {err_msg}"
        );
    }

    #[test]
    fn test_bypass_alerts_severity_check_constraint() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let result = conn.execute(
            "INSERT INTO bypass_alerts \
             (agent_id, pid, image_path, file_path, operation, qpc_timestamp, created_at, severity, correlation_reason) \
             VALUES ('agent-1', 1234, 'C:\\app.exe', 'C:\\file.txt', 'Create', 1000, '2026-01-01T00:00:00Z', 'invalid', 'no_hook_journal')",
            [],
        );
        assert!(
            result.is_err(),
            "invalid severity must fail CHECK constraint"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("CHECK constraint failed"),
            "error must mention CHECK constraint; got: {err_msg}"
        );
    }

    #[test]
    fn test_bypass_alerts_correlation_reason_check_constraint() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        let result = conn.execute(
            "INSERT INTO bypass_alerts \
             (agent_id, pid, image_path, file_path, operation, qpc_timestamp, created_at, severity, correlation_reason) \
             VALUES ('agent-1', 1234, 'C:\\app.exe', 'C:\\file.txt', 'Create', 1000, '2026-01-01T00:00:00Z', 'crit', 'invalid_reason')",
            [],
        );
        assert!(
            result.is_err(),
            "invalid correlation_reason must fail CHECK constraint"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("CHECK constraint failed"),
            "error must mention CHECK constraint; got: {err_msg}"
        );
    }

    #[test]
    fn test_bypass_alerts_file_object_default() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        conn.execute(
            "INSERT INTO bypass_alerts \
             (agent_id, pid, image_path, file_path, operation, qpc_timestamp, created_at, severity, correlation_reason) \
             VALUES ('agent-1', 1234, 'C:\\app.exe', 'C:\\file.txt', 'Create', 1000, '2026-01-01T00:00:00Z', 'crit', 'no_hook_journal')",
            [],
        )
        .expect("insert must succeed");

        let file_object: i64 = conn
            .query_row(
                "SELECT file_object FROM bypass_alerts WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .expect("query file_object");
        assert_eq!(
            file_object, 0,
            "file_object must default to 0 when not provided"
        );
    }

    #[test]
    fn test_bypass_alerts_ack_foreign_key() {
        let pool = new_pool(":memory:").expect("create pool");
        let conn = pool.get().expect("acquire connection");

        // Insert an admin user so the FK can resolve.
        conn.execute(
            "INSERT INTO admin_users (username, password_hash, created_at) \
             VALUES ('admin-1', 'hash', '2026-01-01T00:00:00Z')",
            [],
        )
        .expect("insert admin user");

        conn.execute(
            "INSERT INTO bypass_alerts \
             (agent_id, pid, image_path, file_path, operation, qpc_timestamp, created_at, severity, correlation_reason) \
             VALUES ('agent-1', 1234, 'C:\\app.exe', 'C:\\file.txt', 'Create', 1000, '2026-01-01T00:00:00Z', 'crit', 'no_hook_journal')",
            [],
        )
        .expect("insert bypass alert");

        // Update ack_by to a valid admin user.
        conn.execute(
            "UPDATE bypass_alerts SET ack_by = 'admin-1', ack_at = '2026-01-02T00:00:00Z' WHERE id = 1",
            [],
        )
        .expect("ack with valid admin must succeed");

        // Update ack_by to an invalid admin user must fail FK.
        let result = conn.execute(
            "UPDATE bypass_alerts SET ack_by = 'nonexistent-admin' WHERE id = 1",
            [],
        );
        assert!(
            result.is_err(),
            "ack_by referencing nonexistent admin must fail FK constraint"
        );
    }
}
