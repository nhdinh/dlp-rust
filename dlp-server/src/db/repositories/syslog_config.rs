//! Repository for the `syslog_config` table.
//!
//! Single-row configuration table (enforced via `CHECK (id = 1)`).
//! Provides typed access to syslog forwarding settings for RFC 5424
//! over TLS transport.
//!
//! Unlike `siem_config`, this repository has no encrypted secrets --
//! syslog configuration uses the system CA store only (no custom CA or
//! mTLS per D-10/D-11). The `crypto` parameter is kept for API
//! consistency with `SiemConfigRepository`.

use rusqlite::params;

use crate::crypto::SecretCrypto;
use crate::db::{Pool, UnitOfWork};
use crate::AppError;

/// Plain data row for the syslog configuration.
///
/// All fields are plain String/i64; no encryption helpers needed for
/// this repository since there are no secrets in syslog config.
#[derive(Debug, Clone)]
pub struct SyslogConfigRow {
    /// Syslog collector hostname or IP address.
    pub host: String,
    /// Syslog collector port (default 514 for TLS).
    pub port: i64,
    /// Whether syslog forwarding is enabled (0 = disabled, 1 = enabled).
    pub enabled: i64,
    /// Transport protocol -- 'tls' only in Phase 62.
    pub protocol: String,
    /// RFC 5424 facility code (16-23 for LOCAL0-LOCAL7, default 20 = LOCAL4).
    pub facility_code: i64,
    /// Message format -- 'json' for JSON-in-MSG (D-01).
    pub format: String,
    /// Whether batched newline-delimited JSON is enabled (D-05).
    pub batching_enabled: i64,
    /// Severity for Alert events (default 3 = ERROR per D-03).
    pub severity_alert: i64,
    /// Severity for Block events (default 4 = WARNING per D-03).
    pub severity_block: i64,
    /// Severity for all other audit events (default 6 = INFO per D-03).
    pub severity_audit: i64,
    /// Queue eviction policy -- 'fifo_tail_drop', 'fifo_head_drop', 'ring_buffer'.
    pub queue_policy: String,
    /// Maximum queue size (default 100,000 server-side per D-09).
    pub queue_max_size: i64,
    /// Minimum TLS version -- '1.2' or '1.3' (D-11).
    pub tls_min_version: String,
    /// ISO-8601 timestamp of last configuration update.
    pub updated_at: String,
}

/// Stateless repository for the `syslog_config` table.
pub struct SyslogConfigRepository;

impl SyslogConfigRepository {
    /// Reads the syslog config row from the database.
    ///
    /// # Arguments
    ///
    /// * `pool` -- connection pool (read).
    /// * `crypto` -- active KEK handle (unused in Phase 62, kept for API consistency).
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Database`] when the underlying SELECT fails.
    pub fn get(pool: &Pool, _crypto: &SecretCrypto) -> Result<SyslogConfigRow, AppError> {
        let conn = pool.get().map_err(AppError::from)?;
        conn.query_row(
            "SELECT host, port, enabled, protocol, facility_code, format, \
             batching_enabled, severity_alert, severity_block, severity_audit, \
             queue_policy, queue_max_size, tls_min_version, updated_at \
             FROM syslog_config WHERE id = 1",
            [],
            |row| {
                Ok(SyslogConfigRow {
                    host: row.get(0)?,
                    port: row.get(1)?,
                    enabled: row.get(2)?,
                    protocol: row.get(3)?,
                    facility_code: row.get(4)?,
                    format: row.get(5)?,
                    batching_enabled: row.get(6)?,
                    severity_alert: row.get(7)?,
                    severity_block: row.get(8)?,
                    severity_audit: row.get(9)?,
                    queue_policy: row.get(10)?,
                    queue_max_size: row.get(11)?,
                    tls_min_version: row.get(12)?,
                    updated_at: row.get(13)?,
                })
            },
        )
        .map_err(AppError::Database)
    }

    /// Writes the full syslog config row.
    ///
    /// All columns are updated in a single UPDATE so the change is
    /// atomic with respect to readers.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Database`] if the UPDATE fails.
    pub fn update(
        uow: &UnitOfWork<'_>,
        record: &SyslogConfigRow,
        _crypto: &SecretCrypto,
    ) -> Result<(), AppError> {
        uow.tx
            .execute(
                "UPDATE syslog_config SET \
                 host = ?1, port = ?2, enabled = ?3, protocol = ?4, \
                 facility_code = ?5, format = ?6, batching_enabled = ?7, \
                 severity_alert = ?8, severity_block = ?9, severity_audit = ?10, \
                 queue_policy = ?11, queue_max_size = ?12, tls_min_version = ?13, \
                 updated_at = ?14 \
                 WHERE id = 1",
                params![
                    record.host,
                    record.port,
                    record.enabled,
                    record.protocol,
                    record.facility_code,
                    record.format,
                    record.batching_enabled,
                    record.severity_alert,
                    record.severity_block,
                    record.severity_audit,
                    record.queue_policy,
                    record.queue_max_size,
                    record.tls_min_version,
                    record.updated_at,
                ],
            )
            .map_err(AppError::Database)?;
        Ok(())
    }
}

/// Validates that a facility code is in the RFC 5424 LOCAL0-LOCAL7 range.
///
/// # Errors
///
/// Returns [`AppError::UnprocessableEntity`] if `v` is outside 16-23.
pub fn validate_facility_code(v: i64) -> Result<(), AppError> {
    if (16..=23).contains(&v) {
        Ok(())
    } else {
        Err(AppError::UnprocessableEntity(format!(
            "facility_code must be between 16 (LOCAL0) and 23 (LOCAL7), got {v}"
        )))
    }
}

/// Validates that a severity value is in the RFC 5424 valid range.
///
/// # Errors
///
/// Returns [`AppError::UnprocessableEntity`] if `v` is outside 0-7.
pub fn validate_severity(v: i64) -> Result<(), AppError> {
    if (0..=7).contains(&v) {
        Ok(())
    } else {
        Err(AppError::UnprocessableEntity(format!(
            "severity must be between 0 (EMERGENCY) and 7 (DEBUG), got {v}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{SecretCrypto, ENVELOPE_VERSION_V1};
    use crate::db::new_pool;
    use crate::db::UnitOfWork;

    const TEST_KEK: [u8; 32] = [
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42,
    ];

    fn fixture_crypto() -> SecretCrypto {
        SecretCrypto::from_kek(TEST_KEK, ENVELOPE_VERSION_V1)
    }

    fn fixture_row() -> SyslogConfigRow {
        SyslogConfigRow {
            host: "syslog.example.com".to_string(),
            port: 6514,
            enabled: 1,
            protocol: "tls".to_string(),
            facility_code: 20,
            format: "json".to_string(),
            batching_enabled: 1,
            severity_alert: 3,
            severity_block: 4,
            severity_audit: 6,
            queue_policy: "fifo_tail_drop".to_string(),
            queue_max_size: 100000,
            tls_min_version: "1.2".to_string(),
            updated_at: "2026-05-14T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn get_returns_defaults_from_seed_row() {
        let crypto = fixture_crypto();
        let pool = new_pool(":memory:").expect("create pool");

        let got = SyslogConfigRepository::get(&pool, &crypto).expect("get defaults");
        assert_eq!(got.host, "");
        assert_eq!(got.port, 514);
        assert_eq!(got.enabled, 0);
        assert_eq!(got.protocol, "tls");
        assert_eq!(got.facility_code, 20);
        assert_eq!(got.format, "json");
        assert_eq!(got.batching_enabled, 1);
        assert_eq!(got.severity_alert, 3);
        assert_eq!(got.severity_block, 4);
        assert_eq!(got.severity_audit, 6);
        assert_eq!(got.queue_policy, "fifo_tail_drop");
        assert_eq!(got.queue_max_size, 100000);
        assert_eq!(got.tls_min_version, "1.2");
    }

    #[test]
    fn update_then_get_round_trips_all_fields() {
        let crypto = fixture_crypto();
        let pool = new_pool(":memory:").expect("create pool");

        let original = fixture_row();
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SyslogConfigRepository::update(&uow, &original, &crypto).expect("update");
            uow.commit().expect("commit");
        }

        let got = SyslogConfigRepository::get(&pool, &crypto).expect("get after update");
        assert_eq!(got.host, original.host);
        assert_eq!(got.port, original.port);
        assert_eq!(got.enabled, original.enabled);
        assert_eq!(got.protocol, original.protocol);
        assert_eq!(got.facility_code, original.facility_code);
        assert_eq!(got.format, original.format);
        assert_eq!(got.batching_enabled, original.batching_enabled);
        assert_eq!(got.severity_alert, original.severity_alert);
        assert_eq!(got.severity_block, original.severity_block);
        assert_eq!(got.severity_audit, original.severity_audit);
        assert_eq!(got.queue_policy, original.queue_policy);
        assert_eq!(got.queue_max_size, original.queue_max_size);
        assert_eq!(got.tls_min_version, original.tls_min_version);
        assert_eq!(got.updated_at, original.updated_at);
    }

    #[test]
    fn validate_facility_code_accepts_valid_range() {
        for v in 16..=23 {
            validate_facility_code(v).expect("{v} must be valid");
        }
    }

    #[test]
    fn validate_facility_code_rejects_out_of_range() {
        let err = validate_facility_code(15).expect_err("15 must be rejected");
        assert!(err.to_string().contains("facility_code"));
        let err = validate_facility_code(24).expect_err("24 must be rejected");
        assert!(err.to_string().contains("facility_code"));
    }

    #[test]
    fn validate_severity_accepts_valid_range() {
        for v in 0..=7 {
            validate_severity(v).expect("{v} must be valid");
        }
    }

    #[test]
    fn validate_severity_rejects_out_of_range() {
        let err = validate_severity(8).expect_err("8 must be rejected");
        assert!(err.to_string().contains("severity"));
        let err = validate_severity(-1).expect_err("-1 must be rejected");
        assert!(err.to_string().contains("severity"));
    }
}
