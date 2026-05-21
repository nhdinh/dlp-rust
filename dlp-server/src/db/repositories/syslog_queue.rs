//! Repository for the `syslog_queue` table.
//!
//! Multi-row queue table storing KEK-encrypted audit events for later
//! retry when syslog forwarding fails. Uses peek-confirm-delete
//! semantics for at-least-once delivery (R-62-02).
//!
//! # Design
//!
//! - `enqueue`: Pre-insert capacity check (R-62-03). Rejects event when
//!   full instead of deleting after insert (FIFO tail-drop per D-08).
//! - `peek_oldest`: Returns decrypted events WITHOUT removing rows
//!   (peek-confirm pattern per R-62-02).
//! - `delete`: Called ONLY after confirmed successful delivery.
//! - `mark_failed`: Updates retry_count, last_error, and next_attempt_at
//!   for time-based scheduling.
//! - `count_ready`: Returns events eligible for immediate retry (respects
//!   backoff scheduling).

use rusqlite::params;
use secrecy::ExposeSecret;

use crate::crypto::envelope::NONCE_LEN;
use crate::crypto::{aad_for, Envelope, SecretCrypto, ENVELOPE_VERSION_V1};
use crate::db::{Pool, UnitOfWork};
use crate::AppError;

/// Queue entry returned by peek/drain operations.
///
/// Contains the decrypted event JSON and retry metadata.
#[derive(Debug, Clone)]
pub struct QueuedEvent {
    /// Row id in the queue table.
    pub id: i64,
    /// Decrypted event JSON payload.
    pub event_json: String,
    /// Number of failed delivery attempts so far.
    pub retry_count: i64,
    /// Last error message from failed delivery attempt.
    pub last_error: String,
}

/// Stateless repository for the `syslog_queue` table.
pub struct SyslogQueueRepository;

impl SyslogQueueRepository {
    /// Enqueue a single event with KEK encryption.
    ///
    /// Returns `Err` if queue is at max capacity (pre-insert tail-drop per R-62-03).
    ///
    /// # Arguments
    ///
    /// * `uow` -- active unit of work for the INSERT.
    /// * `event_json` -- the JSON-serialized audit event to encrypt and store.
    /// * `crypto` -- active KEK handle for encryption.
    /// * `max_size` -- maximum allowed queue depth; events are rejected when exceeded.
    ///
    /// # Errors
    ///
    /// - [`AppError::BadRequest`] when queue is at capacity.
    /// - [`AppError::Internal`] when encryption fails.
    /// - [`AppError::Database`] when the INSERT fails.
    pub fn enqueue(
        uow: &UnitOfWork,
        event_json: &str,
        crypto: &SecretCrypto,
        max_size: i64,
    ) -> Result<(), AppError> {
        // Pre-insert tail-drop: check capacity BEFORE encrypting/inserting.
        let count: i64 = uow
            .tx
            .query_row("SELECT COUNT(*) FROM syslog_queue", [], |row| row.get(0))
            .map_err(AppError::Database)?;
        if count >= max_size {
            return Err(AppError::BadRequest(format!(
                "syslog queue at capacity ({max_size}), event dropped"
            )));
        }

        let aad = aad_for("syslog_queue", "event_json");
        let envelope = crypto
            .encrypt(event_json.as_bytes(), &aad)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("encrypt failed: {e}")))?;
        uow.tx
            .execute(
                "INSERT INTO syslog_queue \
                 (event_json_encrypted, event_json_nonce, created_at, retry_count, last_error, next_attempt_at) \
                 VALUES (?1, ?2, ?3, 0, '', '')",
                params![
                    envelope.ciphertext,
                    envelope.nonce.as_slice(),
                    chrono::Utc::now().to_rfc3339(),
                ],
            )
            .map_err(AppError::Database)?;
        Ok(())
    }

    /// Peek oldest N events eligible for retry (next_attempt_at <= now or empty).
    ///
    /// Returns decrypted events WITHOUT removing rows. Callers must
    /// invoke [`delete`] after confirmed successful delivery.
    ///
    /// # Arguments
    ///
    /// * `pool` -- connection pool (read).
    /// * `crypto` -- active KEK handle for decryption.
    /// * `batch_size` -- maximum number of events to return.
    ///
    /// # Errors
    ///
    /// - [`AppError::Database`] on SELECT or decrypt failure.
    pub fn peek_oldest(
        pool: &Pool,
        crypto: &SecretCrypto,
        batch_size: usize,
    ) -> Result<Vec<QueuedEvent>, AppError> {
        let conn = pool.get().map_err(AppError::from)?;
        let now = chrono::Utc::now().to_rfc3339();
        let mut stmt = conn
            .prepare(
                "SELECT id, event_json_encrypted, event_json_nonce, retry_count, last_error \
                 FROM syslog_queue \
                 WHERE next_attempt_at = '' OR next_attempt_at <= ?1 \
                 ORDER BY created_at LIMIT ?2",
            )
            .map_err(AppError::Database)?;
        let rows = stmt
            .query_map(params![&now, batch_size as i64], |row| {
                let id: i64 = row.get(0)?;
                let ciphertext: Vec<u8> = row.get(1)?;
                let nonce_bytes: Vec<u8> = row.get(2)?;
                let retry_count: i64 = row.get(3)?;
                let last_error: String = row.get(4)?;

                let mut nonce = [0u8; NONCE_LEN];
                nonce.copy_from_slice(&nonce_bytes);
                let envelope = Envelope::new(ENVELOPE_VERSION_V1, nonce, ciphertext)
                    .map_err(|e| rusqlite::Error::InvalidParameterName(format!("envelope: {e}")))?;
                let aad = aad_for("syslog_queue", "event_json");
                let plaintext = crypto
                    .decrypt(&envelope, &aad)
                    .map_err(|e| rusqlite::Error::InvalidParameterName(format!("decrypt: {e}")))?;
                let event_json = plaintext.expose_secret().to_string();
                Ok(QueuedEvent {
                    id,
                    event_json,
                    retry_count,
                    last_error,
                })
            })
            .map_err(AppError::Database)?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(AppError::Database)?);
        }
        Ok(results)
    }

    /// Delete specific rows by id after successful forwarding (confirm-delete per R-62-02).
    ///
    /// # Arguments
    ///
    /// * `uow` -- active unit of work for the DELETE.
    /// * `ids` -- slice of row ids to remove.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Database`] when the DELETE fails.
    pub fn delete(uow: &UnitOfWork, ids: &[i64]) -> Result<(), AppError> {
        if ids.is_empty() {
            return Ok(());
        }
        let placeholders: Vec<String> = ids.iter().map(|_| "?".to_string()).collect();
        let sql = format!(
            "DELETE FROM syslog_queue WHERE id IN ({})",
            placeholders.join(",")
        );
        let mut stmt = uow.tx.prepare(&sql).map_err(AppError::Database)?;
        let params: Vec<&dyn rusqlite::ToSql> =
            ids.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
        stmt.execute(rusqlite::params_from_iter(params.iter()))
            .map_err(AppError::Database)?;
        Ok(())
    }

    /// Update retry metadata after a failed forward attempt.
    ///
    /// Increments `retry_count`, sets `last_error`, and schedules the
    /// next attempt via `next_attempt_at`.
    ///
    /// # Arguments
    ///
    /// * `uow` -- active unit of work for the UPDATE.
    /// * `id` -- row id to update.
    /// * `error` -- error message from the failed attempt.
    /// * `next_attempt_at` -- RFC-3339 timestamp for the next retry attempt.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Database`] when the UPDATE fails.
    pub fn mark_failed(
        uow: &UnitOfWork,
        id: i64,
        error: &str,
        next_attempt_at: &str,
    ) -> Result<(), AppError> {
        uow.tx
            .execute(
                "UPDATE syslog_queue SET retry_count = retry_count + 1, last_error = ?1, \
                 next_attempt_at = ?2 WHERE id = ?3",
                params![error, next_attempt_at, id],
            )
            .map_err(AppError::Database)?;
        Ok(())
    }

    /// Return current queue depth.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Database`] when the COUNT query fails.
    pub fn count(pool: &Pool) -> Result<i64, AppError> {
        let conn = pool.get().map_err(AppError::from)?;
        conn.query_row("SELECT COUNT(*) FROM syslog_queue", [], |row| row.get(0))
            .map_err(AppError::Database)
    }

    /// Return count of events ready for retry (next_attempt_at <= now or empty).
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Database`] when the COUNT query fails.
    pub fn count_ready(pool: &Pool) -> Result<i64, AppError> {
        let conn = pool.get().map_err(AppError::from)?;
        let now = chrono::Utc::now().to_rfc3339();
        conn.query_row(
            "SELECT COUNT(*) FROM syslog_queue WHERE next_attempt_at = '' OR next_attempt_at <= ?1",
            params![&now],
            |row| row.get(0),
        )
        .map_err(AppError::Database)
    }

    /// Peek-and-claim oldest N events eligible for retry.
    ///
    /// Atomically sets `leased_until` on selected rows to prevent concurrent
    /// drain workers (or drain across process restarts) from double-sending
    /// the same events. Only selects rows that are unleased or whose lease
    /// has expired.
    ///
    /// # Arguments
    ///
    /// * `pool` -- connection pool (read+write for claim).
    /// * `crypto` -- active KEK handle for decryption.
    /// * `batch_size` -- maximum number of events to return.
    /// * `lease_duration_secs` -- how long the lease lasts.
    ///
    /// # Errors
    ///
    /// - [`AppError::Database`] on SELECT, UPDATE, or decrypt failure.
    pub fn peek_and_claim(
        pool: &Pool,
        crypto: &SecretCrypto,
        batch_size: usize,
        lease_duration_secs: u64,
    ) -> Result<Vec<QueuedEvent>, AppError> {
        let conn = pool.get().map_err(AppError::from)?;
        let now = chrono::Utc::now().to_rfc3339();
        let lease_until = (chrono::Utc::now()
            + chrono::Duration::seconds(lease_duration_secs as i64))
        .to_rfc3339();

        // Select eligible rows (unleased or expired lease).
        let mut stmt = conn
            .prepare(
                "SELECT id, event_json_encrypted, event_json_nonce, retry_count, last_error \
                 FROM syslog_queue \
                 WHERE (next_attempt_at = '' OR next_attempt_at <= ?1) \
                   AND (leased_until = '' OR leased_until <= ?1) \
                 ORDER BY created_at LIMIT ?2",
            )
            .map_err(AppError::Database)?;
        let claimed_ids: Vec<i64> = stmt
            .query_map(params![&now, batch_size as i64], |row| {
                let id: i64 = row.get(0)?;
                Ok(id)
            })
            .map_err(AppError::Database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(AppError::Database)?;
        drop(stmt);

        // Set lease on claimed rows.
        if !claimed_ids.is_empty() {
            let placeholders: Vec<String> =
                claimed_ids.iter().map(|_| "?".to_string()).collect();
            let sql = format!(
                "UPDATE syslog_queue SET leased_until = ?1 WHERE id IN ({})",
                placeholders.join(",")
            );
            let mut update_stmt = conn.prepare(&sql).map_err(AppError::Database)?;
            let mut params_vec: Vec<&dyn rusqlite::ToSql> = vec![&lease_until];
            for id in &claimed_ids {
                params_vec.push(id);
            }
            update_stmt
                .execute(rusqlite::params_from_iter(params_vec.iter()))
                .map_err(AppError::Database)?;
        }

        // Re-select claimed rows to decrypt and return.
        if claimed_ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders: Vec<String> =
            claimed_ids.iter().map(|_| "?".to_string()).collect();
        let sql = format!(
            "SELECT id, event_json_encrypted, event_json_nonce, retry_count, last_error \
             FROM syslog_queue \
             WHERE id IN ({}) \
             ORDER BY created_at",
            placeholders.join(",")
        );
        let mut stmt = conn.prepare(&sql).map_err(AppError::Database)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(claimed_ids.iter()), |row| {
                let id: i64 = row.get(0)?;
                let ciphertext: Vec<u8> = row.get(1)?;
                let nonce_bytes: Vec<u8> = row.get(2)?;
                let retry_count: i64 = row.get(3)?;
                let last_error: String = row.get(4)?;

                let mut nonce = [0u8; NONCE_LEN];
                nonce.copy_from_slice(&nonce_bytes);
                let envelope = Envelope::new(ENVELOPE_VERSION_V1, nonce, ciphertext)
                    .map_err(|e| {
                        rusqlite::Error::InvalidParameterName(format!("envelope: {e}"))
                    })?;
                let aad = aad_for("syslog_queue", "event_json");
                let plaintext = crypto
                    .decrypt(&envelope, &aad)
                    .map_err(|e| {
                        rusqlite::Error::InvalidParameterName(format!("decrypt: {e}"))
                    })?;
                let event_json = plaintext.expose_secret().to_string();
                Ok(QueuedEvent {
                    id,
                    event_json,
                    retry_count,
                    last_error,
                })
            })
            .map_err(AppError::Database)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(AppError::Database)
    }

    /// Release the lease on specific rows so they can be claimed again.
    ///
    /// Call this when a forward attempt fails and the events should be
    /// retried sooner than the lease expiry.
    ///
    /// # Arguments
    ///
    /// * `uow` -- active unit of work for the UPDATE.
    /// * `ids` -- slice of row ids to release.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Database`] when the UPDATE fails.
    pub fn release_lease(uow: &UnitOfWork, ids: &[i64]) -> Result<(), AppError> {
        if ids.is_empty() {
            return Ok(());
        }
        let placeholders: Vec<String> = ids.iter().map(|_| "?".to_string()).collect();
        let sql = format!(
            "UPDATE syslog_queue SET leased_until = '' WHERE id IN ({})",
            placeholders.join(",")
        );
        let mut stmt = uow.tx.prepare(&sql).map_err(AppError::Database)?;
        let params: Vec<&dyn rusqlite::ToSql> =
            ids.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
        stmt.execute(rusqlite::params_from_iter(params.iter()))
            .map_err(AppError::Database)?;
        Ok(())
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

    #[test]
    fn enqueue_then_peek_round_trip() {
        let crypto = fixture_crypto();
        let pool = new_pool(":memory:").expect("create pool");

        let event_json = r#"{"event_id":"test-123","timestamp":"2026-05-14T00:00:00Z"}"#;
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SyslogQueueRepository::enqueue(&uow, event_json, &crypto, 100000).expect("enqueue");
            uow.commit().expect("commit");
        }

        let events = SyslogQueueRepository::peek_oldest(&pool, &crypto, 10).expect("peek");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_json, event_json);
        assert_eq!(events[0].retry_count, 0);
        assert_eq!(events[0].last_error, "");
    }

    #[test]
    fn peek_oldest_returns_fifo_order() {
        let crypto = fixture_crypto();
        let pool = new_pool(":memory:").expect("create pool");

        let events = vec![
            r#"{"event_id":"first"}"#,
            r#"{"event_id":"second"}"#,
            r#"{"event_id":"third"}"#,
        ];
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            for e in &events {
                SyslogQueueRepository::enqueue(&uow, e, &crypto, 100000).expect("enqueue");
            }
            uow.commit().expect("commit");
        }

        let peeked = SyslogQueueRepository::peek_oldest(&pool, &crypto, 10).expect("peek");
        assert_eq!(peeked.len(), 3);
        assert_eq!(peeked[0].event_json, events[0]);
        assert_eq!(peeked[1].event_json, events[1]);
        assert_eq!(peeked[2].event_json, events[2]);
    }

    #[test]
    fn peek_oldest_respects_batch_size() {
        let crypto = fixture_crypto();
        let pool = new_pool(":memory:").expect("create pool");

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            for i in 0..5 {
                SyslogQueueRepository::enqueue(
                    &uow,
                    &format!("{{\"event_id\":\"{i}\"}}"),
                    &crypto,
                    100000,
                )
                .expect("enqueue");
            }
            uow.commit().expect("commit");
        }

        let peeked = SyslogQueueRepository::peek_oldest(&pool, &crypto, 2).expect("peek");
        assert_eq!(peeked.len(), 2);
    }

    #[test]
    fn peek_does_not_delete_rows() {
        let crypto = fixture_crypto();
        let pool = new_pool(":memory:").expect("create pool");

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SyslogQueueRepository::enqueue(&uow, "test", &crypto, 100000).expect("enqueue");
            uow.commit().expect("commit");
        }

        let _ = SyslogQueueRepository::peek_oldest(&pool, &crypto, 10).expect("peek");
        let count = SyslogQueueRepository::count(&pool).expect("count");
        assert_eq!(count, 1, "peek must not delete rows");
    }

    #[test]
    fn delete_removes_specified_rows() {
        let crypto = fixture_crypto();
        let pool = new_pool(":memory:").expect("create pool");

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            for i in 0..3 {
                SyslogQueueRepository::enqueue(
                    &uow,
                    &format!("{{\"event_id\":\"{i}\"}}"),
                    &crypto,
                    100000,
                )
                .expect("enqueue");
            }
            uow.commit().expect("commit");
        }

        let peeked = SyslogQueueRepository::peek_oldest(&pool, &crypto, 10).expect("peek");
        assert_eq!(peeked.len(), 3);

        // Delete only the middle row.
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SyslogQueueRepository::delete(&uow, &[peeked[1].id]).expect("delete");
            uow.commit().expect("commit");
        }

        let count = SyslogQueueRepository::count(&pool).expect("count");
        assert_eq!(count, 2);

        let remaining = SyslogQueueRepository::peek_oldest(&pool, &crypto, 10).expect("peek");
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].event_json, peeked[0].event_json);
        assert_eq!(remaining[1].event_json, peeked[2].event_json);
    }

    #[test]
    fn enqueue_rejects_when_queue_full() {
        let crypto = fixture_crypto();
        let pool = new_pool(":memory:").expect("create pool");

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            for i in 0..3 {
                SyslogQueueRepository::enqueue(
                    &uow,
                    &format!("{{\"event_id\":\"{i}\"}}"),
                    &crypto,
                    3, // max_size = 3
                )
                .expect("enqueue");
            }
            uow.commit().expect("commit");
        }

        // Fourth event should be rejected (pre-insert tail-drop).
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            let err = SyslogQueueRepository::enqueue(&uow, "overflow", &crypto, 3)
                .expect_err("must reject when full");
            assert!(err.to_string().contains("at capacity"));
        }

        let count = SyslogQueueRepository::count(&pool).expect("count");
        assert_eq!(count, 3, "queue must still have exactly 3 events");
    }

    #[test]
    fn mark_failed_updates_retry_metadata() {
        let crypto = fixture_crypto();
        let pool = new_pool(":memory:").expect("create pool");

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SyslogQueueRepository::enqueue(&uow, "test", &crypto, 100000).expect("enqueue");
            uow.commit().expect("commit");
        }

        let peeked = SyslogQueueRepository::peek_oldest(&pool, &crypto, 10).expect("peek");
        let id = peeked[0].id;

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SyslogQueueRepository::mark_failed(
                &uow,
                id,
                "connection timeout",
                "2099-01-01T00:00:00Z", // far future so peek_oldest filters it out
            )
            .expect("mark_failed");
            uow.commit().expect("commit");
        }

        let after = SyslogQueueRepository::peek_oldest(&pool, &crypto, 10).expect("peek");
        // After mark_failed, next_attempt_at is in the future so peek_oldest
        // (which filters next_attempt_at <= now) should return nothing.
        assert_eq!(after.len(), 0);

        // But count should still show 1 row.
        let count = SyslogQueueRepository::count(&pool).expect("count");
        assert_eq!(count, 1);
    }

    #[test]
    fn count_ready_respects_next_attempt_at() {
        let crypto = fixture_crypto();
        let pool = new_pool(":memory:").expect("create pool");

        // Insert one event ready now, one scheduled for future.
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SyslogQueueRepository::enqueue(&uow, "ready", &crypto, 100000).expect("enqueue");
            SyslogQueueRepository::enqueue(&uow, "future", &crypto, 100000).expect("enqueue");
            uow.commit().expect("commit");
        }

        // Mark the second event as scheduled for the future.
        let peeked = SyslogQueueRepository::peek_oldest(&pool, &crypto, 10).expect("peek");
        assert_eq!(peeked.len(), 2);
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SyslogQueueRepository::mark_failed(
                &uow,
                peeked[1].id,
                "temp failure",
                "2099-01-01T00:00:00Z", // far future
            )
            .expect("mark_failed");
            uow.commit().expect("commit");
        }

        let ready = SyslogQueueRepository::count_ready(&pool).expect("count_ready");
        assert_eq!(ready, 1, "only one event should be ready for retry");
    }

    #[test]
    fn wrong_key_decrypt_fails() {
        let crypto = fixture_crypto();
        let pool = new_pool(":memory:").expect("create pool");

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SyslogQueueRepository::enqueue(&uow, "secret", &crypto, 100000).expect("enqueue");
            uow.commit().expect("commit");
        }

        // Create a different crypto with a different key.
        let wrong_kek: [u8; 32] = [
            0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
            0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
            0x99, 0x99, 0x99, 0x99,
        ];
        let wrong_crypto = SecretCrypto::from_kek(wrong_kek, ENVELOPE_VERSION_V1);

        let result = SyslogQueueRepository::peek_oldest(&pool, &wrong_crypto, 10);
        assert!(result.is_err(), "decrypt with wrong key must fail");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("decrypt") || err_msg.contains("InvalidParameterName"),
            "error should mention decrypt failure; got: {err_msg}"
        );
    }

    #[test]
    fn peek_and_claim_sets_lease() {
        let crypto = fixture_crypto();
        let pool = new_pool(":memory:").expect("create pool");

        let event_json = r#"{"event_id":"claim-test","timestamp":"2026-05-14T00:00:00Z"}"#;
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SyslogQueueRepository::enqueue(&uow, event_json, &crypto, 100000).expect("enqueue");
            uow.commit().expect("commit");
        }

        let claimed =
            SyslogQueueRepository::peek_and_claim(&pool, &crypto, 10, 300).expect("peek_and_claim");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].event_json, event_json);

        // Second claim should return nothing because lease is still active.
        let second =
            SyslogQueueRepository::peek_and_claim(&pool, &crypto, 10, 300).expect("second claim");
        assert_eq!(second.len(), 0, "active lease must prevent re-claim");
    }

    #[test]
    fn release_lease_allows_reclaim() {
        let crypto = fixture_crypto();
        let pool = new_pool(":memory:").expect("create pool");

        let event_json = r#"{"event_id":"release-test"}"#;
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SyslogQueueRepository::enqueue(&uow, event_json, &crypto, 100000).expect("enqueue");
            uow.commit().expect("commit");
        }

        let claimed =
            SyslogQueueRepository::peek_and_claim(&pool, &crypto, 10, 300).expect("peek_and_claim");
        assert_eq!(claimed.len(), 1);
        let id = claimed[0].id;

        // Release lease.
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            SyslogQueueRepository::release_lease(&uow, &[id]).expect("release_lease");
            uow.commit().expect("commit");
        }

        // Should be reclaimable immediately.
        let reclaimed =
            SyslogQueueRepository::peek_and_claim(&pool, &crypto, 10, 300).expect("reclaim");
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].id, id);
    }

    #[test]
    fn peek_and_claim_returns_fifo_order() {
        let crypto = fixture_crypto();
        let pool = new_pool(":memory:").expect("create pool");

        let events = vec![
            r#"{"event_id":"first"}"#,
            r#"{"event_id":"second"}"#,
            r#"{"event_id":"third"}"#,
        ];
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            for e in &events {
                SyslogQueueRepository::enqueue(&uow, e, &crypto, 100000).expect("enqueue");
            }
            uow.commit().expect("commit");
        }

        let claimed =
            SyslogQueueRepository::peek_and_claim(&pool, &crypto, 10, 300).expect("peek_and_claim");
        assert_eq!(claimed.len(), 3);
        assert_eq!(claimed[0].event_json, events[0]);
        assert_eq!(claimed[1].event_json, events[1]);
        assert_eq!(claimed[2].event_json, events[2]);
    }

    #[test]
    fn peek_and_claim_respects_batch_size() {
        let crypto = fixture_crypto();
        let pool = new_pool(":memory:").expect("create pool");

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("begin uow");
            for i in 0..5 {
                SyslogQueueRepository::enqueue(
                    &uow,
                    &format!("{{\"event_id\":\"{i}\"}}"),
                    &crypto,
                    100000,
                )
                .expect("enqueue");
            }
            uow.commit().expect("commit");
        }

        let claimed =
            SyslogQueueRepository::peek_and_claim(&pool, &crypto, 2, 300).expect("peek_and_claim");
        assert_eq!(claimed.len(), 2);
    }
}
