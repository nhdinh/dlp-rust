//! Repository for the `audit_events` table.
//!
//! Encapsulates all SQL for audit event insertion and querying.
//! Callers are responsible for JSON-serializing enum fields (event_type,
//! classification, action_attempted, decision, access_context) before
//! passing them to write methods.

use std::collections::HashMap;

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Filter parameters for audit event queries.
#[derive(Debug, Clone, Default)]
pub struct AuditEventFilter {
    pub agent_id: Option<String>,
    pub user_name: Option<String>,
    pub classification: Option<String>,
    pub event_type: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// Plain data row for a single audit event write.
///
/// All enum fields must be pre-serialized to strings by the caller.
#[derive(Debug, Clone)]
pub struct AuditEventRow {
    /// ISO-8601 timestamp when the event occurred.
    pub timestamp: String,
    /// Serialized event type (e.g., `"FileRead"`).
    pub event_type: String,
    /// Windows SID of the user who triggered the event.
    pub user_sid: String,
    /// Display name of the user.
    pub user_name: String,
    /// Full filesystem path of the accessed resource.
    pub resource_path: String,
    /// Serialized data classification tier (e.g., `"Confidential"`).
    pub classification: String,
    /// Serialized attempted action (e.g., `"Write"`).
    pub action_attempted: String,
    /// Serialized policy decision (e.g., `"Allow"`, `"Deny"`).
    pub decision: String,
    /// Optional policy UUID that produced the decision.
    pub policy_id: Option<String>,
    /// Optional human-readable policy name.
    pub policy_name: Option<String>,
    /// Agent UUID that reported the event.
    pub agent_id: String,
    /// Session identifier linking related events.
    pub session_id: i64,
    /// Serialized access context (e.g., `"local"`, `"vpn"`).
    pub access_context: String,
    /// Optional UUID for cross-system correlation. Must be globally unique.
    pub correlation_id: Option<String>,
    /// Optional SHA-256 hash of the accessed file content (evidence integrity).
    pub content_sha256: Option<String>,
    /// The `prev_hash` for this event in the tamper-evident audit chain.
    pub prev_hash: Option<String>,
    /// The `chain_hash` (SHA-256) for this event in the tamper-evident audit chain.
    pub chain_hash: Option<String>,
}

/// Stateless repository for the `audit_events` table.
pub struct AuditEventRepository;

impl AuditEventRepository {
    /// Returns the total count of audit events stored.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn count(pool: &Pool) -> rusqlite::Result<i64> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.query_row("SELECT COUNT(*) FROM audit_events", [], |r| r.get(0))
    }

    /// Inserts a batch of audit events using `INSERT OR IGNORE` to skip duplicates.
    ///
    /// All enum fields in each row must be pre-serialized to strings by the caller.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the writes within.
    /// * `rows` - Slice of pre-serialized audit event rows to insert.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` on the first statement failure.
    pub fn insert_batch(uow: &UnitOfWork<'_>, rows: &[AuditEventRow]) -> rusqlite::Result<()> {
        for row in rows {
            uow.tx.execute(
                "INSERT OR IGNORE INTO audit_events (
                    timestamp, event_type, user_sid, user_name, resource_path,
                    classification, action_attempted, decision, policy_id, policy_name,
                    agent_id, session_id, access_context, correlation_id, content_sha256,
                    prev_hash, chain_hash
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
                params![
                    row.timestamp,
                    row.event_type,
                    row.user_sid,
                    row.user_name,
                    row.resource_path,
                    row.classification,
                    row.action_attempted,
                    row.decision,
                    row.policy_id,
                    row.policy_name,
                    row.agent_id,
                    row.session_id,
                    row.access_context,
                    row.correlation_id,
                    row.content_sha256,
                    row.prev_hash,
                    row.chain_hash,
                ],
            )?;
        }
        Ok(())
    }

    /// Queries audit events with optional filters, returning a vector of
    /// JSON objects ordered by timestamp descending.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `filter` - Filter parameters (all fields optional).
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn query(
        pool: &Pool,
        filter: &AuditEventFilter,
    ) -> rusqlite::Result<Vec<serde_json::Value>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let mut conditions: Vec<String> = Vec::new();
        let mut params_map: HashMap<usize, String> = HashMap::new();

        if let Some(ref v) = filter.agent_id {
            let n = conditions.len() + 1;
            conditions.push(format!("agent_id = ?{n}"));
            params_map.insert(n, v.clone());
        }
        if let Some(ref v) = filter.user_name {
            let n = conditions.len() + 1;
            conditions.push(format!("user_name = ?{n}"));
            params_map.insert(n, v.clone());
        }
        if let Some(ref v) = filter.classification {
            let n = conditions.len() + 1;
            conditions.push(format!("classification = ?{n}"));
            params_map.insert(n, v.clone());
        }
        if let Some(ref v) = filter.event_type {
            let n = conditions.len() + 1;
            conditions.push(format!("event_type = ?{n}"));
            params_map.insert(n, v.clone());
        }
        if let Some(ref v) = filter.from {
            let n = conditions.len() + 1;
            conditions.push(format!("timestamp >= ?{n}"));
            params_map.insert(n, v.clone());
        }
        if let Some(ref v) = filter.to {
            let n = conditions.len() + 1;
            conditions.push(format!("timestamp <= ?{n}"));
            params_map.insert(n, v.clone());
        }

        let base_count = conditions.len();
        let limit = filter.limit.unwrap_or(100) as i64;
        let offset = filter.offset.unwrap_or(0) as i64;

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let sql = format!(
            "SELECT id, timestamp, event_type, user_sid, user_name, \
                    resource_path, classification, action_attempted, \
                    decision, policy_id, policy_name, agent_id, \
                    session_id, access_context, correlation_id, content_sha256 \
             FROM audit_events {where_clause} \
             ORDER BY timestamp DESC \
             LIMIT ?{} OFFSET ?{}",
            base_count + 1,
            base_count + 2,
        );

        let mut stmt = conn.prepare(&sql)?;
        let mut param_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        for i in 1..=base_count {
            param_vec.push(Box::new(params_map[&i].clone()));
        }
        param_vec.push(Box::new(limit));
        param_vec.push(Box::new(offset));

        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            param_vec.iter().map(|p| p.as_ref()).collect();

        let rows = stmt
            .query_map(param_refs.as_slice(), |row| {
                Ok(serde_json::json!({
                    "id": row.get::<_, i64>(0)?,
                    "timestamp": row.get::<_, String>(1)?,
                    "event_type": row.get::<_, String>(2)?,
                    "user_sid": row.get::<_, String>(3)?,
                    "user_name": row.get::<_, String>(4)?,
                    "resource_path": row.get::<_, String>(5)?,
                    "classification": row.get::<_, String>(6)?,
                    "action_attempted": row.get::<_, String>(7)?,
                    "decision": row.get::<_, String>(8)?,
                    "policy_id": row.get::<_, Option<String>>(9)?,
                    "policy_name": row.get::<_, Option<String>>(10)?,
                    "agent_id": row.get::<_, String>(11)?,
                    "session_id": row.get::<_, i64>(12)?,
                    "access_context": row.get::<_, String>(13)?,
                    "correlation_id": row.get::<_, Option<String>>(14)?,
                    "content_sha256": row.get::<_, Option<String>>(15)?,
                }))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Returns the most recent chain hash for a given agent.
    ///
    /// Used by the server-side chain verifier to validate the `prev_hash`
    /// of newly ingested events. Returns `None` if the agent has no
    /// chain-verified events yet.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `agent_id` - The agent UUID whose chain tail to look up.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn get_last_chain_hash(pool: &Pool, agent_id: &str) -> rusqlite::Result<Option<String>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.query_row(
            "SELECT chain_hash FROM audit_events \
             WHERE agent_id = ?1 AND chain_hash IS NOT NULL \
             ORDER BY id DESC LIMIT 1",
            [agent_id],
            |row| row.get(0),
        )
    }

    /// Detects chain continuity breaks in the tamper-evident audit log.
    ///
    /// Uses a SQLite window function (LAG) to compare each event's
    /// `prev_hash` against the `chain_hash` of the preceding event for
    /// the same agent. Only rows where `chain_hash IS NOT NULL` are
    /// considered.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `since_id` - Optional lower bound on `id` (exclusive) for pagination.
    /// * `limit` - Maximum number of candidate rows to examine.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    /// If the SQLite version does not support window functions (pre-3.25),
    /// the query will fail — callers should handle this gracefully.
    pub fn get_chain_breaks(
        pool: &Pool,
        since_id: Option<i64>,
        limit: usize,
    ) -> rusqlite::Result<Vec<serde_json::Value>> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let sql = "SELECT id, agent_id, prev_hash, chain_hash, \
                   LAG(chain_hash) OVER (PARTITION BY agent_id ORDER BY id) AS expected_prev \
            FROM audit_events \
            WHERE chain_hash IS NOT NULL \
              AND (?1 IS NULL OR id > ?1) \
            ORDER BY id \
            LIMIT ?2";

        let mut stmt = conn.prepare(sql)?;
        let rows = stmt
            .query_map(rusqlite::params![since_id, limit as i64], |row| {
                let id: i64 = row.get(0)?;
                let agent_id: String = row.get(1)?;
                let prev_hash: Option<String> = row.get(2)?;
                let chain_hash: String = row.get(3)?;
                let expected_prev: Option<String> = row.get(4)?;
                Ok((id, agent_id, prev_hash, chain_hash, expected_prev))
            })?
            .filter_map(|r| {
                r.ok()
                    .and_then(|(id, agent_id, prev_hash, chain_hash, expected_prev)| {
                        // Skip the first event per agent (expected_prev IS NULL).
                        // A break occurs when prev_hash != expected_prev.
                        let expected = expected_prev?;
                        let actual = prev_hash.as_deref().unwrap_or("");
                        if actual != expected {
                            Some(serde_json::json!({
                                "id": id,
                                "agent_id": agent_id,
                                "prev_hash": prev_hash,
                                "chain_hash": chain_hash,
                                "expected_prev": expected,
                            }))
                        } else {
                            None
                        }
                    })
            })
            .collect();
        Ok(rows)
    }
}

/// Validates that a hash string is exactly 64 hexadecimal characters.
///
/// Defense-in-depth helper used before binding hash fields to SQL
/// parameters, ensuring only well-formed SHA-256 digests reach the DB.
///
/// # Arguments
///
/// * `hash` - The hash string to validate.
///
/// # Returns
///
/// `true` if the string is 64 characters and all hex digits; `false` otherwise.
pub fn is_valid_hash_format(hash: &str) -> bool {
    hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::new_pool;

    /// Helper: build a minimal AuditEventRow for test insertion.
    fn test_row(
        agent_id: &str,
        chain_hash: Option<&str>,
        prev_hash: Option<&str>,
    ) -> AuditEventRow {
        AuditEventRow {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            event_type: "FileRead".to_string(),
            user_sid: "S-1-5-18".to_string(),
            user_name: "test".to_string(),
            resource_path: r"C:\test.txt".to_string(),
            classification: "T1".to_string(),
            action_attempted: "Read".to_string(),
            decision: "Allow".to_string(),
            policy_id: None,
            policy_name: None,
            agent_id: agent_id.to_string(),
            session_id: 1,
            access_context: "local".to_string(),
            correlation_id: None,
            prev_hash: prev_hash.map(String::from),
            chain_hash: chain_hash.map(String::from),
            content_sha256: None,
        }
    }

    #[test]
    fn test_get_last_chain_hash_returns_none_for_unknown_agent() {
        let pool = new_pool(":memory:").expect("create pool");
        // get_last_chain_hash returns QueryReturnedNoRows when no matching row exists;
        // map that to None for a cleaner API.
        let result = match AuditEventRepository::get_last_chain_hash(&pool, "unknown-agent") {
            Ok(hash) => hash,
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => panic!("unexpected error: {e}"),
        };
        assert_eq!(result, None, "unknown agent must have no chain hash");
    }

    #[test]
    fn test_get_last_chain_hash_returns_latest_hash() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db file");
        let path = tmp.path().to_str().expect("temp path utf8");
        let pool = new_pool(path).expect("create pool");
        let mut conn = pool.get().expect("acquire connection");
        let uow = crate::db::UnitOfWork::new(&mut conn).expect("create uow");

        // Insert three events for the same agent with ascending chain hashes.
        let rows = vec![
            test_row("agent-a", Some("hash-001"), Some("genesis")),
            test_row("agent-a", Some("hash-002"), Some("hash-001")),
            test_row("agent-a", Some("hash-003"), Some("hash-002")),
        ];
        AuditEventRepository::insert_batch(&uow, &rows).expect("insert batch");
        uow.commit().expect("commit");

        let latest = AuditEventRepository::get_last_chain_hash(&pool, "agent-a").expect("query");
        assert_eq!(
            latest,
            Some("hash-003".to_string()),
            "must return the most recent chain hash"
        );
    }

    #[test]
    fn test_get_chain_breaks_detects_mismatch() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db file");
        let path = tmp.path().to_str().expect("temp path utf8");
        let pool = new_pool(path).expect("create pool");
        let mut conn = pool.get().expect("acquire connection");
        let uow = crate::db::UnitOfWork::new(&mut conn).expect("create uow");

        // Agent-a: continuous chain (no break).
        // Agent-b: break at event 2 (prev_hash does not match event 1's chain_hash).
        let rows = vec![
            test_row("agent-a", Some("hash-a1"), Some("genesis")),
            test_row("agent-a", Some("hash-a2"), Some("hash-a1")),
            test_row("agent-b", Some("hash-b1"), Some("genesis")),
            test_row("agent-b", Some("hash-b2"), Some("tampered")), // break!
        ];
        AuditEventRepository::insert_batch(&uow, &rows).expect("insert batch");
        uow.commit().expect("commit");

        let breaks = AuditEventRepository::get_chain_breaks(&pool, None, 100).expect("query");
        assert_eq!(breaks.len(), 1, "must detect exactly one break");
        assert_eq!(
            breaks[0]["agent_id"], "agent-b",
            "break must belong to agent-b"
        );
        assert_eq!(
            breaks[0]["expected_prev"], "hash-b1",
            "expected_prev must be hash-b1"
        );
        assert_eq!(
            breaks[0]["prev_hash"], "tampered",
            "prev_hash must show tampered value"
        );
    }

    #[test]
    fn test_get_chain_breaks_respects_pagination() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db file");
        let path = tmp.path().to_str().expect("temp path utf8");
        let pool = new_pool(path).expect("create pool");
        let mut conn = pool.get().expect("acquire connection");
        let uow = crate::db::UnitOfWork::new(&mut conn).expect("create uow");

        // Insert 5 events for agent-a; only event 3 has a break.
        let rows = vec![
            test_row("agent-a", Some("h1"), Some("genesis")),
            test_row("agent-a", Some("h2"), Some("h1")),
            test_row("agent-a", Some("h3"), Some("BAD")), // break at id 3
            test_row("agent-a", Some("h4"), Some("h3")),
            test_row("agent-a", Some("h5"), Some("h4")),
        ];
        AuditEventRepository::insert_batch(&uow, &rows).expect("insert batch");
        uow.commit().expect("commit");

        // Limit to 2 rows (ids 1 and 2) — no break yet.
        let breaks_early = AuditEventRepository::get_chain_breaks(&pool, None, 2).expect("query");
        assert_eq!(breaks_early.len(), 0, "no break within first 2 rows");

        // Limit to 4 rows (ids 1..4) — break at id 3 is included.
        let breaks_mid = AuditEventRepository::get_chain_breaks(&pool, None, 4).expect("query");
        assert_eq!(breaks_mid.len(), 1, "break at id 3 must be detected");

        // since_id = 3 excludes id 3; remaining rows (4, 5) are continuous.
        let breaks_since =
            AuditEventRepository::get_chain_breaks(&pool, Some(3), 100).expect("query");
        assert_eq!(breaks_since.len(), 0, "no break after id 3");
    }

    #[test]
    fn test_is_valid_hash_format_accepts_and_rejects() {
        // Valid 64-char hex.
        assert!(
            is_valid_hash_format(
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            ),
            "64-char hex must be valid"
        );

        // Too short.
        assert!(
            !is_valid_hash_format("abcdef0123456789"),
            "16-char hex must be rejected"
        );

        // Too long.
        assert!(
            !is_valid_hash_format(
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789aa"
            ),
            "66-char hex must be rejected"
        );

        // Non-hex character.
        assert!(
            !is_valid_hash_format(
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345678g"
            ),
            "non-hex char must be rejected"
        );

        // Empty.
        assert!(!is_valid_hash_format(""), "empty string must be rejected");

        // Uppercase hex is valid.
        assert!(
            is_valid_hash_format(
                "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
            ),
            "uppercase 64-char hex must be valid"
        );
    }
}
