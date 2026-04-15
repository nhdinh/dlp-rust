//! Repository for the `agents` table.
//!
//! Encapsulates all SQL for agent registration, heartbeat, listing,
//! lookup, and offline sweeping.

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Plain data row returned by agent reads.
///
/// Does not derive `Serialize`/`Deserialize` — conversion to HTTP response
/// types is handled at the handler layer.
#[derive(Debug, Clone)]
pub struct AgentRow {
    /// Unique agent identifier (UUID string).
    pub agent_id: String,
    /// Hostname of the machine running the agent.
    pub hostname: String,
    /// IP address of the agent machine.
    pub ip: String,
    /// Operating system version string.
    pub os_version: String,
    /// Agent software version string.
    pub agent_version: String,
    /// ISO-8601 timestamp of last heartbeat.
    pub last_heartbeat: String,
    /// Agent status: `"online"` or `"offline"`.
    pub status: String,
    /// ISO-8601 timestamp of initial registration.
    pub registered_at: String,
}

/// Stateless repository for the `agents` table.
pub struct AgentRepository;

impl AgentRepository {
    /// Returns all agents ordered by hostname.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn list(pool: &Pool) -> rusqlite::Result<Vec<AgentRow>> {
        let conn = pool.get().map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(e))
        })?;
        let mut stmt = conn.prepare(
            "SELECT agent_id, hostname, ip, os_version, agent_version, \
             last_heartbeat, status, registered_at \
             FROM agents ORDER BY hostname",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(AgentRow {
                agent_id: row.get(0)?,
                hostname: row.get(1)?,
                ip: row.get(2)?,
                os_version: row.get(3)?,
                agent_version: row.get(4)?,
                last_heartbeat: row.get(5)?,
                status: row.get(6)?,
                registered_at: row.get(7)?,
            })
        })?;
        rows.collect()
    }

    /// Inserts or updates an agent record (upsert by `agent_id`).
    ///
    /// On conflict, updates all mutable fields except `registered_at`.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `record` - Agent data to upsert.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the statement fails.
    pub fn upsert(uow: &UnitOfWork<'_>, record: &AgentRow) -> rusqlite::Result<()> {
        uow.tx.execute(
            "INSERT INTO agents (
                agent_id, hostname, ip, os_version, agent_version,
                last_heartbeat, status, registered_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(agent_id) DO UPDATE SET
                hostname       = excluded.hostname,
                ip             = excluded.ip,
                os_version     = excluded.os_version,
                agent_version  = excluded.agent_version,
                last_heartbeat = excluded.last_heartbeat,
                status         = excluded.status",
            params![
                record.agent_id,
                record.hostname,
                record.ip,
                record.os_version,
                record.agent_version,
                record.last_heartbeat,
                record.status,
                record.registered_at,
            ],
        )?;
        Ok(())
    }
}
