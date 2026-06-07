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
    /// Stable device fingerprint (v1:SHA256).
    pub fingerprint: String,
    /// JSON-serialized MAC address list.
    pub mac_addresses: String,
    /// Whether a VPN adapter is currently active.
    pub vpn_active: bool,
    /// Whether the machine is joined to an Active Directory domain.
    pub domain_joined: bool,
    /// Device health status: healthy, degraded, offline, tampered.
    pub health_status: String,
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
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let mut stmt = conn.prepare(
            "SELECT agent_id, hostname, ip, os_version, agent_version, \
             last_heartbeat, status, registered_at, \
             fingerprint, mac_addresses, vpn_active, domain_joined, health_status \
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
                fingerprint: row.get(8)?,
                mac_addresses: row.get(9)?,
                vpn_active: row.get(10)?,
                domain_joined: row.get(11)?,
                health_status: row.get(12)?,
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
                last_heartbeat, status, registered_at,
                fingerprint, mac_addresses, vpn_active, domain_joined, health_status
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(agent_id) DO UPDATE SET
                hostname       = excluded.hostname,
                ip             = excluded.ip,
                os_version     = excluded.os_version,
                agent_version  = excluded.agent_version,
                last_heartbeat = excluded.last_heartbeat,
                status         = excluded.status,
                fingerprint    = excluded.fingerprint,
                mac_addresses  = excluded.mac_addresses,
                vpn_active     = excluded.vpn_active,
                domain_joined  = excluded.domain_joined,
                health_status  = excluded.health_status",
            params![
                record.agent_id,
                record.hostname,
                record.ip,
                record.os_version,
                record.agent_version,
                record.last_heartbeat,
                record.status,
                record.registered_at,
                record.fingerprint,
                record.mac_addresses,
                record.vpn_active,
                record.domain_joined,
                record.health_status,
            ],
        )?;
        Ok(())
    }

    /// Returns a single agent by its `agent_id`.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `agent_id` - The agent UUID to look up.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error::QueryReturnedNoRows` if the agent is not found.
    pub fn get_by_id(pool: &Pool, agent_id: &str) -> rusqlite::Result<AgentRow> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.query_row(
            "SELECT agent_id, hostname, ip, os_version, agent_version, \
             last_heartbeat, status, registered_at, \
             fingerprint, mac_addresses, vpn_active, domain_joined, health_status \
             FROM agents WHERE agent_id = ?1",
            params![agent_id],
            |row| {
                Ok(AgentRow {
                    agent_id: row.get(0)?,
                    hostname: row.get(1)?,
                    ip: row.get(2)?,
                    os_version: row.get(3)?,
                    agent_version: row.get(4)?,
                    last_heartbeat: row.get(5)?,
                    status: row.get(6)?,
                    registered_at: row.get(7)?,
                    fingerprint: row.get(8)?,
                    mac_addresses: row.get(9)?,
                    vpn_active: row.get(10)?,
                    domain_joined: row.get(11)?,
                    health_status: row.get(12)?,
                })
            },
        )
    }

    /// Updates the last heartbeat timestamp, sets status to `"online"`, and
    /// persists device identity fields for the given agent.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `agent_id` - Agent UUID to update.
    /// * `heartbeat` - ISO-8601 timestamp for the heartbeat.
    /// * `device_identity` - Optional endpoint identity from the heartbeat payload.
    ///   When `None`, defaults are used (empty fingerprint, empty MAC list, false flags, healthy).
    ///
    /// # Returns
    ///
    /// Returns the number of rows affected (0 means the agent was not found).
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the statement fails.
    pub fn update_heartbeat(
        uow: &UnitOfWork<'_>,
        agent_id: &str,
        heartbeat: &str,
        device_identity: Option<&dlp_common::EndpointIdentity>,
    ) -> rusqlite::Result<usize> {
        let (fingerprint, mac_addresses, vpn_active, domain_joined, health_status) =
            match device_identity {
                Some(id) => {
                    let macs = serde_json::to_string(&id.mac_addresses)
                        .unwrap_or_else(|_| "[]".to_string());
                    let health = serde_json::to_string(&id.health_status)
                        .unwrap_or_else(|_| "\"healthy\"".to_string())
                        .trim_matches('"')
                        .to_string();
                    (
                        id.fingerprint.clone(),
                        macs,
                        id.vpn_active,
                        id.domain_joined,
                        health,
                    )
                }
                None => (
                    "".to_string(),
                    "[]".to_string(),
                    false,
                    false,
                    "healthy".to_string(),
                ),
            };

        let rows = uow.tx.execute(
            "UPDATE agents SET
                last_heartbeat = ?1,
                status = 'online',
                fingerprint = ?3,
                mac_addresses = ?4,
                vpn_active = ?5,
                domain_joined = ?6,
                health_status = ?7
             WHERE agent_id = ?2",
            params![
                heartbeat,
                agent_id,
                fingerprint,
                mac_addresses,
                vpn_active,
                domain_joined,
                health_status,
            ],
        )?;
        Ok(rows)
    }

    /// Marks all agents as `"offline"` whose last heartbeat is older than the
    /// given cutoff timestamp.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `cutoff` - ISO-8601 timestamp; agents with `last_heartbeat < cutoff`
    ///   are marked offline.
    ///
    /// # Returns
    ///
    /// Returns the number of rows affected.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the statement fails.
    pub fn mark_stale_offline(uow: &UnitOfWork<'_>, cutoff: &str) -> rusqlite::Result<usize> {
        let rows = uow.tx.execute(
            "UPDATE agents SET status = 'offline', health_status = 'offline' \
             WHERE status = 'online' AND last_heartbeat < ?1",
            params![cutoff],
        )?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{new_pool, UnitOfWork};

    #[test]
    fn test_update_heartbeat_with_device_identity() {
        let pool = new_pool(":memory:").expect("create pool");
        let mut conn = pool.get().expect("acquire connection");
        let uow = UnitOfWork::new(&mut conn).expect("begin tx");

        // Seed an agent row.
        uow.tx
            .execute(
                "INSERT INTO agents (agent_id, hostname, ip, os_version, agent_version, \
                 last_heartbeat, status, registered_at) \
                 VALUES ('agent-1', 'host', '10.0.0.1', 'Windows 11', '0.1.0', \
                 '2026-01-01T00:00:00Z', 'online', '2026-01-01T00:00:00Z')",
                [],
            )
            .expect("insert agent");

        let identity = dlp_common::EndpointIdentity {
            fingerprint: "v1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            mac_addresses: vec!["AABBCCDDEEFF".to_string(), "001122334455".to_string()],
            vpn_active: true,
            domain_joined: true,
            health_status: dlp_common::DeviceHealthStatus::Healthy,
        };

        let rows = AgentRepository::update_heartbeat(
            &uow,
            "agent-1",
            "2026-06-07T12:00:00Z",
            Some(&identity),
        )
        .expect("update heartbeat");
        assert_eq!(rows, 1);

        let row: (String, String, i64, i64, String) = uow
            .tx
            .query_row(
                "SELECT fingerprint, mac_addresses, vpn_active, domain_joined, health_status \
                 FROM agents WHERE agent_id = 'agent-1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .expect("query row");

        assert_eq!(row.0, identity.fingerprint);
        assert_eq!(row.1, "[\"AABBCCDDEEFF\",\"001122334455\"]");
        assert_eq!(row.2, 1);
        assert_eq!(row.3, 1);
        assert_eq!(row.4, "healthy");
    }

    #[test]
    fn test_update_heartbeat_none_uses_defaults() {
        let pool = new_pool(":memory:").expect("create pool");
        let mut conn = pool.get().expect("acquire connection");
        let uow = UnitOfWork::new(&mut conn).expect("begin tx");

        // Seed an agent row with existing identity data.
        uow.tx
            .execute(
                "INSERT INTO agents (agent_id, hostname, ip, os_version, agent_version, \
                 last_heartbeat, status, registered_at, fingerprint, mac_addresses, \
                 vpn_active, domain_joined, health_status) \
                 VALUES ('agent-1', 'host', '10.0.0.1', 'Windows 11', '0.1.0', \
                 '2026-01-01T00:00:00Z', 'online', '2026-01-01T00:00:00Z', \
                 'v1:old', '[]', 1, 1, 'degraded')",
                [],
            )
            .expect("insert agent");

        let rows = AgentRepository::update_heartbeat(&uow, "agent-1", "2026-06-07T12:00:00Z", None)
            .expect("update heartbeat");
        assert_eq!(rows, 1);

        let row: (String, String, i64, i64, String) = uow
            .tx
            .query_row(
                "SELECT fingerprint, mac_addresses, vpn_active, domain_joined, health_status \
                 FROM agents WHERE agent_id = 'agent-1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .expect("query row");

        // None should overwrite with empty defaults per current behavior.
        assert_eq!(row.0, "");
        assert_eq!(row.1, "[]");
        assert_eq!(row.2, 0);
        assert_eq!(row.3, 0);
        assert_eq!(row.4, "healthy");
    }

    #[test]
    fn test_mark_stale_offline_sets_health_status() {
        let pool = new_pool(":memory:").expect("create pool");
        let mut conn = pool.get().expect("acquire connection");
        let uow = UnitOfWork::new(&mut conn).expect("begin tx");

        // Seed two agents: one stale, one fresh.
        uow.tx
            .execute(
                "INSERT INTO agents (agent_id, hostname, ip, os_version, agent_version, \
                 last_heartbeat, status, registered_at) \
                 VALUES ('stale', 'host', '10.0.0.1', 'Windows 11', '0.1.0', \
                 '2026-01-01T00:00:00Z', 'online', '2026-01-01T00:00:00Z')",
                [],
            )
            .expect("insert stale agent");
        uow.tx
            .execute(
                "INSERT INTO agents (agent_id, hostname, ip, os_version, agent_version, \
                 last_heartbeat, status, registered_at) \
                 VALUES ('fresh', 'host', '10.0.0.1', 'Windows 11', '0.1.0', \
                 '2099-01-01T00:00:00Z', 'online', '2026-01-01T00:00:00Z')",
                [],
            )
            .expect("insert fresh agent");

        let rows = AgentRepository::mark_stale_offline(&uow, "2026-06-01T00:00:00Z")
            .expect("mark stale offline");
        assert_eq!(rows, 1);

        let stale_status: (String, String) = uow
            .tx
            .query_row(
                "SELECT status, health_status FROM agents WHERE agent_id = 'stale'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query stale");
        assert_eq!(stale_status.0, "offline");
        assert_eq!(stale_status.1, "offline");

        let fresh_status: (String, String) = uow
            .tx
            .query_row(
                "SELECT status, health_status FROM agents WHERE agent_id = 'fresh'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query fresh");
        assert_eq!(fresh_status.0, "online");
        assert_eq!(fresh_status.1, "healthy");
    }
}
