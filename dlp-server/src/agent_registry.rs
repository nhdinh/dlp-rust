//! Agent registration and heartbeat tracking (P5-T02).
//!
//! Endpoints register themselves on startup, then send periodic heartbeats.
//! Agents that miss a heartbeat window (90 s) are marked offline by a
//! background sweeper task.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::db::Database;
use crate::AppError;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Payload sent by a dlp-agent when it first registers with the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Unique identifier for this agent instance.
    pub agent_id: String,
    /// Machine hostname (e.g., "WORKSTATION-01").
    pub hostname: String,
    /// Agent's IP address.
    pub ip: String,
    /// Operating system version string.
    pub os_version: String,
    /// dlp-agent build version.
    pub agent_version: String,
}

/// Payload sent with each heartbeat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    /// Current agent status description (optional metadata).
    #[serde(default)]
    pub status: Option<String>,
}

/// Full agent record returned by list/get endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfoResponse {
    /// Unique agent identifier.
    pub agent_id: String,
    /// Machine hostname.
    pub hostname: String,
    /// Agent IP address.
    pub ip: String,
    /// OS version string.
    pub os_version: String,
    /// dlp-agent build version.
    pub agent_version: String,
    /// ISO 8601 timestamp of the last heartbeat.
    pub last_heartbeat: String,
    /// Current status: "online" or "offline".
    pub status: String,
    /// ISO 8601 timestamp when the agent first registered.
    pub registered_at: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /agents/register` — register a new agent or update an existing one.
///
/// # Errors
///
/// Returns `AppError::BadRequest` if required fields are empty.
/// Returns `AppError::Database` on SQLite failures.
pub async fn register_agent(
    State(db): State<Arc<Database>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<AgentInfoResponse>, AppError> {
    if payload.agent_id.is_empty() {
        return Err(AppError::BadRequest(
            "agent_id is required".to_string(),
        ));
    }

    let now = Utc::now().to_rfc3339();
    let agent_id = payload.agent_id.clone();
    let hostname = payload.hostname.clone();
    let ip = payload.ip.clone();
    let os_version = payload.os_version.clone();
    let agent_version = payload.agent_version.clone();
    let registered_at = now.clone();

    // Wrap synchronous SQLite access in spawn_blocking.
    let info = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let conn = db.conn().lock();
        conn.execute(
            "INSERT INTO agents \
                (agent_id, hostname, ip, os_version, agent_version, \
                 last_heartbeat, status, registered_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'online', ?7) \
             ON CONFLICT(agent_id) DO UPDATE SET \
                hostname = excluded.hostname, \
                ip = excluded.ip, \
                os_version = excluded.os_version, \
                agent_version = excluded.agent_version, \
                last_heartbeat = excluded.last_heartbeat, \
                status = 'online'",
            rusqlite::params![
                agent_id,
                hostname,
                ip,
                os_version,
                agent_version,
                registered_at,
                registered_at,
            ],
        )?;

        Ok(AgentInfoResponse {
            agent_id,
            hostname,
            ip,
            os_version,
            agent_version,
            last_heartbeat: registered_at.clone(),
            status: "online".to_string(),
            registered_at,
        })
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(agent_id = %info.agent_id, "agent registered");
    Ok(Json(info))
}

/// `POST /agents/{id}/heartbeat` — update last heartbeat, mark online.
///
/// # Errors
///
/// Returns `AppError::NotFound` if the agent is not registered.
pub async fn heartbeat(
    State(db): State<Arc<Database>>,
    Path(agent_id): Path<String>,
    Json(_payload): Json<HeartbeatRequest>,
) -> Result<StatusCode, AppError> {
    let now = Utc::now().to_rfc3339();
    let id = agent_id.clone();

    let rows_updated = tokio::task::spawn_blocking(move || {
        let conn = db.conn().lock();
        conn.execute(
            "UPDATE agents SET last_heartbeat = ?1, status = 'online' \
             WHERE agent_id = ?2",
            rusqlite::params![now, id],
        )
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    if rows_updated == 0 {
        return Err(AppError::NotFound(
            format!("agent {agent_id} not registered"),
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /agents` — list all registered agents.
///
/// # Errors
///
/// Returns `AppError::Database` on SQLite failures.
pub async fn list_agents(
    State(db): State<Arc<Database>>,
) -> Result<Json<Vec<AgentInfoResponse>>, AppError> {
    let agents = tokio::task::spawn_blocking(move || {
        let conn = db.conn().lock();
        let mut stmt = conn.prepare(
            "SELECT agent_id, hostname, ip, os_version, \
                    agent_version, last_heartbeat, status, \
                    registered_at \
             FROM agents ORDER BY hostname",
        )?;

        let rows = stmt
            .query_map([], |row| {
                Ok(AgentInfoResponse {
                    agent_id: row.get(0)?,
                    hostname: row.get(1)?,
                    ip: row.get(2)?,
                    os_version: row.get(3)?,
                    agent_version: row.get(4)?,
                    last_heartbeat: row.get(5)?,
                    status: row.get(6)?,
                    registered_at: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok::<_, rusqlite::Error>(rows)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(agents))
}

/// `GET /agents/{id}` — get a single agent's details.
///
/// # Errors
///
/// Returns `AppError::NotFound` if the agent does not exist.
pub async fn get_agent(
    State(db): State<Arc<Database>>,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentInfoResponse>, AppError> {
    let id = agent_id.clone();

    let agent = tokio::task::spawn_blocking(move || {
        let conn = db.conn().lock();
        conn.query_row(
            "SELECT agent_id, hostname, ip, os_version, \
                    agent_version, last_heartbeat, status, \
                    registered_at \
             FROM agents WHERE agent_id = ?1",
            rusqlite::params![id],
            |row| {
                Ok(AgentInfoResponse {
                    agent_id: row.get(0)?,
                    hostname: row.get(1)?,
                    ip: row.get(2)?,
                    os_version: row.get(3)?,
                    agent_version: row.get(4)?,
                    last_heartbeat: row.get(5)?,
                    status: row.get(6)?,
                    registered_at: row.get(7)?,
                })
            },
        )
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))?;

    match agent {
        Ok(a) => Ok(Json(a)),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            Err(AppError::NotFound(
                format!("agent {agent_id} not found"),
            ))
        }
        Err(e) => Err(AppError::Database(e)),
    }
}

/// Spawns a background task that marks agents as "offline" if their
/// last heartbeat is older than 90 seconds.
///
/// This task runs every 30 seconds and never returns under normal
/// operation.
pub fn spawn_offline_sweeper(db: Arc<Database>) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(30));

        loop {
            interval.tick().await;

            let db = Arc::clone(&db);
            let result = tokio::task::spawn_blocking(move || {
                let cutoff = (Utc::now()
                    - chrono::Duration::seconds(90))
                .to_rfc3339();
                let conn = db.conn().lock();
                conn.execute(
                    "UPDATE agents SET status = 'offline' \
                     WHERE status = 'online' \
                       AND last_heartbeat < ?1",
                    rusqlite::params![cutoff],
                )
            })
            .await;

            match result {
                Ok(Ok(count)) if count > 0 => {
                    tracing::info!(
                        count,
                        "marked agents offline (stale heartbeat)"
                    );
                }
                Ok(Err(e)) => {
                    tracing::error!("offline sweeper db error: {e}");
                }
                Err(e) => {
                    tracing::error!("offline sweeper join error: {e}");
                }
                _ => {} // count == 0, nothing to log
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_request_serde() {
        let req = RegisterRequest {
            agent_id: "AGENT-001".to_string(),
            hostname: "WS01".to_string(),
            ip: "10.0.0.1".to_string(),
            os_version: "Windows 11".to_string(),
            agent_version: "0.1.0".to_string(),
        };
        let json = serde_json::to_string(&req)
            .expect("serialize");
        let rt: RegisterRequest = serde_json::from_str(&json)
            .expect("deserialize");
        assert_eq!(req.agent_id, rt.agent_id);
    }

    #[test]
    fn test_heartbeat_request_default() {
        let json = "{}";
        let req: HeartbeatRequest = serde_json::from_str(json)
            .expect("deserialize empty heartbeat");
        assert!(req.status.is_none());
    }
}
