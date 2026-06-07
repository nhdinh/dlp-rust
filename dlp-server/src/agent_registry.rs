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

use crate::db::repositories::agents::AgentRow;
use crate::db::repositories::AgentRepository;
use crate::db::UnitOfWork;
use crate::AppError;
use crate::AppState;

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
    /// Device identity collected at runtime (fingerprint, MACs, VPN, domain, health).
    #[serde(default)]
    pub device_identity: Option<dlp_common::EndpointIdentity>,
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
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<AgentInfoResponse>, AppError> {
    if payload.agent_id.is_empty() {
        return Err(AppError::BadRequest("agent_id is required".to_string()));
    }

    let now = Utc::now().to_rfc3339();
    let agent_id = payload.agent_id.clone();
    let hostname = payload.hostname.clone();
    let ip = payload.ip.clone();
    let os_version = payload.os_version.clone();
    let agent_version = payload.agent_version.clone();
    let registered_at = now.clone();

    // Wrap synchronous SQLite access in spawn_blocking.
    let pool = Arc::clone(&state.pool);
    // Distinct clones for the closure (they move into spawn_blocking).
    let agent_id_for_sb = agent_id.clone();
    let hostname_for_sb = hostname.clone();
    let ip_for_sb = ip.clone();
    let os_version_for_sb = os_version.clone();
    let agent_version_for_sb = agent_version.clone();
    let registered_at_for_sb = registered_at.clone();

    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let record = AgentRow {
            agent_id: agent_id_for_sb,
            hostname: hostname_for_sb,
            ip: ip_for_sb,
            os_version: os_version_for_sb,
            agent_version: agent_version_for_sb,
            last_heartbeat: registered_at_for_sb.clone(),
            status: "online".to_string(),
            registered_at: registered_at_for_sb,
        };
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = UnitOfWork::new(&mut conn).map_err(AppError::from)?;
        AgentRepository::upsert(&uow, &record).map_err(AppError::from)?;
        uow.commit().map_err(AppError::from)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(agent_id = %agent_id, hostname = %hostname, ip = %ip, agent_version = %agent_version, "agent connected");
    Ok(Json(AgentInfoResponse {
        agent_id,
        hostname,
        ip,
        os_version,
        agent_version,
        last_heartbeat: registered_at.clone(),
        status: "online".to_string(),
        registered_at,
    }))
}

/// `POST /agents/{id}/heartbeat` — update last heartbeat, mark online.
///
/// # Errors
///
/// Returns `AppError::NotFound` if the agent is not registered.
pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    Json(payload): Json<HeartbeatRequest>,
) -> Result<StatusCode, AppError> {
    let now = Utc::now().to_rfc3339();
    let id = agent_id.clone();
    let pool = Arc::clone(&state.pool);

    // Validate device identity before passing to repository.
    let device_identity = validate_device_identity(&agent_id, payload.device_identity);

    let rows_updated = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = UnitOfWork::new(&mut conn).map_err(AppError::from)?;
        let rows = AgentRepository::update_heartbeat(
            &uow,
            &id,
            &now,
            device_identity.as_ref(),
        )
        .map_err(AppError::from)?;
        uow.commit().map_err(AppError::from)?;
        Ok(rows)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    if rows_updated == 0 {
        return Err(AppError::NotFound(format!(
            "agent {agent_id} not registered"
        )));
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Validates device identity fields from the heartbeat payload.
///
/// Returns `None` if validation fails (graceful degradation).
/// Emits structured `tracing::warn!` on validation failure.
fn validate_device_identity(
    agent_id: &str,
    device_identity: Option<dlp_common::EndpointIdentity>,
) -> Option<dlp_common::EndpointIdentity> {
    let Some(identity) = device_identity else {
        return None;
    };

    // Validate fingerprint format: v1: prefix + 64 lowercase hex chars.
    let fp = &identity.fingerprint;
    let fp_valid = fp.starts_with("v1:")
        && fp.len() == 67
        && fp[3..].chars().all(|c| c.is_ascii_hexdigit() && c.is_ascii_lowercase());
    if !fp_valid {
        tracing::warn!(
            agent_id = %agent_id,
            field = "fingerprint",
            reason = "must match ^v1:[0-9a-f]{64}$",
            "device identity validation failed"
        );
        return None;
    }

    // Validate MAC format: uppercase hex, no separators, 12 chars.
    if identity.mac_addresses.len() > 32 {
        tracing::warn!(
            agent_id = %agent_id,
            field = "mac_addresses",
            reason = "too many MACs (max 32)",
            "device identity validation failed"
        );
        return None;
    }
    for mac in &identity.mac_addresses {
        let mac_valid = mac.len() == 12
            && mac.chars().all(|c| c.is_ascii_hexdigit() && c.is_ascii_uppercase());
        if !mac_valid {
            tracing::warn!(
                agent_id = %agent_id,
                field = "mac_addresses",
                reason = "must match ^[0-9A-F]{12}$",
                "device identity validation failed"
            );
            return None;
        }
    }

    Some(identity)
}

/// `GET /agents` — list all registered agents.
///
/// # Errors
///
/// Returns `AppError::Database` on SQLite failures.
pub async fn list_agents(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<AgentInfoResponse>>, AppError> {
    let pool = Arc::clone(&state.pool);
    let repo_rows = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let rows = AgentRepository::list(&pool).map_err(AppError::from)?;
        Ok(rows)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    let agents: Vec<AgentInfoResponse> = repo_rows
        .into_iter()
        .map(|r| AgentInfoResponse {
            agent_id: r.agent_id,
            hostname: r.hostname,
            ip: r.ip,
            os_version: r.os_version,
            agent_version: r.agent_version,
            last_heartbeat: r.last_heartbeat,
            status: r.status,
            registered_at: r.registered_at,
            fingerprint: r.fingerprint,
            mac_addresses: r.mac_addresses,
            vpn_active: r.vpn_active,
            domain_joined: r.domain_joined,
            health_status: r.health_status,
        })
        .collect();

    Ok(Json(agents))
}

/// `GET /agents/{id}` — get a single agent's details.
///
/// # Errors
///
/// Returns `AppError::NotFound` if the agent does not exist.
pub async fn get_agent(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentInfoResponse>, AppError> {
    let id = agent_id.clone();
    let pool = Arc::clone(&state.pool);

    let agent = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let repo_row = AgentRepository::get_by_id(&pool, &id).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                AppError::NotFound(format!("agent {id} not registered"))
            }
            other => AppError::from(other),
        })?;
        Ok(AgentInfoResponse {
            agent_id: repo_row.agent_id,
            hostname: repo_row.hostname,
            ip: repo_row.ip,
            os_version: repo_row.os_version,
            agent_version: repo_row.agent_version,
            last_heartbeat: repo_row.last_heartbeat,
            status: repo_row.status,
            registered_at: repo_row.registered_at,
        })
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))?;

    match agent {
        Ok(a) => Ok(Json(a)),
        Err(AppError::NotFound(msg)) => Err(AppError::NotFound(msg)),
        Err(e) => Err(e),
    }
}

/// Spawns a background task that marks agents as "offline" if their
/// last heartbeat is older than 90 seconds.
///
/// This task runs every 30 seconds and never returns under normal
/// operation.
pub fn spawn_offline_sweeper(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));

        loop {
            interval.tick().await;

            let pool = Arc::clone(&state.pool);
            let result = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
                let cutoff = (Utc::now() - chrono::Duration::seconds(90)).to_rfc3339();
                let mut conn = pool.get().map_err(AppError::from)?;
                let uow = UnitOfWork::new(&mut conn).map_err(AppError::from)?;
                let rows =
                    AgentRepository::mark_stale_offline(&uow, &cutoff).map_err(AppError::from)?;
                uow.commit().map_err(AppError::from)?;
                Ok(rows)
            })
            .await;

            match result {
                Ok(Ok(count)) if count > 0 => {
                    tracing::info!(count, "marked agents offline (stale heartbeat)");
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
        let json = serde_json::to_string(&req).expect("serialize");
        let rt: RegisterRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(req.agent_id, rt.agent_id);
    }

    #[test]
    fn test_heartbeat_request_default() {
        let json = "{}";
        let req: HeartbeatRequest =
            serde_json::from_str(json).expect("deserialize empty heartbeat");
        assert!(req.status.is_none());
    }
}
