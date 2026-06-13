//! Offline mode (T-18, F-AGT-11).
//!
//! Detects when the Policy Engine is unreachable and falls back to the local
//! [`Cache`](crate::cache::Cache).  When the engine comes back online,
//! reconnects automatically via a heartbeat loop.
//!
//! ## Fail-closed semantics
//!
//! - T3/T4 resources: DENY on cache miss (fail-closed).
//! - T1/T2 resources: ALLOW on cache miss (default-allow for non-sensitive).
//!
//! The caller should consult [`offline_decision`] when `EngineClient::evaluate`
//! fails with `EngineClientError::Unreachable`.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dlp_common::{AgentInfo, Classification, EvaluateRequest, EvaluateResponse};
use tracing::{debug, info, warn};

use crate::cache::{self, Cache};
use crate::engine_client::{EngineClient, EngineClientError};
use crate::server_client::ServerClient;

/// Default heartbeat interval for reconnection attempts.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Manages online/offline state for the Policy Engine connection.
///
/// When the engine is unreachable, the manager transitions to offline mode
/// and delegates decisions to the local cache.  A background heartbeat task
/// probes the engine periodically and restores online mode when it responds.
pub struct OfflineManager {
    /// `true` when the Policy Engine is reachable.
    online: Arc<AtomicBool>,
    /// The local decision cache.
    cache: Arc<Cache>,
    /// The HTTPS client to the Policy Engine.
    client: EngineClient,
    /// How often to probe the engine when offline.
    heartbeat_interval: Duration,
    /// Machine hostname, included in heartbeat probe requests.
    machine_name: Option<String>,
    /// Optional client for sending heartbeats to dlp-server.
    /// When set, each heartbeat iteration also pings the central server.
    server_client: Option<ServerClient>,
    /// Consecutive heartbeat failure counter (Phase 64).
    /// 3 failures = Degraded, 10 failures = Offline.
    heartbeat_failures: AtomicU8,
}

impl OfflineManager {
    /// Constructs a new manager.  Starts in online mode.
    ///
    /// # Arguments
    ///
    /// * `client` -- the HTTPS client to the Policy Engine
    /// * `cache` -- the shared policy decision cache
    /// * `machine_name` -- optional hostname for heartbeat probe requests
    pub fn new(client: EngineClient, cache: Arc<Cache>, machine_name: Option<String>) -> Self {
        Self {
            online: Arc::new(AtomicBool::new(true)),
            cache,
            client,
            heartbeat_interval: HEARTBEAT_INTERVAL,
            machine_name,
            server_client: None,
            heartbeat_failures: AtomicU8::new(0),
        }
    }

    /// Constructs a new manager with a custom heartbeat interval.
    #[must_use]
    pub fn with_heartbeat_interval(
        client: EngineClient,
        cache: Arc<Cache>,
        interval: Duration,
        machine_name: Option<String>,
    ) -> Self {
        Self {
            online: Arc::new(AtomicBool::new(true)),
            cache,
            client,
            heartbeat_interval: interval,
            machine_name,
            server_client: None,
            heartbeat_failures: AtomicU8::new(0),
        }
    }

    /// Attaches a `ServerClient` for sending heartbeats to dlp-server.
    ///
    /// When set, the heartbeat loop will also call
    /// `server_client.send_heartbeat()` every iteration.
    #[must_use]
    pub fn with_server_client(mut self, sc: ServerClient) -> Self {
        self.server_client = Some(sc);
        self
    }

    /// Returns `true` if the Policy Engine is currently considered reachable.
    #[must_use]
    pub fn is_online(&self) -> bool {
        self.online.load(Ordering::Acquire)
    }

    /// Evaluates a request, falling back to offline mode if the engine
    /// is unreachable.
    ///
    /// 1. If online, sends the request to the engine.
    ///    - On success, caches the result and returns it.
    ///    - On `Unreachable`, transitions to offline and falls through.
    /// 2. If offline, consults the local cache.
    ///    - On cache hit, returns the cached decision.
    ///    - On cache miss, returns [`cache::fail_closed_response`].
    pub async fn evaluate(&self, request: &EvaluateRequest) -> EvaluateResponse {
        if self.is_online() {
            match self.client.evaluate(request).await {
                Ok(response) => {
                    // Cache the successful response.
                    self.cache.insert(
                        &request.resource.path,
                        &request.subject.user_sid,
                        response.clone(),
                    );
                    return response;
                }
                Err(EngineClientError::Unreachable { .. }) => {
                    self.transition_offline();
                }
                Err(e) => {
                    warn!(error = %e, "engine error — falling back to cache");
                }
            }
        }

        // Offline: consult the cache.
        self.offline_decision(request)
    }

    /// Returns a decision from the local cache, or a fail-closed default.
    #[must_use]
    pub fn offline_decision(&self, request: &EvaluateRequest) -> EvaluateResponse {
        if let Some(cached) = self
            .cache
            .get(&request.resource.path, &request.subject.user_sid)
        {
            debug!(
                path = %request.resource.path,
                decision = ?cached.decision,
                "offline: cache hit"
            );
            return cached;
        }

        // Cache miss — apply fail-closed semantics.
        cache::fail_closed_response(request.resource.classification)
    }

    /// Runs the heartbeat loop that probes the engine when offline.
    ///
    /// Intended to run inside `tokio::spawn`.  Exits when the provided
    /// `shutdown` signal resolves.
    pub async fn heartbeat_loop(&self, shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut shutdown = shutdown;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(self.heartbeat_interval) => {}
                _ = shutdown.changed() => {
                    debug!("heartbeat loop shutting down");
                    return;
                }
            }

            // Best-effort heartbeat to dlp-server (independent of
            // Policy Engine online/offline state).
            let server_connected = if let Some(ref sc) = self.server_client {
                let endpoint_identity = crate::device_identity::build_endpoint_identity();
                let ok = sc.send_heartbeat(Some(&endpoint_identity)).await.is_ok();
                if ok {
                    // Success: reset failure counter and recover to Healthy if needed.
                    let prev_failures = self.heartbeat_failures.swap(0, Ordering::SeqCst);
                    if prev_failures > 0 {
                        info!(
                            prev_failures,
                            "dlp-server heartbeat recovered after failures"
                        );
                        let current = crate::device_identity::current_health();
                        if current != dlp_common::DeviceHealthStatus::Healthy {
                            let _ = crate::device_identity::transition_health_async(
                                dlp_common::DeviceHealthStatus::Healthy,
                            )
                            .await;
                        }
                    }
                } else {
                    // Failure: increment counter and trigger health transitions.
                    let failures = self.heartbeat_failures.fetch_add(1, Ordering::SeqCst) + 1;
                    warn!(failures, "dlp-server heartbeat failed (best-effort)");
                    if failures == 3 {
                        warn!(
                            failures,
                            "3 consecutive heartbeat failures -- transitioning to Degraded"
                        );
                        let _ = crate::device_identity::transition_health_async(
                            dlp_common::DeviceHealthStatus::Degraded,
                        )
                        .await;
                    } else if failures == 10 {
                        warn!(
                            failures,
                            "10 consecutive heartbeat failures -- transitioning to Offline"
                        );
                        let _ = crate::device_identity::transition_health_async(
                            dlp_common::DeviceHealthStatus::Offline,
                        )
                        .await;
                    }
                }
                ok
            } else {
                false
            };

            // When the server is reachable, drain the offline audit queue
            // and forward any queued events.  The atomic drain lock ensures
            // only one heartbeat iteration performs the drain at a time.
            //
            // All SQLite operations run inside spawn_blocking because
            // rusqlite::Connection is not Send.
            if server_connected && crate::offline_audit_queue::try_acquire_drain_lock() {
                let drain_result = tokio::task::spawn_blocking(|| {
                    let Some(mutex) = crate::service::agent_db() else {
                        return Ok(Vec::new());
                    };
                    let Ok(conn) = mutex.lock() else {
                        return Err("failed to lock agent DB".to_string());
                    };
                    match crate::offline_audit_queue::count(&conn) {
                        Ok(0) => Ok(Vec::new()),
                        Ok(n) if n > 0 => {
                            match crate::offline_audit_queue::drain(
                                &conn,
                                crate::offline_audit_queue::DEFAULT_BATCH_SIZE,
                            ) {
                                Ok(events) => Ok(events),
                                Err(e) => Err(format!("drain failed: {e}")),
                            }
                        }
                        _ => Ok(Vec::new()),
                    }
                })
                .await;

                match drain_result {
                    Ok(Ok(events)) if !events.is_empty() => {
                        let ids: Vec<i64> = events.iter().map(|(id, _)| *id).collect();
                        let json_events: Vec<String> =
                            events.into_iter().map(|(_, json)| json).collect();
                        // Forward to server via the existing HTTP client.
                        if let Some(ref sc) = self.server_client {
                            match sc.send_audit_events_json(&json_events).await {
                                Ok(_response) => {
                                    // Delete successfully forwarded events.
                                    let ids_clone = ids.clone();
                                    let delete_result = tokio::task::spawn_blocking(move || {
                                        let Some(mutex) = crate::service::agent_db() else {
                                            return Err("agent DB not available".to_string());
                                        };
                                        let Ok(conn) = mutex.lock() else {
                                            return Err("failed to lock agent DB".to_string());
                                        };
                                        crate::offline_audit_queue::delete(&conn, &ids_clone)
                                            .map_err(|e| format!("delete failed: {e}"))
                                    })
                                    .await;
                                    match delete_result {
                                        Ok(Ok(())) => {
                                            info!(
                                                count = ids.len(),
                                                "drained queued audit events to server"
                                            );
                                        }
                                        Ok(Err(e)) => {
                                            warn!(error = %e, "failed to delete forwarded events from queue");
                                        }
                                        Err(e) => {
                                            warn!(error = %e, "delete task panicked");
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(error = %e, "failed to forward drained events — will retry on next heartbeat");
                                }
                            }
                        }
                    }
                    Ok(Ok(_)) => {
                        // Queue empty — nothing to do.
                    }
                    Ok(Err(e)) => {
                        warn!(error = %e, "offline audit queue drain failed");
                    }
                    Err(e) => {
                        warn!(error = %e, "drain spawn_blocking task panicked");
                    }
                }
                crate::offline_audit_queue::release_drain_lock();
            }

            // Broadcast the current Agent->Server connection state to all UI clients.
            // The UI stores this atomically and displays it in the tray tooltip.
            // Fire-and-forget — no acknowledgement expected.
            crate::ipc::pipe2::BROADCASTER.broadcast(
                &crate::ipc::messages::Pipe2AgentMsg::ServerConnected {
                    connected: server_connected,
                },
            );

            if self.is_online() {
                continue;
            }

            // Probe the engine with a minimal request.
            debug!("heartbeat: probing Policy Engine");
            let probe = build_probe_request(self.machine_name.as_deref());
            match self.client.evaluate(&probe).await {
                Ok(_) => {
                    self.transition_online();
                }
                Err(_) => {
                    debug!("heartbeat: engine still unreachable");
                }
            }
        }
    }

    /// Transitions to offline mode.
    fn transition_offline(&self) {
        if self.online.swap(false, Ordering::AcqRel) {
            warn!("Policy Engine unreachable — entering offline mode");
        }
    }

    /// Transitions back to online mode.
    fn transition_online(&self) {
        if !self.online.swap(true, Ordering::AcqRel) {
            info!("Policy Engine reachable — resuming online mode");
        }
    }
}

/// Builds a minimal probe request for the heartbeat.
fn build_probe_request(machine_name: Option<&str>) -> EvaluateRequest {
    EvaluateRequest {
        subject: dlp_common::Subject {
            user_sid: "S-1-0-0".to_string(),
            user_name: "heartbeat-probe".to_string(),
            groups: Vec::new(),
            device_trust: dlp_common::DeviceTrust::Unknown,
            network_location: dlp_common::NetworkLocation::Unknown,
            device_health: dlp_common::DeviceHealthStatus::default(),
        },
        resource: dlp_common::Resource {
            path: "heartbeat-probe".to_string(),
            classification: Classification::T1,
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 0,
            access_context: dlp_common::AccessContext::Local,
        },
        action: dlp_common::Action::READ,
        agent: machine_name.map(|name| AgentInfo {
            machine_name: Some(name.to_string()),
            current_user: None,
        }),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlp_common::{AccessContext, Action, Decision, Environment, Resource, Subject};

    fn make_request(path: &str, sid: &str, cls: Classification) -> EvaluateRequest {
        EvaluateRequest {
            subject: Subject {
                user_sid: sid.to_string(),
                user_name: "testuser".to_string(),
                groups: Vec::new(),
                device_trust: dlp_common::DeviceTrust::Managed,
                network_location: dlp_common::NetworkLocation::Corporate,
                device_health: dlp_common::DeviceHealthStatus::default(),
            },
            resource: Resource {
                path: path.to_string(),
                classification: cls,
            },
            environment: Environment {
                timestamp: chrono::Utc::now(),
                session_id: 1,
                access_context: AccessContext::Local,
            },
            action: Action::WRITE,
            ..Default::default()
        }
    }

    fn make_response(decision: Decision) -> EvaluateResponse {
        EvaluateResponse {
            decision,
            matched_policy_id: None,
            reason: "test".to_string(),
            enforcement_mode: None,
            would_have_denied: decision.is_denied(),
            matched_label_id: None,
        }
    }

    #[test]
    fn test_offline_decision_cache_hit() {
        let cache = Arc::new(Cache::new());
        let client = EngineClient::default_client().unwrap();
        let manager = OfflineManager::new(client, cache.clone(), None);

        // Pre-populate cache.
        cache.insert(
            r"C:\Data\file.txt",
            "S-1-5-21-123",
            make_response(Decision::ALLOW),
        );

        let req = make_request(r"C:\Data\file.txt", "S-1-5-21-123", Classification::T2);
        let resp = manager.offline_decision(&req);
        assert_eq!(resp.decision, Decision::ALLOW);
    }

    #[test]
    fn test_offline_decision_cache_miss_t4_denied() {
        let cache = Arc::new(Cache::new());
        let client = EngineClient::default_client().unwrap();
        let manager = OfflineManager::new(client, cache, None);

        let req = make_request(
            r"C:\Restricted\secret.xlsx",
            "S-1-5-21-999",
            Classification::T4,
        );
        let resp = manager.offline_decision(&req);
        assert!(resp.decision.is_denied());
    }

    #[test]
    fn test_offline_decision_cache_miss_t1_allowed() {
        let cache = Arc::new(Cache::new());
        let client = EngineClient::default_client().unwrap();
        let manager = OfflineManager::new(client, cache, None);

        let req = make_request(r"C:\Public\readme.txt", "S-1-5-21-999", Classification::T1);
        let resp = manager.offline_decision(&req);
        assert!(!resp.decision.is_denied());
    }

    #[test]
    fn test_starts_online() {
        let cache = Arc::new(Cache::new());
        let client = EngineClient::default_client().unwrap();
        let manager = OfflineManager::new(client, cache, None);
        assert!(manager.is_online());
    }

    #[test]
    fn test_transition_offline_online() {
        let cache = Arc::new(Cache::new());
        let client = EngineClient::default_client().unwrap();
        let manager = OfflineManager::new(client, cache, None);

        manager.transition_offline();
        assert!(!manager.is_online());

        manager.transition_online();
        assert!(manager.is_online());
    }

    #[test]
    fn test_build_probe_request() {
        let probe = build_probe_request(None);
        assert_eq!(probe.subject.user_sid, "S-1-0-0");
        assert_eq!(probe.resource.classification, Classification::T1);
    }
}
