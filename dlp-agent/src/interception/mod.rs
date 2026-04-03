//! File interception engine (T-11).
//!
//! Monitors file system operations on the endpoint using the `notify` crate
//! (see [`file_monitor`](file_monitor::file_monitor)).  Captures CreateFile,
//! WriteFile, DeleteFile, and Rename/Move operations and forwards them
//! as [`FileAction`] events through a Tokio channel to the event loop.
//!
//! ## Audit event pipeline
//!
//! The [`run_event_loop`] function is the integration point between the file
//! monitor and the rest of the agent.  It:
//!
//!  1. Receives [`FileAction`] events from the file monitor.
//!  2. Resolves the user identity from the process PID.
//!  3. Evaluates the action against the Policy Engine (via [`OfflineManager`]).
//!  4. Emits an audit event to the local JSONL log.
//!  5. Sends a [`Pipe1AgentMsg::BlockNotify`] to the UI when the engine returns
//!     a blocking decision.

pub mod file_monitor;
pub mod policy_mapper;

pub use file_monitor::{FileAction, InterceptionEngine};

use std::sync::Arc;

use dlp_common::{
    AccessContext, AuditAccessContext, AuditEvent, Decision, Environment, EvaluateRequest,
    EventType, Resource, Subject,
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::audit_emitter::{self, emit_audit, EmitContext};
use crate::ipc::messages::Pipe1AgentMsg;
use crate::ipc::pipe1;
use crate::offline::OfflineManager;
use crate::session_identity::SessionIdentityMap;

/// Runs the file interception event loop.
///
/// This is the core audit pipeline integration point.  It receives [`FileAction`]
/// events from the file monitor via `rx`, evaluates each one, emits an audit
/// event, and — for blocking decisions — notifies the UI via Pipe 1.
///
/// Intended to run inside `tokio::spawn`.  Exits when `rx` is closed or an
/// unrecoverable error occurs.
///
/// # Arguments
///
/// * `rx` — channel receiving [`FileAction`] events from the file monitor
/// * `offline` — the shared offline manager (engine client + cache)
/// * `ctx` — shared audit context (agent_id, session)
/// * `session_map` — per-session identity map for resolving file owners
pub async fn run_event_loop(
    mut rx: mpsc::Receiver<FileAction>,
    offline: Arc<OfflineManager>,
    ctx: EmitContext,
    session_map: Arc<SessionIdentityMap>,
) {
    info!("interception event loop started");

    while let Some(action) = rx.recv().await {
        let action = action.clone();
        let path = action.path().to_string();
        let pid = action.process_id();

        // ── Resolve identity ───────────────────────────────────────────────
        let (user_sid, user_name) = {
            let (app_path, _app_hash) = audit_emitter::get_application_metadata(pid);
            debug!(pid, path = %path, ?app_path, "file action received");
            // Resolve the actual user from the file path using the
            // per-session identity map (path heuristic + single-user
            // fallback).
            session_map.resolve_for_path(&path)
        };

        let abac_action = PolicyMapper::action_for(&action);

        // ── Provisional classification (offline mode / extension layer) ───
        // provisional_classification always returns >= T1, so no max() needed.
        let classification = PolicyMapper::provisional_classification(&path);

        // ── Build evaluation request ──────────────────────────────────────
        let request = EvaluateRequest {
            subject: Subject {
                user_sid: user_sid.clone(),
                user_name: user_name.clone(),
                groups: Vec::new(),
                device_trust: dlp_common::DeviceTrust::Unknown,
                network_location: dlp_common::NetworkLocation::Unknown,
            },
            resource: Resource {
                path: path.clone(),
                classification,
            },
            environment: Environment {
                timestamp: chrono::Utc::now(),
                session_id: ctx.session_id,
                access_context: AccessContext::Local,
            },
            action: abac_action,
        };

        // ── Evaluate against Policy Engine ────────────────────────────────
        let response = offline.evaluate(&request).await;

        // ── Determine event type and decision ─────────────────────────────
        let response_reason = response.reason.clone();
        let response_policy_id = response.matched_policy_id.clone();
        let decision = response.decision;

        let event_type = match decision {
            Decision::ALLOW | Decision::AllowWithLog => EventType::Access,
            Decision::DENY => EventType::Block,
            Decision::DenyWithAlert => EventType::Alert,
        };

        let is_denied = decision.is_denied();

        // ── Emit audit event ───────────────────────────────────────────────
        let policy_id_str = response_policy_id.unwrap_or_default();
        let audit_event = AuditEvent::new(
            event_type,
            user_sid.clone(),
            user_name.clone(),
            path.clone(),
            classification,
            abac_action,
            decision,
            ctx.agent_id.clone(),
            ctx.session_id,
        )
        .with_access_context(AuditAccessContext::Local)
        .with_policy(policy_id_str.clone(), response_reason.clone());

        emit_audit(&ctx, &mut audit_event.clone());

        // ── UI notification for blocking decisions ──────────────────────────
        if is_denied {
            if let Err(e) = pipe1::send_to_ui(
                ctx.session_id,
                &Pipe1AgentMsg::BlockNotify {
                    reason: response_reason,
                    classification: classification.to_string(),
                    resource_path: path,
                    policy_id: policy_id_str,
                },
            ) {
                warn!(error = %e, session_id = ctx.session_id, "failed to send BlockNotify to UI");
            }
        }
    }

    info!("interception event loop exited");
}
pub use policy_mapper::PolicyMapper;
