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
    AccessContext, AgentInfo, AuditAccessContext, AuditEvent, Decision, Environment,
    EvaluateRequest, EventType, Resource, Subject, UsbTrustTier,
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::audit_emitter::{self, emit_audit, EmitContext};
use crate::disk_enforcer::DiskEnforcer;
use crate::identity::WindowsIdentity;
use crate::ipc::messages::{Pipe1AgentMsg, Pipe2AgentMsg};
use crate::ipc::pipe1;
use crate::offline::OfflineManager;
use crate::session_identity::SessionIdentityMap;
use crate::usb_enforcer::UsbEnforcer;

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
/// * `ad_client` — optional AD client for group/trust/location resolution (None = fallback to placeholder)
/// * `usb_enforcer` — optional USB trust-tier enforcer; fires before ABAC evaluation (None = USB enforcement disabled)
/// * `disk_enforcer` — optional fixed-disk write enforcer; fires after USB, before ABAC (None = disk enforcement disabled)
pub async fn run_event_loop(
    mut rx: mpsc::Receiver<FileAction>,
    offline: Arc<OfflineManager>,
    ctx: EmitContext,
    session_map: Arc<SessionIdentityMap>,
    ad_client: Arc<Option<dlp_common::AdClient>>,
    usb_enforcer: Option<Arc<UsbEnforcer>>,
    disk_enforcer: Option<Arc<DiskEnforcer>>,
) {
    info!("interception event loop started");

    while let Some(action) = rx.recv().await {
        let action = action.clone();
        let path = action.path().to_string();
        let pid = action.process_id();

        // ── Resolve identity ───────────────────────────────────────────────
        // Resolved early so that both the USB short-circuit path and the ABAC
        // path emit accurate user attribution in their audit events.
        let (user_sid, user_name) = {
            let (app_path, _app_hash) = audit_emitter::get_application_metadata(pid);
            debug!(pid, path = %path, ?app_path, "file action received");
            // Resolve the actual user from the file path using the
            // per-session identity map (path heuristic + single-user
            // fallback).
            session_map.resolve_for_path(&path)
        };

        // ── USB enforcement (pre-ABAC check) ─────────────────────────────
        // Fires before the ABAC engine. Blocked or ReadOnly+write operations
        // short-circuit here and emit an audit Block event (D-11).
        if let Some(ref enforcer) = usb_enforcer {
            if let Some(usb_result) = enforcer.check(&path, &action) {
                let mut audit_event = AuditEvent::new(
                    EventType::Block,
                    user_sid.clone(),
                    user_name.clone(),
                    path.clone(),
                    // Classification not yet resolved at this point; T1 is the
                    // conservative public-tier placeholder (not used for ABAC here).
                    dlp_common::Classification::T1,
                    // Action placeholder — USB check fires before action mapping.
                    dlp_common::Action::WRITE,
                    usb_result.decision,
                    ctx.agent_id.clone(),
                    ctx.session_id,
                )
                .with_access_context(AuditAccessContext::Local)
                .with_policy(
                    String::new(),
                    "USB enforcement: device blocked or read-only".to_string(),
                );

                emit_audit(&ctx, &mut audit_event);

                if usb_result.decision.is_denied() {
                    if let Err(e) = pipe1::send_to_ui(
                        ctx.session_id,
                        &Pipe1AgentMsg::BlockNotify {
                            reason: "USB enforcement: device blocked or read-only".to_string(),
                            classification: match usb_result.tier {
                                UsbTrustTier::Blocked => "USB-Blocked".to_string(),
                                UsbTrustTier::ReadOnly => "USB-ReadOnly".to_string(),
                                UsbTrustTier::FullAccess => {
                                    unreachable!("FullAccess never produces a block result")
                                }
                            },
                            resource_path: path.clone(),
                            policy_id: String::new(),
                        },
                    ) {
                        warn!(
                            error = %e,
                            session_id = ctx.session_id,
                            "failed to send USB BlockNotify to UI"
                        );
                    }
                }
                // USB-04: toast notification — fires only when per-drive cooldown has not suppressed it.
                if usb_result.notify {
                    let (title, body) = match usb_result.tier {
                        UsbTrustTier::Blocked => (
                            "USB Device Blocked".to_string(),
                            format!(
                                "{} - this device is not permitted",
                                usb_result.identity.description
                            ),
                        ),
                        UsbTrustTier::ReadOnly => (
                            "USB Device Read-Only".to_string(),
                            format!(
                                "{} - write operations are not permitted",
                                usb_result.identity.description
                            ),
                        ),
                        UsbTrustTier::FullAccess => {
                            unreachable!(
                                "FullAccess never returns a block result from UsbEnforcer::check"
                            )
                        }
                    };
                    crate::ipc::pipe2::BROADCASTER.broadcast(&Pipe2AgentMsg::Toast { title, body });
                }
                continue; // skip ABAC evaluation for this event
            }
        }

        // ── Disk enforcement (pre-ABAC check) ────────────────────────────
        // Fires after USB enforcement, before the ABAC engine. Blocks writes
        // to unregistered fixed disks (DISK-04, D-06, D-07). Uses `continue`
        // to skip ABAC evaluation when blocked, mirroring the USB pattern.
        if let Some(ref enforcer) = disk_enforcer {
            if let Some(disk_result) = enforcer.check(&path, &action) {
                let mut audit_event = AuditEvent::new(
                    EventType::Block,
                    user_sid.clone(),
                    user_name.clone(),
                    path.clone(),
                    // Classification not yet resolved at this stage; T1 is the
                    // conservative public-tier placeholder (AUDIT-02).
                    dlp_common::Classification::T1,
                    dlp_common::Action::WRITE,
                    disk_result.decision,
                    ctx.agent_id.clone(),
                    ctx.session_id,
                )
                .with_access_context(AuditAccessContext::Local)
                .with_policy(
                    String::new(),
                    "Disk enforcement: unregistered fixed disk".to_string(),
                )
                .with_blocked_disk(disk_result.disk.clone());

                emit_audit(&ctx, &mut audit_event);

                // AUDIT-02: Pipe 1 BlockNotify for SIEM / dashboard visibility.
                if disk_result.decision.is_denied() {
                    if let Err(e) = pipe1::send_to_ui(
                        ctx.session_id,
                        &Pipe1AgentMsg::BlockNotify {
                            reason: "Disk enforcement: unregistered fixed disk".to_string(),
                            classification: "Disk-Unregistered".to_string(),
                            resource_path: path.clone(),
                            policy_id: String::new(),
                        },
                    ) {
                        warn!(
                            error = %e,
                            session_id = ctx.session_id,
                            "failed to send disk BlockNotify to UI"
                        );
                    }
                }

                // Toast notification (D-02 per-drive 30-second cooldown embedded in DiskEnforcer).
                if disk_result.notify {
                    let drive_part = disk_result
                        .disk
                        .drive_letter
                        .map(|l| format!(" ({l}:)"))
                        .unwrap_or_default();
                    let body = format!(
                        "{}{drive_part} - this disk is not registered",
                        disk_result.disk.model
                    );
                    crate::ipc::pipe2::BROADCASTER.broadcast(&Pipe2AgentMsg::Toast {
                        title: "Unregistered Disk Blocked".to_string(),
                        body,
                    });
                }
                continue; // skip ABAC evaluation for this event
            }
        }

        let abac_action = PolicyMapper::action_for(&action);

        // ── Provisional classification (offline mode / extension layer) ───
        // provisional_classification always returns >= T1, so no max() needed.
        let classification = PolicyMapper::provisional_classification(&path);

        // ── Build evaluation request ──────────────────────────────────────
        let subject = if let Some(ref client) = *ad_client {
            let vpn_subnets = client.vpn_subnets_str();
            let identity = WindowsIdentity {
                sid: user_sid.clone(),
                username: user_name.clone(),
                primary_group: None,
            };
            identity.to_subject_with_ad(client, &vpn_subnets).await
        } else {
            // Fallback: placeholder values (no AD configured).
            Subject {
                user_sid: user_sid.clone(),
                user_name: user_name.clone(),
                groups: Vec::new(),
                device_trust: dlp_common::DeviceTrust::Unknown,
                network_location: dlp_common::NetworkLocation::Unknown,
            }
        };

        let request = EvaluateRequest {
            subject,
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
            agent: ctx.machine_name.as_ref().map(|machine_name| AgentInfo {
                machine_name: Some(machine_name.clone()),
                current_user: Some(user_name.clone()),
            }),
            ..Default::default()
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
        let mut audit_event = AuditEvent::new(
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

        emit_audit(&ctx, &mut audit_event);

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
