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

pub mod drag_drop;
pub mod file_monitor;
pub mod policy_mapper;

pub use drag_drop::{
    init_emit_context as init_drag_drop_emit_context, install_drag_drop_hook,
    uninstall_drag_drop_hook, DragDropEnforcer,
};
pub use file_monitor::{FileAction, InterceptionEngine};

use std::sync::Arc;

use dlp_common::{
    AccessContext, AgentInfo, AuditAccessContext, AuditEvent, Decision, Environment,
    EvaluateRequest, EventType, Resource, Subject, UsbTrustTier,
};
// EnforcementMode is used via dlp_common::abac::EnforcementMode at call sites
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::audit_emitter::{self, emit_audit, EmitContext};
use crate::cloud_enforcer::CloudEnforcer;
use crate::disk_enforcer::DiskEnforcer;
use crate::identity::WindowsIdentity;
use crate::ipc::messages::{Pipe1AgentMsg, Pipe2AgentMsg};
use crate::ipc::pipe1;
use crate::offline::OfflineManager;
use crate::session_identity::SessionIdentityMap;
use crate::usb_enforcer::UsbEnforcer;

/// Builds the classification string for a USB trust tier.
fn usb_classification(tier: UsbTrustTier) -> String {
    match tier {
        UsbTrustTier::Blocked => "USB-Blocked".to_string(),
        UsbTrustTier::ReadOnly => "USB-ReadOnly".to_string(),
        UsbTrustTier::FullAccess => {
            unreachable!("FullAccess never produces a block result")
        }
    }
}

/// Builds the toast title and body for a USB block result.
fn usb_toast_message(usb_result: &crate::usb_enforcer::UsbBlockResult) -> (String, String) {
    match usb_result.tier {
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
            unreachable!("FullAccess never returns a block result from UsbEnforcer::check")
        }
    }
}

/// Emits a USB block audit event and notifies the UI.
fn handle_usb_block(
    ctx: &EmitContext,
    user_sid: &str,
    user_name: &str,
    path: &str,
    pid: u32,
    usb_result: &crate::usb_enforcer::UsbBlockResult,
) {
    let mut audit_event = AuditEvent::new(
        EventType::Block,
        user_sid.to_string(),
        user_name.to_string(),
        path.to_string(),
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
    .with_device_identity(Some(usb_result.identity.clone()))
    .with_owner(usb_result.owner_sid.clone(), usb_result.owner_user.clone());
    // WR-03: no policy matched this enforcement — leave policy_id as None
    // so SIEM rules that test `policy_id IS NOT NULL` are not misled.
    // Set only policy_name to convey the enforcement reason.
    audit_event.policy_name = Some("USB enforcement: device blocked or read-only".to_string());

    // AUDIT-04 (Phase 42): Enrich with app identity from the initiating process.
    crate::audit_emitter::enrich_audit_with_app_identity(&mut audit_event, pid);
    crate::audit_emitter::set_destination_application(&mut audit_event, None);

    emit_audit(ctx, &mut audit_event);

    if usb_result.decision.is_denied() {
        let msg = Pipe1AgentMsg::BlockNotify {
            reason: "USB enforcement: device blocked or read-only".to_string(),
            classification: usb_classification(usb_result.tier),
            resource_path: path.to_string(),
            policy_id: String::new(),
        };
        if let Err(e) = pipe1::send_to_ui(ctx.session_id, &msg) {
            warn!(
                error = %e,
                session_id = ctx.session_id,
                "failed to send USB BlockNotify to UI"
            );
        }
    }

    // USB-04: toast notification — fires only when per-drive cooldown has not suppressed it.
    if usb_result.notify {
        let (title, body) = usb_toast_message(usb_result);
        crate::ipc::pipe2::BROADCASTER.broadcast(&Pipe2AgentMsg::Toast { title, body });
    }
}

/// Emits a disk block audit event and notifies the UI.
fn handle_disk_block(
    ctx: &EmitContext,
    user_sid: &str,
    user_name: &str,
    path: &str,
    pid: u32,
    disk_result: &crate::disk_enforcer::DiskBlockResult,
) {
    let mut audit_event = AuditEvent::new(
        EventType::Block,
        user_sid.to_string(),
        user_name.to_string(),
        path.to_string(),
        // Classification not yet resolved at this stage; T1 is the
        // conservative public-tier placeholder (AUDIT-02).
        dlp_common::Classification::T1,
        dlp_common::Action::WRITE,
        disk_result.decision,
        ctx.agent_id.clone(),
        ctx.session_id,
    )
    .with_access_context(AuditAccessContext::Local)
    .with_blocked_disk(disk_result.disk.clone());
    // WR-03: no policy matched this enforcement — leave policy_id as None
    // so SIEM rules that test `policy_id IS NOT NULL` are not misled.
    // Set only policy_name to convey the enforcement reason.
    audit_event.policy_name = Some("Disk enforcement: unregistered fixed disk".to_string());

    // AUDIT-04 (Phase 42): Enrich with app identity from the initiating process.
    crate::audit_emitter::enrich_audit_with_app_identity(&mut audit_event, pid);
    crate::audit_emitter::set_destination_application(&mut audit_event, None);

    emit_audit(ctx, &mut audit_event);

    // AUDIT-02: Pipe 1 BlockNotify for SIEM / dashboard visibility.
    if disk_result.decision.is_denied() {
        let msg = Pipe1AgentMsg::BlockNotify {
            reason: "Disk enforcement: unregistered fixed disk".to_string(),
            classification: "Disk-Unregistered".to_string(),
            resource_path: path.to_string(),
            policy_id: String::new(),
        };
        if let Err(e) = pipe1::send_to_ui(ctx.session_id, &msg) {
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
}

/// Emits a cloud block audit event and notifies the UI.
fn handle_cloud_block(
    ctx: &EmitContext,
    user_sid: &str,
    user_name: &str,
    path: &str,
    pid: u32,
    cloud_result: &crate::cloud_enforcer::CloudBlockResult,
) {
    let mut audit_event = AuditEvent::new(
        EventType::Block,
        user_sid.to_string(),
        user_name.to_string(),
        path.to_string(),
        // Classification not yet resolved at this stage; T1 is the
        // conservative public-tier placeholder (AUDIT-02).
        dlp_common::Classification::T1,
        dlp_common::Action::CLOUD_UPLOAD,
        cloud_result.decision,
        ctx.agent_id.clone(),
        ctx.session_id,
    )
    .with_access_context(AuditAccessContext::Local);
    // WR-03: no policy matched this enforcement — leave policy_id as None.
    audit_event.policy_name = Some(cloud_result.reason.clone());

    // AUDIT-04 (Phase 42): Enrich with app identity from the initiating process.
    crate::audit_emitter::enrich_audit_with_app_identity(&mut audit_event, pid);
    crate::audit_emitter::set_destination_application(&mut audit_event, None);

    emit_audit(ctx, &mut audit_event);

    // AUDIT-02: Pipe 1 BlockNotify for SIEM / dashboard visibility.
    if cloud_result.decision.is_denied() {
        let msg = Pipe1AgentMsg::BlockNotify {
            reason: cloud_result.reason.clone(),
            classification: format!("Cloud-{}", cloud_result.provider),
            resource_path: path.to_string(),
            policy_id: String::new(),
        };
        if let Err(e) = pipe1::send_to_ui(ctx.session_id, &msg) {
            warn!(
                error = %e,
                session_id = ctx.session_id,
                "failed to send cloud BlockNotify to UI"
            );
        }
    }

    // Toast notification.
    if cloud_result.notify {
        crate::ipc::pipe2::BROADCASTER.broadcast(&Pipe2AgentMsg::Toast {
            title: "Cloud Sync Blocked".to_string(),
            body: format!("{} — upload to {} is blocked", path, cloud_result.provider),
        });
    }
}

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
/// * `cloud_enforcer` — optional cloud sync enforcer; fires after disk, before ABAC (None = cloud enforcement disabled)
#[allow(clippy::too_many_arguments)]
pub async fn run_event_loop(
    mut rx: mpsc::Receiver<FileAction>,
    offline: Arc<OfflineManager>,
    ctx: EmitContext,
    session_map: Arc<SessionIdentityMap>,
    ad_client: Arc<Option<dlp_common::AdClient>>,
    usb_enforcer: Option<Arc<UsbEnforcer>>,
    disk_enforcer: Option<Arc<DiskEnforcer>>,
    cloud_enforcer: Option<Arc<CloudEnforcer>>,
    _approval_cache: Option<Arc<crate::approval_cache::ApprovalCache>>,
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
                handle_usb_block(&ctx, &user_sid, &user_name, &path, pid, &usb_result);
                continue; // skip ABAC evaluation for this event
            }
        }

        // ── Disk enforcement (pre-ABAC check) ────────────────────────────
        // Fires after USB enforcement, before the ABAC engine. Blocks writes
        // to unregistered fixed disks (DISK-04, D-06, D-07). Uses `continue`
        // to skip ABAC evaluation when blocked, mirroring the USB pattern.
        if let Some(ref enforcer) = disk_enforcer {
            if let Some(disk_result) = enforcer.check(&path, &action) {
                handle_disk_block(&ctx, &user_sid, &user_name, &path, pid, &disk_result);
                continue; // skip ABAC evaluation for this event
            }
        }

        // ── Cloud enforcement (pre-ABAC check) ───────────────────────────
        // Fires after disk enforcement, before the ABAC engine. Resolves
        // classification via PolicyMapper before calling check() so the
        // enforcer does not need to infer sensitivity from path text.
        // provisional_classification is infallible; if a future evaluator
        // integration introduces a fallible path, fail open with T2 to avoid
        // blocking legitimate I/O on evaluator unavailability (ADR: M017/S02).
        if let Some(ref enforcer) = cloud_enforcer {
            let cloud_classification = PolicyMapper::provisional_classification(&path);
            tracing::trace!(
                path_hash = %fnv1a_hex(&path),
                classification = ?cloud_classification,
                "cloud enforcer: classification resolved"
            );
            if let Some(cloud_result) = enforcer.check(&path, &action, cloud_classification) {
                handle_cloud_block(&ctx, &user_sid, &user_name, &path, pid, &cloud_result);
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
                device_health: dlp_common::DeviceHealthStatus::default(),
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

        // ── Compute effective enforcement mode (Phase 55) ─────────────────
        // Read global mode from config; default to Block if config unavailable (fail-safe).
        let global_mode = crate::service::with_config(|cfg| cfg.enforcement.global_mode)
            .unwrap_or(dlp_common::abac::EnforcementMode::Block);

        let policy_mode = response
            .enforcement_mode
            .unwrap_or(dlp_common::abac::EnforcementMode::Block);
        let effective_mode = dlp_common::abac::compute_effective_mode(global_mode, policy_mode);

        // ── Determine final decision based on effective mode ──────────────
        // Audit mode: always ALLOW the physical operation, but record what would have happened.
        let mut final_decision = if effective_mode.is_audit() {
            Decision::ALLOW
        } else {
            response.decision
        };

        let mut response_reason = response.reason.clone();
        let response_policy_id = response.matched_policy_id.clone();

        // Stage 3: Approval cache override (only when blocking and DENY).
        // Audit mode short-circuits before this check (avoids unnecessary JWT verification).
        let mut override_granted = false;
        let mut override_claims: Option<dlp_common::approval::ApprovalClaims> = None;
        if effective_mode.is_blocking() && final_decision.is_denied() {
            if let Some(ref ac) = _approval_cache {
                if let Some((ovr, claims)) = crate::approval_cache::check_approval_override(
                    ac,
                    &response,
                    &user_sid,
                    &format!("{:?}", abac_action),
                    None, // TODO: derive dst from operation context for copy/move to external destinations
                ) {
                    final_decision = ovr.decision;
                    override_granted = true;
                    override_claims = Some(claims);
                    debug!(
                        sid = %user_sid,
                        label_id = ?response.matched_label_id,
                        "approval override granted"
                    );
                } else {
                    debug!(
                        sid = %user_sid,
                        label_id = ?response.matched_label_id,
                        "approval override missed — keeping DENY"
                    );
                    // Annotate block reason when a label matched but no approval exists.
                    if response.matched_label_id.is_some() {
                        response_reason = format!("{} — no active approval", response_reason);
                    }
                }
            }
        }

        let is_denied = final_decision.is_denied();

        // Event type reflects the physical operation outcome, not the policy intent.
        let event_type = match final_decision {
            Decision::ALLOW | Decision::AllowWithLog => EventType::Access,
            Decision::DENY => EventType::Block,
            Decision::DenyWithAlert => EventType::Alert,
        };

        // ── Emit enriched audit event ──────────────────────────────────────
        let policy_id_str = if override_granted {
            override_claims
                .as_ref()
                .map(|c| format!("approval:{}", c.jti))
                .unwrap_or_default()
        } else {
            response_policy_id.unwrap_or_default()
        };

        let mut audit_event = AuditEvent::new(
            if override_granted {
                EventType::ApprovalOverride
            } else {
                event_type
            },
            user_sid.clone(),
            user_name.clone(),
            path.clone(),
            classification,
            abac_action,
            final_decision,
            ctx.agent_id.clone(),
            ctx.session_id,
        )
        .with_access_context(AuditAccessContext::Local)
        .with_policy(policy_id_str.clone(), response_reason.clone())
        .with_policy_mode(format!("{:?}", effective_mode))
        .with_would_have_denied(if override_granted {
            true
        } else {
            response.would_have_denied
        });

        if override_granted {
            if let Some(ref claims) = override_claims {
                audit_event.approver_sid = Some(claims.sub.clone());
                audit_event.approval_expiry = Some(claims.exp);
                audit_event.justification = Some(
                    claims
                        .dst
                        .clone()
                        .unwrap_or_else(|| "pre-approved".to_string()),
                );
                audit_event.override_granted = true;
            }
        }

        // AUDIT-04 (Phase 42): Enrich with app identity from the initiating process.
        crate::audit_emitter::enrich_audit_with_app_identity(&mut audit_event, pid);
        crate::audit_emitter::set_destination_application(&mut audit_event, None);

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

/// FNV-1a 64-bit hash of a string, returned as a lowercase hex string.
///
/// Used to log a non-sensitive path identifier in audit traces without
/// exposing the raw path in log sinks that forward to external systems.
fn fnv1a_hex(s: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

pub use policy_mapper::PolicyMapper;

/// Computes the effective decision after considering the approval cache override.
///
/// This is a pure function extracted from `run_event_loop` for testability.
/// It encapsulates the Stage 3 approval cache override logic.
///
/// # Arguments
///
/// * `initial_decision` — the decision after effective mode computation.
/// * `effective_mode` — the computed effective enforcement mode.
/// * `response` — the ABAC evaluation response (contains matched_label_id).
/// * `approval_cache` — optional reference to the approval cache.
/// * `user_sid` — the requesting user's SID.
/// * `action_str` — the action as a string (e.g. "WRITE").
///
/// # Returns
///
/// `(final_decision, override_granted, override_claims, annotated_reason)`
#[must_use]
#[allow(clippy::type_complexity)]
#[allow(dead_code)]
fn compute_override_decision(
    initial_decision: Decision,
    effective_mode: dlp_common::abac::EnforcementMode,
    response: &dlp_common::EvaluateResponse,
    approval_cache: Option<&crate::approval_cache::ApprovalCache>,
    user_sid: &str,
    action_str: &str,
) -> (
    Decision,
    bool,
    Option<dlp_common::approval::ApprovalClaims>,
    String,
) {
    let mut final_decision = initial_decision;
    let mut override_granted = false;
    let mut override_claims: Option<dlp_common::approval::ApprovalClaims> = None;
    let mut annotated_reason = response.reason.clone();

    if effective_mode.is_blocking() && final_decision.is_denied() {
        if let Some(ac) = approval_cache {
            if let Some((ovr, claims)) = crate::approval_cache::check_approval_override(
                ac, response, user_sid, action_str, None,
            ) {
                final_decision = ovr.decision;
                override_granted = true;
                override_claims = Some(claims);
            } else if response.matched_label_id.is_some() {
                annotated_reason = format!("{} — no active approval", annotated_reason);
            }
        }
    }

    (
        final_decision,
        override_granted,
        override_claims,
        annotated_reason,
    )
}

#[cfg(test)]
mod tests {
    use dlp_common::abac::{compute_effective_mode, EnforcementMode};

    #[test]
    fn test_compute_effective_mode_audit_overrides_block() {
        let effective = compute_effective_mode(EnforcementMode::Audit, EnforcementMode::Block);
        assert_eq!(effective, EnforcementMode::Audit);
    }

    #[test]
    fn test_compute_effective_mode_block_overrides_audit() {
        let effective = compute_effective_mode(EnforcementMode::Block, EnforcementMode::Audit);
        assert_eq!(effective, EnforcementMode::Block);
    }

    #[test]
    fn test_compute_effective_mode_perpolicy_defersto_policy() {
        let effective = compute_effective_mode(EnforcementMode::PerPolicy, EnforcementMode::Audit);
        assert_eq!(effective, EnforcementMode::Audit);
    }

    #[test]
    fn test_compute_effective_mode_perpolicy_defersto_block() {
        let effective = compute_effective_mode(EnforcementMode::PerPolicy, EnforcementMode::Block);
        assert_eq!(effective, EnforcementMode::Block);
    }

    // ── Approval override integration tests ───────────────────────────────

    use super::*;

    #[test]
    fn test_compute_override_decision_no_cache_keeps_deny() {
        let response = dlp_common::EvaluateResponse {
            decision: Decision::DENY,
            matched_policy_id: Some("policy-1".to_string()),
            reason: "default deny".to_string(),
            enforcement_mode: None,
            would_have_denied: false,
            matched_label_id: Some("label-001".to_string()),
        };

        let (final_decision, override_granted, claims, reason) = compute_override_decision(
            Decision::DENY,
            EnforcementMode::Block,
            &response,
            None,
            "S-1-5-21-1",
            "WRITE",
        );

        assert_eq!(final_decision, Decision::DENY);
        assert!(!override_granted);
        assert!(claims.is_none());
        // No approval cache configured — reason is NOT annotated.
        assert_eq!(reason, "default deny");
    }

    #[test]
    fn test_compute_override_decision_empty_cache_annotates_reason() {
        // When approval cache is Some but empty, and a label matched,
        // the reason is annotated with "no active approval".
        let response = dlp_common::EvaluateResponse {
            decision: Decision::DENY,
            matched_policy_id: Some("policy-1".to_string()),
            reason: "default deny".to_string(),
            enforcement_mode: None,
            would_have_denied: false,
            matched_label_id: Some("label-001".to_string()),
        };

        let cache = crate::approval_cache::ApprovalCache::new();

        let (final_decision, override_granted, claims, reason) = compute_override_decision(
            Decision::DENY,
            EnforcementMode::Block,
            &response,
            Some(&cache),
            "S-1-5-21-1",
            "WRITE",
        );

        assert_eq!(final_decision, Decision::DENY);
        assert!(!override_granted);
        assert!(claims.is_none());
        assert_eq!(reason, "default deny — no active approval");
    }

    #[test]
    fn test_compute_override_decision_audit_mode_skips_check() {
        let response = dlp_common::EvaluateResponse {
            decision: Decision::DENY,
            matched_policy_id: Some("policy-1".to_string()),
            reason: "default deny".to_string(),
            enforcement_mode: None,
            would_have_denied: false,
            matched_label_id: Some("label-001".to_string()),
        };

        let cache = crate::approval_cache::ApprovalCache::new();

        let (final_decision, override_granted, claims, reason) = compute_override_decision(
            Decision::ALLOW, // audit mode short-circuits to ALLOW before override
            EnforcementMode::Audit,
            &response,
            Some(&cache),
            "S-1-5-21-1",
            "WRITE",
        );

        // Audit mode: decision is already ALLOW, override check is skipped.
        assert_eq!(final_decision, Decision::ALLOW);
        assert!(!override_granted);
        assert!(claims.is_none());
        assert_eq!(reason, "default deny");
    }

    #[test]
    fn test_compute_override_decision_no_label_id_skips_reason_annotation() {
        // When matched_label_id is None (offline mode / no label resolution),
        // the cache check is skipped and no reason annotation occurs.
        let response = dlp_common::EvaluateResponse {
            decision: Decision::DENY,
            matched_policy_id: None,
            reason: "offline mode".to_string(),
            enforcement_mode: None,
            would_have_denied: false,
            matched_label_id: None,
        };

        let cache = crate::approval_cache::ApprovalCache::new();

        let (final_decision, override_granted, claims, reason) = compute_override_decision(
            Decision::DENY,
            EnforcementMode::Block,
            &response,
            Some(&cache),
            "S-1-5-21-1",
            "WRITE",
        );

        assert_eq!(final_decision, Decision::DENY);
        assert!(!override_granted);
        assert!(claims.is_none());
        // No "no active approval" annotation because matched_label_id is None.
        assert_eq!(reason, "offline mode");
    }

    #[test]
    fn test_compute_override_decision_allow_bypasses_check() {
        // When initial decision is already ALLOW, override check is skipped.
        let response = dlp_common::EvaluateResponse {
            decision: Decision::ALLOW,
            matched_policy_id: Some("policy-1".to_string()),
            reason: "allowed".to_string(),
            enforcement_mode: None,
            would_have_denied: false,
            matched_label_id: Some("label-001".to_string()),
        };

        let cache = crate::approval_cache::ApprovalCache::new();

        let (final_decision, override_granted, claims, reason) = compute_override_decision(
            Decision::ALLOW,
            EnforcementMode::Block,
            &response,
            Some(&cache),
            "S-1-5-21-1",
            "WRITE",
        );

        assert_eq!(final_decision, Decision::ALLOW);
        assert!(!override_granted);
        assert!(claims.is_none());
        assert_eq!(reason, "allowed");
    }
}
