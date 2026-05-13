//! Admin and agent HTTP API for approval lifecycle management.
//!
//! Provides endpoints for:
//! - Admin: list, create, get, grant, reject, revoke approvals
//! - Agent: submit approval requests, sync active approvals, get public key
//!
//! T4 Board digital signature verification happens at grant time.
//! All state changes emit audit events and alerts.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use dlp_common::{Approval, ApprovalClaims, ApprovalStatus};

use crate::audit_store;
use crate::db::repositories::{
    approvals::{ApprovalRepository, ApprovalRow, ApprovalUpsertRow},
    labels::LabelRepository,
};
use crate::db::UnitOfWork;
use crate::AppError;
use crate::AppState;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Query parameters for `GET /admin/approvals`.
#[derive(Debug, Clone, Deserialize)]
pub struct ApprovalListQuery {
    /// Optional status filter (pending, approved, rejected, revoked, expired).
    pub status: Option<String>,
    /// 1-based page number, default 1.
    pub page: Option<u32>,
    /// Items per page, default 50, max 100.
    pub per_page: Option<u32>,
}

/// Request body for `POST /admin/approvals`.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateApprovalRequest {
    /// AD SID of the requesting user.
    pub requester_sid: String,
    /// FK to labels.id (soft reference).
    pub data_object_id: String,
    /// Action being approved (e.g. "WRITE", "COPY").
    pub allowed_action: String,
    /// Where the data can go (None = any).
    pub destination_scope: Option<String>,
    /// User-provided justification (max 500 chars).
    pub justification: String,
    /// Device fingerprint for binding the approval to a specific endpoint.
    pub device_fingerprint: Option<String>,
}

impl CreateApprovalRequest {
    /// Validates the request fields.
    ///
    /// # Errors
    ///
    /// Returns `AppError::BadRequest` if justification exceeds 500 characters
    /// or destination_scope exceeds 200 characters.
    pub fn validate(&self) -> Result<(), AppError> {
        if self.justification.len() > 500 {
            return Err(AppError::BadRequest(
                "justification exceeds 500 characters".to_string(),
            ));
        }
        if self.destination_scope.as_deref().unwrap_or("").len() > 200 {
            return Err(AppError::BadRequest(
                "destination_scope exceeds 200 characters".to_string(),
            ));
        }
        Ok(())
    }
}

/// Request body for `POST /admin/approvals/{id}/grant`.
#[derive(Debug, Clone, Deserialize)]
pub struct GrantRequest {
    /// Expiry timestamp (ISO-8601).
    pub valid_until: String,
    /// Hex-encoded Ed25519 signature for T4 Board approval.
    pub signature: Option<String>,
}

/// Request body for `POST /admin/approvals/{id}/reject`.
#[derive(Debug, Clone, Deserialize)]
pub struct RejectRequest {
    /// Optional reason for rejection.
    pub reason: Option<String>,
}

/// Single approval response with resolved tier.
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalResponse {
    /// The approval record.
    pub approval: Approval,
    /// Resolved tier from labels (T1, T2, T3, T4).
    pub tier: Option<String>,
}

/// Paginated list response for approvals.
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalListResponse {
    /// List of approvals.
    pub approvals: Vec<ApprovalResponse>,
    /// Total count of approvals matching the query.
    pub total: i64,
    /// Current page number (1-based).
    pub page: u32,
    /// Items per page.
    pub per_page: u32,
}

/// Detailed approval response with T4 canonical message.
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalDetailResponse {
    /// The approval record.
    pub approval: Approval,
    /// Resolved tier from labels.
    pub tier: Option<String>,
    /// Canonical message for T4 Board signature (displayed for copy-paste).
    pub t4_canonical_message: Option<String>,
}

/// Response after granting an approval.
#[derive(Debug, Clone, Serialize)]
pub struct GrantResponse {
    /// The updated approval record.
    pub approval: Approval,
    /// The signed JWT token.
    pub token: String,
}

/// Request body for `POST /agent/approval-request`.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentApprovalRequest {
    /// AD SID of the requesting user.
    pub requester_sid: String,
    /// FK to labels.id (soft reference).
    pub data_object_id: String,
    /// Action being approved.
    pub allowed_action: String,
    /// Where the data can go (None = any).
    pub destination_scope: Option<String>,
    /// User-provided justification (max 500 chars).
    pub justification: String,
    /// Device fingerprint for binding.
    pub device_fingerprint: Option<String>,
}

impl AgentApprovalRequest {
    /// Validates the request fields.
    ///
    /// # Errors
    ///
    /// Returns `AppError::BadRequest` if justification exceeds 500 characters
    /// or destination_scope exceeds 200 characters.
    pub fn validate(&self) -> Result<(), AppError> {
        if self.justification.len() > 500 {
            return Err(AppError::BadRequest(
                "justification exceeds 500 characters".to_string(),
            ));
        }
        if self.destination_scope.as_deref().unwrap_or("").len() > 200 {
            return Err(AppError::BadRequest(
                "destination_scope exceeds 200 characters".to_string(),
            ));
        }
        Ok(())
    }
}

/// Response after submitting an approval request from agent.
#[derive(Debug, Clone, Serialize)]
pub struct AgentApprovalResponse {
    /// The approval ID.
    pub id: String,
    /// Current status (always "pending" on creation).
    pub status: String,
}

/// Request body for `PUT /admin/board-public-key`.
#[derive(Debug, Clone, Deserialize)]
pub struct BoardPublicKeyRequest {
    /// Hex-encoded Ed25519 public key.
    pub pubkey_hex: String,
}

/// Response for active approval tokens (agent startup sync).
#[derive(Debug, Clone, Serialize)]
pub struct ActiveApprovalResponse {
    /// The signed JWT token.
    pub token: String,
    /// The token claims.
    pub claims: ApprovalClaims,
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Maps an `ApprovalRow` to the shared `Approval` struct.
fn row_to_approval(row: ApprovalRow) -> Approval {
    Approval {
        id: row.id,
        requester_sid: row.requester_sid,
        approver_sid: row.approver_sid,
        data_object_id: row.data_object_id,
        allowed_action: row.allowed_action,
        destination_scope: row.destination_scope,
        valid_from: row.valid_from,
        valid_until: row.valid_until,
        signature: row.signature,
        status: row.status.as_str().try_into().unwrap_or(ApprovalStatus::Pending),
        justification: row.justification,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

/// Resolves the tier for a data object from the labels table.
fn resolve_tier(pool: &crate::db::Pool, data_object_id: &str) -> Result<Option<String>, AppError> {
    match LabelRepository::get_by_id(pool, data_object_id) {
        Ok(row) => Ok(Some(row.tier)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(AppError::Database(e)),
    }
}

/// Maps an action string to the closest `Action` enum variant.
fn action_from_str(s: &str) -> dlp_common::Action {
    match s.to_uppercase().as_str() {
        "READ" => dlp_common::Action::READ,
        "WRITE" => dlp_common::Action::WRITE,
        "COPY" => dlp_common::Action::COPY,
        "DELETE" => dlp_common::Action::DELETE,
        "MOVE" => dlp_common::Action::MOVE,
        "PASTE" => dlp_common::Action::PASTE,
        "DRAG_DROP" => dlp_common::Action::DRAG_DROP,
        "CLOUD_UPLOAD" => dlp_common::Action::CLOUD_UPLOAD,
        "PRINT" => dlp_common::Action::PRINT,
        _ => dlp_common::Action::READ,
    }
}

/// Builds an audit event for approval lifecycle changes.
fn build_approval_audit_event(
    event_type: dlp_common::EventType,
    approval: &Approval,
    admin_name: &str,
) -> dlp_common::AuditEvent {
    dlp_common::AuditEvent::new(
        event_type,
        approval.requester_sid.clone(),
        admin_name.to_string(),
        format!("approval:{}", approval.id),
        dlp_common::Classification::T3,
        action_from_str(&approval.allowed_action),
        dlp_common::Decision::ALLOW,
        "server".to_string(),
        0,
    )
    .with_justification(approval.justification.clone())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /admin/approvals` — list approvals with optional status filter and pagination.
pub async fn list_approvals(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ApprovalListQuery>,
) -> Result<Json<ApprovalListResponse>, AppError> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(50).clamp(1, 100);
    let limit = per_page as i64;
    let offset = ((page - 1) * per_page) as i64;

    let pool = Arc::clone(&state.pool);
    let (rows, total) = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let rows = if let Some(ref status) = q.status {
            ApprovalRepository::list_by_status(&pool, status, Some(limit), Some(offset))?
        } else {
            ApprovalRepository::list(&pool, Some(limit), Some(offset))?
        };
        let total = if let Some(ref status) = q.status {
            ApprovalRepository::count_by_status(&pool, status)?
        } else {
            // Count all statuses by summing individual counts or use a separate query.
            // For simplicity, we count all rows via a direct query.
            let conn = pool
                .get()
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            conn.query_row("SELECT COUNT(*) FROM approvals", [], |r| r.get(0))?
        };
        Ok((rows, total))
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    let approvals: Vec<ApprovalResponse> = rows
        .into_iter()
        .map(|row| {
            let tier = resolve_tier(&state.pool, &row.data_object_id).ok().flatten();
            ApprovalResponse {
                approval: row_to_approval(row),
                tier,
            }
        })
        .collect();

    Ok(Json(ApprovalListResponse {
        approvals,
        total,
        page,
        per_page,
    }))
}

/// `POST /admin/approvals` — create a new pending approval.
pub async fn create_approval(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateApprovalRequest>,
) -> Result<Json<ApprovalResponse>, AppError> {
    body.validate()?;

    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Clone values for the spawn_blocking closure (ApprovalUpsertRow borrows).
    let id_clone = id.clone();
    let requester_sid = body.requester_sid.clone();
    let data_object_id = body.data_object_id.clone();
    let allowed_action = body.allowed_action.clone();
    let destination_scope = body.destination_scope.clone();
    let justification = body.justification.clone();
    let now_clone = now.clone();

    let pool = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let record = ApprovalUpsertRow {
            id: &id_clone,
            requester_sid: &requester_sid,
            data_object_id: &data_object_id,
            allowed_action: &allowed_action,
            destination_scope: destination_scope.as_deref(),
            justification: &justification,
            created_at: &now_clone,
            updated_at: &now_clone,
        };
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = UnitOfWork::new(&mut conn).map_err(AppError::from)?;
        ApprovalRepository::insert(&uow, &record).map_err(AppError::from)?;
        uow.commit().map_err(AppError::from)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // Emit audit event (best-effort).
    let approval = Approval {
        id: id.clone(),
        requester_sid: body.requester_sid.clone(),
        approver_sid: None,
        data_object_id: body.data_object_id.clone(),
        allowed_action: body.allowed_action.clone(),
        destination_scope: body.destination_scope.clone(),
        valid_from: None,
        valid_until: None,
        signature: None,
        status: ApprovalStatus::Pending,
        justification: body.justification.clone(),
        created_at: now.clone(),
        updated_at: now.clone(),
    };
    let audit_event =
        build_approval_audit_event(dlp_common::EventType::ApprovalRequest, &approval, "admin");
    let pool = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = UnitOfWork::new(&mut conn).map_err(AppError::from)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::from)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    let tier = resolve_tier(&state.pool, &body.data_object_id).ok().flatten();
    Ok(Json(ApprovalResponse { approval, tier }))
}

/// `GET /admin/approvals/{id}` — get a single approval with tier and T4 canonical message.
pub async fn get_approval(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ApprovalDetailResponse>, AppError> {
    let pool = Arc::clone(&state.pool);
    let row = tokio::task::spawn_blocking(move || -> Result<ApprovalRow, AppError> {
        ApprovalRepository::get_by_id(&pool, &id).map_err(AppError::from)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    let tier = resolve_tier(&state.pool, &row.data_object_id).ok().flatten();
    let t4_canonical_message = if tier.as_deref() == Some("T4") {
        Some(crate::approval_token::t4_canonical_message(
            &row.id,
            &row.requester_sid,
            &row.data_object_id,
            &row.allowed_action,
            row.valid_until.as_deref().unwrap_or(""),
        ))
    } else {
        None
    };

    Ok(Json(ApprovalDetailResponse {
        approval: row_to_approval(row),
        tier,
        t4_canonical_message,
    }))
}

/// `POST /admin/approvals/{id}/grant` — grant a pending approval.
///
/// T4 approvals require a valid Board Ed25519 signature.
pub async fn grant_approval(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<GrantRequest>,
) -> Result<Json<GrantResponse>, AppError> {
    // Validate valid_until is in the future.
    let valid_until_dt = chrono::DateTime::parse_from_rfc3339(&body.valid_until)
        .map_err(|e| AppError::BadRequest(format!("invalid valid_until: {e}")))?;
    if valid_until_dt <= Utc::now() {
        return Err(AppError::BadRequest(
            "valid_until must be in the future".to_string(),
        ));
    }

    // Fetch the approval row.
    let id_for_fetch = id.clone();
    let pool = Arc::clone(&state.pool);
    let row = tokio::task::spawn_blocking(move || -> Result<ApprovalRow, AppError> {
        ApprovalRepository::get_by_id(&pool, &id_for_fetch).map_err(AppError::from)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    if row.status != "pending" {
        return Err(AppError::Conflict(
            "approval is not in pending status".to_string(),
        ));
    }

    // Resolve tier for T4 check.
    let tier = resolve_tier(&state.pool, &row.data_object_id).ok().flatten();

    // T4 signature verification.
    if tier.as_deref() == Some("T4") {
        let signature = body.signature.as_deref().ok_or_else(|| {
            AppError::BadRequest("T4 approval requires valid Board signature".to_string())
        })?;

        let board_pubkey = {
            let pool = Arc::clone(&state.pool);
            tokio::task::spawn_blocking(move || -> Result<Option<String>, AppError> {
                let conn = pool.get().map_err(AppError::from)?;
                crate::approval_token::ApprovalTokenService::get_board_public_key(&conn)
                    .map_err(AppError::from)
            })
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??
        };

        let pubkey_hex = board_pubkey.ok_or_else(|| {
            AppError::BadRequest("Board public key not configured".to_string())
        })?;

        let canonical = crate::approval_token::t4_canonical_message(
            &id,
            &row.requester_sid,
            &row.data_object_id,
            &row.allowed_action,
            &body.valid_until,
        );

        let valid = crate::approval_token::ApprovalTokenService::verify_board_signature(
            &pubkey_hex,
            canonical.as_bytes(),
            signature,
        )?;

        if !valid {
            return Err(AppError::BadRequest(
                "T4 approval requires valid Board signature".to_string(),
            ));
        }
    }

    // Get approver SID from JWT claims (extracted by auth middleware).
    // We use "admin" as fallback if not available in extension.
    let approver_sid = "admin".to_string();

    let now = Utc::now();
    let valid_from_str = now.to_rfc3339();
    let valid_until_str = valid_until_dt.to_rfc3339();

    // Generate token claims.
    let claims = ApprovalClaims {
        iss: "dlp-server".to_string(),
        sub: row.requester_sid.clone(),
        obj: row.data_object_id.clone(),
        act: row.allowed_action.clone(),
        dst: row.destination_scope.clone(),
        dev: None,
        iat: now.timestamp(),
        exp: valid_until_dt.timestamp(),
        jti: id.clone(),
    };

    // Sign the token.
    let token = state.approval_token_service.sign_token(&claims)?;

    // Update approval state with TOCTOU guard.
    let id_for_update = id.clone();
    let approver_sid_for_update = approver_sid.clone();
    let valid_from_for_update = valid_from_str.clone();
    let valid_until_for_update = valid_until_str.clone();
    let now_str = now.to_rfc3339();
    let pool = Arc::clone(&state.pool);
    let signature_clone = body.signature.clone();
    let affected = tokio::task::spawn_blocking(move || -> Result<usize, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = UnitOfWork::new(&mut conn).map_err(AppError::from)?;
        let affected = ApprovalRepository::update_state(
            &uow,
            &id_for_update,
            "pending",
            "approved",
            Some(&approver_sid_for_update),
            Some(&valid_from_for_update),
            Some(&valid_until_for_update),
            signature_clone.as_deref(),
            &now_str,
        )
        .map_err(AppError::from)?;
        uow.commit().map_err(AppError::from)?;
        Ok(affected)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    if affected == 0 {
        return Err(AppError::Conflict(
            "approval was already processed".to_string(),
        ));
    }

    // Build updated approval for response.
    let approval = Approval {
        id: id.clone(),
        requester_sid: row.requester_sid.clone(),
        approver_sid: Some(approver_sid.clone()),
        data_object_id: row.data_object_id.clone(),
        allowed_action: row.allowed_action.clone(),
        destination_scope: row.destination_scope.clone(),
        valid_from: Some(valid_from_str),
        valid_until: Some(valid_until_str),
        signature: body.signature.clone(),
        status: ApprovalStatus::Approved,
        justification: row.justification.clone(),
        created_at: row.created_at.clone(),
        updated_at: now.to_rfc3339(),
    };

    // Emit audit event.
    let audit_event =
        build_approval_audit_event(dlp_common::EventType::ApprovalGrant, &approval, "admin");
    let pool = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = UnitOfWork::new(&mut conn).map_err(AppError::from)?;
        audit_store::store_events_sync(&uow, &[audit_event.clone()])?;
        uow.commit().map_err(AppError::from)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // Emit alert (best-effort, fire-and-forget).
    let alert = state.alert.clone();
    let approval_for_alert = approval.clone();
    tokio::spawn(async move {
        let alert_event =
            build_approval_audit_event(dlp_common::EventType::ApprovalGrant, &approval_for_alert, "admin");
        if let Err(e) = alert.send_alert(&alert_event).await {
            tracing::warn!(error = %e, "alert delivery failed (best-effort)");
        }
    });

    Ok(Json(GrantResponse { approval, token }))
}

/// `POST /admin/approvals/{id}/reject` — reject a pending approval.
pub async fn reject_approval(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(_body): Json<RejectRequest>,
) -> Result<Json<ApprovalResponse>, AppError> {
    let id_for_fetch = id.clone();
    let pool = Arc::clone(&state.pool);
    let row = tokio::task::spawn_blocking(move || -> Result<ApprovalRow, AppError> {
        ApprovalRepository::get_by_id(&pool, &id_for_fetch).map_err(AppError::from)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    if row.status != "pending" {
        return Err(AppError::Conflict(
            "approval is not in pending status".to_string(),
        ));
    }

    let now = Utc::now().to_rfc3339();
    let approver_sid = "admin".to_string();

    let id_for_update = id.clone();
    let approver_sid_for_update = approver_sid.clone();
    let now_for_update = now.clone();
    let pool = Arc::clone(&state.pool);
    let affected = tokio::task::spawn_blocking(move || -> Result<usize, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = UnitOfWork::new(&mut conn).map_err(AppError::from)?;
        let affected = ApprovalRepository::update_state(
            &uow,
            &id_for_update,
            "pending",
            "rejected",
            Some(&approver_sid_for_update),
            None,
            None,
            None,
            &now_for_update,
        )
        .map_err(AppError::from)?;
        uow.commit().map_err(AppError::from)?;
        Ok(affected)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    if affected == 0 {
        return Err(AppError::Conflict(
            "approval was already processed".to_string(),
        ));
    }

    let approval = row_to_approval(ApprovalRow {
        status: "rejected".to_string(),
        approver_sid: Some(approver_sid),
        updated_at: now,
        ..row
    });

    // Emit audit event.
    let audit_event =
        build_approval_audit_event(dlp_common::EventType::ApprovalRevoke, &approval, "admin");
    let pool = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = UnitOfWork::new(&mut conn).map_err(AppError::from)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::from)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    let tier = resolve_tier(&state.pool, &approval.data_object_id).ok().flatten();
    Ok(Json(ApprovalResponse { approval, tier }))
}

/// `POST /admin/approvals/{id}/revoke` — revoke an approved approval.
pub async fn revoke_approval(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ApprovalResponse>, AppError> {
    let id_for_fetch = id.clone();
    let pool = Arc::clone(&state.pool);
    let row = tokio::task::spawn_blocking(move || -> Result<ApprovalRow, AppError> {
        ApprovalRepository::get_by_id(&pool, &id_for_fetch).map_err(AppError::from)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    if row.status != "approved" {
        return Err(AppError::Conflict(
            "approval is not in approved status".to_string(),
        ));
    }

    let now = Utc::now().to_rfc3339();
    let now_for_update = now.clone();
    let id_for_update = id.clone();

    let pool = Arc::clone(&state.pool);
    let affected = tokio::task::spawn_blocking(move || -> Result<usize, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = UnitOfWork::new(&mut conn).map_err(AppError::from)?;
        let affected = ApprovalRepository::update_state(
            &uow,
            &id_for_update,
            "approved",
            "revoked",
            None,
            None,
            None,
            None,
            &now_for_update,
        )
        .map_err(AppError::from)?;
        uow.commit().map_err(AppError::from)?;
        Ok(affected)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    if affected == 0 {
        return Err(AppError::Conflict(
            "approval was already processed".to_string(),
        ));
    }

    let approval = row_to_approval(ApprovalRow {
        status: "revoked".to_string(),
        updated_at: now,
        ..row
    });

    // Emit audit event.
    let audit_event =
        build_approval_audit_event(dlp_common::EventType::ApprovalRevoke, &approval, "admin");
    let pool = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = UnitOfWork::new(&mut conn).map_err(AppError::from)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::from)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    let tier = resolve_tier(&state.pool, &approval.data_object_id).ok().flatten();
    Ok(Json(ApprovalResponse { approval, tier }))
}

/// `POST /agent/approval-request` — submit an approval request from the agent.
pub async fn submit_approval_request(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AgentApprovalRequest>,
) -> Result<Json<AgentApprovalResponse>, AppError> {
    body.validate()?;

    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Clone values for the spawn_blocking closure.
    let id_clone = id.clone();
    let requester_sid = body.requester_sid.clone();
    let data_object_id = body.data_object_id.clone();
    let allowed_action = body.allowed_action.clone();
    let destination_scope = body.destination_scope.clone();
    let justification = body.justification.clone();
    let now_clone = now.clone();

    let pool = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let record = ApprovalUpsertRow {
            id: &id_clone,
            requester_sid: &requester_sid,
            data_object_id: &data_object_id,
            allowed_action: &allowed_action,
            destination_scope: destination_scope.as_deref(),
            justification: &justification,
            created_at: &now_clone,
            updated_at: &now_clone,
        };
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = UnitOfWork::new(&mut conn).map_err(AppError::from)?;
        ApprovalRepository::insert(&uow, &record).map_err(AppError::from)?;
        uow.commit().map_err(AppError::from)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // Emit audit event (best-effort).
    let approval = Approval {
        id: id.clone(),
        requester_sid: body.requester_sid.clone(),
        approver_sid: None,
        data_object_id: body.data_object_id.clone(),
        allowed_action: body.allowed_action.clone(),
        destination_scope: body.destination_scope.clone(),
        valid_from: None,
        valid_until: None,
        signature: None,
        status: ApprovalStatus::Pending,
        justification: body.justification.clone(),
        created_at: now.clone(),
        updated_at: now.clone(),
    };
    let audit_event =
        build_approval_audit_event(dlp_common::EventType::ApprovalRequest, &approval, "agent");
    let pool = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = UnitOfWork::new(&mut conn).map_err(AppError::from)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::from)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(AgentApprovalResponse {
        id,
        status: "pending".to_string(),
    }))
}

/// `GET /agent/approvals/active` — return all approved+unexpired tokens for agent sync.
pub async fn list_active_approvals(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ActiveApprovalResponse>>, AppError> {
    let now = Utc::now().to_rfc3339();
    let pool = Arc::clone(&state.pool);

    let rows = tokio::task::spawn_blocking(move || -> Result<Vec<ApprovalRow>, AppError> {
        let conn = pool
            .get()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let mut stmt = conn.prepare(
            "SELECT id, requester_sid, approver_sid, data_object_id, allowed_action, \
             destination_scope, valid_from, valid_until, signature, status, \
             justification, created_at, updated_at \
             FROM approvals WHERE status = 'approved' AND valid_until > ?1 \
             ORDER BY valid_until ASC",
        )?;
        let rows = stmt.query_map(rusqlite::params![&now], |row| {
            Ok(ApprovalRow {
                id: row.get(0)?,
                requester_sid: row.get(1)?,
                approver_sid: row.get(2)?,
                data_object_id: row.get(3)?,
                allowed_action: row.get(4)?,
                destination_scope: row.get(5)?,
                valid_from: row.get(6)?,
                valid_until: row.get(7)?,
                signature: row.get(8)?,
                status: row.get(9)?,
                justification: row.get(10)?,
                created_at: row.get(11)?,
                updated_at: row.get(12)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| AppError::Database(e))
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    let mut responses = Vec::new();
    for row in rows {
        let valid_until = row.valid_until.as_deref().ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!("approved approval missing valid_until"))
        })?;
        let valid_until_dt = chrono::DateTime::parse_from_rfc3339(valid_until)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("invalid valid_until: {e}")))?;

        let claims = ApprovalClaims {
            iss: "dlp-server".to_string(),
            sub: row.requester_sid.clone(),
            obj: row.data_object_id.clone(),
            act: row.allowed_action.clone(),
            dst: row.destination_scope.clone(),
            dev: None,
            iat: Utc::now().timestamp(),
            exp: valid_until_dt.timestamp(),
            jti: row.id.clone(),
        };

        let token = state.approval_token_service.sign_token(&claims)?;
        responses.push(ActiveApprovalResponse { token, claims });
    }

    Ok(Json(responses))
}

/// `GET /agent/approvals/public-key` — return the server's Ed25519 verifying key.
pub async fn get_public_key(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let pubkey_hex = state.approval_token_service.verifying_key_hex();
    Ok(Json(serde_json::json!({ "public_key": pubkey_hex })))
}

/// `PUT /admin/board-public-key` — update the Board public key (admin only).
pub async fn update_board_public_key(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BoardPublicKeyRequest>,
) -> Result<StatusCode, AppError> {
    // Validate pubkey_hex is valid hex-encoded Ed25519 public key (64 chars hex = 32 bytes).
    let decoded = hex::decode(&body.pubkey_hex).map_err(|e| {
        AppError::BadRequest(format!("invalid hex in board public key: {e}"))
    })?;
    if decoded.len() != 32 {
        return Err(AppError::BadRequest(
            "board public key must be 32 bytes (64 hex chars)".to_string(),
        ));
    }

    let pubkey_hex = body.pubkey_hex.clone();
    let pool = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let conn = pool.get().map_err(AppError::from)?;
        crate::approval_token::ApprovalTokenService::store_board_public_key(&conn, &pubkey_hex)
            .map_err(AppError::from)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // Emit audit event for board key update.
    let audit_event = dlp_common::AuditEvent::new(
        dlp_common::EventType::ApprovalBoardKeyUpdate,
        String::new(),
        "admin".to_string(),
        format!("board_public_key:{}", &body.pubkey_hex[..16.min(body.pubkey_hex.len())]),
        dlp_common::Classification::T4,
        dlp_common::Action::PolicyCreate,
        dlp_common::Decision::ALLOW,
        "server".to_string(),
        0,
    );
    let pool = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = UnitOfWork::new(&mut conn).map_err(AppError::from)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::from)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approval_list_query_defaults() {
        let json = r#"{}"#;
        let q: ApprovalListQuery = serde_json::from_str(json).expect("deserialize");
        assert!(q.status.is_none());
        assert!(q.page.is_none());
        assert!(q.per_page.is_none());
    }

    #[test]
    fn test_create_approval_request_validate_justification_too_long() {
        let req = CreateApprovalRequest {
            requester_sid: "S-1-5-21-1".to_string(),
            data_object_id: "label-001".to_string(),
            allowed_action: "WRITE".to_string(),
            destination_scope: None,
            justification: "x".repeat(501),
            device_fingerprint: None,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn test_create_approval_request_validate_ok() {
        let req = CreateApprovalRequest {
            requester_sid: "S-1-5-21-1".to_string(),
            data_object_id: "label-001".to_string(),
            allowed_action: "WRITE".to_string(),
            destination_scope: Some("C:\\Data".to_string()),
            justification: "Business need".to_string(),
            device_fingerprint: None,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_agent_approval_request_validate_justification_too_long() {
        let req = AgentApprovalRequest {
            requester_sid: "S-1-5-21-1".to_string(),
            data_object_id: "label-001".to_string(),
            allowed_action: "WRITE".to_string(),
            destination_scope: None,
            justification: "x".repeat(501),
            device_fingerprint: None,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn test_grant_request_deserializes() {
        let json = r#"{"valid_until":"2026-05-15T00:00:00Z","signature":"deadbeef"}"#;
        let req: GrantRequest = serde_json::from_str(json).expect("deserialize");
        assert_eq!(req.valid_until, "2026-05-15T00:00:00Z");
        assert_eq!(req.signature, Some("deadbeef".to_string()));
    }

    #[test]
    fn test_reject_request_deserializes() {
        let json = r#"{"reason":"not needed"}"#;
        let req: RejectRequest = serde_json::from_str(json).expect("deserialize");
        assert_eq!(req.reason, Some("not needed".to_string()));
    }

    #[test]
    fn test_approval_list_response_serde() {
        let resp = ApprovalListResponse {
            approvals: vec![],
            total: 0,
            page: 1,
            per_page: 50,
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert!(json.contains("\"total\":0"));
        assert!(json.contains("\"page\":1"));
    }

    #[test]
    fn test_approval_detail_response_serde() {
        let resp = ApprovalDetailResponse {
            approval: Approval {
                id: "app-001".to_string(),
                requester_sid: "S-1-5-21-1".to_string(),
                approver_sid: None,
                data_object_id: "label-001".to_string(),
                allowed_action: "WRITE".to_string(),
                destination_scope: None,
                valid_from: None,
                valid_until: None,
                signature: None,
                status: ApprovalStatus::Pending,
                justification: "test".to_string(),
                created_at: "2026-05-14T00:00:00Z".to_string(),
                updated_at: "2026-05-14T00:00:00Z".to_string(),
            },
            tier: Some("T3".to_string()),
            t4_canonical_message: None,
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert!(json.contains("\"tier\":\"T3\""));
    }

    #[test]
    fn test_agent_approval_response_serde() {
        let resp = AgentApprovalResponse {
            id: "app-001".to_string(),
            status: "pending".to_string(),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert!(json.contains("\"id\":\"app-001\""));
        assert!(json.contains("\"status\":\"pending\""));
    }

    #[test]
    fn test_active_approval_response_serde() {
        let claims = ApprovalClaims {
            iss: "dlp-server".to_string(),
            sub: "S-1-5-21-1".to_string(),
            obj: "label-001".to_string(),
            act: "WRITE".to_string(),
            dst: Some("C:\\Data".to_string()),
            dev: None,
            iat: 1_000_000_000,
            exp: 2_000_000_000,
            jti: "app-001".to_string(),
        };
        let resp = ActiveApprovalResponse {
            token: "jwt-token".to_string(),
            claims,
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert!(json.contains("\"token\":\"jwt-token\""));
        assert!(json.contains("\"jti\":\"app-001\""));
    }

    #[test]
    fn test_board_public_key_request_deserializes() {
        let json = r#"{"pubkey_hex":"deadbeef"}"#;
        let req: BoardPublicKeyRequest = serde_json::from_str(json).expect("deserialize");
        assert_eq!(req.pubkey_hex, "deadbeef");
    }

    #[test]
    fn test_row_to_approval_maps_fields() {
        let row = ApprovalRow {
            id: "app-001".to_string(),
            requester_sid: "S-1-5-21-1".to_string(),
            approver_sid: Some("S-1-5-21-2".to_string()),
            data_object_id: "label-001".to_string(),
            allowed_action: "WRITE".to_string(),
            destination_scope: Some("C:\\Data".to_string()),
            valid_from: Some("2026-05-14T00:00:00Z".to_string()),
            valid_until: Some("2026-05-15T00:00:00Z".to_string()),
            signature: Some("sig".to_string()),
            status: "approved".to_string(),
            justification: "Business need".to_string(),
            created_at: "2026-05-14T00:00:00Z".to_string(),
            updated_at: "2026-05-14T01:00:00Z".to_string(),
        };
        let approval = row_to_approval(row);
        assert_eq!(approval.id, "app-001");
        assert_eq!(approval.status, ApprovalStatus::Approved);
    }
}
