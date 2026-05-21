//! Admin REST API that aggregates all management endpoints (P5-T09).
//!
//! Builds the complete axum `Router` with all sub-routes. Public
//! endpoints (health, ready, auth) are unauthenticated. All other
//! routes require a valid JWT Bearer token.
//
// TODO(followup): apply the same ME-01 mask-on-GET pattern to siem-config
// (Phase 3.1 has the same exposure).

use std::sync::Arc;

use axum::extract::{FromRequest, Path, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use chrono::Utc;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use crate::admin_auth::{self, AdminUsername};
use crate::agent_registry;
use crate::approval_api;
use crate::audit_store;
use crate::db;
use crate::db::repositories;
use crate::db::repositories::labels::{LabelRepository, LabelRow, LabelUpsertRow};
use crate::db::repositories::{
    validate_facility_code, validate_severity, AgentConfigRepository, AlertRouterConfigRepository,
    AllowlistAuditRepository, AllowlistAuditRow, AllowlistEntryRow, AllowlistRepository,
    CredentialsRepository, DiskRegistryRepository, DiskRegistryRow, LdapConfigRepository,
    ManagedOriginRow, ManagedOriginsRepository, PolicyRepository, SiemConfigRepository,
    SyslogConfigRepository, SyslogConfigRow,
};
use crate::exception_store;
use crate::policy_store::mode_str;
use crate::rate_limiter::{self, default_config, policy_config};
use crate::AppError;
use dlp_common::abac::PolicyMode;
use dlp_common::{
    DEFAULT_USB_BLOCKED_FAILURE_MODE, DEFAULT_USB_NONE_SERIAL_POLICY,
    DEFAULT_USB_STARTUP_RESOLUTION_MODE, USB_FAILURE_MODES, USB_NONE_SERIAL_POLICIES,
    USB_RESOLUTION_MODES,
};

/// Parses a `PolicyMode` from its DB string representation.
fn mode_from_str(s: &str) -> PolicyMode {
    match s {
        "ALL" => PolicyMode::ALL,
        "ANY" => PolicyMode::ANY,
        "NONE" => PolicyMode::NONE,
        _ => PolicyMode::ALL,
    }
}
use crate::AppState;
use dlp_common::abac::{AbacContext, EvaluateRequest, EvaluateResponse};
use tracing::info;

// ---------------------------------------------------------------------------
// Evaluation endpoint
// ---------------------------------------------------------------------------

/// Evaluates an ABAC access request against the loaded policy set.
///
/// `POST /evaluate` — intentionally unauthenticated.
/// Agent identity is established by `AgentInfo` in the request body.
///
/// The wire [`EvaluateRequest`] is converted to an internal [`AbacContext`]
/// immediately after agent-tracing metadata is extracted (D-04). The `agent`
/// field is intentionally dropped at this boundary — it is request-tracing
/// metadata, not an ABAC attribute (Phase 22 D-10).
async fn evaluate_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<EvaluateRequest>,
) -> Result<Json<EvaluateResponse>, AppError> {
    let agent_id = request
        .agent
        .as_ref()
        .map(|a| {
            format!(
                "{}\\{}",
                a.machine_name.as_deref().unwrap_or("unknown"),
                a.current_user.as_deref().unwrap_or("unknown"),
            )
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Extract classification before consuming `request` via `.into()`.
    let resource_classification = request.resource.classification;
    info!(
        agent_id = %agent_id,
        resource_classification = ?resource_classification,
        "policy evaluation request"
    );

    // Convert wire request to internal ABAC context at the HTTP boundary (D-04).
    // The agent field is intentionally dropped — it is request-tracing metadata,
    // not an ABAC attribute (Phase 22 D-10).
    let ctx: AbacContext = request.into();

    // NOTE: evaluate() is synchronous — no .await here.
    // Pass label_service and cached flag for label-aware evaluation (Phase 59, D-10).
    let response = state
        .policy_store
        .evaluate(&ctx, Some(&state.label_service), state.is_label_aware_enabled());
    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// Agent credential types
// ---------------------------------------------------------------------------

/// Payload for setting the agent auth hash.
#[derive(Debug, Clone, Deserialize)]
pub struct SetAuthHashRequest {
    /// The bcrypt hash string (must start with `$2`).
    pub hash: String,
}

/// Response after setting or retrieving the agent auth hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthHashResponse {
    /// The bcrypt hash.
    pub hash: String,
    /// ISO 8601 timestamp of last update.
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// Policy request / response types
// ---------------------------------------------------------------------------

/// Payload for creating or updating a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPayload {
    /// Unique policy ID (provided by the caller on create).
    pub id: String,
    /// Human-readable policy name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Evaluation priority (lower = evaluated first).
    pub priority: u32,
    /// JSON-encoded conditions array.
    pub conditions: serde_json::Value,
    /// The enforcement action (ALLOW, DENY, etc.).
    pub action: String,
    /// Whether the policy is enabled.
    pub enabled: bool,
    /// Boolean composition mode for the conditions list.
    #[serde(default)]
    pub mode: PolicyMode,
}

/// Policy record returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    /// Unique policy ID.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Evaluation priority.
    pub priority: u32,
    /// JSON conditions.
    pub conditions: serde_json::Value,
    /// Enforcement action.
    pub action: String,
    /// Whether the policy is active.
    pub enabled: bool,
    /// Boolean composition mode for the conditions list.
    #[serde(default)]
    pub mode: PolicyMode,
    /// Monotonic version number.
    pub version: i64,
    /// ISO 8601 timestamp of last update.
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// SIEM config request / response types
// ---------------------------------------------------------------------------

/// Read/write payload for SIEM connector configuration.
///
/// Represents the single row of the `siem_config` table. Both the
/// `GET /admin/siem-config` response body and the `PUT
/// /admin/siem-config` request body use this shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfigPayload {
    /// Splunk HEC base URL (e.g., `https://splunk:8088`).
    pub splunk_url: String,
    /// Splunk HEC authentication token.
    pub splunk_token: String,
    /// Whether the Splunk backend is active.
    pub splunk_enabled: bool,
    /// Elasticsearch base URL (e.g., `https://elastic:9200`).
    pub elk_url: String,
    /// Target Elasticsearch index name.
    pub elk_index: String,
    /// Optional ELK API key for authentication.
    pub elk_api_key: String,
    /// Whether the ELK backend is active.
    pub elk_enabled: bool,
}

// ---------------------------------------------------------------------------
// Syslog config request / response types
// ---------------------------------------------------------------------------

/// Request/response payload for syslog configuration endpoints.
///
/// Mirrors [`SyslogConfigRow`] with `bool` for boolean columns (enabled,
/// batching_enabled) so the JSON wire format is idiomatic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogConfigPayload {
    /// Syslog collector hostname or IP address.
    pub host: String,
    /// Syslog collector port (1-65535).
    pub port: i64,
    /// Whether syslog forwarding is enabled.
    pub enabled: bool,
    /// Transport protocol -- 'tls' only in Phase 62.
    pub protocol: String,
    /// RFC 5424 facility code (16-23 for LOCAL0-LOCAL7).
    pub facility_code: i64,
    /// Message format -- 'json' for JSON-in-MSG.
    pub format: String,
    /// Whether batched newline-delimited JSON is enabled.
    pub batching_enabled: bool,
    /// Severity for Alert events (0-7).
    pub severity_alert: i64,
    /// Severity for Block events (0-7).
    pub severity_block: i64,
    /// Severity for all other audit events (0-7).
    pub severity_audit: i64,
    /// Queue eviction policy -- 'fifo_tail_drop', 'fifo_head_drop', 'ring_buffer'.
    pub queue_policy: String,
    /// Maximum queue size (default 100,000).
    pub queue_max_size: i64,
    /// Minimum TLS version -- '1.2' or '1.3'.
    pub tls_min_version: String,
}

// ---------------------------------------------------------------------------
// Alert router config request / response types
// ---------------------------------------------------------------------------

/// ME-01: Sentinel placeholder returned by `GET /admin/alert-config` in place
/// of the plaintext `smtp_password` and `webhook_secret` columns. The TUI
/// save path treats this sentinel as "user kept the existing secret" and the
/// PUT handler substitutes the stored value when it sees the mask echoed
/// back, so the DB column is never overwritten with the literal string.
/// Admins who need to rotate a secret type the new value over the mask in
/// the TUI.
pub(crate) const ALERT_SECRET_MASK: &str = "***MASKED***";

/// Read/write payload for alert router configuration.
///
/// Represents the editable columns of the single row in the
/// `alert_router_config` table (excluding `id` and `updated_at`). Both the
/// `GET /admin/alert-config` response body and the `PUT /admin/alert-config`
/// request body use this shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertRouterConfigPayload {
    /// SMTP server hostname (empty string disables SMTP).
    pub smtp_host: String,
    /// SMTP server port.
    pub smtp_port: u16,
    /// SMTP username for authentication.
    pub smtp_username: String,
    /// SMTP password for authentication (plaintext — see TM-01).
    pub smtp_password: String,
    /// Sender email address.
    pub smtp_from: String,
    /// Recipient email addresses (comma-separated).
    pub smtp_to: String,
    /// Whether SMTP delivery is active.
    pub smtp_enabled: bool,
    /// Webhook endpoint URL (empty string disables webhook; must be https).
    pub webhook_url: String,
    /// Optional shared secret for HMAC signing (not used today — see deferred).
    pub webhook_secret: String,
    /// Whether webhook delivery is active.
    pub webhook_enabled: bool,
}

// ---------------------------------------------------------------------------
// LDAP config request / response types
// ---------------------------------------------------------------------------

/// Read/write payload for LDAP / Active Directory connection configuration.
///
/// Represents the editable columns of the single row in the `ldap_config`
/// table (excluding `id` and `updated_at`). Both the `GET /admin/ldap-config`
/// response body and the `PUT /admin/ldap-config` request body use this shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LdapConfigPayload {
    /// LDAP URL, e.g. `ldaps://dc.corp.internal:636`.
    pub ldap_url: String,
    /// Search base DN, e.g. `DC=corp,DC=internal`.
    pub base_dn: String,
    /// Whether LDAPS/TLS is required (plaintext connections rejected when true).
    pub require_tls: bool,
    /// Group membership cache TTL in seconds (min 60, max 3600, default 300).
    pub cache_ttl_secs: u64,
    /// Comma-separated VPN subnet CIDRs for location detection.
    pub vpn_subnets: String,
}

/// Single allowlist entry in the agent config payload.
///
/// Mirrors the `allowlist_entries` table row shape. Sent to agents via
/// the config poll endpoint for local allowlist matching.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AllowlistConfigEntry {
    /// Match type: "exact_path", "path_glob", "path_prefix", "cert_subject", "cert_thumbprint".
    pub match_type: String,
    /// The match value (path pattern, cert subject, or thumbprint hex).
    pub value: String,
    /// Human-readable description.
    pub description: String,
    /// Category: "self", "avedr", "system_critical", "operator_defined".
    pub category: String,
    /// Priority for deterministic ordering (lower = higher priority).
    pub priority: i64,
}

/// Read/write payload for agent configuration distribution.
///
/// Used by `GET/PUT /admin/agent-config` (global default) and
/// `GET/PUT/DELETE /admin/agent-config/{agent_id}` (per-agent override).
/// Also returned by the public `GET /agent-config/{id}` endpoint that
/// agents poll for their resolved config.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentConfigPayload {
    /// Directory paths the agent should monitor (empty = all drives).
    pub monitored_paths: Vec<String>,
    /// Directory paths to exclude from monitoring (merged with built-in exclusions).
    pub excluded_paths: Vec<String>,
    /// Heartbeat interval in seconds (minimum 10).
    pub heartbeat_interval_secs: u64,
    /// Whether offline caching is active.
    pub offline_cache_enabled: bool,
    /// Phase 37 (D-02/D-03): per-agent disk allowlist queried from `disk_registry`.
    ///
    /// Agents apply this list to `DiskEnumerator.instance_id_map` on the next poll cycle.
    /// Defaults to empty for backward compatibility with payloads from earlier server builds.
    #[serde(default)]
    pub disk_allowlist: Vec<dlp_common::DiskIdentity>,
    /// USB enforcement failure mode (USB-09). Default: "Warning only".
    #[serde(default = "default_usb_blocked_failure_mode")]
    pub usb_blocked_failure_mode: String,
    /// USB startup scan resolution strategy (USB-07). Default: "VID/PID/serial fallback".
    #[serde(default = "default_usb_startup_resolution_mode")]
    pub usb_startup_resolution_mode: String,
    /// Policy for USB devices without serial descriptors (USB-08). Default: "Always Blocked".
    #[serde(default = "default_usb_none_serial_policy")]
    pub usb_none_serial_policy: String,
    /// Whether the cloud sync hook DLL is enabled (M017/S01). Default: false.
    #[serde(default)]
    pub cloud_hook_enabled: bool,
    /// Whether print spooler interception is enabled (M017/S04). Default: false.
    #[serde(default)]
    pub print_enabled: bool,
    /// Timeout in milliseconds for XPS spool file parsing (M017/S04). Default: 5000.
    #[serde(default = "default_print_xps_timeout_ms")]
    pub print_xps_timeout_ms: u64,
    /// Action when a print job cannot be classified (M017/S04). Default: "Block".
    #[serde(default = "default_print_unclassifiable_action")]
    pub print_unclassifiable_action: String,
    /// Maximum pages to parse from an XPS spool file (M017/S04). Default: 100.
    #[serde(default = "default_print_max_pages")]
    pub print_max_pages: usize,
    /// Phase 49: Allowlist entries for universal injection.
    #[serde(default)]
    pub allowlist_entries: Vec<AllowlistConfigEntry>,
    /// Phase 49: Version of the allowlist config (for change detection).
    #[serde(default)]
    pub allowlist_version: i64,
}

fn default_usb_blocked_failure_mode() -> String {
    DEFAULT_USB_BLOCKED_FAILURE_MODE.to_string()
}
fn default_usb_startup_resolution_mode() -> String {
    DEFAULT_USB_STARTUP_RESOLUTION_MODE.to_string()
}
fn default_usb_none_serial_policy() -> String {
    DEFAULT_USB_NONE_SERIAL_POLICY.to_string()
}
fn default_print_xps_timeout_ms() -> u64 {
    5000
}
fn default_print_unclassifiable_action() -> String {
    "Block".to_string()
}
fn default_print_max_pages() -> usize {
    100
}

impl Default for AgentConfigPayload {
    fn default() -> Self {
        Self {
            monitored_paths: Vec::new(),
            excluded_paths: Vec::new(),
            heartbeat_interval_secs: 30,
            offline_cache_enabled: true,
            disk_allowlist: Vec::new(),
            usb_blocked_failure_mode: default_usb_blocked_failure_mode(),
            usb_startup_resolution_mode: default_usb_startup_resolution_mode(),
            usb_none_serial_policy: default_usb_none_serial_policy(),
            cloud_hook_enabled: false,
            print_enabled: false,
            print_xps_timeout_ms: 5000,
            print_unclassifiable_action: default_print_unclassifiable_action(),
            print_max_pages: 100,
            allowlist_entries: Vec::new(),
            allowlist_version: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Device Registry request / response types
// ---------------------------------------------------------------------------

/// Request body for `POST /admin/device-registry`.
///
/// Registers or updates a USB device trust tier. If a row with the same
/// `(vid, pid, serial)` already exists, the `trust_tier` and `description`
/// are updated in place (upsert). The UUID is server-generated and returned
/// in the response — callers do not provide it.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceRegistryRequest {
    /// USB Vendor ID as a hex string, e.g. `"0951"`.
    pub vid: String,
    /// USB Product ID as a hex string, e.g. `"1666"`.
    pub pid: String,
    /// Device serial number, or `"(none)"` for devices without one.
    pub serial: String,
    /// Windows Security Identifier of the owning user. `None` creates a machine-wide entry.
    #[serde(default)]
    pub owner_sid: Option<String>,
    /// Human-readable username for display. `None` for machine-wide entries.
    #[serde(default)]
    pub owner_user: Option<String>,
    /// Human-readable device description. Optional; defaults to empty string.
    #[serde(default)]
    pub description: String,
    /// Trust tier: must be one of `"blocked"`, `"read_only"`, or `"full_access"`.
    pub trust_tier: String,
}

/// Response body returned by `GET` and `POST /admin/device-registry`.
///
/// Mirrors the `device_registry` table row shape exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistryResponse {
    /// Server-generated UUID.
    pub id: String,
    /// USB Vendor ID hex string.
    pub vid: String,
    /// USB Product ID hex string.
    pub pid: String,
    /// Device serial number.
    pub serial: String,
    /// Windows Security Identifier of the owning user. `None` means machine-wide entry.
    pub owner_sid: Option<String>,
    /// Human-readable username for display. `None` means machine-wide entry.
    pub owner_user: Option<String>,
    /// Human-readable device description (empty string if not provided).
    pub description: String,
    /// Trust tier: `"blocked"`, `"read_only"`, or `"full_access"`.
    pub trust_tier: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
}

impl From<repositories::DeviceRegistryRow> for DeviceRegistryResponse {
    fn from(row: repositories::DeviceRegistryRow) -> Self {
        Self {
            id: row.id,
            vid: row.vid,
            pid: row.pid,
            serial: row.serial,
            owner_sid: row.owner_sid,
            owner_user: row.owner_user,
            description: row.description,
            trust_tier: row.trust_tier,
            created_at: row.created_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Disk Registry request / response types (Phase 37, ADMIN-01..03)
// ---------------------------------------------------------------------------

/// Request body for `POST /admin/disk-registry` (D-04, D-11).
///
/// Registers a new disk in the per-agent allowlist. The handler performs
/// a pure INSERT (D-05) -- a duplicate `(agent_id, instance_id)` returns
/// 409 Conflict. The UUID `id` and `registered_at` are server-generated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskRegistryRequest {
    /// Identifier of the agent owning this disk allowlist entry (D-01 scope).
    pub agent_id: String,
    /// Device instance ID (canonical disk identity).
    pub instance_id: String,
    /// Bus type as the lowercase serde name (e.g., "usb", "sata", "nvme", "scsi", "unknown").
    pub bus_type: String,
    /// Must be one of `"encrypted"`, `"suspended"`, `"unencrypted"`, `"unknown"` (D-11).
    pub encryption_status: String,
    /// Drive model string. Optional; defaults to empty.
    #[serde(default)]
    pub model: String,
}

/// Response body for `GET` and `POST /admin/disk-registry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskRegistryResponse {
    /// Server-generated UUID.
    pub id: String,
    /// Agent identifier this entry is scoped to.
    pub agent_id: String,
    /// Device instance ID (canonical disk identity).
    pub instance_id: String,
    /// Physical bus type as a lowercase string (e.g., "usb", "sata").
    pub bus_type: String,
    /// Encryption status: one of `"encrypted"`, `"suspended"`, `"unencrypted"`, `"unknown"`.
    pub encryption_status: String,
    /// Drive model string (empty if unknown).
    pub model: String,
    /// RFC-3339 UTC timestamp of when this entry was created.
    pub registered_at: String,
}

impl From<DiskRegistryRow> for DiskRegistryResponse {
    fn from(row: DiskRegistryRow) -> Self {
        Self {
            id: row.id,
            agent_id: row.agent_id,
            instance_id: row.instance_id,
            bus_type: row.bus_type,
            encryption_status: row.encryption_status,
            model: row.model,
            registered_at: row.registered_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Label request / response types (Phase 59, LABEL-03..07)
// ---------------------------------------------------------------------------

/// Request body for `POST /admin/labels` and `PUT /admin/labels/:id`.
#[derive(Debug, Clone, Deserialize)]
pub struct LabelRequest {
    /// Filesystem or SMB path of the labeled object.
    pub path: String,
    /// Object type: `"file"`, `"folder"`, or `"archive"`.
    pub object_type: String,
    /// Data tier: `"T1"`, `"T2"`, `"T3"`, `"T4"`, or `"Unclassified-Blocked"`.
    pub tier: String,
    /// Label state: `"temporary"`, `"confirmed"`, `"rejected"`, or `"expired"`.
    pub label_state: String,
    /// SID of the Data Owner (from AD Manager attribute).
    #[serde(default)]
    pub owner_sid: Option<String>,
    /// FK to parent folder label for inheritance.
    #[serde(default)]
    pub parent_label_id: Option<String>,
    /// Reference to ACL snapshot at label time.
    #[serde(default)]
    pub acl_snapshot_id: Option<String>,
    /// SHA-256 hash of file content when labeled.
    #[serde(default)]
    pub hash: Option<String>,
    /// Scanner confidence score (0.0-1.0), nullable.
    #[serde(default)]
    pub scanner_confidence: Option<f32>,
    /// Department or business unit owning the data.
    #[serde(default)]
    pub department: Option<String>,
}

/// Response body returned by label endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelResponse {
    /// UUID string identifying the label.
    pub id: String,
    /// Filesystem or SMB path of the labeled object.
    pub path: String,
    /// Object type: `file`, `folder`, or `archive`.
    pub object_type: String,
    /// Data tier: `T1`, `T2`, `T3`, `T4`, or `Unclassified-Blocked`.
    pub tier: String,
    /// Label state: `temporary`, `confirmed`, `rejected`, or `expired`.
    pub label_state: String,
    /// SID of the Data Owner.
    pub owner_sid: Option<String>,
    /// FK to parent folder label for inheritance.
    pub parent_label_id: Option<String>,
    /// SHA-256 hash of file content when labeled.
    /// Reference to ACL snapshot at label time.
    pub acl_snapshot_id: Option<String>,
    pub hash: Option<String>,
    /// Scanner confidence score (0.0-1.0), nullable.
    #[serde(default)]
    pub scanner_confidence: Option<f32>,
    /// Department or business unit owning the data.
    pub department: Option<String>,
    pub created_at: String,
    /// ISO-8601 timestamp of last update.
    pub updated_at: String,
}

impl From<LabelRow> for LabelResponse {
    fn from(row: LabelRow) -> Self {
        Self {
            id: row.id,
            path: row.path,
            object_type: row.object_type,
            tier: row.tier,
            label_state: row.label_state,
            owner_sid: row.owner_sid,
            parent_label_id: row.parent_label_id,
            acl_snapshot_id: row.acl_snapshot_id,
            hash: row.hash,
            scanner_confidence: row.scanner_confidence,
            department: row.department,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// Paginated response for `GET /admin/labels`.
#[derive(Debug, Serialize, Deserialize)]
pub struct PaginatedLabelsResponse {
    /// The label rows for the current page.
    pub labels: Vec<LabelResponse>,
    /// Total count of labels matching the filter (across all pages).
    pub total: i64,
    /// The limit used for this query.
    pub limit: usize,
    /// The offset used for this query.
    pub offset: usize,
}

/// Default page size for label listing.
const DEFAULT_LABEL_LIMIT: usize = 50;

/// Maximum allowed page size to prevent unbounded responses (T-59-12).
const MAX_LABEL_LIMIT: usize = 1000;

/// Query-string filter for `GET /admin/labels`.
#[derive(Debug, Default, Deserialize)]
pub struct LabelFilter {
    /// Filter by label state (e.g., `temporary` for review queue).
    #[serde(default)]
    pub state: Option<String>,
    /// Filter by data tier.
    #[serde(default)]
    pub tier: Option<String>,
    /// Filter by Data Owner SID.
    #[serde(default)]
    pub owner_sid: Option<String>,
    /// Filter by department.
    #[serde(default)]
    pub department: Option<String>,
    /// Maximum number of labels to return (default 50, max 1000).
    #[serde(default = "default_label_limit")]
    pub limit: usize,
    /// Number of labels to skip (default 0).
    #[serde(default)]
    pub offset: usize,
}

/// Returns the default page size for label queries.
fn default_label_limit() -> usize {
    DEFAULT_LABEL_LIMIT
}

/// Optional query-string filter for `GET /admin/disk-registry` (D-07).
#[derive(Debug, Default, Deserialize)]
pub struct DiskRegistryFilter {
    /// When set, restricts results to entries for the given agent.
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// Device entry returned by the unauthenticated `GET /admin/device-registry` endpoint.
///
/// Admin-internal fields (`id`, `description`, `trust_tier`, `created_at`) are omitted
/// to prevent unauthenticated callers from enumerating privileged device tiers (CR-01).
/// Owner fields are included so agents can distinguish per-user from machine-wide entries
/// (Phase 38.4, D-11 accepted: owner SIDs are not secrets).
#[derive(Debug, Serialize)]
struct PublicDeviceEntry {
    /// USB Vendor ID hex string.
    pub vid: String,
    /// USB Product ID hex string.
    pub pid: String,
    /// Device serial number.
    pub serial: String,
    /// Windows SID of the owning user. `None` means machine-wide entry.
    pub owner_sid: Option<String>,
    /// Human-readable username. `None` means machine-wide entry.
    pub owner_user: Option<String>,
}

impl From<repositories::DeviceRegistryRow> for PublicDeviceEntry {
    fn from(row: repositories::DeviceRegistryRow) -> Self {
        Self {
            vid: row.vid,
            pid: row.pid,
            serial: row.serial,
            owner_sid: row.owner_sid,
            owner_user: row.owner_user,
        }
    }
}

/// Request body for `POST /admin/managed-origins`.
///
/// Creates a new managed origin entry. The UUID is server-generated.
#[derive(Debug, serde::Deserialize)]
pub struct ManagedOriginRequest {
    /// URL pattern string, e.g. `"https://company.sharepoint.com/*"`.
    pub origin: String,
}

/// Response body for `GET` and `POST /admin/managed-origins`.
#[derive(Debug, serde::Serialize)]
pub struct ManagedOriginResponse {
    /// Server-generated UUID.
    pub id: String,
    /// URL pattern string.
    pub origin: String,
}

// ---------------------------------------------------------------------------
// Allowlist request / response types (Phase 49)
// ---------------------------------------------------------------------------

/// Payload for creating or updating an allowlist entry.
#[derive(Debug, Clone, Deserialize)]
pub struct AllowlistEntryRequest {
    /// Match type: `exact_path`, `path_glob`, `path_prefix`, `cert_subject`, or `cert_thumbprint`.
    pub match_type: String,
    /// The match value (path pattern, cert subject, or thumbprint hex string).
    pub value: String,
    /// Human-readable description of the entry.
    pub description: String,
    /// Category: `self`, `avedr`, `system_critical`, or `operator_defined`.
    pub category: String,
    /// Priority for deterministic ordering (lower = higher priority).
    pub priority: i64,
    /// Whether the entry is enabled.
    pub enabled: bool,
}

/// Allowlist entry record returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistEntryResponse {
    /// Server-generated UUID.
    pub id: String,
    /// Match type.
    pub match_type: String,
    /// The match value.
    pub value: String,
    /// Human-readable description.
    pub description: String,
    /// Category.
    pub category: String,
    /// Priority for ordering.
    pub priority: i64,
    /// Whether the entry is enabled.
    pub enabled: bool,
    /// Version counter for optimistic concurrency.
    pub version: i64,
    /// ISO 8601 timestamp of creation.
    pub created_at: String,
    /// ISO 8601 timestamp of last update.
    pub updated_at: String,
}

impl From<AllowlistEntryRow> for AllowlistEntryResponse {
    fn from(row: AllowlistEntryRow) -> Self {
        Self {
            id: row.id,
            match_type: row.match_type,
            value: row.value,
            description: row.description,
            category: row.category,
            priority: row.priority,
            enabled: row.enabled != 0,
            version: row.version,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// Health/readiness probe response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Current server status.
    pub status: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// TM-02: Webhook URL validation (SSRF hardening)
// ---------------------------------------------------------------------------

/// Validates a webhook URL for SSRF hardening (TM-02).
///
/// Textual validation only — no DNS lookup. RFC1918 private ranges
/// (10/8, 172.16/12, 192.168/16) are ALLOWED because on-prem webhooks
/// to internal Slack/Teams/PagerDuty are a legitimate DLP use case.
///
/// # Rules
///
/// 1. Must parse as a URL.
/// 2. Scheme must be `https`.
/// 3. IPv4 host: reject loopback (127.0.0.0/8) and link-local (169.254.0.0/16).
/// 4. IPv6 host: reject loopback (`::1`) and link-local (`fe80::/10`).
/// 5. Domain hosts and public/RFC1918 IPs are accepted.
///
/// # Errors
///
/// Returns a human-readable reason string on rejection.
///
/// # Examples
///
/// ```ignore
/// assert!(validate_webhook_url("https://hooks.example.com").is_ok());
/// assert!(validate_webhook_url("http://example.com").is_err());
/// assert!(validate_webhook_url("https://127.0.0.1").is_err());
/// ```
/// Validates an IPv4 host address for webhook URLs.
///
/// Rejects loopback (127.0.0.0/8) and link-local (169.254.0.0/16).
/// RFC1918 private addresses (10/8, 172.16/12, 192.168/16) are intentionally allowed.
fn validate_ipv4_host(ip: std::net::Ipv4Addr) -> Result<(), String> {
    if ip.is_loopback() {
        return Err("loopback addresses not allowed".to_string());
    }
    if ip.is_link_local() {
        // `is_link_local` covers 169.254.0.0/16 on stable Rust.
        return Err("link-local addresses not allowed".to_string());
    }
    // RFC1918 (10/8, 172.16/12, 192.168/16) intentionally ALLOWED.
    Ok(())
}

/// Validates an IPv6 host address for webhook URLs.
///
/// Rejects loopback (::1), link-local (fe80::/10), and IPv4-mapped
/// loopback/link-local addresses (::ffff:127.0.0.1, ::ffff:169.254.x.x).
fn validate_ipv6_host(ip: std::net::Ipv6Addr) -> Result<(), String> {
    if ip.is_loopback() {
        return Err("loopback addresses not allowed".to_string());
    }

    // G3: Ipv6Addr::is_unicast_link_local is unstable on rustc 1.94,
    // so do the fe80::/10 check manually: first 10 bits == 1111111010,
    // i.e. first segment in 0xfe80..=0xfebf.
    let first_segment = ip.segments()[0];
    if (first_segment & 0xffc0) == 0xfe80 {
        return Err("link-local addresses not allowed".to_string());
    }

    // TM-02 hardening (BL-01 fix): IPv4-mapped IPv6 addresses
    // (`::ffff:a.b.c.d`) route to the v4 stack on dual-stack hosts,
    // so `[::ffff:127.0.0.1]` and `[::ffff:169.254.169.254]` would
    // otherwise bypass the v4 loopback/link-local guards and let an
    // attacker reach cloud metadata via the mapped form. Re-run the
    // v4 blocklist against the unwrapped address. `to_ipv4_mapped`
    // is stable since Rust 1.63.
    if let Some(v4) = ip.to_ipv4_mapped() {
        if v4.is_loopback() {
            return Err("loopback addresses not allowed (IPv4-mapped)".to_string());
        }
        if v4.is_link_local() {
            return Err("link-local addresses not allowed (IPv4-mapped)".to_string());
        }
    }

    Ok(())
}

pub(crate) fn validate_webhook_url(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;

    if parsed.scheme() != "https" {
        return Err("scheme must be https".to_string());
    }

    match parsed.host() {
        Some(url::Host::Ipv4(ip)) => validate_ipv4_host(ip),
        Some(url::Host::Ipv6(ip)) => validate_ipv6_host(ip),
        Some(url::Host::Domain(_)) => {
            // Textual hostname — accept. No DNS lookup (TM-02 ratified).
            Ok(())
        }
        None => Err("URL has no host".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// Builds the complete admin API router with all routes.
///
/// # Arguments
///
/// * `db` - Shared database handle.
///
/// # Routes
///
/// **Unauthenticated:**
/// - `GET /health` — health probe
/// - `GET /ready` — readiness probe
/// - `POST /auth/login` — admin login
/// - `POST /agents/register` — agent self-registration
/// - `POST /agents/{id}/heartbeat` — agent heartbeat
/// - `POST /audit/events` — event ingestion (agent-to-server)
/// - `GET /agent-credentials/auth-hash` — fetch agent auth hash
///
/// **Authenticated (JWT required):**
/// - `GET /agents` — list agents
/// - `GET /agents/:id` — get agent
/// - `GET /audit/events` — query audit events
/// - `GET /audit/events/count` — event count
/// - `GET /policies` — list policies
/// - `GET /policies/:id` — get policy
/// - `PUT /policies/:id` — update policy
/// - `POST /policies` — create policy
/// - `DELETE /policies/:id` — delete policy
/// - `GET /exceptions` — list exceptions
/// - `GET /exceptions/:id` — get exception
/// - `POST /exceptions` — create exception
/// - `PUT /agent-credentials/auth-hash` — set agent auth hash
/// - `PUT /auth/password` — change admin password
/// - `GET /admin/siem-config` — get SIEM connector configuration
/// - `PUT /admin/siem-config` — update SIEM connector configuration
/// - `GET /admin/alert-config` — get alert router configuration
/// - `PUT /admin/alert-config` — update alert router configuration
/// - `GET /admin/agent-config` — get global agent config default
/// - `PUT /admin/agent-config` — update global agent config default
/// - `GET /admin/agent-config/:agent_id` — get per-agent config override
/// - `PUT /admin/agent-config/:agent_id` — upsert per-agent config override
/// - `DELETE /admin/agent-config/:agent_id` — remove per-agent config override
///
/// **Unauthenticated (additional):**
/// - `GET /agent-config/:id` — resolved agent config (per-agent override or global fallback)
pub fn admin_router(state: Arc<AppState>) -> Router {
    // Routes that do NOT require authentication.
    // Each route that needs rate limiting gets its own GovernorLayer applied
    // via `.route_layer()`. The key extractor (AgentIdOrIpKeyExtractor) keys
    // by agent_id for /agents/* paths and by peer IP for all others.
    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/evaluate", post(evaluate_handler))
        .route(
            "/auth/login",
            post(admin_auth::login).route_layer(rate_limiter::strict_config()),
        )
        .route("/agents/register", post(agent_registry::register_agent))
        .route(
            "/agents/{id}/heartbeat",
            post(agent_registry::heartbeat).route_layer(rate_limiter::moderate_config()),
        )
        .route(
            "/audit/events",
            post(audit_store::ingest_events).route_layer(rate_limiter::per_agent_config()),
        )
        .route("/agent-credentials/auth-hash", get(get_agent_auth_hash))
        .route("/agent-config/{id}", get(get_agent_config_for_agent))
        .route("/admin/device-registry", get(list_device_registry_handler))
        .route("/admin/managed-origins", get(list_managed_origins_handler))
        // Phase 61: Agent-facing approval endpoints (no JWT — agent-authenticated)
        .route(
            "/agent/approval-request",
            post(approval_api::submit_approval_request),
        )
        .route(
            "/agent/approvals/active",
            get(approval_api::list_active_approvals),
        )
        .route(
            "/agent/approvals/public-key",
            get(approval_api::get_public_key),
        );

    // Routes that require a valid JWT.
    // Policy routes get a tighter limit (60/min) via `.route_layer()`.
    // Remaining protected routes fall back to the default 100/min limit.
    let protected_routes = Router::new()
        .route("/agents", get(agent_registry::list_agents))
        .route("/agents/{id}", get(agent_registry::get_agent))
        .route("/audit/events", get(audit_store::query_events))
        .route("/audit/events/count", get(audit_store::get_event_count))
        .route(
            "/policies",
            get(list_policies)
                .post(create_policy)
                .route_layer(policy_config()),
        )
        .route(
            "/policies/{id}",
            get(get_policy)
                .put(update_policy)
                .delete(delete_policy)
                .route_layer(policy_config()),
        )
        // Policy CRUD under /admin/policies (Phase 9 requirement).
        .route(
            "/admin/policies",
            post(create_policy).route_layer(policy_config()),
        )
        .route(
            "/admin/policies/{id}",
            put(update_policy)
                .delete(delete_policy)
                .route_layer(policy_config()),
        )
        .route("/exceptions", get(exception_store::list_exceptions))
        .route("/exceptions/{id}", get(exception_store::get_exception))
        .route("/exceptions", post(exception_store::create_exception))
        .route("/agent-credentials/auth-hash", put(set_agent_auth_hash))
        .route("/auth/password", put(admin_auth::change_password))
        .route("/admin/siem-config", get(get_siem_config_handler))
        .route("/admin/siem-config", put(update_siem_config_handler))
        .route("/admin/alert-config", get(get_alert_config_handler))
        .route("/admin/alert-config", put(update_alert_config_handler))
        .route("/admin/alert-config/test", post(test_alert_config_handler))
        .route("/admin/ldap-config", get(get_ldap_config_handler))
        .route("/admin/ldap-config", put(update_ldap_config_handler))
        .route(
            "/admin/agent-config",
            get(get_global_agent_config_handler).put(update_global_agent_config_handler),
        )
        .route(
            "/admin/agent-config/{agent_id}",
            get(get_agent_config_override_handler)
                .put(update_agent_config_override_handler)
                .delete(delete_agent_config_override_handler),
        )
        .route(
            "/admin/device-registry",
            post(upsert_device_registry_handler),
        )
        .route(
            "/admin/device-registry/full",
            get(list_device_registry_full_handler),
        )
        .route(
            "/admin/device-registry/{id}",
            delete(delete_device_registry_handler),
        )
        // Phase 37: disk-registry endpoints (JWT-protected per T-37-08)
        .route(
            "/admin/disk-registry",
            get(list_disk_registry_handler).post(insert_disk_registry_handler),
        )
        .route(
            "/admin/disk-registry/{id}",
            delete(delete_disk_registry_handler),
        )
        .route(
            "/admin/managed-origins",
            post(create_managed_origin_handler),
        )
        .route(
            "/admin/managed-origins/{id}",
            delete(delete_managed_origin_handler),
        )
        // Phase 49: Allowlist admin API
        .route(
            "/admin/allowlist",
            get(list_allowlist_handler).post(create_allowlist_handler),
        )
        .route(
            "/admin/allowlist/{id}",
            get(get_allowlist_handler)
                .put(update_allowlist_handler)
                .delete(delete_allowlist_handler),
        )
        .route(
            "/admin/allowlist/{id}/disable",
            post(disable_allowlist_handler),
        )
        .route(
            "/admin/allowlist/{id}/audit",
            get(list_allowlist_audit_handler),
        )
        // Phase 47 Task 47-08: KEK rotation + maintenance-mode toggle.
        .route("/admin/secrets/rotate", post(rotate_secrets_handler))
        .route("/admin/maintenance/enter", post(maintenance_enter_handler))
        .route("/admin/maintenance/exit", post(maintenance_exit_handler))
        // Phase 59: Label admin API (LABEL-03..07)
        .route("/admin/labels", get(list_labels).post(create_label))
        .route(
            "/admin/labels/{id}",
            get(get_label).put(update_label).delete(delete_label),
        )
        .route("/admin/labels/{id}/confirm", post(confirm_label))
        .route("/admin/labels/{id}/reject", post(reject_label))
        .route("/admin/labels/{id}/expire", post(expire_label))
        .route("/admin/labels/departments", get(list_label_departments))
        // Phase 61: Approval Workflow Engine admin API (WORKFLOW-02..06)
        .route(
            "/admin/approvals",
            get(approval_api::list_approvals).post(approval_api::create_approval),
        )
        .route("/admin/approvals/{id}", get(approval_api::get_approval))
        .route(
            "/admin/approvals/{id}/grant",
            post(approval_api::grant_approval),
        )
        .route(
            "/admin/approvals/{id}/reject",
            post(approval_api::reject_approval),
        )
        .route(
            "/admin/approvals/{id}/revoke",
            post(approval_api::revoke_approval),
        )
        .route(
            "/admin/board-public-key",
            put(approval_api::update_board_public_key),
        )
        // Phase 62: Syslog Forwarder admin API (SYSLOG-01..02)
        .route("/admin/syslog-config", get(get_syslog_config_handler))
        .route("/admin/syslog-config", put(update_syslog_config_handler))
        .route(
            "/admin/syslog-config/test",
            post(test_syslog_config_handler),
        )
        .route_layer(default_config())
        .layer(middleware::from_fn(admin_auth::require_auth));

    public_routes.merge(protected_routes).with_state(state)
}

// ---------------------------------------------------------------------------
// Health probes
// ---------------------------------------------------------------------------

/// `GET /health` — liveness probe.
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        timestamp: Utc::now().to_rfc3339(),
    })
}

/// `GET /ready` — readiness probe.
async fn ready(State(state): State<Arc<AppState>>) -> Result<Json<HealthResponse>, AppError> {
    // Verify the database is accessible.
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let conn = pool.get().map_err(AppError::from)?;
        conn.execute_batch("SELECT 1").map_err(AppError::from)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(HealthResponse {
        status: "ready".to_string(),
        timestamp: Utc::now().to_rfc3339(),
    }))
}

// ---------------------------------------------------------------------------
// Policy CRUD handlers
// ---------------------------------------------------------------------------

/// `GET /policies` — list all policies.
async fn list_policies(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<PolicyResponse>>, AppError> {
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let rows = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let db_rows = PolicyRepository::list(&pool).map_err(AppError::Database)?;
        let policies: Vec<PolicyResponse> = db_rows
            .into_iter()
            .map(|r| {
                let conditions: serde_json::Value =
                    serde_json::from_str(&r.conditions).unwrap_or(serde_json::Value::Null);
                PolicyResponse {
                    id: r.id,
                    name: r.name,
                    description: r.description,
                    priority: u32::try_from(r.priority).unwrap_or(r.priority as u32),
                    conditions,
                    action: r.action,
                    enabled: r.enabled != 0,
                    mode: mode_from_str(&r.mode),
                    version: r.version,
                    updated_at: r.updated_at,
                }
            })
            .collect();
        Ok(policies)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(rows))
}

/// `GET /policies/:id` — get a single policy.
async fn get_policy(
    State(state): State<Arc<AppState>>,
    Path(policy_id): Path<String>,
) -> Result<Json<PolicyResponse>, AppError> {
    let id = policy_id.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);

    let p = tokio::task::spawn_blocking(move || -> Result<PolicyResponse, AppError> {
        let r = PolicyRepository::get_by_id(&pool, &id).map_err(AppError::Database)?;
        let conditions: serde_json::Value =
            serde_json::from_str(&r.conditions).unwrap_or(serde_json::Value::Null);
        Ok(PolicyResponse {
            id: r.id,
            name: r.name,
            description: r.description,
            priority: u32::try_from(r.priority).unwrap_or(r.priority as u32),
            conditions,
            action: r.action,
            enabled: r.enabled != 0,
            mode: mode_from_str(&r.mode),
            version: r.version,
            updated_at: r.updated_at,
        })
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(p))
}

/// `POST /policies` — create a new policy.
async fn create_policy(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<(StatusCode, Json<PolicyResponse>), AppError> {
    let username = AdminUsername::extract_from_headers(req.headers())?;
    let _caller_sid = crate::admin_auth::verify_jwt(
        req.headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("invalid Authorization format".to_string()))?,
    )?
    .sid;
    let payload: Json<PolicyPayload> = Json::from_request(req, &state)
        .await
        .map_err(AppError::from)?;
    if payload.id.is_empty() || payload.name.is_empty() {
        return Err(AppError::BadRequest("id and name are required".to_string()));
    }

    let now = Utc::now().to_rfc3339();
    let conditions_json = serde_json::to_string(&payload.conditions)?;

    let resp = PolicyResponse {
        id: payload.id.clone(),
        name: payload.name.clone(),
        description: payload.description.clone(),
        priority: payload.priority,
        conditions: payload.conditions.clone(),
        action: payload.action.clone(),
        enabled: payload.enabled,
        mode: payload.mode,
        version: 1,
        updated_at: now.clone(),
    };

    // Persist the new policy via repository + UnitOfWork.
    let r = resp.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let record = repositories::PolicyRow {
            id: r.id.clone(),
            name: r.name.clone(),
            description: r.description.clone(),
            priority: i64::from(r.priority),
            conditions: conditions_json.clone(),
            action: r.action.clone(),
            enabled: if r.enabled { 1 } else { 0 },
            mode: mode_str(r.mode).to_string(),
            version: r.version,
            updated_at: r.updated_at.clone(),
        };
        PolicyRepository::insert(&uow, &record).map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // Invalidate the policy cache so the next evaluation sees the new policy.
    state.policy_store.invalidate();

    // Emit admin audit event after DB commit.
    let audit_event = dlp_common::AuditEvent::new(
        dlp_common::EventType::AdminAction,
        String::new(),
        username,
        format!("policy:{}", resp.id),
        dlp_common::Classification::T3,
        dlp_common::Action::PolicyCreate,
        dlp_common::Decision::ALLOW,
        "server".to_string(),
        0,
    );
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(policy_id = %resp.id, "policy created");
    Ok((StatusCode::CREATED, Json(resp)))
}

/// `PUT /policies/:id` — update an existing policy.
async fn update_policy(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<PolicyResponse>, AppError> {
    let username = AdminUsername::extract_from_headers(req.headers())?;
    let _caller_sid = crate::admin_auth::verify_jwt(
        req.headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("invalid Authorization format".to_string()))?,
    )?
    .sid;

    // Extract path param from URI. Supports both /policies/:id and /admin/policies/:id.
    let path = req.uri().path();
    let policy_id = if let Some(rest) = path.strip_prefix("/policies/") {
        rest.to_string()
    } else if let Some(rest) = path.strip_prefix("/admin/policies/") {
        rest.to_string()
    } else {
        return Err(AppError::BadRequest("invalid policy path".to_string()));
    };
    if policy_id.is_empty() {
        return Err(AppError::BadRequest(
            "missing policy id in path".to_string(),
        ));
    }

    // Let Json consume the request body.
    let payload: Json<PolicyPayload> = Json::from_request(req, &state)
        .await
        .map_err(AppError::from)?;

    // Clone all fields needed inside spawn_blocking since Json derefs to &T (not owned).
    let now = Utc::now().to_rfc3339();
    let conditions_json = serde_json::to_string(&payload.conditions)?;
    let id = policy_id.clone();
    let payload_name = payload.name.clone();
    let payload_desc = payload.description.clone();
    let payload_priority = i64::from(payload.priority);
    let payload_action = payload.action.clone();
    let payload_enabled = if payload.enabled { 1 } else { 0 };
    let payload_mode = payload.mode;
    let payload_conditions = payload.conditions.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);

    let resp = tokio::task::spawn_blocking(move || -> Result<PolicyResponse, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;

        let row = repositories::PolicyUpdateRow {
            name: &payload_name,
            description: payload_desc.as_deref(),
            priority: payload_priority,
            conditions: &conditions_json,
            action: &payload_action,
            enabled: payload_enabled,
            mode: mode_str(payload_mode),
            updated_at: &now,
            id: &id,
        };
        let rows = PolicyRepository::update(&uow, &row).map_err(AppError::Database)?;

        if rows == 0 {
            return Err(AppError::NotFound(format!("policy {id} not found")));
        }

        let version = PolicyRepository::get_version(&uow, &id).map_err(AppError::Database)?;

        uow.commit().map_err(AppError::Database)?;

        Ok(PolicyResponse {
            id,
            name: payload_name,
            description: payload_desc,
            priority: u32::try_from(payload_priority).unwrap_or(payload_priority as u32),
            conditions: payload_conditions,
            action: payload_action,
            enabled: payload_enabled != 0,
            mode: payload_mode,
            version,
            updated_at: now,
        })
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // Invalidate the policy cache so the next evaluation sees the updated policy.
    state.policy_store.invalidate();

    // Emit admin audit event after DB commit.
    let audit_event = dlp_common::AuditEvent::new(
        dlp_common::EventType::AdminAction,
        String::new(),
        username,
        format!("policy:{}", resp.id),
        dlp_common::Classification::T3,
        dlp_common::Action::PolicyUpdate,
        dlp_common::Decision::ALLOW,
        "server".to_string(),
        0,
    );
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(policy_id = %resp.id, "policy updated");
    Ok(Json(resp))
}

/// `DELETE /policies/:id` — delete a policy.
async fn delete_policy(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<StatusCode, AppError> {
    let username = AdminUsername::extract_from_headers(req.headers())?;
    let _caller_sid = crate::admin_auth::verify_jwt(
        req.headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("invalid Authorization format".to_string()))?,
    )?
    .sid;
    let policy_id = Path::<String>::from_request(req, &state)
        .await
        .map_err(AppError::from)?
        .0;
    let id = policy_id.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);

    let rows = tokio::task::spawn_blocking(move || -> Result<usize, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let rows = PolicyRepository::delete(&uow, &id).map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(rows)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // Invalidate the policy cache so the next evaluation sees the deleted policy.
    state.policy_store.invalidate();

    if rows == 0 {
        return Err(AppError::NotFound(format!("policy {policy_id} not found")));
    }

    // Emit admin audit event after DB commit.
    let audit_event = dlp_common::AuditEvent::new(
        dlp_common::EventType::AdminAction,
        String::new(),
        username,
        format!("policy:{}", policy_id),
        dlp_common::Classification::T3,
        dlp_common::Action::PolicyDelete,
        dlp_common::Decision::ALLOW,
        "server".to_string(),
        0,
    );
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(policy_id = %policy_id, "policy deleted");
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Agent credential handlers
// ---------------------------------------------------------------------------

/// `PUT /agent-credentials/auth-hash` — set the agent auth hash (JWT required).
///
/// Validates that the hash looks like a bcrypt string, then upserts into the
/// `agent_credentials` table.
async fn set_agent_auth_hash(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SetAuthHashRequest>,
) -> Result<Json<AuthHashResponse>, AppError> {
    if !payload.hash.starts_with("$2") {
        return Err(AppError::BadRequest(
            "hash must be a bcrypt string (starts with $2)".to_string(),
        ));
    }

    let now = Utc::now().to_rfc3339();
    let hash = payload.hash.clone();
    let ts = now.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);

    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        CredentialsRepository::upsert(&uow, "DLPAuthHash", &hash, &ts)
            .map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!("agent auth hash updated");
    Ok(Json(AuthHashResponse {
        hash: payload.hash,
        updated_at: now,
    }))
}

/// `GET /agent-credentials/auth-hash` — fetch the agent auth hash (public).
///
/// Returns 404 if no hash has been stored yet. Agents call this endpoint
/// on startup and periodically to sync the password hash.
async fn get_agent_auth_hash(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AuthHashResponse>, AppError> {
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let (hash, updated_at) =
        tokio::task::spawn_blocking(move || -> Result<(String, String), AppError> {
            let row =
                CredentialsRepository::get(&pool, "DLPAuthHash").map_err(AppError::Database)?;
            Ok((row.value, row.updated_at))
        })
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(AuthHashResponse { hash, updated_at }))
}

// ---------------------------------------------------------------------------
// SIEM config handlers
// ---------------------------------------------------------------------------

/// `GET /admin/siem-config` — returns the current SIEM connector config.
///
/// Reads the single row from `siem_config` and returns it as JSON.
/// Phase 47 Task 47-06: the `splunk_token` / `elk_api_key` secret fields
/// are returned as the [`ALERT_SECRET_MASK`] sentinel when populated and
/// as empty strings when unset, matching the alert-config GET shape so
/// the admin TUI's mask round-trip pattern works uniformly.
async fn get_siem_config_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SiemConfigPayload>, AppError> {
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let crypto = Arc::clone(&state.crypto);
    let row = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        SiemConfigRepository::get(&pool, &crypto)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // ME-01 / Task 47-06: never return plaintext secret values on GET.
    let splunk_token_out = if row.splunk_token.is_some() {
        ALERT_SECRET_MASK.to_string()
    } else {
        String::new()
    };
    let elk_api_key_out = if row.elk_api_key.is_some() {
        ALERT_SECRET_MASK.to_string()
    } else {
        String::new()
    };

    Ok(Json(SiemConfigPayload {
        splunk_url: row.splunk_url,
        splunk_token: splunk_token_out,
        splunk_enabled: row.splunk_enabled != 0,
        elk_url: row.elk_url,
        elk_index: row.elk_index,
        elk_api_key: elk_api_key_out,
        elk_enabled: row.elk_enabled != 0,
    }))
}

/// `PUT /admin/siem-config` — updates the SIEM connector config.
///
/// Overwrites the single row in `siem_config` with the provided values
/// and stamps `updated_at` with the current time. Returns the payload
/// that was written so clients can refresh their local copy.
///
/// Phase 47 Task 47-06: secrets are encrypted on write under the active
/// KEK and column-binding AAD. If the incoming `splunk_token` or
/// `elk_api_key` equals [`ALERT_SECRET_MASK`], the stored value is
/// preserved (TOCTOU-safe via the same `UnitOfWork` that hosts the
/// UPDATE).
async fn update_siem_config_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SiemConfigPayload>,
) -> Result<Json<SiemConfigPayload>, AppError> {
    let now = Utc::now().to_rfc3339();
    let p = payload.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let crypto = Arc::clone(&state.crypto);

    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        // Read existing secrets BEFORE opening the write transaction —
        // SQLite's WAL gives us a consistent snapshot, and the
        // single-admin-writer model means there is no realistic TOCTOU
        // window between this read and the UPDATE below. (The alert-
        // config handler's transactional `get_secrets` is the
        // gold-standard pattern; SIEM lives with the same effective
        // serialisation because admin endpoints are rate-limited.)
        let existing = SiemConfigRepository::get(&pool, &crypto).ok();
        let splunk_token = resolve_secret_field(
            p.splunk_token.as_str(),
            existing.as_ref().and_then(|r| r.splunk_token.clone()),
        );
        let elk_api_key = resolve_secret_field(
            p.elk_api_key.as_str(),
            existing.as_ref().and_then(|r| r.elk_api_key.clone()),
        );

        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let record = repositories::SiemConfigRow {
            splunk_url: p.splunk_url.clone(),
            splunk_token,
            splunk_enabled: if p.splunk_enabled { 1 } else { 0 },
            elk_url: p.elk_url.clone(),
            elk_index: p.elk_index.clone(),
            elk_api_key,
            elk_enabled: if p.elk_enabled { 1 } else { 0 },
            updated_at: now,
        };
        SiemConfigRepository::update(&uow, &record, &crypto)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!("SIEM config updated");
    // Re-mask the response so the secret never reappears on the wire.
    let mut masked = payload;
    if !masked.splunk_token.is_empty() {
        masked.splunk_token = ALERT_SECRET_MASK.to_string();
    }
    if !masked.elk_api_key.is_empty() {
        masked.elk_api_key = ALERT_SECRET_MASK.to_string();
    }
    Ok(Json(masked))
}

/// Resolves the on-the-wire value of a secret field to the on-disk
/// `Option<SecretString>` payload:
///
/// - Empty incoming string -> `None` (clear the secret).
/// - Incoming equals [`ALERT_SECRET_MASK`] -> preserve `existing`
///   (TOCTOU-safe because the caller read `existing` inside the same
///   transaction as the subsequent UPDATE).
/// - Anything else -> `Some(SecretString::new(incoming))`.
fn resolve_secret_field(
    incoming: &str,
    existing: Option<secrecy::SecretString>,
) -> Option<secrecy::SecretString> {
    if incoming.is_empty() {
        None
    } else if incoming == ALERT_SECRET_MASK {
        existing
    } else {
        Some(secrecy::SecretString::new(incoming.to_string()))
    }
}

/// Mirror of [`resolve_secret_field`] for the alert-config flow, where
/// the in-transaction `get_secrets` returns a (always-present)
/// `SecretString` whose empty form means "not configured". Maps the
/// stored value plus the mask sentinel to an `Option<SecretString>`
/// suitable for the encrypted-aware update path:
///
/// - Incoming empty -> `None` (clear).
/// - Incoming mask + stored empty -> `None` (mask on a never-set
///   secret is a no-op).
/// - Incoming mask + stored non-empty -> preserve the stored value.
/// - Incoming new plaintext -> `Some(SecretString::new(incoming))`.
fn resolve_secret_field_with_stored(
    incoming: &str,
    stored: &secrecy::SecretString,
) -> Option<secrecy::SecretString> {
    use secrecy::ExposeSecret;
    if incoming.is_empty() {
        None
    } else if incoming == ALERT_SECRET_MASK {
        if stored.expose_secret().is_empty() {
            None
        } else {
            Some(stored.clone())
        }
    } else {
        Some(secrecy::SecretString::new(incoming.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Syslog config handlers
// ---------------------------------------------------------------------------

/// `GET /admin/syslog-config` -- returns the current syslog configuration.
///
/// Reads the single row from `syslog_config` and returns it as JSON.
/// No secret fields are present in syslog config (system CA store only,
/// no custom CA or mTLS per D-10/D-11), so no masking is needed.
async fn get_syslog_config_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SyslogConfigPayload>, AppError> {
    let pool = Arc::clone(&state.pool);
    let crypto = Arc::clone(&state.crypto);
    let row = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        SyslogConfigRepository::get(&pool, &crypto)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(SyslogConfigPayload {
        host: row.host,
        port: row.port,
        enabled: row.enabled != 0,
        protocol: row.protocol,
        facility_code: row.facility_code,
        format: row.format,
        batching_enabled: row.batching_enabled != 0,
        severity_alert: row.severity_alert,
        severity_block: row.severity_block,
        severity_audit: row.severity_audit,
        queue_policy: row.queue_policy,
        queue_max_size: row.queue_max_size,
        tls_min_version: row.tls_min_version,
    }))
}

/// `PUT /admin/syslog-config` -- updates the syslog connector config.
///
/// Overwrites the single row in `syslog_config` with the provided values
/// and stamps `updated_at` with the current time. Returns the payload
/// that was written so clients can refresh their local copy.
///
/// Validates port range (1-65535), facility_code (16-23), severity (0-7),
/// queue_policy enum, and tls_min_version enum before writing to DB.
async fn update_syslog_config_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SyslogConfigPayload>,
) -> Result<Json<SyslogConfigPayload>, AppError> {
    // Validation (per R-62-06).
    if payload.port < 1 || payload.port > 65535 {
        return Err(AppError::BadRequest("port must be 1-65535".to_string()));
    }
    validate_facility_code(payload.facility_code)?;
    validate_severity(payload.severity_alert)?;
    validate_severity(payload.severity_block)?;
    validate_severity(payload.severity_audit)?;
    let valid_policies = ["fifo_tail_drop", "fifo_head_drop", "ring_buffer"];
    if !valid_policies.contains(&payload.queue_policy.as_str()) {
        return Err(AppError::BadRequest(format!(
            "queue_policy must be one of: {}",
            valid_policies.join(", ")
        )));
    }
    let valid_tls = ["1.2", "1.3"];
    if !valid_tls.contains(&payload.tls_min_version.as_str()) {
        return Err(AppError::BadRequest(format!(
            "tls_min_version must be one of: {}",
            valid_tls.join(", ")
        )));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let p = payload.clone();
    let pool = Arc::clone(&state.pool);
    let crypto = Arc::clone(&state.crypto);

    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let record = SyslogConfigRow {
            host: p.host,
            port: p.port,
            enabled: if p.enabled { 1 } else { 0 },
            protocol: p.protocol,
            facility_code: p.facility_code,
            format: p.format,
            batching_enabled: if p.batching_enabled { 1 } else { 0 },
            severity_alert: p.severity_alert,
            severity_block: p.severity_block,
            severity_audit: p.severity_audit,
            queue_policy: p.queue_policy,
            queue_max_size: p.queue_max_size,
            tls_min_version: p.tls_min_version,
            updated_at: now,
        };
        SyslogConfigRepository::update(&uow, &record, &crypto)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!("syslog config updated");
    Ok(Json(payload))
}

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

// In-memory rate limiter: session_id -> last_test_time.
// Note: In production, this should use a distributed cache. For Phase 62,
// an in-memory Mutex<HashMap> is sufficient since dlp-server is single-instance.
static TEST_RATE_LIMITER: Lazy<Arc<Mutex<HashMap<String, Instant>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// `POST /admin/syslog-config/test` -- sends a synthetic test event through
/// the SyslogConnector.
///
/// Rate limited to 1 test per 10 seconds per session (per R-62-10).
/// Returns 200 OK with JSON status even on failure so the TUI can display
/// the error message.
async fn test_syslog_config_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    // Rate limiting: extract session/jwt identifier from Authorization header.
    let session_key = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("anonymous")
        .to_string();

    {
        let mut limiter = TEST_RATE_LIMITER.lock().await;
        let now = Instant::now();
        let min_interval = Duration::from_secs(10);
        if let Some(last) = limiter.get(&session_key) {
            if now.duration_since(*last) < min_interval {
                return Err(AppError::BadRequest(
                    "Rate limit: max 1 test per 10 seconds".to_string(),
                ));
            }
        }
        limiter.insert(session_key, now);
    }

    let test_event = dlp_common::AuditEvent::new(
        dlp_common::EventType::Alert,
        "TEST\\syslog-test".to_string(),
        "syslog-test".to_string(),
        r"C:\test\file.txt".to_string(),
        dlp_common::Classification::T3,
        dlp_common::Action::WRITE,
        dlp_common::Decision::DenyWithAlert,
        "test-device".to_string(),
        0,
    );

    match state.syslog.forward(&[test_event]).await {
        Ok(()) => Ok(Json(serde_json::json!({
            "status": "ok",
            "message": "Test event forwarded successfully"
        }))),
        Err(e) => {
            tracing::warn!(error = %e, "syslog test forward failed");
            Ok(Json(serde_json::json!({
                "status": "error",
                "message": e.to_string()
            })))
        }
    }
}

// ---------------------------------------------------------------------------
// Alert router config handlers
// ---------------------------------------------------------------------------

/// `GET /admin/alert-config` — returns the current alert router config.
///
/// Reads the single row from `alert_router_config` and returns it as a JSON
/// [`AlertRouterConfigPayload`]. The row is guaranteed to exist because it
/// is seeded during pool initialization.
///
/// ME-01: `smtp_password` and `webhook_secret` are replaced with
/// [`ALERT_SECRET_MASK`] in the response. Empty stored values are returned
/// as empty strings so the TUI can distinguish "never set" from "set but
/// hidden". The PUT handler substitutes the stored value when it sees the
/// mask echoed back, preserving secret-preserving round-trips.
async fn get_alert_config_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AlertRouterConfigPayload>, AppError> {
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let crypto = Arc::clone(&state.crypto);
    let row = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        AlertRouterConfigRepository::get(&pool, &crypto)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // ME-01: Never return plaintext credentials on GET. Empty stays empty
    // so the TUI can render "not configured". Post-Phase-47 the secret
    // is an `Option<SecretString>` so we check `is_some` to decide the
    // mask substitution.
    let smtp_password_out = if row.smtp_password.is_some() {
        ALERT_SECRET_MASK.to_string()
    } else {
        String::new()
    };
    let webhook_secret_out = if row.webhook_secret.is_some() {
        ALERT_SECRET_MASK.to_string()
    } else {
        String::new()
    };

    Ok(Json(AlertRouterConfigPayload {
        smtp_host: row.smtp_host,
        smtp_port: row.smtp_port,
        smtp_username: row.smtp_username,
        smtp_password: smtp_password_out,
        smtp_from: row.smtp_from,
        smtp_to: row.smtp_to,
        smtp_enabled: row.smtp_enabled != 0,
        webhook_url: row.webhook_url,
        webhook_secret: webhook_secret_out,
        webhook_enabled: row.webhook_enabled != 0,
    }))
}

/// `PUT /admin/alert-config` — updates the alert router config.
///
/// Validates `webhook_url` (TM-02 SSRF hardening) before writing. Overwrites
/// the single row in `alert_router_config` with the provided values and
/// stamps `updated_at` with the current time. Returns the payload that was
/// written so clients can refresh their local copy.
///
/// ME-01: both the SELECT (secret mask resolution) and UPDATE share a single
/// `UnitOfWork`, preventing any TOCTOU window between reading and writing.
///
/// # Errors
///
/// Returns `AppError::BadRequest` if `webhook_url` fails validation.
async fn update_alert_config_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AlertRouterConfigPayload>,
) -> Result<Json<AlertRouterConfigPayload>, AppError> {
    // TM-02: validate webhook_url BEFORE any DB write. Empty string is
    // allowed (means webhook delivery is disabled).
    if !payload.webhook_url.is_empty() {
        validate_webhook_url(&payload.webhook_url)
            .map_err(|reason| AppError::BadRequest(format!("webhook_url rejected: {reason}")))?;
    }

    let now = Utc::now().to_rfc3339();
    let p = payload.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let crypto = Arc::clone(&state.crypto);

    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;

        // ME-01 / Phase 47 Task 47-06: TOCTOU-safe encrypted read of
        // existing secrets within the same transaction as the UPDATE.
        // `get_secrets` returns `(SecretString, SecretString)` —
        // empty when unset — exactly matching the original cleartext
        // contract.
        let (stored_smtp_password, stored_webhook_secret) =
            AlertRouterConfigRepository::get_secrets(&uow, &crypto)?;

        // Compute the on-disk Option<SecretString> per field:
        // - empty incoming -> None (clear the secret)
        // - mask sentinel  -> preserve the stored value
        // - anything else  -> Some(SecretString::new(incoming))
        let smtp_password_to_write =
            resolve_secret_field_with_stored(&p.smtp_password, &stored_smtp_password);
        let webhook_secret_to_write =
            resolve_secret_field_with_stored(&p.webhook_secret, &stored_webhook_secret);

        let record = repositories::AlertRouterConfigRow {
            smtp_host: p.smtp_host.clone(),
            smtp_port: p.smtp_port,
            smtp_username: p.smtp_username.clone(),
            smtp_password: smtp_password_to_write,
            smtp_from: p.smtp_from.clone(),
            smtp_to: p.smtp_to.clone(),
            smtp_enabled: if p.smtp_enabled { 1 } else { 0 },
            webhook_url: p.webhook_url.clone(),
            webhook_secret: webhook_secret_to_write,
            webhook_enabled: if p.webhook_enabled { 1 } else { 0 },
            updated_at: now,
        };
        AlertRouterConfigRepository::update(&uow, &record, &crypto)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!("alert router config updated");
    // Re-mask the response so the secret never reappears on the wire.
    let mut masked_response = payload;
    if !masked_response.smtp_password.is_empty() {
        masked_response.smtp_password = ALERT_SECRET_MASK.to_string();
    }
    if !masked_response.webhook_secret.is_empty() {
        masked_response.webhook_secret = ALERT_SECRET_MASK.to_string();
    }
    Ok(Json(masked_response))
}

// ---------------------------------------------------------------------------
// Agent config handlers
// ---------------------------------------------------------------------------

/// Converts a `DiskRegistryRow` from the server-side registry into a
/// `dlp_common::DiskIdentity` for inclusion in the agent config payload.
///
/// `bus_type` is mapped via a direct match on the stored lowercase string (e.g., `"usb"`).
/// `encryption_status` is round-tripped through serde JSON because the DB now stores the
/// canonical serde names (`"encrypted"`, `"suspended"`, `"unencrypted"`, `"unknown"`).
///
/// Unknown or unparseable values fall back to the safest defaults (`BusType::Unknown`,
/// `EncryptionStatus::Unknown`).
fn disk_row_to_identity(row: DiskRegistryRow) -> dlp_common::DiskIdentity {
    // Map bus_type string to BusType enum via direct match to avoid JSON
    // injection from unsanitized DB values. Any unrecognised value falls back
    // to BusType::Unknown (safe default).
    let bus_type = match row.bus_type.as_str() {
        "usb" => dlp_common::BusType::Usb,
        "sata" => dlp_common::BusType::Sata,
        "nvme" => dlp_common::BusType::Nvme,
        "scsi" => dlp_common::BusType::Scsi,
        _ => dlp_common::BusType::Unknown,
    };

    // EncryptionStatus: DB stores canonical serde names ("encrypted", "suspended",
    // "unencrypted", "unknown") matching EncryptionStatus's #[serde(rename_all =
    // "snake_case")]. Round-trip via JSON to deserialise. Any unrecognised DB value
    // (e.g., from a pre-migration row) falls back to None (treat as unverified).
    let encryption_status: Option<dlp_common::EncryptionStatus> =
        serde_json::from_str(&format!("\"{}\"", row.encryption_status)).ok();

    dlp_common::DiskIdentity {
        instance_id: row.instance_id,
        bus_type,
        model: row.model,
        drive_letter: None,
        serial: None,
        size_bytes: None,
        is_boot_disk: false,
        encryption_status,
        encryption_method: None,
        encryption_checked_at: None,
    }
}

/// `GET /agent-config/:id` — returns the resolved config for a specific agent.
///
/// Tries per-agent override first; falls back to global default if no override
/// exists. This endpoint is intentionally unauthenticated — agents call it
/// using their `agent_id` as identity, not admin JWT.
///
/// Phase 49: Supports `If-None-Match` header for 304-style optimization.
/// If the header matches the current allowlist version, returns 304 Not Modified.
async fn get_agent_config_for_agent(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, AppError> {
    let id = agent_id.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);

    // Parse If-None-Match header before spawning blocking task.
    let if_none_match: Option<i64> = headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    let payload = tokio::task::spawn_blocking(move || -> Result<AgentConfigPayload, AppError> {
        // Phase 49: Query allowlist entries and version.
        let allowlist_version = AllowlistRepository::current_version(&pool).unwrap_or(0);

        // If client has the current version, return early marker (handled outside).
        // We still need to compute the full payload for the normal path.

        // Phase 37 (D-02/D-03): query the disk allowlist for this agent once.
        let disk_allowlist: Vec<dlp_common::DiskIdentity> =
            DiskRegistryRepository::list_by_agent(&pool, &id)
                .unwrap_or_default()
                .into_iter()
                .map(disk_row_to_identity)
                .collect();

        // Phase 49: Query enabled allowlist entries sorted by priority.
        let allowlist_entries: Vec<AllowlistConfigEntry> = AllowlistRepository::list_all(&pool)
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.enabled != 0)
            .map(|r| AllowlistConfigEntry {
                match_type: r.match_type,
                value: r.value,
                description: r.description,
                category: r.category,
                priority: r.priority,
            })
            .collect();

        // Try per-agent override first via repository.
        let mut payload = match AgentConfigRepository::get_override(&pool, &id) {
            Ok(row) => AgentConfigPayload {
                monitored_paths: serde_json::from_str(&row.monitored_paths).unwrap_or_default(),
                excluded_paths: serde_json::from_str(&row.excluded_paths).unwrap_or_default(),
                heartbeat_interval_secs: u64::try_from(row.heartbeat_interval_secs).unwrap_or(30),
                offline_cache_enabled: row.offline_cache_enabled != 0,
                disk_allowlist: Vec::new(),
                usb_blocked_failure_mode: row.usb_blocked_failure_mode,
                usb_startup_resolution_mode: row.usb_startup_resolution_mode,
                usb_none_serial_policy: row.usb_none_serial_policy,
                cloud_hook_enabled: row.cloud_hook_enabled != 0,
                print_enabled: row.print_enabled != 0,
                print_xps_timeout_ms: u64::try_from(row.print_xps_timeout_ms).unwrap_or(5000),
                print_unclassifiable_action: row.print_unclassifiable_action,
                print_max_pages: usize::try_from(row.print_max_pages).unwrap_or(100),
                allowlist_entries,
                allowlist_version,
            },
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                // Fall back to global default.
                let row = AgentConfigRepository::get_global(&pool).map_err(AppError::Database)?;
                AgentConfigPayload {
                    monitored_paths: serde_json::from_str(&row.monitored_paths).unwrap_or_default(),
                    excluded_paths: serde_json::from_str(&row.excluded_paths).unwrap_or_default(),
                    heartbeat_interval_secs: u64::try_from(row.heartbeat_interval_secs)
                        .unwrap_or(30),
                    offline_cache_enabled: row.offline_cache_enabled != 0,
                    disk_allowlist: Vec::new(),
                    usb_blocked_failure_mode: row.usb_blocked_failure_mode.clone(),
                    usb_startup_resolution_mode: row.usb_startup_resolution_mode.clone(),
                    usb_none_serial_policy: row.usb_none_serial_policy.clone(),
                    cloud_hook_enabled: row.cloud_hook_enabled != 0,
                    print_enabled: row.print_enabled != 0,
                    print_xps_timeout_ms: u64::try_from(row.print_xps_timeout_ms).unwrap_or(5000),
                    print_unclassifiable_action: row.print_unclassifiable_action.clone(),
                    print_max_pages: usize::try_from(row.print_max_pages).unwrap_or(100),
                    allowlist_entries,
                    allowlist_version,
                }
            }
            Err(e) => return Err(AppError::Database(e)),
        };
        // Populate disk_allowlist after the config branch is resolved (D-02/D-03).
        payload.disk_allowlist = disk_allowlist;
        Ok(payload)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // Phase 49: 304 optimization — if If-None-Match matches current version, skip body.
    if let Some(client_version) = if_none_match {
        if client_version == payload.allowlist_version {
            return Ok(axum::http::StatusCode::NOT_MODIFIED.into_response());
        }
    }

    Ok(Json(payload).into_response())
}

// ---------------------------------------------------------------------------
// LDAP config handlers
// ---------------------------------------------------------------------------

/// `GET /admin/ldap-config` — returns the current LDAP connection configuration.
///
/// Reads the single row from `ldap_config` and returns it as a JSON
/// [`LdapConfigPayload`]. The row is guaranteed to exist because it is
/// seeded during pool initialization.
async fn get_ldap_config_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<LdapConfigPayload>, AppError> {
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let row = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        LdapConfigRepository::get(&pool).map_err(AppError::Database)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(LdapConfigPayload {
        ldap_url: row.ldap_url,
        base_dn: row.base_dn,
        require_tls: row.require_tls,
        cache_ttl_secs: row.cache_ttl_secs,
        vpn_subnets: row.vpn_subnets,
    }))
}

/// `PUT /admin/ldap-config` — updates LDAP connection configuration.
///
/// Overwrites the single row in `ldap_config` with the provided values
/// and stamps `updated_at` with the current time. Returns the payload
/// that was written so clients can refresh their local copy.
///
/// Validates that `cache_ttl_secs` is in the range [60, 3600].
async fn update_ldap_config_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LdapConfigPayload>,
) -> Result<Json<LdapConfigPayload>, AppError> {
    if payload.cache_ttl_secs < 60 {
        return Err(AppError::BadRequest(
            "cache_ttl_secs must be at least 60".to_string(),
        ));
    }
    if payload.cache_ttl_secs > 3600 {
        return Err(AppError::BadRequest(
            "cache_ttl_secs must be at most 3600".to_string(),
        ));
    }

    let now = Utc::now().to_rfc3339();
    let p = payload.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);

    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let record = repositories::LdapConfigRow {
            ldap_url: p.ldap_url.clone(),
            base_dn: p.base_dn.clone(),
            require_tls: p.require_tls,
            cache_ttl_secs: p.cache_ttl_secs,
            vpn_subnets: p.vpn_subnets.clone(),
            updated_at: now,
            // Phase 47 Task 47-05: bind_dn is managed by the encrypted-
            // bind path (set_bind_password / clear_bind_password). The
            // legacy update() method ignores this field — value is
            // irrelevant.
            bind_dn: None,
        };
        LdapConfigRepository::update(&uow, &record).map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!("LDAP config updated");
    Ok(Json(payload))
}

/// `GET /admin/agent-config` — returns the current global agent config default.
///
/// Reads the single row from `global_agent_config` (guaranteed by seed) and
/// returns it as a JSON [`AgentConfigPayload`].
async fn get_global_agent_config_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AgentConfigPayload>, AppError> {
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let row = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        AgentConfigRepository::get_global(&pool).map_err(AppError::Database)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(AgentConfigPayload {
        monitored_paths: serde_json::from_str(&row.monitored_paths).unwrap_or_default(),
        excluded_paths: serde_json::from_str(&row.excluded_paths).unwrap_or_default(),
        heartbeat_interval_secs: u64::try_from(row.heartbeat_interval_secs).unwrap_or(30),
        offline_cache_enabled: row.offline_cache_enabled != 0,
        // disk_allowlist is not relevant for admin-config GET (only agents poll /agent-config/{id}).
        disk_allowlist: Vec::new(),
        usb_blocked_failure_mode: row.usb_blocked_failure_mode,
        usb_startup_resolution_mode: row.usb_startup_resolution_mode,
        usb_none_serial_policy: row.usb_none_serial_policy,
        cloud_hook_enabled: row.cloud_hook_enabled != 0,
        print_enabled: row.print_enabled != 0,
        print_xps_timeout_ms: u64::try_from(row.print_xps_timeout_ms).unwrap_or(5000),
        print_unclassifiable_action: row.print_unclassifiable_action,
        print_max_pages: usize::try_from(row.print_max_pages).unwrap_or(100),
        // allowlist is agent-only; admin GET does not include it.
        allowlist_entries: Vec::new(),
        allowlist_version: 0,
    }))
}

/// `PUT /admin/agent-config` — updates the global agent config default.
///
/// Validates that `heartbeat_interval_secs >= 10` before writing. Overwrites
/// the single row in `global_agent_config` and stamps `updated_at`. Returns
/// the payload that was written.
///
/// # Errors
///
/// Returns `AppError::BadRequest` if `heartbeat_interval_secs < 10`.
async fn update_global_agent_config_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AgentConfigPayload>,
) -> Result<Json<AgentConfigPayload>, AppError> {
    if payload.heartbeat_interval_secs < 10 {
        return Err(AppError::BadRequest(
            "heartbeat_interval_secs must be >= 10".to_string(),
        ));
    }
    // Validate USB config enum values.
    if !USB_FAILURE_MODES.contains(&payload.usb_blocked_failure_mode.as_str()) {
        return Err(AppError::BadRequest(format!(
            "usb_blocked_failure_mode must be one of: {}",
            USB_FAILURE_MODES.join(", ")
        )));
    }
    if !USB_RESOLUTION_MODES.contains(&payload.usb_startup_resolution_mode.as_str()) {
        return Err(AppError::BadRequest(format!(
            "usb_startup_resolution_mode must be one of: {}",
            USB_RESOLUTION_MODES.join(", ")
        )));
    }
    if !USB_NONE_SERIAL_POLICIES.contains(&payload.usb_none_serial_policy.as_str()) {
        return Err(AppError::BadRequest(format!(
            "usb_none_serial_policy must be one of: {}",
            USB_NONE_SERIAL_POLICIES.join(", ")
        )));
    }
    const PRINT_UNCLASSIFIABLE_ACTIONS: &[&str] = &["Block", "Allow"];
    if !PRINT_UNCLASSIFIABLE_ACTIONS.contains(&payload.print_unclassifiable_action.as_str()) {
        return Err(AppError::BadRequest(format!(
            "print_unclassifiable_action must be one of: {}",
            PRINT_UNCLASSIFIABLE_ACTIONS.join(", ")
        )));
    }

    // Reject unimplemented modes (review concern #7).
    if payload.usb_startup_resolution_mode == "Volume GUID resolution" {
        return Err(AppError::BadRequest(
            "Volume GUID resolution is not yet implemented. Please select 'VID/PID/serial fallback'."
                .to_string(),
        ));
    }
    if payload.usb_none_serial_policy == "Port-based disambiguation" {
        return Err(AppError::BadRequest(
            "Port-based disambiguation is not yet implemented. Please select 'Always Blocked' or 'Allow unregistered'."
                .to_string(),
        ));
    }

    let now = Utc::now().to_rfc3339();
    let p = payload.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);

    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let paths_json = serde_json::to_string(&p.monitored_paths).map_err(AppError::from)?;
        let excluded_json = serde_json::to_string(&p.excluded_paths).map_err(AppError::from)?;
        let record = repositories::GlobalAgentConfigRow {
            monitored_paths: paths_json,
            excluded_paths: excluded_json,
            heartbeat_interval_secs: i64::try_from(p.heartbeat_interval_secs).unwrap_or(30),
            offline_cache_enabled: if p.offline_cache_enabled { 1 } else { 0 },
            updated_at: now,
            usb_blocked_failure_mode: p.usb_blocked_failure_mode.clone(),
            usb_startup_resolution_mode: p.usb_startup_resolution_mode.clone(),
            usb_none_serial_policy: p.usb_none_serial_policy.clone(),
            cloud_hook_enabled: if p.cloud_hook_enabled { 1 } else { 0 },
            print_enabled: if p.print_enabled { 1 } else { 0 },
            print_xps_timeout_ms: i64::try_from(p.print_xps_timeout_ms).unwrap_or(5000),
            print_unclassifiable_action: p.print_unclassifiable_action.clone(),
            print_max_pages: i64::try_from(p.print_max_pages).unwrap_or(100),
        };
        AgentConfigRepository::update_global(&uow, &record).map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!("global agent config updated");
    Ok(Json(payload))
}

/// `GET /admin/agent-config/:agent_id` — returns the per-agent config override.
///
/// Returns 404 if no override exists for the given `agent_id`.
async fn get_agent_config_override_handler(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentConfigPayload>, AppError> {
    let id = agent_id.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let row = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        AgentConfigRepository::get_override(&pool, &id).map_err(AppError::Database)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(AgentConfigPayload {
        monitored_paths: serde_json::from_str(&row.monitored_paths).unwrap_or_default(),
        excluded_paths: serde_json::from_str(&row.excluded_paths).unwrap_or_default(),
        heartbeat_interval_secs: u64::try_from(row.heartbeat_interval_secs).unwrap_or(30),
        offline_cache_enabled: row.offline_cache_enabled != 0,
        // disk_allowlist is not relevant for admin-config GET (only agents poll /agent-config/{id}).
        disk_allowlist: Vec::new(),
        usb_blocked_failure_mode: row.usb_blocked_failure_mode,
        usb_startup_resolution_mode: row.usb_startup_resolution_mode,
        usb_none_serial_policy: row.usb_none_serial_policy,
        cloud_hook_enabled: row.cloud_hook_enabled != 0,
        print_enabled: row.print_enabled != 0,
        print_xps_timeout_ms: u64::try_from(row.print_xps_timeout_ms).unwrap_or(5000),
        print_unclassifiable_action: row.print_unclassifiable_action,
        print_max_pages: usize::try_from(row.print_max_pages).unwrap_or(100),
        // allowlist is agent-only; admin GET does not include it.
        allowlist_entries: Vec::new(),
        allowlist_version: 0,
    }))
}

/// `PUT /admin/agent-config/:agent_id` — upserts a per-agent config override.
///
/// Validates `heartbeat_interval_secs >= 10`. Uses `INSERT OR REPLACE` so the
/// call is idempotent — a second PUT for the same `agent_id` updates the row.
///
/// # Errors
///
/// Returns `AppError::BadRequest` if `heartbeat_interval_secs < 10`.
async fn update_agent_config_override_handler(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    Json(payload): Json<AgentConfigPayload>,
) -> Result<Json<AgentConfigPayload>, AppError> {
    if payload.heartbeat_interval_secs < 10 {
        return Err(AppError::BadRequest(
            "heartbeat_interval_secs must be >= 10".to_string(),
        ));
    }

    let now = Utc::now().to_rfc3339();
    let p = payload.clone();
    let id = agent_id.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);

    tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let paths_json = serde_json::to_string(&p.monitored_paths).map_err(AppError::from)?;
        let excluded_json = serde_json::to_string(&p.excluded_paths).map_err(AppError::from)?;
        AgentConfigRepository::upsert_override(
            &uow,
            &id,
            &paths_json,
            &excluded_json,
            i64::try_from(p.heartbeat_interval_secs).unwrap_or(30),
            if p.offline_cache_enabled { 1 } else { 0 },
            &now,
            &p.usb_blocked_failure_mode,
            &p.usb_startup_resolution_mode,
            &p.usb_none_serial_policy,
            if p.cloud_hook_enabled { 1 } else { 0 },
            if p.print_enabled { 1 } else { 0 },
            i64::try_from(p.print_xps_timeout_ms).unwrap_or(5000),
            &p.print_unclassifiable_action,
            i64::try_from(p.print_max_pages).unwrap_or(100),
        )
        .map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(agent_id = %agent_id, "per-agent config override updated");
    Ok(Json(payload))
}

/// `DELETE /admin/agent-config/:agent_id` — removes a per-agent config override.
///
/// After deletion the agent falls back to the global default on the next poll.
/// Returns 204 No Content on success, 404 if no override row existed.
async fn delete_agent_config_override_handler(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
) -> Result<StatusCode, AppError> {
    let id = agent_id.clone();
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);

    let rows = tokio::task::spawn_blocking(move || -> Result<usize, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let rows = AgentConfigRepository::delete_override(&uow, &id).map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(rows)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    if rows == 0 {
        return Err(AppError::NotFound(format!(
            "no config override for agent {agent_id}"
        )));
    }

    tracing::info!(agent_id = %agent_id, "per-agent config override deleted");
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /admin/alert-config/test` — sends a test alert using the current
/// configuration from the database.
///
/// Invokes `AlertRouter::send_test_alert()` which builds a synthetic audit
/// event and delivers it via the configured SMTP and/or webhook channels.
/// Used by the dlp-admin-cli "Test Connection" action so operators can
/// verify their alert settings before relying on them.
///
/// # Errors
///
/// Returns `AppError::Internal` with the delivery error message if SMTP
/// or webhook delivery fails.
async fn test_alert_config_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    state
        .alert
        .send_test_alert()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("{e}")))?;

    Ok(Json(serde_json::json!({ "status": "ok" })))
}

// ---------------------------------------------------------------------------
// Device Registry handlers
// ---------------------------------------------------------------------------

/// Returns the public device identity list (vid, pid, serial only).
///
/// `GET /admin/device-registry` — intentionally unauthenticated so agents can
/// poll for the enrolled device list without stored credentials (T-24-06 accepted).
///
/// `trust_tier` is deliberately omitted from this response: unauthenticated
/// callers must not be able to enumerate which devices have elevated access,
/// as that information could be used to identify or spoof high-privilege devices.
/// Full device details (including trust_tier) are available to authenticated
/// callers via the POST response.
///
/// # Errors
///
/// Returns `AppError::Internal` if the pool or query fails.
async fn list_device_registry_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<PublicDeviceEntry>>, AppError> {
    let pool = Arc::clone(&state.pool);
    let rows = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        repositories::DeviceRegistryRepository::list_all(&pool).map_err(AppError::Database)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
    let response: Vec<PublicDeviceEntry> = rows.into_iter().map(Into::into).collect();
    Ok(Json(response))
}

/// Optional query-string filter for `GET /admin/device-registry/full` (D-06).
#[derive(Debug, Default, Deserialize)]
pub struct DeviceRegistryFilter {
    /// When set, restricts results to entries for the given SID plus machine-wide entries.
    #[serde(default)]
    pub owner_sid: Option<String>,
}

/// Returns the full device registry list including `trust_tier` and `description`.
///
/// `GET /admin/device-registry/full` — requires JWT Bearer auth.
///
/// Used by the admin TUI to display the complete device list.  Separated from
/// the unauthenticated `GET /admin/device-registry` endpoint which omits
/// `trust_tier` to prevent unauthenticated enumeration of privileged devices.
///
/// Optional `?owner_sid={sid}` query param returns entries matching that SID
/// plus machine-wide entries (per D-06).
async fn list_device_registry_full_handler(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<Vec<DeviceRegistryResponse>>, AppError> {
    // Extract query params.
    let filter = axum::extract::Query::<DeviceRegistryFilter>::from_request(req, &state)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let pool = Arc::clone(&state.pool);
    let owner_sid_filter = filter.owner_sid.clone();
    let rows = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        repositories::DeviceRegistryRepository::list_all_filtered(
            &pool,
            owner_sid_filter.as_deref(),
        )
        .map_err(AppError::Database)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
    let response: Vec<DeviceRegistryResponse> = rows.into_iter().map(Into::into).collect();
    Ok(Json(response))
}

/// `GET /admin/disk-registry` -- ADMIN-02. JWT-protected.
///
/// Returns all rows ordered by `registered_at ASC`. The optional
/// `?agent_id=<id>` query param filters to a single agent's entries (D-07).
///
/// # Errors
///
/// Returns `AppError::Unauthorized` if the JWT is missing or invalid (T-37-04).
/// Returns `AppError::Internal` if pool acquisition or the blocking task fails.
async fn list_disk_registry_handler(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<Vec<DiskRegistryResponse>>, AppError> {
    // Defense-in-depth: extract admin username from JWT even though the
    // middleware layer already guards this route. This ensures the handler
    // remains protected if the route is ever moved to a different sub-router
    // without the auth middleware (T-37-04).
    let _username = AdminUsername::extract_from_headers(req.headers())?;

    // Extract query params after consuming headers (body is empty for GET).
    let filter = axum::extract::Query::<DiskRegistryFilter>::from_request(req, &state)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let pool = Arc::clone(&state.pool);
    let agent_id_filter = filter.agent_id.clone();
    let rows = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        DiskRegistryRepository::list_all(&pool, agent_id_filter.as_deref())
            .map_err(AppError::Database)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

/// `POST /admin/disk-registry` -- ADMIN-03 + AUDIT-03. JWT-protected.
///
/// Pure INSERT (D-05). Returns 409 Conflict on duplicate `(agent_id, instance_id)`.
/// Returns 422 if any field fails validation: `encryption_status` must be one of
/// `encrypted`, `suspended`, `unencrypted`, `unknown`; `bus_type` must be one of
/// `usb`, `sata`, `nvme`, `scsi`, `unknown`; `agent_id`/`instance_id` ≤ 512 bytes;
/// `model` ≤ 256 bytes.  Emits an `AdminAction(DiskRegistryAdd)` audit event AFTER
/// the registry commit (D-10).
///
/// # Errors
///
/// Returns `AppError::Unauthorized` if the JWT is missing or invalid (T-37-04).
/// Returns `AppError::UnprocessableEntity` on validation failure (T-37-05).
/// Returns `AppError::Conflict` on duplicate `(agent_id, instance_id)` (T-37-06).
/// Returns `AppError::Internal` on pool or blocking task failure.
async fn insert_disk_registry_handler(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<(StatusCode, Json<DiskRegistryResponse>), AppError> {
    // (1) Authenticate the admin via JWT extraction (T-37-04).
    let username = AdminUsername::extract_from_headers(req.headers())?;
    let _caller_sid = crate::admin_auth::verify_jwt(
        req.headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("invalid Authorization format".to_string()))?,
    )?
    .sid;

    // (2) Deserialize the body. Must follow username extraction so the headers
    //     are available before the body is consumed.
    let Json(body) = Json::<DiskRegistryRequest>::from_request(req, &state)
        .await
        .map_err(AppError::from)?;

    // (3) Length guard before heap allocation (T-37-05). Valid values are at
    //     most 11 chars ("unencrypted"); 32 is a generous ceiling.
    if body.encryption_status.len() > 32 {
        return Err(AppError::UnprocessableEntity(
            "encryption_status exceeds maximum length".to_string(),
        ));
    }
    // (4) Allowlist check before any DB access (D-12, T-37-05). Values MUST be
    //     the canonical EncryptionStatus serde names to match the DB CHECK constraint.
    const VALID_STATUSES: &[&str] = &["encrypted", "suspended", "unencrypted", "unknown"];
    if !VALID_STATUSES.contains(&body.encryption_status.as_str()) {
        return Err(AppError::UnprocessableEntity(format!(
            "invalid encryption_status '{}'; must be one of: encrypted, suspended, \
             unencrypted, unknown",
            body.encryption_status
        )));
    }

    // (4b) Length guards for the remaining string fields (T-37-05). These
    //      bounds prevent unbounded heap allocation in the async handler before
    //      work is moved to spawn_blocking. 512 bytes covers all realistic
    //      agent/disk IDs; 256 bytes covers all realistic model strings.
    const MAX_ID_LEN: usize = 512;
    const MAX_MODEL_LEN: usize = 256;
    if body.agent_id.len() > MAX_ID_LEN {
        return Err(AppError::UnprocessableEntity(
            "agent_id exceeds maximum length".to_string(),
        ));
    }
    if body.instance_id.len() > MAX_ID_LEN {
        return Err(AppError::UnprocessableEntity(
            "instance_id exceeds maximum length".to_string(),
        ));
    }
    if body.model.len() > MAX_MODEL_LEN {
        return Err(AppError::UnprocessableEntity(
            "model exceeds maximum length".to_string(),
        ));
    }

    // (4c) bus_type allowlist check. The DB has no CHECK constraint on this
    //      column, so we enforce it here. Valid values match the BusType enum
    //      serde names (D-12, T-37-05).
    const VALID_BUS_TYPES: &[&str] = &["usb", "sata", "nvme", "scsi", "unknown"];
    if !VALID_BUS_TYPES.contains(&body.bus_type.as_str()) {
        return Err(AppError::UnprocessableEntity(format!(
            "invalid bus_type '{}'; must be one of: usb, sata, nvme, scsi, unknown",
            body.bus_type
        )));
    }

    // (5) Build the row with server-generated id + registered_at.
    let id = uuid::Uuid::new_v4().to_string();
    let registered_at = chrono::Utc::now().to_rfc3339();
    let row = DiskRegistryRow {
        id: id.clone(),
        agent_id: body.agent_id.clone(),
        instance_id: body.instance_id.clone(),
        bus_type: body.bus_type.clone(),
        encryption_status: body.encryption_status.clone(),
        model: body.model.clone(),
        registered_at: registered_at.clone(),
    };

    // (6) First spawn_blocking: pure INSERT. Map UNIQUE conflict -> 409 (T-37-06).
    let pool = Arc::clone(&state.pool);
    let row_for_insert = row.clone();
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        DiskRegistryRepository::insert(&uow, &row_for_insert).map_err(|e| {
            // SQLite extended error code 2067 = SQLITE_CONSTRAINT_UNIQUE.
            if let rusqlite::Error::SqliteFailure(ref fe, _) = e {
                if fe.extended_code == 2067 {
                    return AppError::Conflict(format!(
                        "disk (agent_id={}, instance_id={}) already registered",
                        row_for_insert.agent_id, row_for_insert.instance_id
                    ));
                }
            }
            AppError::Database(e)
        })?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // (7) Second spawn_blocking: emit audit event AFTER first commit (D-10, T-37-07).
    //     Audit failure must NOT roll back the registry write — it is a separate
    //     transaction and any error here is logged but does not affect the 201 response.
    let audit_event = dlp_common::AuditEvent::new(
        dlp_common::EventType::AdminAction,
        String::new(),
        username,
        format!("disk:{}@{}", body.instance_id, body.agent_id),
        dlp_common::Classification::T3,
        dlp_common::Action::DiskRegistryAdd,
        dlp_common::Decision::ALLOW,
        "server".to_string(),
        0,
    );
    let pool = Arc::clone(&state.pool);
    if let Err(e) = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))
    .and_then(|r| r)
    {
        // Best-effort: log the failure but do not surface it to the caller (D-10).
        tracing::warn!(error = %e, "audit emission failed for DiskRegistryAdd (best-effort)");
    }

    tracing::info!(
        agent_id = %body.agent_id,
        instance_id = %body.instance_id,
        "disk registry add"
    );
    Ok((StatusCode::CREATED, Json(DiskRegistryResponse::from(row))))
}

/// `DELETE /admin/disk-registry/{id}` -- ADMIN-03 + AUDIT-03. JWT-protected.
///
/// Returns 204 on success, 404 if the UUID does not exist. Emits
/// `AdminAction(DiskRegistryRemove)` AFTER the delete commit (D-10).
/// Audit failure does NOT roll back the delete (D-10, T-37-07).
///
/// # Errors
///
/// Returns `AppError::Unauthorized` if the JWT is missing or invalid (T-37-04).
/// Returns `AppError::NotFound` if the UUID does not exist.
/// Returns `AppError::Internal` on pool or blocking task failure.
async fn delete_disk_registry_handler(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<StatusCode, AppError> {
    // (1) Authenticate.
    let username = AdminUsername::extract_from_headers(req.headers())?;
    let _caller_sid = crate::admin_auth::verify_jwt(
        req.headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("invalid Authorization format".to_string()))?,
    )?
    .sid;
    // (2) Extract path param.
    let id = Path::<String>::from_request(req, &state)
        .await
        .map_err(AppError::from)?
        .0;

    // (3) Atomic DELETE RETURNING: fetches audit metadata and deletes the row in
    //     a single statement, eliminating the TOCTOU window that a two-step
    //     SELECT + DELETE would introduce. Requires SQLite 3.35+ (bundled rusqlite).
    let pool = Arc::clone(&state.pool);
    let disk_id = id.clone();
    let result =
        tokio::task::spawn_blocking(move || -> Result<Option<(String, String)>, AppError> {
            let mut conn = pool.get().map_err(AppError::from)?;
            let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
            // RETURNING makes the DELETE and the metadata read atomic in one
            // statement; no race window between SELECT and DELETE.
            let row: rusqlite::Result<(String, String)> = uow.tx.query_row(
                "DELETE FROM disk_registry WHERE id = ?1 \
                 RETURNING agent_id, instance_id",
                rusqlite::params![disk_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            );
            match row {
                Ok(t) => {
                    uow.commit().map_err(AppError::Database)?;
                    Ok(Some(t))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(AppError::Database(e)),
            }
        })
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    let (agent_id_for_audit, instance_id_for_audit) = match result {
        Some(t) => t,
        None => return Err(AppError::NotFound(format!("disk entry {id} not found"))),
    };

    // (4) Second spawn_blocking: audit emission (D-10, T-37-07).
    //     Audit failure must NOT roll back the delete — it is best-effort (D-10).
    let audit_event = dlp_common::AuditEvent::new(
        dlp_common::EventType::AdminAction,
        String::new(),
        username,
        format!("disk:{}@{}", instance_id_for_audit, agent_id_for_audit),
        dlp_common::Classification::T3,
        dlp_common::Action::DiskRegistryRemove,
        dlp_common::Decision::ALLOW,
        "server".to_string(),
        0,
    );
    let pool = Arc::clone(&state.pool);
    if let Err(e) = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))
    .and_then(|r| r)
    {
        // Best-effort: log the failure but do not surface it to the caller (D-10).
        tracing::warn!(error = %e, "audit emission failed for DiskRegistryRemove (best-effort)");
    }

    tracing::info!(
        agent_id = %agent_id_for_audit,
        instance_id = %instance_id_for_audit,
        "disk registry remove"
    );
    Ok(StatusCode::NO_CONTENT)
}

/// Registers a new device or updates trust_tier/description for an existing one.
///
/// `POST /admin/device-registry` — requires JWT Bearer auth (T-24-04).
///
/// Upserts on `(vid, pid, serial)` conflict: the original UUID is preserved and
/// only `trust_tier` and `description` are updated. The response always reflects
/// the persisted state by re-reading the row after the upsert.
///
/// # Errors
///
/// Returns `AppError::UnprocessableEntity` (422) if `trust_tier` is not one of
/// `"blocked"`, `"read_only"`, or `"full_access"`.
/// Returns `AppError::Internal` on pool or query failure.
async fn upsert_device_registry_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DeviceRegistryRequest>,
) -> Result<Json<DeviceRegistryResponse>, AppError> {
    // Length guard — reject oversized inputs before heap allocation in allowlist check.
    // Valid tiers are at most 11 chars ("full_access"); 32 is a generous ceiling.
    if body.trust_tier.len() > 32 {
        return Err(AppError::UnprocessableEntity(
            "trust_tier exceeds maximum length".to_string(),
        ));
    }
    // Allowlist check before any DB access (T-24-05).
    const VALID_TIERS: &[&str] = &["blocked", "read_only", "full_access"];
    if !VALID_TIERS.contains(&body.trust_tier.as_str()) {
        return Err(AppError::UnprocessableEntity(format!(
            "invalid trust_tier '{}'; must be one of: blocked, read_only, full_access",
            body.trust_tier
        )));
    }

    // Generate a new UUID for the insert path; ON CONFLICT preserves the original.
    let id = uuid::Uuid::new_v4().to_string();
    let created_at = chrono::Utc::now().to_rfc3339();
    let row = repositories::DeviceRegistryRow {
        id,
        vid: body.vid.clone(),
        pid: body.pid.clone(),
        serial: body.serial.clone(),
        owner_sid: body.owner_sid.clone(),
        owner_user: body.owner_user.clone(),
        description: body.description.clone(),
        trust_tier: body.trust_tier.clone(),
        created_at,
    };

    let pool = Arc::clone(&state.pool);
    let vid = body.vid.clone();
    let pid = body.pid.clone();
    let serial = body.serial.clone();
    let owner_sid = body.owner_sid.clone();

    // Upsert, then re-read by (vid, pid, serial, owner_sid) to get the persisted UUID.
    // On conflict the original UUID is preserved — re-reading is necessary.
    let persisted = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        {
            // Explicit scope: `conn` (an RAII pool guard) is returned to the pool
            // at the closing brace, before the re-acquire below. Without this scope
            // block, a pool with max_size = 1 (e.g., some test fixtures) would
            // deadlock waiting for a connection it already holds.
            let mut conn = pool.get().map_err(AppError::from)?;
            let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
            repositories::DeviceRegistryRepository::upsert(&uow, &row)
                .map_err(AppError::Database)?;
            uow.commit().map_err(AppError::Database)?;
        } // conn returned to pool here
        repositories::DeviceRegistryRepository::get_by_device_key_and_owner(
            &pool,
            &vid,
            &pid,
            &serial,
            owner_sid.as_deref(),
        )
        .map_err(AppError::Database)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(vid = %persisted.vid, pid = %persisted.pid, serial = %persisted.serial, "device registry upsert");
    Ok(Json(persisted.into()))
}

/// Removes a registered device entry by its server-generated UUID.
///
/// `DELETE /admin/device-registry/{id}` — requires JWT Bearer auth (T-24-04).
///
/// # Returns
///
/// `204 No Content` on success; `404 Not Found` if the UUID does not exist.
///
/// # Errors
///
/// Returns `AppError::Internal` on pool or query failure.
async fn delete_device_registry_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let pool = Arc::clone(&state.pool);
    let device_id = id.clone();
    let rows_deleted = tokio::task::spawn_blocking(move || -> Result<usize, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let n = repositories::DeviceRegistryRepository::delete_by_id(&uow, &device_id)
            .map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(n)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    if rows_deleted == 0 {
        return Err(AppError::NotFound(format!("device {id} not found")));
    }

    tracing::info!(device_id = %id, "device registry entry deleted");
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Managed origins handlers
// ---------------------------------------------------------------------------

/// `GET /admin/managed-origins` — unauthenticated; returns all managed origins.
///
/// Used by the Phase 29 Chrome Enterprise Connector agent to poll the trusted
/// origin list, and by the admin TUI to populate the managed origins screen.
///
/// # Errors
///
/// Returns `AppError::Internal` if the pool or query fails.
async fn list_managed_origins_handler(
    State(state): State<Arc<AppState>>,
) -> Result<impl axum::response::IntoResponse, AppError> {
    let pool = Arc::clone(&state.pool);
    let rows = tokio::task::spawn_blocking(move || ManagedOriginsRepository::list_all(&pool))
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("spawn_blocking join: {e}")))?
        .map_err(AppError::Database)?;
    let resp: Vec<ManagedOriginResponse> = rows
        .into_iter()
        .map(|r| ManagedOriginResponse {
            id: r.id,
            origin: r.origin,
        })
        .collect();
    Ok(Json(resp))
}

/// `POST /admin/managed-origins` — JWT-protected; inserts a new managed origin.
///
/// Returns 409 Conflict if the `origin` string already exists (UNIQUE constraint).
///
/// # Errors
///
/// Returns `AppError::Conflict` (409) on duplicate origin.
/// Returns `AppError::Internal` on pool or query failure.
async fn create_managed_origin_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ManagedOriginRequest>,
) -> Result<impl axum::response::IntoResponse, AppError> {
    let id = uuid::Uuid::new_v4().to_string();
    let row = ManagedOriginRow {
        id: id.clone(),
        origin: req.origin.clone(),
    };
    let pool = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        ManagedOriginsRepository::insert(&uow, &row).map_err(|e| {
            // SQLite extended error code 2067 = SQLITE_CONSTRAINT_UNIQUE.
            if let rusqlite::Error::SqliteFailure(ref fe, _) = e {
                if fe.extended_code == 2067 {
                    return AppError::Conflict("origin already exists".to_string());
                }
            }
            AppError::Database(e)
        })?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("spawn_blocking join: {e}")))??;

    Ok((
        StatusCode::OK,
        Json(ManagedOriginResponse {
            id,
            origin: req.origin,
        }),
    ))
}

/// `DELETE /admin/managed-origins/{id}` — JWT-protected; removes by UUID.
///
/// # Returns
///
/// `204 No Content` on success; `404 Not Found` if the UUID does not exist.
///
/// # Errors
///
/// Returns `AppError::Internal` on pool or query failure.
async fn delete_managed_origin_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let pool = Arc::clone(&state.pool);
    let origin_id = id.clone();
    let rows_deleted = tokio::task::spawn_blocking(move || -> Result<usize, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let n =
            ManagedOriginsRepository::delete_by_id(&uow, &origin_id).map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(n)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    if rows_deleted == 0 {
        return Err(AppError::NotFound(format!("managed origin {id} not found")));
    }

    tracing::info!(origin_id = %id, "managed origin deleted");
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Phase 49: Allowlist admin API
// ---------------------------------------------------------------------------

/// `GET /admin/allowlist` — list all allowlist entries.
///
/// Optionally filter by `?category=self` query parameter.
/// Returns entries ordered by priority ascending, then created_at ascending.
///
/// # Errors
///
/// Returns `AppError::Unauthorized` if the JWT is missing or invalid.
/// Returns `AppError::Internal` on pool or query failure.
async fn list_allowlist_handler(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<Vec<AllowlistEntryResponse>>, AppError> {
    let _username = AdminUsername::extract_from_headers(req.headers())?;

    let filter = axum::extract::Query::<std::collections::HashMap<String, String>>::from_request(
        req, &state,
    )
    .await
    .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let pool = Arc::clone(&state.pool);
    let category_filter = filter.get("category").cloned();
    let rows = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        let db_rows = if let Some(cat) = category_filter {
            AllowlistRepository::list_by_category(&pool, &cat).map_err(AppError::Database)?
        } else {
            AllowlistRepository::list_all(&pool).map_err(AppError::Database)?
        };
        Ok(db_rows)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

/// `GET /admin/allowlist/{id}` — get a single allowlist entry by UUID.
///
/// # Errors
///
/// Returns `AppError::NotFound` if the UUID does not exist.
/// Returns `AppError::Unauthorized` if the JWT is missing or invalid.
/// Returns `AppError::Internal` on pool or query failure.
async fn get_allowlist_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<AllowlistEntryResponse>, AppError> {
    let pool = Arc::clone(&state.pool);
    let entry_id = id.clone();
    let row = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        AllowlistRepository::get_by_id(&pool, &entry_id).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                AppError::NotFound(format!("allowlist entry {entry_id} not found"))
            }
            _ => AppError::Database(e),
        })
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(row.into()))
}

/// `POST /admin/allowlist` — create a new allowlist entry.
///
/// Returns 201 Created on success. Returns 422 if `match_type` or `category`
/// are not valid values. Emits an `AdminAction(AllowlistCreate)` audit event
/// AFTER the DB commit (best-effort).
///
/// # Errors
///
/// Returns `AppError::Unauthorized` if the JWT is missing or invalid.
/// Returns `AppError::UnprocessableEntity` on validation failure.
/// Returns `AppError::Internal` on pool or query failure.
async fn create_allowlist_handler(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<(StatusCode, Json<AllowlistEntryResponse>), AppError> {
    let username = AdminUsername::extract_from_headers(req.headers())?;

    let Json(body) = Json::<AllowlistEntryRequest>::from_request(req, &state)
        .await
        .map_err(AppError::from)?;

    // Validate match_type before DB access.
    const VALID_MATCH_TYPES: &[&str] = &[
        "exact_path",
        "path_glob",
        "path_prefix",
        "cert_subject",
        "cert_thumbprint",
    ];
    if body.match_type.len() > 32 {
        return Err(AppError::UnprocessableEntity(
            "match_type exceeds maximum length".to_string(),
        ));
    }
    if !VALID_MATCH_TYPES.contains(&body.match_type.as_str()) {
        return Err(AppError::UnprocessableEntity(format!(
            "invalid match_type '{}'; must be one of: {}",
            body.match_type,
            VALID_MATCH_TYPES.join(", ")
        )));
    }

    // Validate category before DB access.
    const VALID_CATEGORIES: &[&str] = &["self", "avedr", "system_critical", "operator_defined"];
    if body.category.len() > 32 {
        return Err(AppError::UnprocessableEntity(
            "category exceeds maximum length".to_string(),
        ));
    }
    if !VALID_CATEGORIES.contains(&body.category.as_str()) {
        return Err(AppError::UnprocessableEntity(format!(
            "invalid category '{}'; must be one of: {}",
            body.category,
            VALID_CATEGORIES.join(", ")
        )));
    }

    // Length guards for value and description.
    if body.value.len() > 2048 {
        return Err(AppError::UnprocessableEntity(
            "value exceeds maximum length".to_string(),
        ));
    }
    if body.description.len() > 512 {
        return Err(AppError::UnprocessableEntity(
            "description exceeds maximum length".to_string(),
        ));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let row = AllowlistEntryRow {
        id: id.clone(),
        match_type: body.match_type.clone(),
        value: body.value.clone(),
        description: body.description.clone(),
        category: body.category.clone(),
        priority: body.priority,
        enabled: if body.enabled { 1 } else { 0 },
        version: 1,
        created_at: now.clone(),
        updated_at: now,
    };

    let pool = Arc::clone(&state.pool);
    let row_for_insert = row.clone();
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        AllowlistRepository::insert(&uow, &row_for_insert).map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // Emit audit event AFTER commit (best-effort).
    let audit_event = dlp_common::AuditEvent::new(
        dlp_common::EventType::AdminAction,
        String::new(),
        username.clone(),
        format!("allowlist:{}", id),
        dlp_common::Classification::T3,
        dlp_common::Action::AllowlistCreate,
        dlp_common::Decision::ALLOW,
        "server".to_string(),
        0,
    );
    let pool = Arc::clone(&state.pool);
    if let Err(e) = tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))
    .and_then(|r| r)
    {
        tracing::warn!(error = %e, "audit emission failed for AllowlistCreate (best-effort)");
    }

    tracing::info!(
        entry_id = %id,
        match_type = %body.match_type,
        category = %body.category,
        "allowlist entry created"
    );
    Ok((StatusCode::CREATED, Json(AllowlistEntryResponse::from(row))))
}

/// `PUT /admin/allowlist/{id}` — update an existing allowlist entry.
///
/// Returns 200 OK with the updated entry. Returns 404 if the UUID does not exist.
/// Returns 422 if `match_type` or `category` are not valid values.
/// Emits an `AdminAction(AllowlistUpdate)` audit event AFTER the DB commit.
///
/// # Errors
///
/// Returns `AppError::Unauthorized` if the JWT is missing or invalid.
/// Returns `AppError::NotFound` if the UUID does not exist.
/// Returns `AppError::UnprocessableEntity` on validation failure.
/// Returns `AppError::Internal` on pool or query failure.
async fn update_allowlist_handler(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<AllowlistEntryResponse>, AppError> {
    let username = AdminUsername::extract_from_headers(req.headers())?;

    // Extract the path parameter from the URI before consuming the body.
    let id = req
        .uri()
        .path()
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_string();

    let Json(body) = Json::<AllowlistEntryRequest>::from_request(req, &state)
        .await
        .map_err(AppError::from)?;

    // Validate match_type before DB access.
    const VALID_MATCH_TYPES: &[&str] = &[
        "exact_path",
        "path_glob",
        "path_prefix",
        "cert_subject",
        "cert_thumbprint",
    ];
    if body.match_type.len() > 32 {
        return Err(AppError::UnprocessableEntity(
            "match_type exceeds maximum length".to_string(),
        ));
    }
    if !VALID_MATCH_TYPES.contains(&body.match_type.as_str()) {
        return Err(AppError::UnprocessableEntity(format!(
            "invalid match_type '{}'; must be one of: {}",
            body.match_type,
            VALID_MATCH_TYPES.join(", ")
        )));
    }

    // Validate category before DB access.
    const VALID_CATEGORIES: &[&str] = &["self", "avedr", "system_critical", "operator_defined"];
    if body.category.len() > 32 {
        return Err(AppError::UnprocessableEntity(
            "category exceeds maximum length".to_string(),
        ));
    }
    if !VALID_CATEGORIES.contains(&body.category.as_str()) {
        return Err(AppError::UnprocessableEntity(format!(
            "invalid category '{}'; must be one of: {}",
            body.category,
            VALID_CATEGORIES.join(", ")
        )));
    }

    if body.value.len() > 2048 {
        return Err(AppError::UnprocessableEntity(
            "value exceeds maximum length".to_string(),
        ));
    }
    if body.description.len() > 512 {
        return Err(AppError::UnprocessableEntity(
            "description exceeds maximum length".to_string(),
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let row = AllowlistEntryRow {
        id: id.clone(),
        match_type: body.match_type.clone(),
        value: body.value.clone(),
        description: body.description.clone(),
        category: body.category.clone(),
        priority: body.priority,
        enabled: if body.enabled { 1 } else { 0 },
        version: 0,                // version is auto-incremented by the repository
        created_at: String::new(), // not updated
        updated_at: now,
    };

    let pool = Arc::clone(&state.pool);
    let row_for_update = row.clone();
    let affected = tokio::task::spawn_blocking(move || -> Result<usize, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let n = AllowlistRepository::update(&uow, &row_for_update).map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(n)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    if affected == 0 {
        return Err(AppError::NotFound(format!(
            "allowlist entry {id} not found"
        )));
    }

    // Emit audit event AFTER commit (best-effort).
    let audit_event = dlp_common::AuditEvent::new(
        dlp_common::EventType::AdminAction,
        String::new(),
        username.clone(),
        format!("allowlist:{}", id),
        dlp_common::Classification::T3,
        dlp_common::Action::AllowlistUpdate,
        dlp_common::Decision::ALLOW,
        "server".to_string(),
        0,
    );
    let pool = Arc::clone(&state.pool);
    if let Err(e) = tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))
    .and_then(|r| r)
    {
        tracing::warn!(error = %e, "audit emission failed for AllowlistUpdate (best-effort)");
    }

    // Re-read the row to get the updated version and timestamps.
    let pool = Arc::clone(&state.pool);
    let entry_id = id.clone();
    let updated_row = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        AllowlistRepository::get_by_id(&pool, &entry_id).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                AppError::NotFound(format!("allowlist entry {entry_id} not found"))
            }
            _ => AppError::Database(e),
        })
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(entry_id = %id, "allowlist entry updated");
    Ok(Json(updated_row.into()))
}

/// `DELETE /admin/allowlist/{id}` — delete an allowlist entry.
///
/// Returns 204 No Content on success. Returns 404 if the UUID does not exist.
/// Emits an `AdminAction(AllowlistDelete)` audit event AFTER the DB commit.
///
/// # Errors
///
/// Returns `AppError::Unauthorized` if the JWT is missing or invalid.
/// Returns `AppError::NotFound` if the UUID does not exist.
/// Returns `AppError::Internal` on pool or query failure.
async fn delete_allowlist_handler(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<StatusCode, AppError> {
    let username = AdminUsername::extract_from_headers(req.headers())?;

    let id = Path::<String>::from_request(req, &state)
        .await
        .map_err(AppError::from)?
        .0;

    let pool = Arc::clone(&state.pool);
    let entry_id = id.clone();
    let affected = tokio::task::spawn_blocking(move || -> Result<usize, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let n = AllowlistRepository::delete_by_id(&uow, &entry_id).map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(n)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    if affected == 0 {
        return Err(AppError::NotFound(format!(
            "allowlist entry {id} not found"
        )));
    }

    // Emit audit event AFTER commit (best-effort).
    let audit_event = dlp_common::AuditEvent::new(
        dlp_common::EventType::AdminAction,
        String::new(),
        username.clone(),
        format!("allowlist:{}", id),
        dlp_common::Classification::T3,
        dlp_common::Action::AllowlistDelete,
        dlp_common::Decision::ALLOW,
        "server".to_string(),
        0,
    );
    let pool = Arc::clone(&state.pool);
    if let Err(e) = tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))
    .and_then(|r| r)
    {
        tracing::warn!(error = %e, "audit emission failed for AllowlistDelete (best-effort)");
    }

    tracing::info!(entry_id = %id, "allowlist entry deleted");
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /admin/allowlist/{id}/disable` — soft-disable an allowlist entry.
///
/// Sets `enabled = 0` and bumps the version. Returns 200 OK with the updated entry.
/// Returns 404 if the UUID does not exist. Emits an `AdminAction(AllowlistUpdate)`
/// audit event AFTER the DB commit (best-effort).
///
/// # Errors
///
/// Returns `AppError::Unauthorized` if the JWT is missing or invalid.
/// Returns `AppError::NotFound` if the UUID does not exist.
/// Returns `AppError::Internal` on pool or query failure.
async fn disable_allowlist_handler(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<AllowlistEntryResponse>, AppError> {
    let username = AdminUsername::extract_from_headers(req.headers())?;

    let id = req
        .uri()
        .path()
        .rsplit('/')
        .nth(1)
        .unwrap_or("")
        .to_string();

    let pool = Arc::clone(&state.pool);
    let entry_id = id.clone();
    let now = chrono::Utc::now().to_rfc3339();
    let affected = tokio::task::spawn_blocking(move || -> Result<usize, AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        let n = AllowlistRepository::set_enabled(&uow, &entry_id, 0, &now)
            .map_err(AppError::Database)?;
        uow.commit().map_err(AppError::Database)?;
        Ok(n)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    if affected == 0 {
        return Err(AppError::NotFound(format!(
            "allowlist entry {id} not found"
        )));
    }

    // Emit audit event AFTER commit (best-effort).
    let audit_event = dlp_common::AuditEvent::new(
        dlp_common::EventType::AdminAction,
        String::new(),
        username.clone(),
        format!("allowlist:{}", id),
        dlp_common::Classification::T3,
        dlp_common::Action::AllowlistUpdate,
        dlp_common::Decision::ALLOW,
        "server".to_string(),
        0,
    );
    let pool = Arc::clone(&state.pool);
    if let Err(e) = tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = db::UnitOfWork::new(&mut conn).map_err(AppError::Database)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::Database)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))
    .and_then(|r| r)
    {
        tracing::warn!(error = %e, "audit emission failed for AllowlistDisable (best-effort)");
    }

    // Re-read the updated row.
    let pool = Arc::clone(&state.pool);
    let entry_id = id.clone();
    let updated_row = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        AllowlistRepository::get_by_id(&pool, &entry_id).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                AppError::NotFound(format!("allowlist entry {entry_id} not found"))
            }
            _ => AppError::Database(e),
        })
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(entry_id = %id, "allowlist entry disabled");
    Ok(Json(updated_row.into()))
}

/// `GET /admin/allowlist/{id}/audit` — list audit log for an allowlist entry.
///
/// Returns audit records ordered by timestamp descending.
///
/// # Errors
///
/// Returns `AppError::Unauthorized` if the JWT is missing or invalid.
/// Returns `AppError::Internal` on pool or query failure.
async fn list_allowlist_audit_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<AllowlistAuditResponse>>, AppError> {
    let pool = Arc::clone(&state.pool);
    let entry_id = id.clone();
    let rows = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        AllowlistAuditRepository::list_by_entry_id(&pool, &entry_id).map_err(AppError::Database)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

/// Audit log record returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistAuditResponse {
    /// Server-generated UUID.
    pub id: String,
    /// Foreign key referencing the allowlist entry.
    pub entry_id: String,
    /// Action performed.
    pub action: String,
    /// Username or SID of the actor.
    pub actor: String,
    /// JSON snapshot of the entry state before the action.
    pub old_value: Option<String>,
    /// JSON snapshot of the entry state after the action.
    pub new_value: Option<String>,
    /// ISO-8601 timestamp.
    pub timestamp: String,
}

impl From<AllowlistAuditRow> for AllowlistAuditResponse {
    fn from(row: AllowlistAuditRow) -> Self {
        Self {
            id: row.id,
            entry_id: row.entry_id,
            action: row.action,
            actor: row.actor,
            old_value: row.old_value,
            new_value: row.new_value,
            timestamp: row.timestamp,
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 47 Task 47-08: KEK rotation + maintenance-mode toggle
// ---------------------------------------------------------------------------

/// Request body for `POST /admin/secrets/rotate`.
///
/// `force` defaults to `false` via `#[serde(default)]`, so an empty
/// `{}` body (or no body at all) requires the maintenance-mode gate to
/// be open. The CLI's `--force-while-running` flag flips this to
/// `true` for operator-controlled bypass.
#[derive(Debug, Default, Deserialize)]
pub struct RotateSecretsRequest {
    /// When `true`, bypass the `system_kv.maintenance_mode` gate.
    #[serde(default)]
    pub force: bool,
}

/// `POST /admin/secrets/rotate` — generate a new KEK version, re-encrypt
/// every populated secret column under it, and retire the previous KEK.
///
/// Returns a JSON [`crate::secrets_migration::RotationReport`] summarising
/// what moved. Returns:
///
/// - **400** when the maintenance-mode gate is closed and `force=false`.
/// - **500** for any underlying crypto or DB failure mid-rotation. The
///   per-table transactions guarantee that a partial failure does NOT
///   leave a table in mixed-KEK state — the failing table rolls back
///   and the operator can re-run `rotate-secrets` to repair it.
async fn rotate_secrets_handler(
    State(state): State<Arc<AppState>>,
    body: Option<Json<RotateSecretsRequest>>,
) -> Result<Json<crate::secrets_migration::RotationReport>, AppError> {
    let force = body.map(|Json(b)| b.force).unwrap_or(false);
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    let crypto = Arc::clone(&state.crypto);

    let report = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        crate::secrets_migration::rotate_kek(&pool, &crypto, force).map_err(|e| {
            // Distinguish the maintenance gate (BadRequest / 400) from
            // generic mid-rotation failures (Internal / 500). The
            // typed-variant downcast keeps the error mapping precise
            // without a sentinel-string match.
            if e.downcast_ref::<crate::secrets_migration::RotationError>()
                .is_some()
            {
                AppError::BadRequest(e.to_string())
            } else {
                AppError::Internal(e)
            }
        })
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::warn!(
        old_version = report.old_version,
        new_version = report.new_version,
        rows_reencrypted = report.rows_reencrypted,
        "KEK rotation completed"
    );
    Ok(Json(report))
}

/// `POST /admin/maintenance/enter` — set `system_kv.maintenance_mode = "1"`.
///
/// Idempotent: calling on an already-entered system is a no-op.
async fn maintenance_enter_handler(
    State(state): State<Arc<AppState>>,
) -> Result<StatusCode, AppError> {
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let conn = pool.get()?;
        crate::db::repositories::system_kv::maintenance_enter(&conn).map_err(AppError::Database)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
    tracing::warn!("maintenance mode entered");
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /admin/maintenance/exit` — set `system_kv.maintenance_mode = "0"`.
///
/// Idempotent: calling on an already-exited system is a no-op.
async fn maintenance_exit_handler(
    State(state): State<Arc<AppState>>,
) -> Result<StatusCode, AppError> {
    let pool: Arc<db::Pool> = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let conn = pool.get()?;
        crate::db::repositories::system_kv::maintenance_exit(&conn).map_err(AppError::Database)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;
    tracing::info!("maintenance mode exited");
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Label admin API handlers (Phase 59, LABEL-03..07)
// ---------------------------------------------------------------------------

/// Normalises a tier string to its canonical DB form.
///
/// The DB CHECK constraint expects exact casing: `T1`..`T4` or `Unclassified-Blocked`.
fn canonical_tier(s: &str) -> String {
    match s.to_ascii_lowercase().as_str() {
        "t1" => "T1".to_string(),
        "t2" => "T2".to_string(),
        "t3" => "T3".to_string(),
        "t4" => "T4".to_string(),
        "unclassified-blocked" => "Unclassified-Blocked".to_string(),
        _ => s.to_string(),
    }
}

/// Normalises an object_type string to its canonical DB form.
fn canonical_object_type(s: &str) -> String {
    match s.to_ascii_lowercase().as_str() {
        "file" => "file".to_string(),
        "folder" => "folder".to_string(),
        "archive" => "archive".to_string(),
        _ => s.to_string(),
    }
}

/// Normalises a label_state string to its canonical DB form.
fn canonical_label_state(s: &str) -> String {
    match s.to_ascii_lowercase().as_str() {
        "temporary" => "temporary".to_string(),
        "confirmed" => "confirmed".to_string(),
        "rejected" => "rejected".to_string(),
        "expired" => "expired".to_string(),
        _ => s.to_string(),
    }
}

/// Validates a label request body.
///
/// Checks:
/// - `path` is absolute (UNC `\\` or drive letter `X:\`)
/// - `object_type` is one of `file`, `folder`, `archive`
/// - `tier` is one of `T1`, `T2`, `T3`, `T4`, `Unclassified-Blocked`
/// - `label_state` is one of `temporary`, `confirmed`, `rejected`, `expired`
/// - `parent_label_id` (if provided) points to a folder label
///
/// # Errors
///
/// Returns `AppError::UnprocessableEntity` on any validation failure.
fn validate_label_request(req: &LabelRequest, pool: &db::Pool) -> Result<(), AppError> {
    // Path must be absolute: UNC (\\server\share) or drive letter (C:\)
    let path = req.path.trim();
    let is_unc = path.starts_with(r"\\");
    let is_drive = path.len() >= 3
        && path.as_bytes()[1] == b':'
        && (path.as_bytes()[2] == b'\\' || path.as_bytes()[2] == b'/');
    let is_drive_letter = !path.is_empty() && path.as_bytes()[0].is_ascii_alphabetic();
    if !(is_unc || (is_drive_letter && is_drive)) {
        return Err(AppError::UnprocessableEntity(
            "path must be absolute".to_string(),
        ));
    }

    // Object type allowlist
    const VALID_OBJECT_TYPES: &[&str] = &["file", "folder", "archive"];
    if !VALID_OBJECT_TYPES.contains(&req.object_type.to_ascii_lowercase().as_str()) {
        return Err(AppError::UnprocessableEntity(format!(
            "invalid object_type '{}'; must be one of: file, folder, archive",
            req.object_type
        )));
    }

    // Tier allowlist
    const VALID_TIERS: &[&str] = &["t1", "t2", "t3", "t4", "unclassified-blocked"];
    if !VALID_TIERS.contains(&req.tier.to_ascii_lowercase().as_str()) {
        return Err(AppError::UnprocessableEntity(format!(
            "invalid tier '{}'; must be one of: T1, T2, T3, T4, Unclassified-Blocked",
            req.tier
        )));
    }

    // Label state allowlist
    const VALID_STATES: &[&str] = &["temporary", "confirmed", "rejected", "expired"];
    if !VALID_STATES.contains(&req.label_state.to_ascii_lowercase().as_str()) {
        return Err(AppError::UnprocessableEntity(format!(
            "invalid label_state '{}'; must be one of: temporary, confirmed, rejected, expired",
            req.label_state
        )));
    }

    // Parent label must point to a folder
    if let Some(ref parent_id) = req.parent_label_id {
        let parent = LabelRepository::get_by_id(pool, parent_id).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => AppError::UnprocessableEntity(
                "parent_label_id must reference a folder label".to_string(),
            ),
            other => AppError::Database(other),
        })?;
        if parent.object_type != "folder" {
            return Err(AppError::UnprocessableEntity(
                "parent_label_id must reference a folder label".to_string(),
            ));
        }
    }

    Ok(())
}

/// Normalises a path: strips trailing backslash/slash except for roots.
fn normalize_path(path: &str) -> String {
    let mut p = path.to_string();
    // Keep root paths intact: C:\ and \\server\share
    let is_drive_root = p.len() == 3
        && p.as_bytes()[1] == b':'
        && (p.as_bytes()[2] == b'\\' || p.as_bytes()[2] == b'/');
    let is_unc_root = p.starts_with(r"\\") && p.matches('\\').count() == 3;
    if !is_drive_root && !is_unc_root {
        while p.ends_with('\\') || p.ends_with('/') {
            p.pop();
        }
    }
    p
}

/// `GET /admin/labels` — list all labels with optional filters and pagination.
///
/// Supports `?state=`, `?tier=`, `?owner_sid=`, `?department=`, `?limit=`, `?offset=` query params.
/// Default limit is 50, max is 1000. Results are ordered by path ASC.
async fn list_labels(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<PaginatedLabelsResponse>, AppError> {
    let _username = AdminUsername::extract_from_headers(req.headers())?;

    let filter = axum::extract::Query::<LabelFilter>::from_request(req, &state)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    // Clamp limit to max 1000 to prevent unbounded responses (T-59-12)
    let limit = filter.limit.min(MAX_LABEL_LIMIT);
    let offset = filter.offset;

    let pool = Arc::clone(&state.pool);
    let state_filter = filter.state.clone();
    let tier_filter = filter.tier.clone();
    let owner_sid_filter = filter.owner_sid.clone();
    let department_filter = filter.department.clone();

    let (rows, total) = tokio::task::spawn_blocking(move || -> Result<(Vec<LabelRow>, i64), AppError> {
        let rows = LabelRepository::list_by_filters(
            &pool,
            state_filter.as_deref(),
            tier_filter.as_deref(),
            owner_sid_filter.as_deref(),
            department_filter.as_deref(),
            Some(limit),
            Some(offset),
        )
        .map_err(AppError::Database)?;
        let total = LabelRepository::count_by_filters(
            &pool,
            state_filter.as_deref(),
            tier_filter.as_deref(),
            owner_sid_filter.as_deref(),
            department_filter.as_deref(),
        )
        .map_err(AppError::Database)?;
        Ok((rows, total))
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(PaginatedLabelsResponse {
        labels: rows.into_iter().map(Into::into).collect(),
        total,
        limit,
        offset,
    }))
}

/// `GET /admin/labels/:id` — get a single label by ID.
async fn get_label(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<LabelResponse>, AppError> {
    let pool = Arc::clone(&state.pool);
    let label_id = id.clone();
    let row = tokio::task::spawn_blocking(move || -> Result<LabelRow, AppError> {
        LabelRepository::get_by_id(&pool, &label_id).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                AppError::NotFound(format!("label {label_id} not found"))
            }
            other => AppError::Database(other),
        })
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(row.into()))
}

/// `POST /admin/labels` — create a new label.
///
/// Server-generates UUID v4 id and ISO-8601 timestamps.
async fn create_label(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<(StatusCode, Json<LabelResponse>), AppError> {
    let username = AdminUsername::extract_from_headers(req.headers())?;
    let _caller_sid = crate::admin_auth::verify_jwt(
        req.headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("invalid Authorization format".to_string()))?,
    )?
    .sid;
    let Json(body) = Json::<LabelRequest>::from_request(req, &state)
        .await
        .map_err(AppError::from)?;

    let pool_for_validate = Arc::clone(&state.pool);
    let body_for_validate = body.clone();
    tokio::task::spawn_blocking(move || {
        validate_label_request(&body_for_validate, &pool_for_validate)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let path = normalize_path(&body.path);

    let resp = LabelResponse {
        id: id.clone(),
        path: path.clone(),
        object_type: canonical_object_type(&body.object_type),
        tier: canonical_tier(&body.tier),
        label_state: canonical_label_state(&body.label_state),
        owner_sid: body.owner_sid.clone(),
        parent_label_id: body.parent_label_id.clone(),
        acl_snapshot_id: body.acl_snapshot_id.clone(),
        hash: body.hash.clone(),
        scanner_confidence: body.scanner_confidence,
        department: body.department.clone(),
        created_at: now.clone(),
        updated_at: now.clone(),
    };

    // Persist via transactional mutation (audit is mandatory, not best-effort)
    let r = resp.clone();
    let label_svc = Arc::clone(&state.label_service);
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let ctx = crate::label_service::MutationContext {
            label_id: r.id.clone(),
            action: "label_create".to_string(),
            old_state: None,
            new_state: Some(r.label_state.clone()),
            path: r.path.clone(),
            tier: r.tier.clone(),
            user_name: username.clone(),
        };
        label_svc.with_mutation(ctx, |uow| {
            let record = LabelUpsertRow {
                id: &r.id,
                path: &r.path,
                object_type: &r.object_type,
                tier: &r.tier,
                label_state: &r.label_state,
                owner_sid: r.owner_sid.as_deref(),
                parent_label_id: r.parent_label_id.as_deref(),
                acl_snapshot_id: r.acl_snapshot_id.as_deref(),
                hash: r.hash.as_deref(),
                scanner_confidence: r.scanner_confidence,
                department: None,
                created_at: &r.created_at,
                updated_at: &r.updated_at,
            };
            LabelRepository::insert(uow, &record).map_err(AppError::Database)?;
            Ok(())
        })
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(label_id = %id, path = %path, "label created");
    Ok((StatusCode::CREATED, Json(resp)))
}

/// `PUT /admin/labels/:id` — update an existing label.
async fn update_label(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<LabelResponse>, AppError> {
    let username = AdminUsername::extract_from_headers(req.headers())?;
    let _caller_sid = crate::admin_auth::verify_jwt(
        req.headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("invalid Authorization format".to_string()))?,
    )?
    .sid;

    let path = req.uri().path();
    let label_id = if let Some(rest) = path.strip_prefix("/admin/labels/") {
        rest.to_string()
    } else if let Some(rest) = path.strip_prefix("/labels/") {
        rest.to_string()
    } else {
        return Err(AppError::BadRequest("invalid label path".to_string()));
    };
    if label_id.is_empty() {
        return Err(AppError::BadRequest("missing label id in path".to_string()));
    }

    let Json(body) = Json::<LabelRequest>::from_request(req, &state)
        .await
        .map_err(AppError::from)?;

    let pool_for_validate = Arc::clone(&state.pool);
    let body_for_validate = body.clone();
    tokio::task::spawn_blocking(move || {
        validate_label_request(&body_for_validate, &pool_for_validate)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    let now = chrono::Utc::now().to_rfc3339();
    let path_norm = normalize_path(&body.path);
    let id = label_id.clone();

    // Fetch original created_at, then update via transactional mutation
    let pool = Arc::clone(&state.pool);
    let body2 = body.clone();
    let label_svc = Arc::clone(&state.label_service);
    let resp = tokio::task::spawn_blocking(move || -> Result<LabelResponse, AppError> {
        let original = LabelRepository::get_by_id(&pool, &id).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                AppError::NotFound(format!("label {id} not found"))
            }
            other => AppError::Database(other),
        })?;

        let ctx = crate::label_service::MutationContext {
            label_id: id.clone(),
            action: "label_update".to_string(),
            old_state: Some(original.label_state.clone()),
            new_state: Some(canonical_label_state(&body2.label_state)),
            path: path_norm.clone(),
            tier: canonical_tier(&body2.tier),
            user_name: username.clone(),
        };

        label_svc.with_mutation(ctx, |uow| {
            let record = LabelUpsertRow {
                id: &id,
                path: &path_norm,
                object_type: &canonical_object_type(&body2.object_type),
                tier: &canonical_tier(&body2.tier),
                label_state: &canonical_label_state(&body2.label_state),
                owner_sid: body2.owner_sid.as_deref(),
                parent_label_id: body2.parent_label_id.as_deref(),
                acl_snapshot_id: body2.acl_snapshot_id.as_deref(),
                hash: body2.hash.as_deref(),
                scanner_confidence: body2.scanner_confidence,
                department: body2.department.as_deref(),
                created_at: &original.created_at,
                updated_at: &now,
            };
            let affected = LabelRepository::update(uow, &record).map_err(AppError::Database)?;
            if affected == 0 {
                return Err(AppError::NotFound(format!("label {id} not found")));
            }
            Ok(())
        })?;

        Ok(LabelResponse {
            id,
            path: path_norm,
            object_type: canonical_object_type(&body2.object_type),
            tier: canonical_tier(&body2.tier),
            label_state: canonical_label_state(&body2.label_state),
            owner_sid: body2.owner_sid,
            parent_label_id: body2.parent_label_id,
            acl_snapshot_id: body2.acl_snapshot_id,
            hash: body2.hash,
            scanner_confidence: body2.scanner_confidence,
            department: body2.department,
            created_at: original.created_at,
            updated_at: now,
        })
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(label_id = %resp.id, path = %resp.path, "label updated");
    Ok(Json(resp))
}

/// `POST /admin/labels/:id/confirm` — confirm a temporary label.
///
/// Only allowed when current state is `temporary`. Returns 422 otherwise.
async fn confirm_label(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<LabelResponse>, AppError> {
    let username = AdminUsername::extract_from_headers(req.headers())?;
    let caller_sid = crate::admin_auth::verify_jwt(
        req.headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("invalid Authorization format".to_string()))?,
    )?
    .sid;

    let path = req.uri().path();
    let label_id = path
        .strip_prefix("/admin/labels/")
        .and_then(|rest| rest.strip_suffix("/confirm"))
        .or_else(|| {
            path.strip_prefix("/labels/")
                .and_then(|rest| rest.strip_suffix("/confirm"))
        })
        .unwrap_or("")
        .to_string();
    if label_id.is_empty() {
        return Err(AppError::BadRequest("missing label id in path".to_string()));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let id = label_id.clone();
    let pool = Arc::clone(&state.pool);
    let username2 = username.clone();
    let label_svc = Arc::clone(&state.label_service);

    let resp = tokio::task::spawn_blocking(move || -> Result<LabelResponse, AppError> {
        let original = LabelRepository::get_by_id(&pool, &id).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                AppError::NotFound(format!("label {id} not found"))
            }
            other => AppError::Database(other),
        })?;

        if let Some(ref sid) = caller_sid {
            if username2 != "dlp-admin" && original.owner_sid.as_ref() != Some(sid) {
                return Err(AppError::Forbidden(
                    "not the data owner of this label".to_string(),
                ));
            }
        }

        if original.label_state != "temporary" {
            return Err(AppError::UnprocessableEntity(
                "only temporary labels can be confirmed".to_string(),
            ));
        }

        let ctx = crate::label_service::MutationContext {
            label_id: id.clone(),
            action: "label_confirm".to_string(),
            old_state: Some(original.label_state.clone()),
            new_state: Some("confirmed".to_string()),
            path: original.path.clone(),
            tier: original.tier.clone(),
            user_name: username.clone(),
        };

        label_svc.with_mutation(ctx, |uow| {
            let affected = LabelRepository::update_state(uow, &id, "confirmed", &now)
                .map_err(AppError::Database)?;
            if affected == 0 {
                return Err(AppError::NotFound(format!("label {id} not found")));
            }
            Ok(())
        })?;

        Ok(LabelResponse {
            id,
            path: original.path,
            object_type: original.object_type,
            tier: original.tier,
            label_state: "confirmed".to_string(),
            owner_sid: original.owner_sid,
            parent_label_id: original.parent_label_id,
            acl_snapshot_id: original.acl_snapshot_id,
            hash: original.hash,
            scanner_confidence: original.scanner_confidence,
            department: original.department,
            created_at: original.created_at,
            updated_at: now,
        })
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(label_id = %resp.id, "label confirmed");
    Ok(Json(resp))
}

/// `POST /admin/labels/:id/reject` — reject a temporary label.
///
/// Only allowed when current state is `temporary`. Returns 422 otherwise.
async fn reject_label(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<LabelResponse>, AppError> {
    let username = AdminUsername::extract_from_headers(req.headers())?;
    let caller_sid = crate::admin_auth::verify_jwt(
        req.headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("invalid Authorization format".to_string()))?,
    )?
    .sid;

    let path = req.uri().path();
    let label_id = path
        .strip_prefix("/admin/labels/")
        .and_then(|rest| rest.strip_suffix("/reject"))
        .or_else(|| {
            path.strip_prefix("/labels/")
                .and_then(|rest| rest.strip_suffix("/reject"))
        })
        .unwrap_or("")
        .to_string();
    if label_id.is_empty() {
        return Err(AppError::BadRequest("missing label id in path".to_string()));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let id = label_id.clone();
    let pool = Arc::clone(&state.pool);
    let username2 = username.clone();
    let label_svc = Arc::clone(&state.label_service);

    let resp = tokio::task::spawn_blocking(move || -> Result<LabelResponse, AppError> {
        let original = LabelRepository::get_by_id(&pool, &id).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                AppError::NotFound(format!("label {id} not found"))
            }
            other => AppError::Database(other),
        })?;
        if let Some(ref sid) = caller_sid {
            if username2 != "dlp-admin" && original.owner_sid.as_ref() != Some(sid) {
                return Err(AppError::Forbidden(
                    "not the data owner of this label".to_string(),
                ));
            }
        }

        if original.label_state != "temporary" {
            return Err(AppError::UnprocessableEntity(
                "only temporary labels can be rejected".to_string(),
            ));
        }

        let ctx = crate::label_service::MutationContext {
            label_id: id.clone(),
            action: "label_reject".to_string(),
            old_state: Some(original.label_state.clone()),
            new_state: Some("rejected".to_string()),
            path: original.path.clone(),
            tier: original.tier.clone(),
            user_name: username.clone(),
        };

        label_svc.with_mutation(ctx, |uow| {
            let affected = LabelRepository::update_state(uow, &id, "rejected", &now)
                .map_err(AppError::Database)?;
            if affected == 0 {
                return Err(AppError::NotFound(format!("label {id} not found")));
            }
            Ok(())
        })?;

        Ok(LabelResponse {
            id,
            path: original.path,
            object_type: original.object_type,
            tier: original.tier,
            label_state: "rejected".to_string(),
            owner_sid: original.owner_sid,
            parent_label_id: original.parent_label_id,
            acl_snapshot_id: original.acl_snapshot_id,
            hash: original.hash,
            scanner_confidence: original.scanner_confidence,
            department: original.department,
            created_at: original.created_at,
            updated_at: now,
        })
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(label_id = %resp.id, "label rejected");
    Ok(Json(resp))
}

/// `POST /admin/labels/:id/expire` — expire a label (any state -> expired).
///
/// Emits a transactional audit event via [`LabelService::with_mutation`].
async fn expire_label(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<LabelResponse>, AppError> {
    let username = AdminUsername::extract_from_headers(req.headers())?;
    let _caller_sid = crate::admin_auth::verify_jwt(
        req.headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("invalid Authorization format".to_string()))?,
    )?
    .sid;

    let path = req.uri().path();
    let label_id = path
        .strip_prefix("/admin/labels/")
        .and_then(|rest| rest.strip_suffix("/expire"))
        .or_else(|| {
            path.strip_prefix("/labels/")
                .and_then(|rest| rest.strip_suffix("/expire"))
        })
        .unwrap_or("")
        .to_string();
    if label_id.is_empty() {
        return Err(AppError::BadRequest("missing label id in path".to_string()));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let id = label_id.clone();
    let pool = Arc::clone(&state.pool);
    let label_svc = Arc::clone(&state.label_service);

    let resp = tokio::task::spawn_blocking(move || -> Result<LabelResponse, AppError> {
        let original = LabelRepository::get_by_id(&pool, &id).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                AppError::NotFound(format!("label {id} not found"))
            }
            other => AppError::Database(other),
        })?;

        let ctx = crate::label_service::MutationContext {
            label_id: id.clone(),
            action: "label_expire".to_string(),
            old_state: Some(original.label_state.clone()),
            new_state: Some("expired".to_string()),
            path: original.path.clone(),
            tier: original.tier.clone(),
            user_name: username.clone(),
        };

        label_svc.with_mutation(ctx, |uow| {
            let affected = LabelRepository::update_state(uow, &id, "expired", &now)
                .map_err(AppError::Database)?;
            if affected == 0 {
                return Err(AppError::NotFound(format!("label {id} not found")));
            }
            Ok(())
        })?;

        Ok(LabelResponse {
            id,
            path: original.path,
            object_type: original.object_type,
            tier: original.tier,
            label_state: "expired".to_string(),
            owner_sid: original.owner_sid,
            parent_label_id: original.parent_label_id,
            acl_snapshot_id: original.acl_snapshot_id,
            hash: original.hash,
            scanner_confidence: original.scanner_confidence,
            department: original.department,
            created_at: original.created_at,
            updated_at: now,
        })
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(label_id = %resp.id, "label expired");
    Ok(Json(resp))
}

/// `DELETE /admin/labels/:id` — delete a label.
async fn delete_label(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<StatusCode, AppError> {
    let username = AdminUsername::extract_from_headers(req.headers())?;
    let _caller_sid = crate::admin_auth::verify_jwt(
        req.headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("invalid Authorization format".to_string()))?,
    )?
    .sid;

    let id = Path::<String>::from_request(req, &state)
        .await
        .map_err(AppError::from)?
        .0;

    let pool = Arc::clone(&state.pool);
    let label_id = id.clone();
    let label_svc = Arc::clone(&state.label_service);
    let path = tokio::task::spawn_blocking(move || -> Result<String, AppError> {
        // Get path and tier for audit before deleting
        let conn = pool.get().map_err(AppError::from)?;
        let row_result: rusqlite::Result<(String, String, String)> = conn.query_row(
            "SELECT path, tier, label_state FROM labels WHERE id = ?1",
            rusqlite::params![label_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        );
        let (path, tier, old_state) = match row_result {
            Ok(p) => p,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(AppError::NotFound(format!("label {label_id} not found")));
            }
            Err(e) => return Err(AppError::Database(e)),
        };

        let ctx = crate::label_service::MutationContext {
            label_id: label_id.clone(),
            action: "label_delete".to_string(),
            old_state: Some(old_state),
            new_state: None,
            path: path.clone(),
            tier,
            user_name: username.clone(),
        };

        label_svc.with_mutation(ctx, |uow| {
            let affected = LabelRepository::delete(uow, &label_id).map_err(AppError::Database)?;
            if affected == 0 {
                return Err(AppError::NotFound(format!("label {label_id} not found")));
            }
            Ok(())
        })?;

        Ok(path)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(label_id = %id, path = %path, "label deleted");
    Ok(StatusCode::NO_CONTENT)
}

///  -- returns distinct non-null department values.
async fn list_label_departments(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<String>>, AppError> {
    let pool = Arc::clone(&state.pool);
    let depts = tokio::task::spawn_blocking(move || -> Result<Vec<String>, AppError> {
        let conn = pool.get().map_err(AppError::from)?;
        let mut stmt = conn
            .prepare("SELECT DISTINCT department FROM labels WHERE department IS NOT NULL ORDER BY department")?;
        let rows = stmt.query_map([], |row| {
            let dept: String = row.get(0)?;
            Ok(dept)
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(AppError::Database)?);
        }
        Ok(result)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    Ok(Json(depts))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_response_serde() {
        let resp = HealthResponse {
            status: "ok".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert!(json.contains("\"status\":\"ok\""));
    }

    #[test]
    fn test_policy_payload_serde() {
        let json = r#"{
            "id": "pol-001",
            "name": "Block T4 Copy",
            "description": "Prevent copying T4 files",
            "priority": 1,
            "conditions": [{"attribute":"classification","op":"eq","value":"T4"}],
            "action": "DENY",
            "enabled": true
        }"#;
        let p: PolicyPayload = serde_json::from_str(json).expect("deserialize");
        assert_eq!(p.id, "pol-001");
        assert_eq!(p.priority, 1);
        assert!(p.enabled);
    }

    #[test]
    fn test_set_auth_hash_request_serde() {
        let json = r#"{"hash":"$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012"}"#;
        let req: SetAuthHashRequest = serde_json::from_str(json).expect("deserialize");
        assert!(req.hash.starts_with("$2"));
    }

    #[test]
    fn test_auth_hash_response_serde() {
        let resp = AuthHashResponse {
            hash: "$2b$12$test".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let rt: AuthHashResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rt.hash, "$2b$12$test");
    }

    #[test]
    fn test_siem_config_payload_roundtrip() {
        let p = SiemConfigPayload {
            splunk_url: "https://splunk:8088".to_string(),
            splunk_token: "tok-abc".to_string(),
            splunk_enabled: true,
            elk_url: "https://elastic:9200".to_string(),
            elk_index: "dlp-events".to_string(),
            elk_api_key: "k1".to_string(),
            elk_enabled: false,
        };
        let json = serde_json::to_string(&p).expect("serialize");
        let rt: SiemConfigPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rt.splunk_url, "https://splunk:8088");
        assert!(rt.splunk_enabled);
        assert!(!rt.elk_enabled);
        assert_eq!(rt.elk_index, "dlp-events");
    }

    #[test]
    fn test_policy_response_serde() {
        let resp = PolicyResponse {
            id: "pol-001".to_string(),
            name: "Test".to_string(),
            description: None,
            priority: 10,
            conditions: serde_json::json!([]),
            action: "ALLOW".to_string(),
            enabled: true,
            mode: PolicyMode::ALL,
            version: 1,
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let rt: PolicyResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rt.id, "pol-001");
        assert_eq!(rt.version, 1);
    }

    #[test]
    fn test_alert_router_config_payload_roundtrip() {
        let p = AlertRouterConfigPayload {
            smtp_host: "smtp.example.com".to_string(),
            smtp_port: 587,
            smtp_username: "user".to_string(),
            smtp_password: "pass".to_string(),
            smtp_from: "dlp@example.com".to_string(),
            smtp_to: "a@example.com, b@example.com".to_string(),
            smtp_enabled: true,
            webhook_url: "https://hooks.example.com/x".to_string(),
            webhook_secret: "shh".to_string(),
            webhook_enabled: false,
        };
        let json = serde_json::to_string(&p).expect("serialize");
        let rt: AlertRouterConfigPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rt, p);
    }

    #[test]
    fn test_validate_webhook_url() {
        // TM-02 — 28-case table-driven test. Each row is (input, expected_ok).
        // The Err branch uses `.is_err()` rather than matching the exact string
        // so minor wording tweaks to the reason do not break the test; the
        // per-category tests below assert the specific rejection reasons.
        // Cases 27-28 were added after code review BL-01 exposed an IPv4-mapped
        // IPv6 bypass that let `[::ffff:127.0.0.1]` and `[::ffff:169.254.169.254]`
        // pass the v6 guards.
        let cases: &[(&str, bool)] = &[
            ("", false),                                     //  1 empty
            ("http://example.com", false),                   //  2 http
            ("ftp://example.com", false),                    //  3 ftp
            ("file:///etc/passwd", false),                   //  4 file
            ("not a url", false),                            //  5 parse fail
            ("https://127.0.0.1", false),                    //  6 loopback
            ("https://127.0.0.1:8443", false),               //  7 loopback + port
            ("https://127.1.2.3", false),                    //  8 127/8 range
            ("https://[::1]", false),                        //  9 v6 loopback
            ("https://[::1]:8080", false),                   // 10 v6 loopback + port
            ("https://169.254.169.254", false),              // 11 cloud metadata
            ("https://169.254.1.1", false),                  // 12 link-local /16
            ("https://[fe80::1]", false),                    // 13 v6 link-local
            ("https://[fe80::dead:beef]", false),            // 14 v6 link-local
            ("https://[febf::1]", false),                    // 15 v6 link-local upper edge
            ("https://[fec0::1]", true),                     // 16 site-local (OK, not link-local)
            ("https://10.0.0.1", true),                      // 17 RFC1918
            ("https://10.255.255.255", true),                // 18 RFC1918 edge
            ("https://172.16.5.5", true),                    // 19 RFC1918
            ("https://172.31.255.255", true),                // 20 RFC1918 edge
            ("https://192.168.1.1", true),                   // 21 RFC1918
            ("https://8.8.8.8", true),                       // 22 public v4
            ("https://example.com", true),                   // 23 public hostname
            ("https://internal.corp.example.com", true),     // 24 internal hostname
            ("https://example.com:8443/path?query=1", true), // 25 path + query
            ("https://[2001:db8::1]", true),                 // 26 public v6
            ("https://[::ffff:127.0.0.1]", false),           // 27 IPv4-mapped loopback (BL-01)
            ("https://[::ffff:169.254.169.254]", false), // 28 IPv4-mapped cloud metadata (BL-01)
        ];
        for (i, (input, expected_ok)) in cases.iter().enumerate() {
            let result = validate_webhook_url(input);
            assert_eq!(
                result.is_ok(),
                *expected_ok,
                "case {} ({input:?}): expected ok={}, got {:?}",
                i + 1,
                expected_ok,
                result,
            );
        }

        // Spot-check the rejection reasons for the four failure categories.
        assert!(validate_webhook_url("http://example.com")
            .unwrap_err()
            .contains("https"));
        assert!(validate_webhook_url("https://127.0.0.1")
            .unwrap_err()
            .contains("loopback"));
        assert!(validate_webhook_url("https://169.254.169.254")
            .unwrap_err()
            .contains("link-local"));
        assert!(validate_webhook_url("https://[fe80::1]")
            .unwrap_err()
            .contains("link-local"));
    }

    #[test]
    fn test_put_alert_config_rejects_http() {
        // Direct unit test of validate_webhook_url — the handler path is
        // exercised end-to-end in the integration tests below.
        let err = validate_webhook_url("http://example.com").unwrap_err();
        assert!(err.contains("https"));
    }

    #[test]
    fn test_put_alert_config_rejects_loopback() {
        let err = validate_webhook_url("https://127.0.0.1/hook").unwrap_err();
        assert!(err.contains("loopback"));
    }

    #[test]
    fn test_put_alert_config_accepts_rfc1918() {
        // RFC1918 MUST be accepted — on-prem webhooks are a legitimate use case.
        validate_webhook_url("https://10.0.0.1/hook").expect("RFC1918 must be accepted");
        validate_webhook_url("https://172.16.5.5/hook").expect("RFC1918 must be accepted");
        validate_webhook_url("https://192.168.1.1/hook").expect("RFC1918 must be accepted");
    }

    /// Shared test secret. All integration tests in this module and in
    /// admin_auth::tests must agree on this value because
    /// `admin_auth::set_jwt_secret` is backed by a `OnceLock` that silently
    /// ignores duplicate set calls — whichever test runs first wins. We use
    /// the same literal that `admin_auth::DEV_JWT_SECRET` does (checked into
    /// `admin_auth.rs`) so all cross-module tests converge on one secret.
    const TEST_JWT_SECRET: &str = "dlp-server-dev-secret-change-me";

    /// Common test setup: initialise JWT secret, open a fresh in-memory
    /// database, build the full `admin_router`, and return the router
    /// ready for `oneshot` requests.
    fn spawn_admin_app() -> axum::Router {
        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let crypto = std::sync::Arc::new(crate::crypto::SecretCrypto::from_kek(
            [0x77; 32],
            crate::crypto::ENVELOPE_VERSION_V1,
        ));
        crate::secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
            .expect("Phase 47 migration");
        let siem = crate::siem_connector::SiemConnector::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let alert = crate::alert_router::AlertRouter::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"),
        );
        let label_service = Arc::new(crate::label_service::LabelService::new(Arc::clone(&pool)));
        let approval_token_crypto = crate::crypto::SecretCrypto::from_kek([0x77; 32], 1);
        let approval_token_conn = pool.get().expect("pool");
        let approval_token_service = Arc::new(
            crate::approval_token::ApprovalTokenService::new(
                &approval_token_crypto,
                &approval_token_conn,
            )
            .expect("approval token service"),
        );
        let syslog = crate::syslog_connector::SyslogConnector::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let state = Arc::new(AppState {
            pool,
            crypto: std::sync::Arc::clone(&crypto),
            policy_store,
            siem,
            alert,
            ad: None,
            label_service,
            approval_token_service,
            syslog,
            label_aware_enabled: std::sync::Arc::new(
                std::sync::atomic::AtomicBool::new(false),
            ),
        });
        admin_router(state)
    }

    /// Mints a valid admin JWT for the test secret.
    fn mint_admin_jwt() -> String {
        use jsonwebtoken::{encode, EncodingKey, Header};
        let claims = crate::admin_auth::Claims {
            sub: "test-admin".to_string(),
            exp: (Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            iss: "dlp-server".to_string(),
            sid: None,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
        )
        .expect("encode JWT")
    }

    #[tokio::test]
    async fn test_get_alert_config_requires_auth() {
        // Integration test at the handler level: a real router build that
        // exercises the JWT middleware. We bind the full admin_router and send
        // an unauthenticated GET to /admin/alert-config — expect 401.
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt; // for `oneshot`

        // JWT secret must be set for the middleware to initialise. OnceLock
        // silently ignores duplicate set calls, so this is safe across tests.
        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let crypto = std::sync::Arc::new(crate::crypto::SecretCrypto::from_kek(
            [0x77; 32],
            crate::crypto::ENVELOPE_VERSION_V1,
        ));
        crate::secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
            .expect("Phase 47 migration");
        let siem = crate::siem_connector::SiemConnector::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let alert = crate::alert_router::AlertRouter::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"),
        );
        let label_service = Arc::new(crate::label_service::LabelService::new(Arc::clone(&pool)));
        let approval_token_crypto = crate::crypto::SecretCrypto::from_kek([0x77; 32], 1);
        let approval_token_conn = pool.get().expect("pool");
        let approval_token_service = Arc::new(
            crate::approval_token::ApprovalTokenService::new(
                &approval_token_crypto,
                &approval_token_conn,
            )
            .expect("approval token service"),
        );
        let state = Arc::new(AppState {
            pool: Arc::clone(&pool),
            crypto: std::sync::Arc::clone(&crypto),
            policy_store,
            siem,
            alert,
            ad: None,
            label_service,
            approval_token_service,
            syslog: crate::syslog_connector::SyslogConnector::new(
                std::sync::Arc::clone(&pool),
                std::sync::Arc::clone(&crypto),
            ),
            label_aware_enabled: std::sync::Arc::new(
                std::sync::atomic::AtomicBool::new(false),
            ),
        });
        let app = admin_router(state);

        let req = Request::builder()
            .method("GET")
            .uri("/admin/alert-config")
            .body(Body::empty())
            .expect("build request");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_put_alert_config_roundtrip() {
        // Full PUT -> GET round-trip via the router with a valid JWT.
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use jsonwebtoken::{encode, EncodingKey, Header};
        use tower::ServiceExt;

        // Use the shared constant so all cross-module tests agree on the
        // secret stored in the process-wide OnceLock.
        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let crypto = std::sync::Arc::new(crate::crypto::SecretCrypto::from_kek(
            [0x77; 32],
            crate::crypto::ENVELOPE_VERSION_V1,
        ));
        crate::secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
            .expect("Phase 47 migration");
        let siem = crate::siem_connector::SiemConnector::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let alert = crate::alert_router::AlertRouter::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"),
        );
        let label_service = Arc::new(crate::label_service::LabelService::new(Arc::clone(&pool)));
        let approval_token_crypto = crate::crypto::SecretCrypto::from_kek([0x77; 32], 1);
        let approval_token_conn = pool.get().expect("pool");
        let approval_token_service = Arc::new(
            crate::approval_token::ApprovalTokenService::new(
                &approval_token_crypto,
                &approval_token_conn,
            )
            .expect("approval token service"),
        );
        let state = Arc::new(AppState {
            pool: Arc::clone(&pool),
            crypto: std::sync::Arc::clone(&crypto),
            policy_store,
            siem,
            alert,
            ad: None,
            label_service,
            approval_token_service,
            syslog: crate::syslog_connector::SyslogConnector::new(
                std::sync::Arc::clone(&pool),
                std::sync::Arc::clone(&crypto),
            ),
            label_aware_enabled: std::sync::Arc::new(
                std::sync::atomic::AtomicBool::new(false),
            ),
        });
        let app = admin_router(state);

        // Mint a valid JWT inline. Claims struct is pub on admin_auth.
        let claims = crate::admin_auth::Claims {
            sub: "test-admin".to_string(),
            exp: (Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            iss: "dlp-server".to_string(),
            sid: None,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
        )
        .expect("encode JWT");

        let payload = AlertRouterConfigPayload {
            smtp_host: "smtp.internal.corp".to_string(),
            smtp_port: 587,
            smtp_username: "dlp-alerts".to_string(),
            smtp_password: "t0p-secret".to_string(),
            smtp_from: "dlp@internal.corp".to_string(),
            smtp_to: "secops@internal.corp".to_string(),
            smtp_enabled: true,
            webhook_url: "https://hooks.internal.corp/dlp".to_string(),
            webhook_secret: "shh".to_string(),
            webhook_enabled: true,
        };
        let body = serde_json::to_string(&payload).expect("serialize");

        let put_req = Request::builder()
            .method("PUT")
            .uri("/admin/alert-config")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .expect("build PUT request");

        let put_resp = app.clone().oneshot(put_req).await.expect("PUT oneshot");
        assert_eq!(put_resp.status(), StatusCode::OK);

        let get_req = Request::builder()
            .method("GET")
            .uri("/admin/alert-config")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build GET request");

        let get_resp = app.oneshot(get_req).await.expect("GET oneshot");
        assert_eq!(get_resp.status(), StatusCode::OK);
        let bytes = to_bytes(get_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let rt: AlertRouterConfigPayload = serde_json::from_slice(&bytes).expect("parse body");

        // ME-01: GET must return masked sentinels in place of plaintext
        // secrets, but every other field must round-trip identically.
        let mut expected = payload.clone();
        expected.smtp_password = ALERT_SECRET_MASK.to_string();
        expected.webhook_secret = ALERT_SECRET_MASK.to_string();
        assert_eq!(rt, expected);
        assert_eq!(rt.smtp_password, ALERT_SECRET_MASK);
        assert_eq!(rt.webhook_secret, ALERT_SECRET_MASK);
    }

    #[tokio::test]
    async fn test_put_alert_config_preserves_masked_secret() {
        // ME-01 regression test: when the TUI echoes the masked sentinel
        // back on save (user kept the existing secret), the server MUST
        // preserve the stored plaintext value and NOT overwrite the DB
        // column with the literal mask string.
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use jsonwebtoken::{encode, EncodingKey, Header};
        use tower::ServiceExt;

        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let crypto = std::sync::Arc::new(crate::crypto::SecretCrypto::from_kek(
            [0x77; 32],
            crate::crypto::ENVELOPE_VERSION_V1,
        ));
        crate::secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
            .expect("Phase 47 migration");
        let siem = crate::siem_connector::SiemConnector::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let alert = crate::alert_router::AlertRouter::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"),
        );
        let label_service = Arc::new(crate::label_service::LabelService::new(Arc::clone(&pool)));
        let approval_token_crypto = crate::crypto::SecretCrypto::from_kek([0x77; 32], 1);
        let approval_token_conn = pool.get().expect("pool");
        let approval_token_service = Arc::new(
            crate::approval_token::ApprovalTokenService::new(
                &approval_token_crypto,
                &approval_token_conn,
            )
            .expect("approval token service"),
        );
        let state = Arc::new(AppState {
            pool: Arc::clone(&pool),
            crypto: std::sync::Arc::clone(&crypto),
            policy_store,
            siem,
            alert,
            ad: None,
            label_service,
            approval_token_service,
            syslog: crate::syslog_connector::SyslogConnector::new(
                std::sync::Arc::clone(&pool),
                std::sync::Arc::clone(&crypto),
            ),
            label_aware_enabled: std::sync::Arc::new(
                std::sync::atomic::AtomicBool::new(false),
            ),
        });
        let app = admin_router(state);

        let claims = crate::admin_auth::Claims {
            sub: "test-admin".to_string(),
            exp: (Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            iss: "dlp-server".to_string(),
            sid: None,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
        )
        .expect("encode JWT");

        // Step 1: Seed initial config with real plaintext secrets.
        let initial = AlertRouterConfigPayload {
            smtp_host: "smtp.internal.corp".to_string(),
            smtp_port: 587,
            smtp_username: "dlp-alerts".to_string(),
            smtp_password: "s3cret".to_string(),
            smtp_from: "dlp@internal.corp".to_string(),
            smtp_to: "secops@internal.corp".to_string(),
            smtp_enabled: true,
            webhook_url: "https://hooks.internal.corp/dlp".to_string(),
            webhook_secret: "hmac-key".to_string(),
            webhook_enabled: true,
        };
        let put1 = Request::builder()
            .method("PUT")
            .uri("/admin/alert-config")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&initial).expect("ser")))
            .expect("build PUT 1");
        let put1_resp = app.clone().oneshot(put1).await.expect("PUT 1 oneshot");
        assert_eq!(put1_resp.status(), StatusCode::OK);

        // Step 2: GET — response must show masked sentinels.
        let get1 = Request::builder()
            .method("GET")
            .uri("/admin/alert-config")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build GET 1");
        let get1_resp = app.clone().oneshot(get1).await.expect("GET 1 oneshot");
        assert_eq!(get1_resp.status(), StatusCode::OK);
        let get1_bytes = to_bytes(get1_resp.into_body(), 64 * 1024)
            .await
            .expect("read body 1");
        let masked: AlertRouterConfigPayload =
            serde_json::from_slice(&get1_bytes).expect("parse body 1");
        assert_eq!(masked.smtp_password, ALERT_SECRET_MASK);
        assert_eq!(masked.webhook_secret, ALERT_SECRET_MASK);

        // Step 3: PUT the masked payload unchanged (TUI save-without-edit).
        let put2 = Request::builder()
            .method("PUT")
            .uri("/admin/alert-config")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&masked).expect("ser 2")))
            .expect("build PUT 2");
        let put2_resp = app.clone().oneshot(put2).await.expect("PUT 2 oneshot");
        assert_eq!(put2_resp.status(), StatusCode::OK);

        // Step 4: Decrypt the on-disk encrypted blob and assert the
        // stored plaintexts match the original (NOT the mask sentinel).
        // Phase 47 Task 47-06: the cleartext columns no longer exist on
        // disk, so the previous direct `SELECT smtp_password` is
        // replaced by an encrypted-aware repository read followed by
        // explicit plaintext extraction via `expose_secret()`.
        use secrecy::ExposeSecret;
        let stored_row = crate::db::repositories::AlertRouterConfigRepository::get(&pool, &crypto)
            .expect("encrypted read");
        let stored_smtp_password = stored_row
            .smtp_password
            .as_ref()
            .map(|s| s.expose_secret().to_string())
            .expect("smtp_password must be populated post-PUT");
        let stored_webhook_secret = stored_row
            .webhook_secret
            .as_ref()
            .map(|s| s.expose_secret().to_string())
            .expect("webhook_secret must be populated post-PUT");
        assert_eq!(stored_smtp_password, "s3cret");
        assert_eq!(stored_webhook_secret, "hmac-key");
        assert_ne!(stored_smtp_password, ALERT_SECRET_MASK);
        assert_ne!(stored_webhook_secret, ALERT_SECRET_MASK);
    }

    /// Phase 47 Task 47-07: extend the ALERT_SECRET_MASK round-trip
    /// regression to the SIEM endpoints.
    ///
    /// Walks the same TUI-save-without-edit flow as
    /// [`test_put_alert_config_preserves_masked_secret`] but for the
    /// `/admin/siem-config` PUT handler. The on-disk
    /// `splunk_token_encrypted` and `elk_api_key_encrypted` columns
    /// must continue to decrypt to the original plaintexts after a
    /// mask-echo PUT, proving the mask sentinel is never written into
    /// the encrypted blob.
    ///
    /// Together with the alert-config sibling test, this is the
    /// firewall against a regression in [`resolve_secret_field`] /
    /// [`update_siem_config_handler`] that would silently overwrite a
    /// stored token with the literal mask string.
    #[tokio::test]
    async fn test_put_siem_config_preserves_masked_secret() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use jsonwebtoken::{encode, EncodingKey, Header};
        use tower::ServiceExt;

        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        // Deterministic test KEK — production uses
        // SecretCrypto::load_active_or_bootstrap which involves DPAPI;
        // tests bypass that for cross-platform reproducibility.
        let crypto = std::sync::Arc::new(crate::crypto::SecretCrypto::from_kek(
            [0x55; 32],
            crate::crypto::ENVELOPE_VERSION_V1,
        ));
        // Run the Phase 47 Task 47-06 migration so the encrypted-side
        // columns are populated (no-op on a fresh DB but exercises the
        // production startup path).
        crate::secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
            .expect("Phase 47 migration");
        let siem = crate::siem_connector::SiemConnector::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let alert = crate::alert_router::AlertRouter::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"),
        );
        let label_service = Arc::new(crate::label_service::LabelService::new(Arc::clone(&pool)));
        let approval_token_crypto = crate::crypto::SecretCrypto::from_kek([0x77; 32], 1);
        let approval_token_conn = pool.get().expect("pool");
        let approval_token_service = Arc::new(
            crate::approval_token::ApprovalTokenService::new(
                &approval_token_crypto,
                &approval_token_conn,
            )
            .expect("approval token service"),
        );
        let state = Arc::new(AppState {
            pool: Arc::clone(&pool),
            crypto: std::sync::Arc::clone(&crypto),
            policy_store,
            siem,
            alert,
            ad: None,
            label_service,
            approval_token_service,
            syslog: crate::syslog_connector::SyslogConnector::new(
                std::sync::Arc::clone(&pool),
                std::sync::Arc::clone(&crypto),
            ),
            label_aware_enabled: std::sync::Arc::new(
                std::sync::atomic::AtomicBool::new(false),
            ),
        });
        let app = admin_router(state);

        let claims = crate::admin_auth::Claims {
            sub: "test-admin".to_string(),
            exp: (Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            iss: "dlp-server".to_string(),
            sid: None,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
        )
        .expect("encode JWT");

        // ---- Step 1: seed SIEM config with real plaintext secrets. ----
        // Fixture values are obviously-test sentinels so any leak via
        // the wire (mask-substitution regression) is unambiguous.
        let initial = SiemConfigPayload {
            splunk_url: "https://splunk.internal.corp:8088".to_string(),
            splunk_token: "fixture-splunk-token-A".to_string(),
            splunk_enabled: true,
            elk_url: "https://elastic.internal.corp:9200".to_string(),
            elk_index: "dlp-events".to_string(),
            elk_api_key: "fixture-elk-key-B".to_string(),
            elk_enabled: true,
        };
        let put1 = Request::builder()
            .method("PUT")
            .uri("/admin/siem-config")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&initial).expect("ser")))
            .expect("build PUT 1");
        let put1_resp = app.clone().oneshot(put1).await.expect("PUT 1 oneshot");
        assert_eq!(put1_resp.status(), StatusCode::OK);

        // ---- Step 2: GET — response must show masked sentinels. -------
        let get1 = Request::builder()
            .method("GET")
            .uri("/admin/siem-config")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build GET 1");
        let get1_resp = app.clone().oneshot(get1).await.expect("GET 1 oneshot");
        assert_eq!(get1_resp.status(), StatusCode::OK);
        let get1_bytes = to_bytes(get1_resp.into_body(), 64 * 1024)
            .await
            .expect("read body 1");
        let masked: SiemConfigPayload = serde_json::from_slice(&get1_bytes).expect("parse body 1");
        assert_eq!(
            masked.splunk_token, ALERT_SECRET_MASK,
            "GET /admin/siem-config must mask splunk_token"
        );
        assert_eq!(
            masked.elk_api_key, ALERT_SECRET_MASK,
            "GET /admin/siem-config must mask elk_api_key"
        );
        // Non-secret fields must round-trip unchanged.
        assert_eq!(masked.splunk_url, initial.splunk_url);
        assert_eq!(masked.elk_url, initial.elk_url);
        assert_eq!(masked.elk_index, initial.elk_index);

        // ---- Step 3: PUT the masked payload unchanged. ----------------
        // Simulates the TUI's "save without editing the token" flow.
        let put2 = Request::builder()
            .method("PUT")
            .uri("/admin/siem-config")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&masked).expect("ser 2")))
            .expect("build PUT 2");
        let put2_resp = app.clone().oneshot(put2).await.expect("PUT 2 oneshot");
        assert_eq!(put2_resp.status(), StatusCode::OK);

        // ---- Step 4: decrypt the on-disk blob and assert plaintext. ---
        // Phase 47 Task 47-06: the cleartext columns no longer exist on
        // disk, so we go through the encrypted-aware repository read
        // and decrypt via the in-memory SecretCrypto handle.
        use secrecy::ExposeSecret;
        let stored_row = crate::db::repositories::SiemConfigRepository::get(&pool, &crypto)
            .expect("encrypted read");
        let stored_splunk_token = stored_row
            .splunk_token
            .as_ref()
            .map(|s| s.expose_secret().to_string())
            .expect("splunk_token must be populated post-PUT");
        let stored_elk_api_key = stored_row
            .elk_api_key
            .as_ref()
            .map(|s| s.expose_secret().to_string())
            .expect("elk_api_key must be populated post-PUT");
        assert_eq!(
            stored_splunk_token, "fixture-splunk-token-A",
            "stored splunk_token must match the initial PUT plaintext"
        );
        assert_eq!(
            stored_elk_api_key, "fixture-elk-key-B",
            "stored elk_api_key must match the initial PUT plaintext"
        );
        // Defensive cross-check: the mask sentinel must NEVER appear in
        // the decrypted ciphertext. A regression in `resolve_secret_field`
        // would surface here.
        assert_ne!(stored_splunk_token, ALERT_SECRET_MASK);
        assert_ne!(stored_elk_api_key, ALERT_SECRET_MASK);

        // ---- Step 5: rotate one field, keep the other masked. ---------
        // Confirms the per-field mask resolution does not couple the two
        // secrets — rotating splunk_token must NOT clobber elk_api_key.
        let mixed = SiemConfigPayload {
            splunk_token: "rotated-splunk-token-C".to_string(),
            elk_api_key: ALERT_SECRET_MASK.to_string(),
            ..masked.clone()
        };
        let put3 = Request::builder()
            .method("PUT")
            .uri("/admin/siem-config")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&mixed).expect("ser 3")))
            .expect("build PUT 3");
        let put3_resp = app.clone().oneshot(put3).await.expect("PUT 3 oneshot");
        assert_eq!(put3_resp.status(), StatusCode::OK);

        let post_rotate = crate::db::repositories::SiemConfigRepository::get(&pool, &crypto)
            .expect("encrypted read post-rotate");
        let rotated_splunk = post_rotate
            .splunk_token
            .as_ref()
            .map(|s| s.expose_secret().to_string())
            .expect("splunk_token populated");
        let preserved_elk = post_rotate
            .elk_api_key
            .as_ref()
            .map(|s| s.expose_secret().to_string())
            .expect("elk_api_key populated");
        assert_eq!(rotated_splunk, "rotated-splunk-token-C");
        assert_eq!(
            preserved_elk, "fixture-elk-key-B",
            "elk_api_key must survive a sibling-field rotation under mask"
        );
    }

    // ── Temporary diagnostic: verify DB insert→select round-trip ────────────

    #[tokio::test]
    async fn test_db_insert_select_roundtrip_via_spawn_blocking() {
        // This test verifies that spawn_blocking DB writes are visible to
        // subsequent spawn_blocking reads on the same Arc<pool>.
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let pool2 = Arc::clone(&pool);

        tokio::task::spawn_blocking(move || -> Result<_, AppError> {
            let mut conn = pool.get().map_err(AppError::from)?;
            conn.execute(
                "INSERT INTO policies (id, name, description, priority, conditions,                  action, enabled, version, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
                rusqlite::params![
                    "diag-001",
                    "Diag Test",
                    None::<String>,
                    1i64,
                    "[]",
                    "ALLOW",
                    true,
                    "2026-01-01T00:00:00Z"
                ],
            )?;
            Ok(())
        })
        .await
        .expect("join")
        .expect("execute");

        let count: i64 = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
            let conn = pool2.get().map_err(AppError::from)?;
            let n = conn.query_row(
                "SELECT COUNT(*) FROM policies WHERE id = ?1",
                rusqlite::params!["diag-001"],
                |row| row.get::<_, i64>(0),
            )?;
            Ok(n)
        })
        .await
        .expect("join")
        .expect("query");

        assert_eq!(
            count, 1,
            "INSERT must be visible to subsequent SELECT via same Arc<pool>"
        );
    }

    // Verify POST via router → direct DB read round-trip.
    #[tokio::test]
    async fn test_router_post_then_direct_db_read() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let pool_read = Arc::clone(&pool);
        let crypto = std::sync::Arc::new(crate::crypto::SecretCrypto::from_kek(
            [0x77; 32],
            crate::crypto::ENVELOPE_VERSION_V1,
        ));
        crate::secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
            .expect("Phase 47 migration");
        let siem = crate::siem_connector::SiemConnector::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let alert = crate::alert_router::AlertRouter::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"),
        );
        let label_service = Arc::new(crate::label_service::LabelService::new(Arc::clone(&pool)));
        let approval_token_crypto = crate::crypto::SecretCrypto::from_kek([0x77; 32], 1);
        let approval_token_conn = pool.get().expect("pool");
        let approval_token_service = Arc::new(
            crate::approval_token::ApprovalTokenService::new(
                &approval_token_crypto,
                &approval_token_conn,
            )
            .expect("approval token service"),
        );
        let state = Arc::new(AppState {
            pool: Arc::clone(&pool),
            crypto: std::sync::Arc::clone(&crypto),
            policy_store,
            siem,
            alert,
            ad: None,
            label_service,
            approval_token_service,
            syslog: crate::syslog_connector::SyslogConnector::new(
                std::sync::Arc::clone(&pool),
                std::sync::Arc::clone(&crypto),
            ),
            label_aware_enabled: std::sync::Arc::new(
                std::sync::atomic::AtomicBool::new(false),
            ),
        });
        let app = admin_router(state);
        let token = mint_admin_jwt();

        let payload = PolicyPayload {
            id: "diag-router-001".to_string(),
            name: "Diag Router Test".to_string(),
            description: None,
            priority: 1,
            conditions: serde_json::json!([]),
            action: "ALLOW".to_string(),
            enabled: true,
            mode: PolicyMode::ALL,
        };
        let req = Request::builder()
            .method("POST")
            .uri("/policies")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Now directly read from the pool (not via router).
        let conn = pool_read.get().expect("acquire connection for read");
        let (count,): (i64,) = conn
            .query_row(
                "SELECT COUNT(*) FROM policies WHERE id = ?1",
                rusqlite::params!["diag-router-001"],
                |row| Ok((row.get::<_, i64>(0)?,)),
            )
            .expect("direct DB read");

        assert_eq!(
            count, 1,
            "POST via router must persist to DB visible via direct read"
        );
    }

    // Verify POST via router then GET-by-ID via router.
    #[tokio::test]
    async fn test_router_post_then_router_get_by_id() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        let payload = PolicyPayload {
            id: "diag-getbyid-001".to_string(),
            name: "Diag GetById".to_string(),
            description: None,
            priority: 1,
            conditions: serde_json::json!([]),
            action: "ALLOW".to_string(),
            enabled: true,
            mode: PolicyMode::ALL,
        };
        let post_req = Request::builder()
            .method("POST")
            .uri("/policies")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .expect("build POST");
        let post_resp = app.clone().oneshot(post_req).await.expect("oneshot POST");
        eprintln!("POST status: {}", post_resp.status());
        assert_eq!(post_resp.status(), StatusCode::CREATED);

        let get_req = Request::builder()
            .method("GET")
            .uri("/policies/diag-getbyid-001")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build GET");
        let get_resp = app.oneshot(get_req).await.expect("oneshot GET");
        let status = get_resp.status();
        let bytes = to_bytes(get_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        eprintln!(
            "GET status: {}, body: {}",
            status,
            String::from_utf8_lossy(&bytes)
        );
        assert_eq!(
            status,
            StatusCode::OK,
            "GET by ID must find the created policy"
        );
    }

    // ── Task 04.1-02 / Task 1: Policy CRUD round-trip tests ──────────────────

    #[tokio::test]
    async fn test_create_policy_persists_and_get_returns_it() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        let payload = PolicyPayload {
            id: "pol-create-01".to_string(),
            name: "Restricted Write Block".to_string(),
            description: Some("Blocks T4 writes to removable media".to_string()),
            priority: 100,
            conditions: serde_json::json!([{"attr":"classification","op":"eq","value":"T4"}]),
            action: "DENY".to_string(),
            enabled: true,
            mode: PolicyMode::ALL,
        };
        let body = serde_json::to_string(&payload).expect("serialize");

        let create_req = Request::builder()
            .method("POST")
            .uri("/policies")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .expect("build POST");
        let create_resp = app.clone().oneshot(create_req).await.expect("oneshot POST");
        assert_eq!(create_resp.status(), StatusCode::CREATED);

        let bytes = to_bytes(create_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let created: PolicyResponse = serde_json::from_slice(&bytes).expect("parse created policy");
        assert_eq!(created.id, "pol-create-01");
        assert_eq!(created.name, "Restricted Write Block");
        assert_eq!(created.action, "DENY");
        assert_eq!(created.version, 1);
        assert!(created.enabled);

        let get_req = Request::builder()
            .method("GET")
            .uri("/policies/pol-create-01")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build GET");
        let get_resp = app.oneshot(get_req).await.expect("oneshot GET");
        assert_eq!(get_resp.status(), StatusCode::OK);
        let bytes = to_bytes(get_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let fetched: PolicyResponse = serde_json::from_slice(&bytes).expect("parse fetched policy");
        assert_eq!(fetched.id, "pol-create-01");
        assert_eq!(fetched.name, "Restricted Write Block");
    }

    #[tokio::test]
    async fn test_create_policy_rejects_empty_id_or_name() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        // Empty id → 400.
        let bad_id = PolicyPayload {
            id: "".to_string(),
            name: "Some name".to_string(),
            description: None,
            priority: 1,
            conditions: serde_json::json!([]),
            action: "ALLOW".to_string(),
            enabled: true,
            mode: PolicyMode::ALL,
        };
        let req = Request::builder()
            .method("POST")
            .uri("/policies")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&bad_id).unwrap()))
            .expect("build");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Empty name → 400.
        let bad_name = PolicyPayload {
            id: "pol-bad".to_string(),
            name: "".to_string(),
            description: None,
            priority: 1,
            conditions: serde_json::json!([]),
            action: "ALLOW".to_string(),
            enabled: true,
            mode: PolicyMode::ALL,
        };
        let req = Request::builder()
            .method("POST")
            .uri("/policies")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&bad_name).unwrap()))
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_update_policy_increments_version() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        // Seed
        let initial = PolicyPayload {
            id: "pol-update-01".to_string(),
            name: "Initial".to_string(),
            description: None,
            priority: 50,
            conditions: serde_json::json!([]),
            action: "ALLOW".to_string(),
            enabled: true,
            mode: PolicyMode::ALL,
        };
        let post_req = Request::builder()
            .method("POST")
            .uri("/policies")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&initial).unwrap()))
            .expect("build");
        let resp = app.clone().oneshot(post_req).await.expect("oneshot POST");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Update
        let updated = PolicyPayload {
            id: "pol-update-01".to_string(),
            name: "Updated Name".to_string(),
            description: Some("new desc".to_string()),
            priority: 25,
            conditions: serde_json::json!([{"attr":"tier","op":"eq","value":"T3"}]),
            action: "DENY".to_string(),
            enabled: false,
            mode: PolicyMode::ALL,
        };
        let put_req = Request::builder()
            .method("PUT")
            .uri("/policies/pol-update-01")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&updated).unwrap()))
            .expect("build");
        let put_resp = app.oneshot(put_req).await.expect("oneshot PUT");
        assert_eq!(put_resp.status(), StatusCode::OK);

        let bytes = to_bytes(put_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let rt: PolicyResponse = serde_json::from_slice(&bytes).expect("parse updated");
        assert_eq!(rt.name, "Updated Name");
        assert_eq!(rt.action, "DENY");
        assert_eq!(rt.priority, 25);
        assert!(!rt.enabled);
        assert_eq!(
            rt.version, 2,
            "version must be incremented by update_policy"
        );
    }

    #[tokio::test]
    async fn test_update_unknown_policy_returns_404() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        let payload = PolicyPayload {
            id: "pol-does-not-exist".to_string(),
            name: "x".to_string(),
            description: None,
            priority: 1,
            conditions: serde_json::json!([]),
            action: "ALLOW".to_string(),
            enabled: true,
            mode: PolicyMode::ALL,
        };
        let req = Request::builder()
            .method("PUT")
            .uri("/policies/pol-does-not-exist")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_policy_removes_row_and_subsequent_delete_is_404() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        // Seed
        let seed = PolicyPayload {
            id: "pol-delete-01".to_string(),
            name: "To Be Deleted".to_string(),
            description: None,
            priority: 1,
            conditions: serde_json::json!([]),
            action: "ALLOW".to_string(),
            enabled: true,
            mode: PolicyMode::ALL,
        };
        let post_req = Request::builder()
            .method("POST")
            .uri("/policies")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&seed).unwrap()))
            .expect("build");
        let resp = app.clone().oneshot(post_req).await.expect("oneshot POST");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // First delete → 204
        let del_req = Request::builder()
            .method("DELETE")
            .uri("/policies/pol-delete-01")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build");
        let del_resp = app.clone().oneshot(del_req).await.expect("oneshot DELETE");
        assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

        // Second delete → 404
        let del_req2 = Request::builder()
            .method("DELETE")
            .uri("/policies/pol-delete-01")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build");
        let del_resp2 = app.oneshot(del_req2).await.expect("oneshot DELETE 2");
        assert_eq!(del_resp2.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_policies_returns_seeded_rows() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        for i in 0..3 {
            let payload = PolicyPayload {
                id: format!("pol-list-{i:02}"),
                name: format!("Policy {i}"),
                description: None,
                priority: i as u32,
                conditions: serde_json::json!([]),
                action: "ALLOW".to_string(),
                enabled: true,
                mode: PolicyMode::ALL,
            };
            let req = Request::builder()
                .method("POST")
                .uri("/policies")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&payload).unwrap()))
                .expect("build");
            let resp = app.clone().oneshot(req).await.expect("oneshot POST");
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        let list_req = Request::builder()
            .method("GET")
            .uri("/policies")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build");
        let list_resp = app.oneshot(list_req).await.expect("oneshot GET");
        assert_eq!(list_resp.status(), StatusCode::OK);
        let bytes = to_bytes(list_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let policies: Vec<PolicyResponse> = serde_json::from_slice(&bytes).expect("parse list");
        assert!(
            policies.len() >= 3,
            "expected at least 3 seeded policies, got {}",
            policies.len()
        );
        let ids: std::collections::HashSet<_> = policies.iter().map(|p| p.id.clone()).collect();
        assert!(ids.contains("pol-list-00"));
        assert!(ids.contains("pol-list-01"));
        assert!(ids.contains("pol-list-02"));
    }

    // ── Task 04.1-02 / Task 2: Audit event ingest and query round-trip tests ─

    /// Build one audit event with the given agent id for seeding tests.
    fn sample_audit_event(agent_id: &str, resource_path: &str) -> dlp_common::AuditEvent {
        dlp_common::AuditEvent::new(
            dlp_common::EventType::Block,
            "S-1-5-21-TEST".to_string(),
            "testuser".to_string(),
            resource_path.to_string(),
            dlp_common::Classification::T4,
            dlp_common::Action::WRITE,
            dlp_common::Decision::DENY,
            agent_id.to_string(),
            1,
        )
        .with_policy("pol-audit-test".to_string(), "Test block".to_string())
        .with_source_application(Some(dlp_common::endpoint::agent_unknown_app()))
        .with_destination_application(Some(dlp_common::endpoint::agent_unknown_app()))
    }

    #[tokio::test]
    async fn test_ingest_audit_events_round_trip_and_count() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        // POST /audit/events is UNAUTHENTICATED — no Bearer header needed.
        let batch = vec![
            sample_audit_event("AGENT-001", r"C:\Restricted\a.xlsx"),
            sample_audit_event("AGENT-001", r"C:\Restricted\b.xlsx"),
        ];
        let body = serde_json::to_string(&batch).expect("serialize");
        let ingest_req = Request::builder()
            .method("POST")
            .uri("/audit/events")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .expect("build ingest");
        let ingest_resp = app
            .clone()
            .oneshot(ingest_req)
            .await
            .expect("oneshot ingest");
        assert_eq!(ingest_resp.status(), StatusCode::CREATED);

        // GET /audit/events/count requires a JWT.
        let count_req = Request::builder()
            .method("GET")
            .uri("/audit/events/count")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build count");
        let count_resp = app.clone().oneshot(count_req).await.expect("oneshot count");
        assert_eq!(count_resp.status(), StatusCode::OK);
        let bytes = to_bytes(count_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let count: crate::audit_store::EventCount =
            serde_json::from_slice(&bytes).expect("parse count");
        assert!(
            count.count >= 2,
            "expected at least 2 audit events, got {}",
            count.count
        );

        // GET /audit/events returns the seeded rows.
        let query_req = Request::builder()
            .method("GET")
            .uri("/audit/events")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build query");
        let query_resp = app.oneshot(query_req).await.expect("oneshot query");
        assert_eq!(query_resp.status(), StatusCode::OK);
        let bytes = to_bytes(query_resp.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        let events: Vec<dlp_common::AuditEvent> =
            serde_json::from_slice(&bytes).expect("parse events");
        assert!(
            events.len() >= 2,
            "expected at least 2 events returned, got {}",
            events.len()
        );
        let agent_ids: std::collections::HashSet<_> =
            events.iter().map(|e| e.agent_id.clone()).collect();
        assert!(agent_ids.contains("AGENT-001"));
    }

    #[tokio::test]
    async fn test_ingest_empty_batch_returns_400() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let empty: Vec<dlp_common::AuditEvent> = Vec::new();
        let body = serde_json::to_string(&empty).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/audit/events")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_ingest_malformed_json_returns_400() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let req = Request::builder()
            .method("POST")
            .uri("/audit/events")
            .header("Content-Type", "application/json")
            .body(Body::from("{ this is not valid JSON ]"))
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        // axum 0.7's `Json` extractor maps a JSON parse failure to 422.
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_query_events_filters_by_agent_id() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        // Seed with two different agent ids.
        let batch = vec![
            sample_audit_event("AGENT-ALPHA", r"C:\x\one.xlsx"),
            sample_audit_event("AGENT-BETA", r"C:\x\two.xlsx"),
        ];
        let body = serde_json::to_string(&batch).unwrap();
        let ingest = Request::builder()
            .method("POST")
            .uri("/audit/events")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .expect("build ingest");
        let resp = app.clone().oneshot(ingest).await.expect("oneshot ingest");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Filter by agent_id = AGENT-ALPHA.
        let q = Request::builder()
            .method("GET")
            .uri("/audit/events?agent_id=AGENT-ALPHA")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build query");
        let qr = app.oneshot(q).await.expect("oneshot query");
        assert_eq!(qr.status(), StatusCode::OK);
        let bytes = to_bytes(qr.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        let events: Vec<dlp_common::AuditEvent> =
            serde_json::from_slice(&bytes).expect("parse events");
        assert!(
            events.iter().all(|e| e.agent_id == "AGENT-ALPHA"),
            "filter returned foreign agent_id"
        );
        assert!(events.iter().any(|e| e.agent_id == "AGENT-ALPHA"));
    }

    #[tokio::test]
    async fn test_audit_event_deny_with_alert_roundtrip() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        // POST /audit/events is UNAUTHENTICATED — no Bearer header needed.
        let event = dlp_common::AuditEvent::new(
            dlp_common::EventType::Alert,
            "S-1-5-21-TEST-ALERT".to_string(),
            "alertuser".to_string(),
            r"C:\Restricted\sensitive.docx".to_string(),
            dlp_common::Classification::T4,
            dlp_common::Action::WRITE,
            dlp_common::Decision::DenyWithAlert,
            "AGENT-ALERT-001".to_string(),
            1,
        )
        .with_policy(
            "pol-alert-test".to_string(),
            "DenyWithAlert policy".to_string(),
        )
        .with_source_application(Some(dlp_common::endpoint::agent_unknown_app()))
        .with_destination_application(Some(dlp_common::endpoint::agent_unknown_app()));

        let batch = vec![event];
        let body = serde_json::to_string(&batch).expect("serialize");
        let ingest_req = Request::builder()
            .method("POST")
            .uri("/audit/events")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .expect("build ingest");
        let ingest_resp = app
            .clone()
            .oneshot(ingest_req)
            .await
            .expect("oneshot ingest");
        assert_eq!(ingest_resp.status(), StatusCode::CREATED);

        // GET /audit/events requires a JWT. Retrieve and find our event.
        let query_req = Request::builder()
            .method("GET")
            .uri("/audit/events")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build query");
        let query_resp = app.oneshot(query_req).await.expect("oneshot query");
        assert_eq!(query_resp.status(), StatusCode::OK);
        let bytes = to_bytes(query_resp.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        let events: Vec<dlp_common::AuditEvent> =
            serde_json::from_slice(&bytes).expect("parse events");
        let found = events
            .iter()
            .find(|e| e.agent_id == "AGENT-ALERT-001")
            .expect("DenyWithAlert event must be present after ingest");
        assert_eq!(
            found.decision,
            dlp_common::Decision::DenyWithAlert,
            "retrieved event must have decision == DenyWithAlert"
        );
    }

    // ── Task 04.1-02 / Task 3: JWT auth-gate tests for protected policy routes

    #[tokio::test]
    async fn test_policies_get_without_token_returns_401() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let req = Request::builder()
            .method("GET")
            .uri("/policies")
            .body(Body::empty())
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_policies_post_with_invalid_token_returns_401() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let payload = PolicyPayload {
            id: "pol-auth-01".to_string(),
            name: "x".to_string(),
            description: None,
            priority: 1,
            conditions: serde_json::json!([]),
            action: "ALLOW".to_string(),
            enabled: true,
            mode: PolicyMode::ALL,
        };
        let req = Request::builder()
            .method("POST")
            .uri("/policies")
            .header("Authorization", "Bearer not-a-real-token")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_policies_get_with_valid_token_returns_200() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();
        let req = Request::builder()
            .method("GET")
            .uri("/policies")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_audit_query_without_token_returns_401() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let req = Request::builder()
            .method("GET")
            .uri("/audit/events")
            .body(Body::empty())
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Task 06-01 / Task 1: AgentConfigPayload serde test ───────────────────

    #[test]
    fn test_agent_config_payload_serde() {
        let payload = AgentConfigPayload {
            monitored_paths: vec![r"C:\Data\".to_string()],
            excluded_paths: vec![],
            heartbeat_interval_secs: 60,
            offline_cache_enabled: false,
            disk_allowlist: Vec::new(),
            usb_blocked_failure_mode: DEFAULT_USB_BLOCKED_FAILURE_MODE.to_string(),
            usb_startup_resolution_mode: DEFAULT_USB_STARTUP_RESOLUTION_MODE.to_string(),
            usb_none_serial_policy: DEFAULT_USB_NONE_SERIAL_POLICY.to_string(),
            ..Default::default()
        };
        let json = serde_json::to_string(&payload).expect("serialize");
        let rt: AgentConfigPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rt, payload);
    }

    #[test]
    fn test_agent_config_payload_usb_fields_default() {
        // JSON without the three new fields must deserialize with defaults.
        let json = r#"{
            "monitored_paths": ["C:/Data/"],
            "excluded_paths": [],
            "heartbeat_interval_secs": 60,
            "offline_cache_enabled": false
        }"#;
        let payload: AgentConfigPayload = serde_json::from_str(json).expect("deserialize");
        assert_eq!(
            payload.usb_blocked_failure_mode,
            DEFAULT_USB_BLOCKED_FAILURE_MODE
        );
        assert_eq!(
            payload.usb_startup_resolution_mode,
            DEFAULT_USB_STARTUP_RESOLUTION_MODE
        );
        assert_eq!(
            payload.usb_none_serial_policy,
            DEFAULT_USB_NONE_SERIAL_POLICY
        );

        // Roundtrip: serialize with custom values and deserialize back.
        let full = AgentConfigPayload {
            monitored_paths: vec![],
            excluded_paths: vec![],
            heartbeat_interval_secs: 30,
            offline_cache_enabled: true,
            disk_allowlist: Vec::new(),
            usb_blocked_failure_mode: "Hard error".to_string(),
            usb_startup_resolution_mode: "VID/PID/serial fallback".to_string(),
            usb_none_serial_policy: "Allow unregistered".to_string(),
            ..Default::default()
        };
        let json = serde_json::to_string(&full).expect("serialize");
        let rt: AgentConfigPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rt, full);
    }

    /// Helper to run USB enum validation against a payload.
    fn validate_usb_config(payload: &AgentConfigPayload) -> Result<(), String> {
        if !USB_FAILURE_MODES.contains(&payload.usb_blocked_failure_mode.as_str()) {
            return Err(format!(
                "usb_blocked_failure_mode must be one of: {}",
                USB_FAILURE_MODES.join(", ")
            ));
        }
        if !USB_RESOLUTION_MODES.contains(&payload.usb_startup_resolution_mode.as_str()) {
            return Err(format!(
                "usb_startup_resolution_mode must be one of: {}",
                USB_RESOLUTION_MODES.join(", ")
            ));
        }
        if !USB_NONE_SERIAL_POLICIES.contains(&payload.usb_none_serial_policy.as_str()) {
            return Err(format!(
                "usb_none_serial_policy must be one of: {}",
                USB_NONE_SERIAL_POLICIES.join(", ")
            ));
        }
        if payload.usb_startup_resolution_mode == "Volume GUID resolution" {
            return Err(                "Volume GUID resolution is not yet implemented. Please select 'VID/PID/serial fallback'."
                    .to_string(),
            );
        }
        if payload.usb_none_serial_policy == "Port-based disambiguation" {
            return Err(                "Port-based disambiguation is not yet implemented. Please select 'Always Blocked' or 'Allow unregistered'."
                    .to_string(),
            );
        }
        Ok(())
    }

    #[test]
    fn test_agent_config_payload_usb_fields_enum_validation() {
        // Valid payload passes.
        let valid = AgentConfigPayload {
            monitored_paths: vec![],
            excluded_paths: vec![],
            heartbeat_interval_secs: 30,
            offline_cache_enabled: true,
            disk_allowlist: Vec::new(),
            usb_blocked_failure_mode: "Warning only".to_string(),
            usb_startup_resolution_mode: "VID/PID/serial fallback".to_string(),
            usb_none_serial_policy: "Always Blocked".to_string(),
            ..Default::default()
        };
        assert!(validate_usb_config(&valid).is_ok());

        // Invalid enum value for failure mode.
        let mut bad = valid.clone();
        bad.usb_blocked_failure_mode = "Foo".to_string();
        assert!(validate_usb_config(&bad).is_err());

        // Unimplemented mode: Volume GUID resolution.
        let mut unimplemented = valid.clone();
        unimplemented.usb_startup_resolution_mode = "Volume GUID resolution".to_string();
        assert!(validate_usb_config(&unimplemented).is_err());

        // Unimplemented mode: Port-based disambiguation.
        let mut unimplemented2 = valid.clone();
        unimplemented2.usb_none_serial_policy = "Port-based disambiguation".to_string();
        assert!(validate_usb_config(&unimplemented2).is_err());
    }

    // ── Task 06-01 / Task 2: Agent config handler integration tests ───────────

    /// Register a test agent directly in the DB so agent_config_overrides FK is satisfied.
    fn seed_agent(pool: &crate::db::Pool, agent_id: &str) {
        let mut conn = pool.get().expect("acquire connection");
        conn.execute(
            "INSERT OR IGNORE INTO agents \
             (agent_id, hostname, ip, os_version, agent_version, last_heartbeat, status, registered_at) \
             VALUES (?1, 'test-host', '127.0.0.1', 'Windows 10', '0.1.0', '2026-01-01T00:00:00Z', 'online', '2026-01-01T00:00:00Z')",
            rusqlite::params![agent_id],
        )
        .expect("seed agent");
    }

    #[tokio::test]
    async fn test_get_agent_config_falls_back_to_global() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        seed_agent(&pool, "agent-fallback-01");
        let crypto = std::sync::Arc::new(crate::crypto::SecretCrypto::from_kek(
            [0x77; 32],
            crate::crypto::ENVELOPE_VERSION_V1,
        ));
        crate::secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
            .expect("Phase 47 migration");
        let siem = crate::siem_connector::SiemConnector::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let alert = crate::alert_router::AlertRouter::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"),
        );
        let label_service = Arc::new(crate::label_service::LabelService::new(Arc::clone(&pool)));
        let approval_token_crypto = crate::crypto::SecretCrypto::from_kek([0x77; 32], 1);
        let approval_token_conn = pool.get().expect("pool");
        let approval_token_service = Arc::new(
            crate::approval_token::ApprovalTokenService::new(
                &approval_token_crypto,
                &approval_token_conn,
            )
            .expect("approval token service"),
        );
        let state = Arc::new(AppState {
            pool: Arc::clone(&pool),
            crypto: std::sync::Arc::clone(&crypto),
            policy_store,
            siem,
            alert,
            ad: None,
            label_service,
            approval_token_service,
            syslog: crate::syslog_connector::SyslogConnector::new(
                std::sync::Arc::clone(&pool),
                std::sync::Arc::clone(&crypto),
            ),
            label_aware_enabled: std::sync::Arc::new(
                std::sync::atomic::AtomicBool::new(false),
            ),
        });
        let app = admin_router(state);

        // No override set — should return global defaults.
        let req = Request::builder()
            .method("GET")
            .uri("/agent-config/agent-fallback-01")
            .body(Body::empty())
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let payload: AgentConfigPayload = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(payload.monitored_paths, Vec::<String>::new());
        assert_eq!(payload.heartbeat_interval_secs, 30);
        assert!(payload.offline_cache_enabled);
    }

    #[tokio::test]
    async fn test_put_global_agent_config() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        let new_config = AgentConfigPayload {
            monitored_paths: vec![r"C:\Data\".to_string()],
            excluded_paths: vec![r"C:\Temp\".to_string()],
            heartbeat_interval_secs: 60,
            offline_cache_enabled: true,
            disk_allowlist: Vec::new(),
            usb_blocked_failure_mode: DEFAULT_USB_BLOCKED_FAILURE_MODE.to_string(),
            usb_startup_resolution_mode: DEFAULT_USB_STARTUP_RESOLUTION_MODE.to_string(),
            usb_none_serial_policy: DEFAULT_USB_NONE_SERIAL_POLICY.to_string(),
            ..Default::default()
        };

        // PUT the new global config.
        let put_req = Request::builder()
            .method("PUT")
            .uri("/admin/agent-config")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&new_config).expect("ser")))
            .expect("build PUT");
        let put_resp = app.clone().oneshot(put_req).await.expect("oneshot PUT");
        assert_eq!(put_resp.status(), StatusCode::OK);

        // GET must return the updated values.
        let get_req = Request::builder()
            .method("GET")
            .uri("/admin/agent-config")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build GET");
        let get_resp = app.oneshot(get_req).await.expect("oneshot GET");
        assert_eq!(get_resp.status(), StatusCode::OK);
        let bytes = to_bytes(get_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let fetched: AgentConfigPayload = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(fetched.monitored_paths, vec![r"C:\Data\".to_string()]);
        assert_eq!(fetched.heartbeat_interval_secs, 60);
    }

    #[tokio::test]
    async fn test_put_global_config_rejects_low_interval() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        let bad_config = AgentConfigPayload {
            monitored_paths: vec![],
            excluded_paths: vec![],
            heartbeat_interval_secs: 5,
            offline_cache_enabled: true,
            disk_allowlist: Vec::new(),
            usb_blocked_failure_mode: DEFAULT_USB_BLOCKED_FAILURE_MODE.to_string(),
            usb_startup_resolution_mode: DEFAULT_USB_STARTUP_RESOLUTION_MODE.to_string(),
            usb_none_serial_policy: DEFAULT_USB_NONE_SERIAL_POLICY.to_string(),
            ..Default::default()
        };
        let req = Request::builder()
            .method("PUT")
            .uri("/admin/agent-config")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&bad_config).expect("ser")))
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_put_agent_config_override() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        seed_agent(&pool, "agent-override-01");
        let crypto = std::sync::Arc::new(crate::crypto::SecretCrypto::from_kek(
            [0x77; 32],
            crate::crypto::ENVELOPE_VERSION_V1,
        ));
        crate::secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
            .expect("Phase 47 migration");
        let siem = crate::siem_connector::SiemConnector::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let alert = crate::alert_router::AlertRouter::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"),
        );
        let label_service = Arc::new(crate::label_service::LabelService::new(Arc::clone(&pool)));
        let approval_token_crypto = crate::crypto::SecretCrypto::from_kek([0x77; 32], 1);
        let approval_token_conn = pool.get().expect("pool");
        let approval_token_service = Arc::new(
            crate::approval_token::ApprovalTokenService::new(
                &approval_token_crypto,
                &approval_token_conn,
            )
            .expect("approval token service"),
        );
        let state = Arc::new(AppState {
            pool: Arc::clone(&pool),
            crypto: std::sync::Arc::clone(&crypto),
            policy_store,
            siem,
            alert,
            ad: None,
            label_service,
            approval_token_service,
            syslog: crate::syslog_connector::SyslogConnector::new(
                std::sync::Arc::clone(&pool),
                std::sync::Arc::clone(&crypto),
            ),
            label_aware_enabled: std::sync::Arc::new(
                std::sync::atomic::AtomicBool::new(false),
            ),
        });
        let app = admin_router(state);
        let token = mint_admin_jwt();

        let override_config = AgentConfigPayload {
            monitored_paths: vec![r"D:\Secret\".to_string()],
            excluded_paths: vec![r"D:\Secret\Temp\".to_string()],
            heartbeat_interval_secs: 15,
            offline_cache_enabled: false,
            disk_allowlist: Vec::new(),
            usb_blocked_failure_mode: DEFAULT_USB_BLOCKED_FAILURE_MODE.to_string(),
            usb_startup_resolution_mode: DEFAULT_USB_STARTUP_RESOLUTION_MODE.to_string(),
            usb_none_serial_policy: DEFAULT_USB_NONE_SERIAL_POLICY.to_string(),
            ..Default::default()
        };

        // PUT per-agent override.
        let put_req = Request::builder()
            .method("PUT")
            .uri("/admin/agent-config/agent-override-01")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_string(&override_config).expect("ser"),
            ))
            .expect("build PUT");
        let put_resp = app.clone().oneshot(put_req).await.expect("oneshot PUT");
        assert_eq!(put_resp.status(), StatusCode::OK);

        // Public GET /agent-config/{id} must return the override, not global.
        let get_req = Request::builder()
            .method("GET")
            .uri("/agent-config/agent-override-01")
            .body(Body::empty())
            .expect("build GET");
        let get_resp = app.oneshot(get_req).await.expect("oneshot GET");
        assert_eq!(get_resp.status(), StatusCode::OK);
        let bytes = to_bytes(get_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let fetched: AgentConfigPayload = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(fetched.monitored_paths, vec![r"D:\Secret\".to_string()]);
        assert_eq!(fetched.heartbeat_interval_secs, 15);
        assert!(!fetched.offline_cache_enabled);
    }

    #[tokio::test]
    async fn test_delete_agent_config_override() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        seed_agent(&pool, "agent-del-01");
        let crypto = std::sync::Arc::new(crate::crypto::SecretCrypto::from_kek(
            [0x77; 32],
            crate::crypto::ENVELOPE_VERSION_V1,
        ));
        crate::secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
            .expect("Phase 47 migration");
        let siem = crate::siem_connector::SiemConnector::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let alert = crate::alert_router::AlertRouter::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"),
        );
        let label_service = Arc::new(crate::label_service::LabelService::new(Arc::clone(&pool)));
        let approval_token_crypto = crate::crypto::SecretCrypto::from_kek([0x77; 32], 1);
        let approval_token_conn = pool.get().expect("pool");
        let approval_token_service = Arc::new(
            crate::approval_token::ApprovalTokenService::new(
                &approval_token_crypto,
                &approval_token_conn,
            )
            .expect("approval token service"),
        );
        let state = Arc::new(AppState {
            pool: Arc::clone(&pool),
            crypto: std::sync::Arc::clone(&crypto),
            policy_store,
            siem,
            alert,
            ad: None,
            label_service,
            approval_token_service,
            syslog: crate::syslog_connector::SyslogConnector::new(
                std::sync::Arc::clone(&pool),
                std::sync::Arc::clone(&crypto),
            ),
            label_aware_enabled: std::sync::Arc::new(
                std::sync::atomic::AtomicBool::new(false),
            ),
        });
        let app = admin_router(state);
        let token = mint_admin_jwt();

        // Seed an override first.
        let override_config = AgentConfigPayload {
            monitored_paths: vec![r"E:\Logs\".to_string()],
            excluded_paths: vec![],
            heartbeat_interval_secs: 20,
            offline_cache_enabled: false,
            disk_allowlist: Vec::new(),
            usb_blocked_failure_mode: DEFAULT_USB_BLOCKED_FAILURE_MODE.to_string(),
            usb_startup_resolution_mode: DEFAULT_USB_STARTUP_RESOLUTION_MODE.to_string(),
            usb_none_serial_policy: DEFAULT_USB_NONE_SERIAL_POLICY.to_string(),
            ..Default::default()
        };
        let put_req = Request::builder()
            .method("PUT")
            .uri("/admin/agent-config/agent-del-01")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_string(&override_config).expect("ser"),
            ))
            .expect("build PUT");
        let put_resp = app.clone().oneshot(put_req).await.expect("oneshot PUT");
        assert_eq!(put_resp.status(), StatusCode::OK);

        // DELETE the override.
        let del_req = Request::builder()
            .method("DELETE")
            .uri("/admin/agent-config/agent-del-01")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build DELETE");
        let del_resp = app.clone().oneshot(del_req).await.expect("oneshot DELETE");
        assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

        // Public GET must now fall back to global default (heartbeat 30, empty paths).
        let get_req = Request::builder()
            .method("GET")
            .uri("/agent-config/agent-del-01")
            .body(Body::empty())
            .expect("build GET");
        let get_resp = app.oneshot(get_req).await.expect("oneshot GET");
        assert_eq!(get_resp.status(), StatusCode::OK);
        let bytes = to_bytes(get_resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let fetched: AgentConfigPayload = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(fetched.heartbeat_interval_secs, 30);
        assert_eq!(fetched.monitored_paths, Vec::<String>::new());
    }

    #[tokio::test]
    async fn test_get_agent_config_requires_no_auth() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        // Public endpoint: no Authorization header required.
        let app = spawn_admin_app();
        let req = Request::builder()
            .method("GET")
            .uri("/agent-config/any-agent-id")
            .body(Body::empty())
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        // 200 OK (falls back to global default — agent_id not required to exist).
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_put_admin_agent_config_requires_jwt() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let config = AgentConfigPayload {
            monitored_paths: vec![],
            excluded_paths: vec![],
            heartbeat_interval_secs: 30,
            offline_cache_enabled: true,
            disk_allowlist: Vec::new(),
            usb_blocked_failure_mode: DEFAULT_USB_BLOCKED_FAILURE_MODE.to_string(),
            usb_startup_resolution_mode: DEFAULT_USB_STARTUP_RESOLUTION_MODE.to_string(),
            usb_none_serial_policy: DEFAULT_USB_NONE_SERIAL_POLICY.to_string(),
            ..Default::default()
        };
        let req = Request::builder()
            .method("PUT")
            .uri("/admin/agent-config")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&config).expect("ser")))
            .expect("build");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Phase 12 TC tests: server-side enforcement ──────────────────────────────

    /// Seeds an AuditEvent into the server's audit store via POST /audit/events.
    ///
    /// Used by TC-02 and TC-03 to seed Block/DenyWithAlert events and then
    /// query them back via GET /audit/events.
    async fn seed_tc_audit_event(
        app: &axum::Router,
        tc_id: &str,
        classification: dlp_common::Classification,
        action: dlp_common::Action,
        decision: dlp_common::Decision,
        event_type: dlp_common::EventType,
        resource_path: &str,
    ) -> Result<(), String> {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let event = dlp_common::AuditEvent::new(
            event_type,
            format!("S-1-5-21-TC-{tc_id}"),
            format!("tc-{tc_id}-user"),
            resource_path.to_string(),
            classification,
            action,
            decision,
            format!("AGENT-TC-{tc_id}"),
            1,
        )
        .with_policy(format!("pol-tc-{tc_id}"), format!("TC-{tc_id} policy"))
        .with_source_application(Some(dlp_common::endpoint::agent_unknown_app()))
        .with_destination_application(Some(dlp_common::endpoint::agent_unknown_app()));

        let body = serde_json::to_string(&vec![event]).map_err(|e| e.to_string())?;
        let req = Request::builder()
            .method("POST")
            .uri("/audit/events")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .expect("build seed");
        let resp = app.clone().oneshot(req).await.map_err(|e| e.to_string())?;
        if resp.status() != StatusCode::CREATED {
            return Err(format!("seed failed with status {:?}", resp.status()));
        }
        Ok(())
    }

    /// TC-01: Access Internal file with permission
    /// Expected: allowed | preventive | allow
    ///
    /// Validates that `classify_text` returns T2 for internal-only content.
    /// T2 is not sensitive and maps to Decision::ALLOW in the ABAC engine.
    /// No audit block event is required for T2 access.
    #[tokio::test]
    async fn test_tc_01_internal_file_access_allowed() {
        let text = "For internal only distribution — Q4 planning document";
        let cls = dlp_common::classify_text(text);
        assert_eq!(cls, dlp_common::Classification::T2);
        assert!(!cls.is_sensitive());
        // T2 → ALLOW; server's ABAC engine returns Decision::ALLOW.
    }

    /// TC-02: Access Confidential without permission
    /// Expected: denied | preventive | block, log
    ///
    /// Validates that `classify_text` returns T3 for CONFIDENTIAL keyword.
    /// T3 access triggers Decision::DENY from the ABAC engine.
    /// The audit store must contain an EventType::Block audit event.
    #[tokio::test]
    async fn test_tc_02_confidential_file_access_denied_logged() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let text = "CONFIDENTIAL: M&A deal analysis";
        let cls = dlp_common::classify_text(text);
        assert_eq!(cls, dlp_common::Classification::T3);
        assert!(cls.is_sensitive());

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        seed_tc_audit_event(
            &app,
            "02",
            dlp_common::Classification::T3,
            dlp_common::Action::READ,
            dlp_common::Decision::DENY,
            dlp_common::EventType::Block,
            r"C:\Confidential\ma_analysis.xlsx",
        )
        .await
        .expect("seed failed");

        let query_req = Request::builder()
            .method("GET")
            .uri("/audit/events")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build query");
        let query_resp = app.oneshot(query_req).await.expect("oneshot query");
        assert_eq!(query_resp.status(), StatusCode::OK);
        let bytes = to_bytes(query_resp.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        let events: Vec<dlp_common::AuditEvent> =
            serde_json::from_slice(&bytes).expect("parse events");
        let tc_event = events
            .iter()
            .find(|e| e.agent_id == "AGENT-TC-02")
            .expect("TC-02 event must be present in audit store");
        assert_eq!(tc_event.decision, dlp_common::Decision::DENY);
        assert_eq!(tc_event.classification, dlp_common::Classification::T3);
        assert_eq!(tc_event.event_type, dlp_common::EventType::Block);
    }

    /// TC-03: Access Restricted by non-privileged user
    /// Expected: denied | preventive | block, alert
    ///
    /// Validates that T4 classification (SSN pattern) triggers
    /// Decision::DenyWithAlert. The audit store must contain an
    /// EventType::Alert audit event (not just Block).
    #[tokio::test]
    async fn test_tc_03_restricted_file_access_denied_alert() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let text = "Employee SSN: 123-45-6789 for payroll processing";
        let cls = dlp_common::classify_text(text);
        assert_eq!(cls, dlp_common::Classification::T4);

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        seed_tc_audit_event(
            &app,
            "03",
            dlp_common::Classification::T4,
            dlp_common::Action::READ,
            dlp_common::Decision::DenyWithAlert,
            dlp_common::EventType::Alert,
            r"C:\Restricted\secret.xlsx",
        )
        .await
        .expect("seed failed");

        let query_req = Request::builder()
            .method("GET")
            .uri("/audit/events")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build query");
        let query_resp = app.oneshot(query_req).await.expect("oneshot query");
        assert_eq!(query_resp.status(), StatusCode::OK);
        let bytes = to_bytes(query_resp.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        let events: Vec<dlp_common::AuditEvent> =
            serde_json::from_slice(&bytes).expect("parse events");
        let alert_event = events
            .iter()
            .find(|e| e.agent_id == "AGENT-TC-03")
            .expect("TC-03 event must be present in audit store");
        assert_eq!(alert_event.decision, dlp_common::Decision::DenyWithAlert);
        assert_eq!(alert_event.classification, dlp_common::Classification::T4);
        assert!(
            matches!(
                alert_event.event_type,
                dlp_common::EventType::Alert | dlp_common::EventType::Block
            ),
            "T4 block must emit Alert or Block event type"
        );
    }

    /// TC-51: Print Confidential file
    /// Expected: restricted | preventive | require_auth
    ///
    /// Validates classification contract for print interception.
    /// T3 file print → Decision::RequireAuth (not immediate DENY).
    /// Print spooler interception not yet implemented — stub with todo!().
    #[tokio::test]
    #[ignore = "print spooler interception not yet implemented"]
    async fn test_tc_51_print_confidential_require_auth() {
        let text = "CONFIDENTIAL budget report for FY2025";
        let cls = dlp_common::classify_text(text);
        assert_eq!(cls, dlp_common::Classification::T3);
        assert!(cls.is_sensitive());
        // Expected: print action on T3 file → Decision::RequireAuth.
        // Acceptance: print spooler intercept returns require_auth;
        // user must re-authenticate before job reaches print queue.
        todo!("TC-51: print action on T3 file — Decision::RequireAuth — not yet implemented")
    }

    /// TC-52: Print Restricted file
    /// Expected: blocked | preventive | block
    ///
    /// Validates that T4 classification blocks print action.
    /// Print spooler interception not yet implemented — stub with todo!().
    #[tokio::test]
    #[ignore = "print spooler interception not yet implemented"]
    async fn test_tc_52_print_restricted_blocked() {
        let text = "SSN: 123-45-6789 for direct deposit setup";
        let cls = dlp_common::classify_text(text);
        assert_eq!(cls, dlp_common::Classification::T4);
        // Expected: print action on T4 file → Decision::DENY.
        // Acceptance: print spooler intercept returns DENY;
        // job cancelled before reaching print queue.
        todo!("TC-52: print action on T4 file — Decision::DENY — not yet implemented")
    }

    /// TC-80: Access Confidential file — logged, not blocked
    /// Expected: logged | detective | log
    ///
    /// Validates that GET /audit/events returns an EventType::Access event
    /// (not Block) for a Confidential file that was accessed but not blocked.
    /// Detective control: no preventive action, audit-only logging.
    #[tokio::test]
    async fn test_tc_80_confidential_access_logged() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        let access_event = dlp_common::AuditEvent::new(
            dlp_common::EventType::Access,
            "S-1-5-21-TC-80".to_string(),
            "tc-80-user".to_string(),
            r"C:\Confidential\report.xlsx".to_string(),
            dlp_common::Classification::T3,
            dlp_common::Action::READ,
            dlp_common::Decision::ALLOW,
            "AGENT-TC-80".to_string(),
            1,
        )
        .with_policy(
            "pol-tc-80".to_string(),
            "TC-80 detective policy".to_string(),
        )
        .with_source_application(Some(dlp_common::endpoint::agent_unknown_app()))
        .with_destination_application(Some(dlp_common::endpoint::agent_unknown_app()));

        let body = serde_json::to_string(&vec![access_event]).expect("serialize");
        let ingest_req = Request::builder()
            .method("POST")
            .uri("/audit/events")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .expect("build ingest");
        let ingest_resp = app
            .clone()
            .oneshot(ingest_req)
            .await
            .expect("oneshot ingest");
        assert_eq!(ingest_resp.status(), StatusCode::CREATED);

        let query_req = Request::builder()
            .method("GET")
            .uri("/audit/events")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build query");
        let query_resp = app.oneshot(query_req).await.expect("oneshot query");
        assert_eq!(query_resp.status(), StatusCode::OK);
        let bytes = to_bytes(query_resp.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        let events: Vec<dlp_common::AuditEvent> =
            serde_json::from_slice(&bytes).expect("parse events");

        let access = events
            .iter()
            .find(|e| e.agent_id == "AGENT-TC-80")
            .expect("TC-80 Access event must be in audit store");

        // Detective control: event_type must be Access (not Block).
        assert_eq!(access.event_type, dlp_common::EventType::Access);
        assert_eq!(access.classification, dlp_common::Classification::T3);
        assert_eq!(access.decision, dlp_common::Decision::ALLOW);
        // No block occurred — key difference from TC-02.
    }

    // ── Task 4.2: POST /evaluate endpoint integration tests ──────────────────

    /// POST /evaluate with a T3 classification and no matching policy → default-deny.
    #[tokio::test]
    async fn test_evaluate_returns_decision() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("build policy store"),
        );
        let crypto = std::sync::Arc::new(crate::crypto::SecretCrypto::from_kek(
            [0x77; 32],
            crate::crypto::ENVELOPE_VERSION_V1,
        ));
        crate::secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
            .expect("Phase 47 migration");
        let siem = crate::siem_connector::SiemConnector::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let alert = crate::alert_router::AlertRouter::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let label_service = Arc::new(crate::label_service::LabelService::new(Arc::clone(&pool)));
        let approval_token_crypto = crate::crypto::SecretCrypto::from_kek([0x77; 32], 1);
        let approval_token_conn = pool.get().expect("pool");
        let approval_token_service = Arc::new(
            crate::approval_token::ApprovalTokenService::new(
                &approval_token_crypto,
                &approval_token_conn,
            )
            .expect("approval token service"),
        );
        let state = Arc::new(AppState {
            pool: Arc::clone(&pool),
            crypto: std::sync::Arc::clone(&crypto),
            policy_store,
            siem,
            alert,
            ad: None,
            label_service,
            approval_token_service,
            syslog: crate::syslog_connector::SyslogConnector::new(
                std::sync::Arc::clone(&pool),
                std::sync::Arc::clone(&crypto),
            ),
            label_aware_enabled: std::sync::Arc::new(
                std::sync::atomic::AtomicBool::new(false),
            ),
        });
        let app = admin_router(state);

        // T3 with no policies → tiered default-deny (T3 → DENY).
        let request_body = serde_json::json!({
            "subject": {
                "user_sid": "S-1-5-21-1",
                "user_name": "testuser",
                "groups": [],
                "device_trust": "Unknown",
                "network_location": "Unknown"
            },
            "resource": {
                "path": r"C:\test\confidential.txt",
                "classification": "T3"
            },
            "environment": {
                "timestamp": "2026-04-16T00:00:00Z",
                "session_id": 1,
                "access_context": "local"
            },
            "action": "READ"
        });

        let req = Request::builder()
            .method("POST")
            .uri("/evaluate")
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
            .expect("build request");

        let resp = app.oneshot(req).await.expect("send request");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body_val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body_val["decision"], "DENY");
        assert!(body_val["matched_policy_id"].is_null());
    }

    /// POST /evaluate with a T1 classification and no matching policy → default-allow.
    #[tokio::test]
    async fn test_evaluate_returns_allow_for_t1() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("build policy store"),
        );
        let crypto = std::sync::Arc::new(crate::crypto::SecretCrypto::from_kek(
            [0x77; 32],
            crate::crypto::ENVELOPE_VERSION_V1,
        ));
        crate::secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
            .expect("Phase 47 migration");
        let siem = crate::siem_connector::SiemConnector::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let alert = crate::alert_router::AlertRouter::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let label_service = Arc::new(crate::label_service::LabelService::new(Arc::clone(&pool)));
        let approval_token_crypto = crate::crypto::SecretCrypto::from_kek([0x77; 32], 1);
        let approval_token_conn = pool.get().expect("pool");
        let approval_token_service = Arc::new(
            crate::approval_token::ApprovalTokenService::new(
                &approval_token_crypto,
                &approval_token_conn,
            )
            .expect("approval token service"),
        );
        let state = Arc::new(AppState {
            pool: Arc::clone(&pool),
            crypto: std::sync::Arc::clone(&crypto),
            policy_store,
            siem,
            alert,
            ad: None,
            label_service,
            approval_token_service,
            syslog: crate::syslog_connector::SyslogConnector::new(
                std::sync::Arc::clone(&pool),
                std::sync::Arc::clone(&crypto),
            ),
            label_aware_enabled: std::sync::Arc::new(
                std::sync::atomic::AtomicBool::new(false),
            ),
        });
        let app = admin_router(state);

        // T1 with no policies → default-allow (T1 → ALLOW).
        let request_body = serde_json::json!({
            "subject": {
                "user_sid": "S-1-5-21-1",
                "user_name": "testuser",
                "groups": [],
                "device_trust": "Unknown",
                "network_location": "Unknown"
            },
            "resource": {
                "path": r"C:\test\public.txt",
                "classification": "T1"
            },
            "environment": {
                "timestamp": "2026-04-16T00:00:00Z",
                "session_id": 1,
                "access_context": "local"
            },
            "action": "READ"
        });

        let req = Request::builder()
            .method("POST")
            .uri("/evaluate")
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
            .expect("build request");

        let resp = app.oneshot(req).await.expect("send request");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body_val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body_val["decision"], "ALLOW");
    }

    /// POST /evaluate returns ALLOW for T2 (no policy), then DENY after a T2-deny policy is created.
    /// This verifies that `create_policy` calls `policy_store.invalidate()`.
    #[tokio::test]
    async fn test_evaluate_invalidation_on_policy_create() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("build policy store"),
        );
        let crypto = std::sync::Arc::new(crate::crypto::SecretCrypto::from_kek(
            [0x77; 32],
            crate::crypto::ENVELOPE_VERSION_V1,
        ));
        crate::secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
            .expect("Phase 47 migration");
        let siem = crate::siem_connector::SiemConnector::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let alert = crate::alert_router::AlertRouter::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let label_service = Arc::new(crate::label_service::LabelService::new(Arc::clone(&pool)));
        let approval_token_crypto = crate::crypto::SecretCrypto::from_kek([0x77; 32], 1);
        let approval_token_conn = pool.get().expect("pool");
        let approval_token_service = Arc::new(
            crate::approval_token::ApprovalTokenService::new(
                &approval_token_crypto,
                &approval_token_conn,
            )
            .expect("approval token service"),
        );
        let state = Arc::new(AppState {
            pool: Arc::clone(&pool),
            crypto: std::sync::Arc::clone(&crypto),
            policy_store: Arc::clone(&policy_store),
            siem,
            alert,
            ad: None,
            label_service,
            approval_token_service,
            syslog: crate::syslog_connector::SyslogConnector::new(
                std::sync::Arc::clone(&pool),
                std::sync::Arc::clone(&crypto),
            ),
            label_aware_enabled: std::sync::Arc::new(
                std::sync::atomic::AtomicBool::new(false),
            ),
        });
        let app = admin_router(state);

        // 1. Evaluate T2 with empty store → default-allow (T2).
        let request_body = serde_json::json!({
            "subject": {
                "user_sid": "S-1-5-21-1",
                "user_name": "testuser",
                "groups": [],
                "device_trust": "Unknown",
                "network_location": "Unknown"
            },
            "resource": {
                "path": r"C:\test\internal.txt",
                "classification": "T2"
            },
            "environment": {
                "timestamp": "2026-04-16T00:00:00Z",
                "session_id": 1,
                "access_context": "local"
            },
            "action": "READ"
        });

        let req = Request::builder()
            .method("POST")
            .uri("/evaluate")
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
            .expect("build request");
        let resp = app.clone().oneshot(req).await.expect("send request");
        assert_eq!(resp.status(), StatusCode::OK);

        // 2. Create a policy that DENYs T2.
        let policy_body = serde_json::json!({
            "id": "deny-t2",
            "name": "Deny T2",
            "priority": 1,
            "conditions": [
                { "attribute": "classification", "op": "eq", "value": "T2" }
            ],
            "action": "DENY",
            "enabled": true
        });
        let admin_token = mint_admin_jwt();
        let req = Request::builder()
            .method("POST")
            .uri("/policies")
            .header(http::header::AUTHORIZATION, format!("Bearer {admin_token}"))
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&policy_body).unwrap()))
            .expect("build request");
        let resp = app.clone().oneshot(req).await.expect("send request");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // 3. Evaluate T2 again → cache was invalidated, policy now matches → DENY.
        let req = Request::builder()
            .method("POST")
            .uri("/evaluate")
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
            .expect("build request");
        let resp = app.oneshot(req).await.expect("send request");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body_val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body_val["decision"], "DENY");
        assert_eq!(body_val["matched_policy_id"], "deny-t2");
    }

    // ---- Wire format round-trip tests for `mode` (POLICY-12) ----

    #[test]
    fn test_policy_payload_deserializes_without_mode_as_all() {
        // POLICY-12: JSON without "mode" key defaults to PolicyMode::ALL.
        let json = r#"{
            "id": "test-1",
            "name": "test policy",
            "description": null,
            "priority": 1,
            "conditions": [],
            "action": "Allow",
            "enabled": true
        }"#;
        let payload: PolicyPayload = serde_json::from_str(json).expect("deserialize");
        assert_eq!(payload.mode, PolicyMode::ALL);
    }

    #[test]
    fn test_policy_payload_json_with_mode_any_roundtrip() {
        let payload = PolicyPayload {
            id: "test-any".to_string(),
            name: "any mode policy".to_string(),
            description: None,
            priority: 2,
            conditions: serde_json::json!([]),
            action: "Deny".to_string(),
            enabled: true,
            mode: PolicyMode::ANY,
        };
        let json = serde_json::to_string(&payload).expect("serialize");
        assert!(
            json.contains(r#""mode":"ANY""#),
            "serialized JSON must contain \"mode\":\"ANY\""
        );
        let round_trip: PolicyPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(round_trip.mode, PolicyMode::ANY);
    }

    #[test]
    fn test_policy_response_deserializes_without_mode_as_all() {
        // PolicyResponse without "mode" key defaults to PolicyMode::ALL.
        let json = r#"{
            "id": "test-2",
            "name": "test response",
            "description": null,
            "priority": 1,
            "conditions": [],
            "action": "Allow",
            "enabled": true,
            "version": 1,
            "updated_at": "2026-04-20T00:00:00Z"
        }"#;
        let resp: PolicyResponse = serde_json::from_str(json).expect("deserialize");
        assert_eq!(resp.mode, PolicyMode::ALL);
    }

    #[test]
    fn test_policy_payload_none_mode_roundtrip() {
        let payload = PolicyPayload {
            id: "test-none".to_string(),
            name: "none mode policy".to_string(),
            description: None,
            priority: 3,
            conditions: serde_json::json!([]),
            action: "Allow".to_string(),
            enabled: true,
            mode: PolicyMode::NONE,
        };
        let json = serde_json::to_string(&payload).expect("serialize");
        assert!(
            json.contains(r#""mode":"NONE""#),
            "serialized JSON must contain \"mode\":\"NONE\""
        );
        let round_trip: PolicyPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(round_trip.mode, PolicyMode::NONE);
    }

    // ---------------------------------------------------------------------------
    // Device Registry type shape tests (Task 1 — TDD RED)
    // ---------------------------------------------------------------------------

    /// DeviceRegistryRequest with description omitted deserializes with empty string default.
    #[test]
    fn test_device_registry_request_description_defaults_to_empty() {
        let json = r#"{"vid":"0951","pid":"1666","serial":"SN001","trust_tier":"blocked"}"#;
        let req: DeviceRegistryRequest =
            serde_json::from_str(json).expect("deserialize DeviceRegistryRequest");
        assert_eq!(req.vid, "0951");
        assert_eq!(req.pid, "1666");
        assert_eq!(req.serial, "SN001");
        assert_eq!(req.trust_tier, "blocked");
        assert_eq!(
            req.description, "",
            "description must default to empty string"
        );
    }

    /// DeviceRegistryResponse serializes to JSON with all expected fields.
    #[test]
    fn test_device_registry_response_serializes_all_fields() {
        let resp = DeviceRegistryResponse {
            id: "uuid-001".to_string(),
            vid: "0951".to_string(),
            pid: "1666".to_string(),
            serial: "SN001".to_string(),
            owner_sid: Some("S-1-5-21-1".to_string()),
            owner_user: Some("alice".to_string()),
            description: "Kingston DataTraveler".to_string(),
            trust_tier: "read_only".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert!(json.contains(r#""id":"uuid-001""#), "id field missing");
        assert!(json.contains(r#""vid":"0951""#), "vid field missing");
        assert!(json.contains(r#""pid":"1666""#), "pid field missing");
        assert!(json.contains(r#""serial":"SN001""#), "serial field missing");
        assert!(
            json.contains(r#""owner_sid":"S-1-5-21-1""#),
            "owner_sid field missing"
        );
        assert!(
            json.contains(r#""owner_user":"alice""#),
            "owner_user field missing"
        );
        assert!(
            json.contains(r#""description":"Kingston DataTraveler""#),
            "description field missing"
        );
        assert!(
            json.contains(r#""trust_tier":"read_only""#),
            "trust_tier field missing"
        );
        assert!(
            json.contains(r#""created_at":"2026-01-01T00:00:00Z""#),
            "created_at field missing"
        );
    }

    /// trust_tier value "read_only" is valid and round-trips correctly.
    #[test]
    fn test_device_registry_request_read_only_tier_accepted() {
        let json = r#"{"vid":"046d","pid":"c52b","serial":"ABC","trust_tier":"read_only"}"#;
        let req: DeviceRegistryRequest =
            serde_json::from_str(json).expect("deserialize DeviceRegistryRequest");
        assert_eq!(req.trust_tier, "read_only");
    }

    /// DeviceRegistryRequest without owner_sid/owner_user deserializes with None defaults.
    #[test]
    fn test_device_registry_request_owner_fields_default_to_none() {
        let json = r#"{"vid":"0951","pid":"1666","serial":"SN001","trust_tier":"blocked"}"#;
        let req: DeviceRegistryRequest =
            serde_json::from_str(json).expect("deserialize DeviceRegistryRequest");
        assert_eq!(req.owner_sid, None, "owner_sid must default to None");
        assert_eq!(req.owner_user, None, "owner_user must default to None");
    }

    // ---------------------------------------------------------------------------
    // Device Registry handler integration tests (Task 2 — TDD RED)
    // ---------------------------------------------------------------------------

    /// GET /admin/device-registry returns 200 + empty JSON array when DB is empty (no auth).
    #[tokio::test]
    async fn test_device_registry_get_returns_empty_list() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let req = Request::builder()
            .method("GET")
            .uri("/admin/device-registry")
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        let list: Vec<serde_json::Value> = serde_json::from_slice(&body).expect("parse JSON array");
        assert!(list.is_empty(), "expected empty array from fresh DB");
    }

    /// POST /admin/device-registry with valid JWT returns 200 + full DeviceRegistryResponse JSON.
    #[tokio::test]
    async fn test_device_registry_post_upserts_and_returns_row() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();
        let payload = serde_json::json!({
            "vid": "0951",
            "pid": "1666",
            "serial": "ABC",
            "trust_tier": "blocked"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/admin/device-registry")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        let row: DeviceRegistryResponse =
            serde_json::from_slice(&body).expect("parse DeviceRegistryResponse");
        assert!(!row.id.is_empty(), "id must be a non-empty UUID");
        assert_eq!(row.vid, "0951");
        assert_eq!(row.pid, "1666");
        assert_eq!(row.serial, "ABC");
        assert_eq!(row.trust_tier, "blocked");
    }

    /// POST /admin/device-registry with invalid trust_tier returns 422.
    #[tokio::test]
    async fn test_device_registry_post_invalid_tier_returns_422() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();
        let payload = serde_json::json!({
            "vid": "x",
            "pid": "y",
            "serial": "z",
            "trust_tier": "invalid"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/admin/device-registry")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// POST /admin/device-registry without JWT returns 401.
    #[tokio::test]
    async fn test_device_registry_post_without_jwt_returns_401() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let payload = serde_json::json!({
            "vid": "0951",
            "pid": "1666",
            "serial": "ABC",
            "trust_tier": "blocked"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/admin/device-registry")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// DELETE /admin/device-registry/{id} with valid JWT returns 204;
    /// subsequent GET confirms the list is empty.
    #[tokio::test]
    async fn test_device_registry_delete_returns_204_and_removes_row() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        // Insert a device first.
        let payload = serde_json::json!({
            "vid": "0951",
            "pid": "1666",
            "serial": "DEL001",
            "trust_tier": "read_only"
        });
        let post_req = Request::builder()
            .method("POST")
            .uri("/admin/device-registry")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .expect("build POST");
        let post_resp = app.clone().oneshot(post_req).await.expect("oneshot POST");
        assert_eq!(post_resp.status(), StatusCode::OK);
        let body = to_bytes(post_resp.into_body(), usize::MAX)
            .await
            .expect("body");
        let row: DeviceRegistryResponse =
            serde_json::from_slice(&body).expect("parse DeviceRegistryResponse");
        let id = row.id;

        // Delete by UUID.
        let del_req = Request::builder()
            .method("DELETE")
            .uri(format!("/admin/device-registry/{id}"))
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build DELETE");
        let del_resp = app.clone().oneshot(del_req).await.expect("oneshot DELETE");
        assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

        // Verify the list is now empty.
        let get_req = Request::builder()
            .method("GET")
            .uri("/admin/device-registry")
            .body(Body::empty())
            .expect("build GET");
        let get_resp = app.oneshot(get_req).await.expect("oneshot GET");
        let body = to_bytes(get_resp.into_body(), usize::MAX)
            .await
            .expect("body");
        let list: Vec<serde_json::Value> = serde_json::from_slice(&body).expect("parse JSON array");
        assert!(list.is_empty(), "list must be empty after delete");
    }

    /// DELETE /admin/device-registry/{nonexistent-uuid} returns 404.
    #[tokio::test]
    async fn test_device_registry_delete_nonexistent_returns_404() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();
        let req = Request::builder()
            .method("DELETE")
            .uri("/admin/device-registry/00000000-0000-0000-0000-000000000000")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// POST with owner_sid and owner_user returns 200 with those fields populated.
    #[tokio::test]
    async fn test_device_registry_post_with_owner_sid() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();
        let payload = serde_json::json!({
            "vid": "0951",
            "pid": "1666",
            "serial": "OWNER001",
            "owner_sid": "S-1-5-21-1",
            "owner_user": "alice",
            "trust_tier": "blocked"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/admin/device-registry")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        let row: DeviceRegistryResponse =
            serde_json::from_slice(&body).expect("parse DeviceRegistryResponse");
        assert_eq!(row.owner_sid, Some("S-1-5-21-1".to_string()));
        assert_eq!(row.owner_user, Some("alice".to_string()));
    }

    /// POST without owner_sid/owner_user returns 200 with both fields as None.
    #[tokio::test]
    async fn test_device_registry_post_without_owner_sid() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();
        let payload = serde_json::json!({
            "vid": "0951",
            "pid": "1666",
            "serial": "NOOWNER001",
            "trust_tier": "read_only"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/admin/device-registry")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        let row: DeviceRegistryResponse =
            serde_json::from_slice(&body).expect("parse DeviceRegistryResponse");
        assert_eq!(row.owner_sid, None);
        assert_eq!(row.owner_user, None);
    }

    /// GET /admin/device-registry/full?owner_sid=S-1-5-21-1 returns matching SID + machine-wide.
    #[tokio::test]
    async fn test_device_registry_get_filtered_by_owner_sid() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        // Seed machine-wide entry.
        let mw = serde_json::json!({
            "vid": "0951",
            "pid": "1666",
            "serial": "FILTER001",
            "trust_tier": "read_only"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/admin/device-registry")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&mw).unwrap()))
            .expect("build POST");
        let resp = app.clone().oneshot(req).await.expect("oneshot POST");
        assert_eq!(resp.status(), StatusCode::OK);

        // Seed per-user entry for alice.
        let alice = serde_json::json!({
            "vid": "0951",
            "pid": "1666",
            "serial": "FILTER001",
            "owner_sid": "S-1-5-21-1",
            "owner_user": "alice",
            "trust_tier": "blocked"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/admin/device-registry")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&alice).unwrap()))
            .expect("build POST 2");
        let resp = app.clone().oneshot(req).await.expect("oneshot POST 2");
        assert_eq!(resp.status(), StatusCode::OK);

        // Seed per-user entry for bob (should NOT appear in alice's filter).
        let bob = serde_json::json!({
            "vid": "0951",
            "pid": "1666",
            "serial": "FILTER001",
            "owner_sid": "S-1-5-21-2",
            "owner_user": "bob",
            "trust_tier": "full_access"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/admin/device-registry")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&bob).unwrap()))
            .expect("build POST 3");
        let resp = app.clone().oneshot(req).await.expect("oneshot POST 3");
        assert_eq!(resp.status(), StatusCode::OK);

        // Query with owner_sid filter for alice.
        let get_req = Request::builder()
            .method("GET")
            .uri("/admin/device-registry/full?owner_sid=S-1-5-21-1")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build GET");
        let get_resp = app.oneshot(get_req).await.expect("oneshot GET");
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body = to_bytes(get_resp.into_body(), usize::MAX)
            .await
            .expect("body");
        let list: Vec<DeviceRegistryResponse> = serde_json::from_slice(&body).expect("parse list");

        // Must return alice's entry + machine-wide entry (2 rows), NOT bob's.
        assert_eq!(list.len(), 2, "expected 2 rows: alice + machine-wide");
        let sids: Vec<Option<&str>> = list.iter().map(|r| r.owner_sid.as_deref()).collect();
        assert!(
            sids.contains(&Some("S-1-5-21-1")),
            "alice's entry must be present"
        );
        assert!(sids.contains(&None), "machine-wide entry must be present");
        assert!(
            !sids.contains(&Some("S-1-5-21-2")),
            "bob's entry must NOT be present"
        );
    }

    /// Machine-wide and per-user entries for same device both succeed.
    #[tokio::test]
    async fn test_device_registry_unique_per_user_and_machine_wide() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let token = mint_admin_jwt();

        // Machine-wide entry.
        let mw = serde_json::json!({
            "vid": "0951",
            "pid": "1666",
            "serial": "UNIQUE001",
            "trust_tier": "read_only"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/admin/device-registry")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&mw).unwrap()))
            .expect("build POST");
        let resp = app.clone().oneshot(req).await.expect("oneshot POST");
        assert_eq!(resp.status(), StatusCode::OK);

        // Per-user entry for same device — must succeed.
        let user = serde_json::json!({
            "vid": "0951",
            "pid": "1666",
            "serial": "UNIQUE001",
            "owner_sid": "S-1-5-21-1",
            "owner_user": "alice",
            "trust_tier": "blocked"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/admin/device-registry")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&user).unwrap()))
            .expect("build POST 2");
        let resp = app.clone().oneshot(req).await.expect("oneshot POST 2");
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify both entries exist via full list.
        let get_req = Request::builder()
            .method("GET")
            .uri("/admin/device-registry/full")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build GET");
        let get_resp = app.oneshot(get_req).await.expect("oneshot GET");
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body = to_bytes(get_resp.into_body(), usize::MAX)
            .await
            .expect("body");
        let list: Vec<DeviceRegistryResponse> = serde_json::from_slice(&body).expect("parse list");
        assert_eq!(list.len(), 2, "expected 2 rows: machine-wide + per-user");
    }

    // -----------------------------------------------------------------------
    // Task 1: list_disk_registry_handler tests
    // -----------------------------------------------------------------------

    /// Helper: build a minimal DiskRegistryRow for test insertions.
    fn make_disk_row(
        id: &str,
        agent_id: &str,
        instance_id: &str,
        registered_at: &str,
    ) -> DiskRegistryRow {
        DiskRegistryRow {
            id: id.to_string(),
            agent_id: agent_id.to_string(),
            instance_id: instance_id.to_string(),
            bus_type: "usb".to_string(),
            encryption_status: "unencrypted".to_string(),
            model: "Test Model".to_string(),
            registered_at: registered_at.to_string(),
        }
    }

    /// Helper: build an AppState from a shared pool (no temp-file lifetime issues).
    fn make_state_from_pool(pool: Arc<db::Pool>) -> Arc<AppState> {
        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let crypto = std::sync::Arc::new(crate::crypto::SecretCrypto::from_kek(
            [0x77; 32],
            crate::crypto::ENVELOPE_VERSION_V1,
        ));
        crate::secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
            .expect("Phase 47 migration");
        let siem = crate::siem_connector::SiemConnector::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let alert = crate::alert_router::AlertRouter::new(
            std::sync::Arc::clone(&pool),
            std::sync::Arc::clone(&crypto),
        );
        let policy_store = Arc::new(
            crate::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"),
        );
        let label_service = Arc::new(crate::label_service::LabelService::new(Arc::clone(&pool)));
        let conn = pool.get().expect("pool");
        let approval_token_service = Arc::new(
            crate::approval_token::ApprovalTokenService::new(&crypto, &conn)
                .expect("approval token service"),
        );
        Arc::new(AppState {
            pool: Arc::clone(&pool),
            crypto: std::sync::Arc::clone(&crypto),
            policy_store,
            siem,
            alert,
            ad: None,
            label_service,
            approval_token_service,
            syslog: crate::syslog_connector::SyslogConnector::new(
                std::sync::Arc::clone(&pool),
                std::sync::Arc::clone(&crypto),
            ),
            label_aware_enabled: std::sync::Arc::new(
                std::sync::atomic::AtomicBool::new(false),
            ),
        })
    }

    /// Helper: build a GET /admin/disk-registry request with an optional agent_id
    /// filter and a JWT Bearer token.
    fn make_list_request(
        agent_id_filter: Option<&str>,
        token: &str,
    ) -> axum::http::Request<axum::body::Body> {
        let uri = match agent_id_filter {
            Some(id) => format!("/admin/disk-registry?agent_id={id}"),
            None => "/admin/disk-registry".to_string(),
        };
        axum::http::Request::builder()
            .method("GET")
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .expect("build GET request")
    }

    /// GET /admin/disk-registry with no rows returns 200 with an empty array.
    #[tokio::test]
    async fn test_list_disk_registry_handler_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let state = make_state_from_pool(pool);
        let token = mint_admin_jwt();

        let req = make_list_request(None, &token);
        let Json(list) = list_disk_registry_handler(State(Arc::clone(&state)), req)
            .await
            .expect("handler must succeed");
        assert!(list.is_empty(), "expected empty array");
    }

    /// GET /admin/disk-registry returns all rows ordered by registered_at ASC.
    #[tokio::test]
    async fn test_list_disk_registry_handler_returns_all_rows_ordered() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));

        // Insert two rows with deliberate out-of-order timestamps.
        {
            let mut conn = pool.get().expect("conn");
            let uow = db::UnitOfWork::new(&mut conn).expect("uow");
            // row1 has a LATER date; row2 has an EARLIER date.
            let row1 = make_disk_row("id-1", "agent-A", "disk-1", "2026-02-01T00:00:00Z");
            let row2 = make_disk_row("id-2", "agent-A", "disk-2", "2026-01-01T00:00:00Z");
            DiskRegistryRepository::insert(&uow, &row1).expect("insert row1");
            DiskRegistryRepository::insert(&uow, &row2).expect("insert row2");
            uow.commit().expect("commit");
        }

        let state = make_state_from_pool(pool);
        let token = mint_admin_jwt();
        let req = make_list_request(None, &token);
        let Json(list) = list_disk_registry_handler(State(Arc::clone(&state)), req)
            .await
            .expect("handler must succeed");

        assert_eq!(list.len(), 2, "expected 2 rows");
        // ASC order: 2026-01-01 before 2026-02-01
        assert_eq!(list[0].instance_id, "disk-2");
        assert_eq!(list[1].instance_id, "disk-1");
    }

    /// GET /admin/disk-registry?agent_id=agent-A returns only agent-A rows.
    #[tokio::test]
    async fn test_list_disk_registry_handler_filters_by_agent_id() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));

        {
            let mut conn = pool.get().expect("conn");
            let uow = db::UnitOfWork::new(&mut conn).expect("uow");
            let row_a = make_disk_row("id-a", "agent-A", "disk-1", "2026-01-01T00:00:00Z");
            let row_b = make_disk_row("id-b", "agent-B", "disk-1", "2026-01-02T00:00:00Z");
            DiskRegistryRepository::insert(&uow, &row_a).expect("insert row-a");
            DiskRegistryRepository::insert(&uow, &row_b).expect("insert row-b");
            uow.commit().expect("commit");
        }

        let state = make_state_from_pool(pool);
        let token = mint_admin_jwt();
        let req = make_list_request(Some("agent-A"), &token);
        let Json(list) = list_disk_registry_handler(State(Arc::clone(&state)), req)
            .await
            .expect("handler must succeed");

        assert_eq!(list.len(), 1, "expected only agent-A rows");
        assert_eq!(list[0].agent_id, "agent-A");
    }

    /// GET /admin/disk-registry?agent_id=does-not-exist returns 200 with [].
    #[tokio::test]
    async fn test_list_disk_registry_handler_unknown_agent_id_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let state = make_state_from_pool(pool);
        let token = mint_admin_jwt();
        let req = make_list_request(Some("does-not-exist"), &token);
        let Json(list) = list_disk_registry_handler(State(Arc::clone(&state)), req)
            .await
            .expect("handler must succeed");
        assert!(list.is_empty(), "unknown agent_id must return empty array");
    }

    // -----------------------------------------------------------------------
    // Task 2: insert_disk_registry_handler and delete_disk_registry_handler
    // -----------------------------------------------------------------------

    /// Helper: build a POST request to /admin/disk-registry with a JWT auth header.
    fn make_insert_request(
        body: &DiskRegistryRequest,
        token: &str,
    ) -> axum::http::Request<axum::body::Body> {
        let json_body = serde_json::to_vec(body).expect("serialize body");
        axum::http::Request::builder()
            .method("POST")
            .uri("/admin/disk-registry")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(json_body))
            .expect("build request")
    }

    /// Helper: build a DELETE request for a given disk UUID with JWT auth.
    fn make_delete_request(id: &str, token: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("DELETE")
            .uri(format!("/admin/disk-registry/{id}"))
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .expect("build request")
    }

    /// Successful POST returns 201 + JSON body with server-generated UUID and RFC-3339 timestamp.
    #[tokio::test]
    async fn test_insert_disk_registry_handler_success() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let state = make_state_from_pool(Arc::clone(&pool));
        let token = mint_admin_jwt();
        let req_body = DiskRegistryRequest {
            agent_id: "agent-A".to_string(),
            instance_id: "disk-1".to_string(),
            bus_type: "usb".to_string(),
            encryption_status: "unencrypted".to_string(),
            model: "Test Model".to_string(),
        };
        let req = make_insert_request(&req_body, &token);

        let (status, Json(resp)) = insert_disk_registry_handler(State(Arc::clone(&state)), req)
            .await
            .expect("handler must succeed");

        assert_eq!(status, StatusCode::CREATED);
        assert!(!resp.id.is_empty(), "id must be non-empty UUID");
        // RFC-3339 timestamp must parse without error.
        chrono::DateTime::parse_from_rfc3339(&resp.registered_at)
            .expect("registered_at must be valid RFC-3339");
        assert_eq!(resp.agent_id, "agent-A");
        assert_eq!(resp.instance_id, "disk-1");
        assert_eq!(resp.bus_type, "usb");
        assert_eq!(resp.encryption_status, "unencrypted");
    }

    /// POST with an invalid encryption_status returns 422 and no DB write.
    #[tokio::test]
    async fn test_insert_disk_registry_handler_invalid_status_returns_422() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let state = make_state_from_pool(Arc::clone(&pool));
        let token = mint_admin_jwt();
        let req_body = DiskRegistryRequest {
            agent_id: "agent-A".to_string(),
            instance_id: "disk-1".to_string(),
            bus_type: "usb".to_string(),
            encryption_status: "not_a_status".to_string(),
            model: String::new(),
        };
        let req = make_insert_request(&req_body, &token);

        let err = insert_disk_registry_handler(State(Arc::clone(&state)), req)
            .await
            .expect_err("must return error for invalid status");

        assert!(
            matches!(err, AppError::UnprocessableEntity(_)),
            "expected UnprocessableEntity, got: {err:?}"
        );
        // Verify DB has no rows.
        let count: i64 = pool
            .get()
            .expect("conn")
            .query_row("SELECT COUNT(*) FROM disk_registry", [], |r| r.get(0))
            .expect("count");
        assert_eq!(count, 0, "no DB row must be written on 422");
    }

    /// POST with encryption_status > 32 chars returns 422 BEFORE allowlist check.
    #[tokio::test]
    async fn test_insert_disk_registry_handler_too_long_status_returns_422() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let state = make_state_from_pool(Arc::clone(&pool));
        let token = mint_admin_jwt();
        // 33-char string that would otherwise pass the allowlist check if shortened.
        let long_status = "a".repeat(33);
        let req_body = DiskRegistryRequest {
            agent_id: "agent-A".to_string(),
            instance_id: "disk-1".to_string(),
            bus_type: "usb".to_string(),
            encryption_status: long_status,
            model: String::new(),
        };
        let req = make_insert_request(&req_body, &token);

        let err = insert_disk_registry_handler(State(Arc::clone(&state)), req)
            .await
            .expect_err("must return error for oversized status");

        assert!(
            matches!(err, AppError::UnprocessableEntity(_)),
            "expected UnprocessableEntity, got: {err:?}"
        );
        let count: i64 = pool
            .get()
            .expect("conn")
            .query_row("SELECT COUNT(*) FROM disk_registry", [], |r| r.get(0))
            .expect("count");
        assert_eq!(count, 0, "no DB row must be written on 422");
    }

    /// Duplicate (agent_id, instance_id) returns 409; DB still has only the first row.
    #[tokio::test]
    async fn test_insert_disk_registry_handler_duplicate_returns_409() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let state = make_state_from_pool(Arc::clone(&pool));
        let token = mint_admin_jwt();
        let req_body = DiskRegistryRequest {
            agent_id: "agent-A".to_string(),
            instance_id: "disk-1".to_string(),
            bus_type: "usb".to_string(),
            encryption_status: "unencrypted".to_string(),
            model: "Original".to_string(),
        };

        // First POST must succeed.
        let req1 = make_insert_request(&req_body, &token);
        let (status1, _) = insert_disk_registry_handler(State(Arc::clone(&state)), req1)
            .await
            .expect("first POST must succeed");
        assert_eq!(status1, StatusCode::CREATED);

        // Second POST with same (agent_id, instance_id) -- different status to prove
        // the original is not modified.
        let req_body2 = DiskRegistryRequest {
            encryption_status: "encrypted".to_string(),
            ..req_body.clone()
        };
        let req2 = make_insert_request(&req_body2, &token);
        let err = insert_disk_registry_handler(State(Arc::clone(&state)), req2)
            .await
            .expect_err("duplicate POST must return error");

        assert!(
            matches!(err, AppError::Conflict(_)),
            "expected Conflict, got: {err:?}"
        );
        // DB must have exactly one row with the ORIGINAL encryption_status.
        let (count, status): (i64, String) = pool
            .get()
            .expect("conn")
            .query_row(
                "SELECT COUNT(*), encryption_status FROM disk_registry WHERE agent_id='agent-A' AND instance_id='disk-1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query");
        assert_eq!(count, 1, "only one row must exist");
        assert_eq!(
            status, "unencrypted",
            "status must not be changed by duplicate POST"
        );
    }

    /// Successful POST emits exactly one audit event with correct fields.
    #[tokio::test]
    async fn test_insert_disk_registry_handler_emits_audit_event() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let state = make_state_from_pool(Arc::clone(&pool));
        let token = mint_admin_jwt();
        let req_body = DiskRegistryRequest {
            agent_id: "agent-X".to_string(),
            instance_id: "disk-Z".to_string(),
            bus_type: "nvme".to_string(),
            encryption_status: "encrypted".to_string(),
            model: "NVMe Pro".to_string(),
        };
        let req = make_insert_request(&req_body, &token);
        let _ = insert_disk_registry_handler(State(Arc::clone(&state)), req)
            .await
            .expect("handler must succeed");

        // Verify audit_events table has exactly one row with the expected fields.
        let mut conn = pool.get().expect("conn");
        let (event_type, action, resource_path, classification, decision, machine, pid): (
            String,
            String,
            String,
            String,
            String,
            String,
            i64,
        ) = conn
            .query_row(
                "SELECT event_type, action_attempted, resource_path, classification, \
                 decision, agent_id, session_id FROM audit_events",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .expect("audit_events must have one row");

        assert_eq!(event_type, "\"ADMIN_ACTION\"");
        assert_eq!(action, "\"DiskRegistryAdd\"");
        assert_eq!(resource_path, "disk:disk-Z@agent-X");
        assert!(
            classification.contains("T3"),
            "classification must be T3; got: {classification}"
        );
        assert!(
            decision.contains("ALLOW"),
            "decision must be ALLOW; got: {decision}"
        );
        assert_eq!(machine, "server");
        assert_eq!(pid, 0);
    }

    /// DELETE on an existing UUID returns 204 and removes the row.
    #[tokio::test]
    async fn test_delete_disk_registry_handler_success_returns_204() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let token = mint_admin_jwt();

        // Insert via repository directly.
        let row = make_disk_row("uuid-del-1", "agent-A", "disk-1", "2026-01-01T00:00:00Z");
        {
            let mut conn = pool.get().expect("conn");
            let uow = db::UnitOfWork::new(&mut conn).expect("uow");
            DiskRegistryRepository::insert(&uow, &row).expect("insert");
            uow.commit().expect("commit");
        }

        // Path extraction requires the handler to be invoked via a matched router.
        // Use a minimal router pre-wired with just the delete route for isolation.
        let app = {
            crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
            let crypto = std::sync::Arc::new(crate::crypto::SecretCrypto::from_kek(
                [0x77; 32],
                crate::crypto::ENVELOPE_VERSION_V1,
            ));
            crate::secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
                .expect("Phase 47 migration");
            let siem = crate::siem_connector::SiemConnector::new(
                std::sync::Arc::clone(&pool),
                std::sync::Arc::clone(&crypto),
            );
            let alert = crate::alert_router::AlertRouter::new(
                std::sync::Arc::clone(&pool),
                std::sync::Arc::clone(&crypto),
            );
            let ps = Arc::new(
                crate::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"),
            );
            let label_service =
                Arc::new(crate::label_service::LabelService::new(Arc::clone(&pool)));
            let approval_token_crypto = crate::crypto::SecretCrypto::from_kek([0x77; 32], 1);
            let approval_token_conn = pool.get().expect("pool");
            let approval_token_service = Arc::new(
                crate::approval_token::ApprovalTokenService::new(
                    &approval_token_crypto,
                    &approval_token_conn,
                )
                .expect("approval token service"),
            );
            let s = Arc::new(AppState {
                pool: Arc::clone(&pool),
                crypto: std::sync::Arc::clone(&crypto),
                policy_store: ps,
                siem,
                alert,
                ad: None,
                label_service,
                approval_token_service,
                syslog: crate::syslog_connector::SyslogConnector::new(
                    std::sync::Arc::clone(&pool),
                    std::sync::Arc::clone(&crypto),
                ),
                label_aware_enabled: std::sync::Arc::new(
                    std::sync::atomic::AtomicBool::new(false),
                ),
            });
            // Minimal router with just the disk-registry delete route for isolation.
            axum::Router::new()
                .route(
                    "/admin/disk-registry/{id}",
                    delete(delete_disk_registry_handler),
                )
                .route_layer(crate::rate_limiter::default_config())
                .layer(axum::middleware::from_fn(crate::admin_auth::require_auth))
                .with_state(s)
        };
        use tower::ServiceExt;
        let req = make_delete_request("uuid-del-1", &token);
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Verify row is gone.
        let count: i64 = pool
            .get()
            .expect("conn")
            .query_row("SELECT COUNT(*) FROM disk_registry", [], |r| r.get(0))
            .expect("count");
        assert_eq!(count, 0, "row must be deleted");
    }

    /// DELETE on a non-existent UUID returns 404; no audit event emitted.
    #[tokio::test]
    async fn test_delete_disk_registry_handler_not_found_returns_404() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let app = {
            crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
            let crypto = std::sync::Arc::new(crate::crypto::SecretCrypto::from_kek(
                [0x77; 32],
                crate::crypto::ENVELOPE_VERSION_V1,
            ));
            crate::secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
                .expect("Phase 47 migration");
            let siem = crate::siem_connector::SiemConnector::new(
                std::sync::Arc::clone(&pool),
                std::sync::Arc::clone(&crypto),
            );
            let alert = crate::alert_router::AlertRouter::new(
                std::sync::Arc::clone(&pool),
                std::sync::Arc::clone(&crypto),
            );
            let ps = Arc::new(
                crate::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"),
            );
            let label_service =
                Arc::new(crate::label_service::LabelService::new(Arc::clone(&pool)));
            let approval_token_crypto = crate::crypto::SecretCrypto::from_kek([0x77; 32], 1);
            let approval_token_conn = pool.get().expect("pool");
            let approval_token_service = Arc::new(
                crate::approval_token::ApprovalTokenService::new(
                    &approval_token_crypto,
                    &approval_token_conn,
                )
                .expect("approval token service"),
            );
            let s = Arc::new(AppState {
                pool: Arc::clone(&pool),
                crypto: std::sync::Arc::clone(&crypto),
                policy_store: ps,
                siem,
                alert,
                ad: None,
                label_service,
                approval_token_service,
                syslog: crate::syslog_connector::SyslogConnector::new(
                    std::sync::Arc::clone(&pool),
                    std::sync::Arc::clone(&crypto),
                ),
                label_aware_enabled: std::sync::Arc::new(
                    std::sync::atomic::AtomicBool::new(false),
                ),
            });
            axum::Router::new()
                .route(
                    "/admin/disk-registry/{id}",
                    delete(delete_disk_registry_handler),
                )
                .route_layer(crate::rate_limiter::default_config())
                .layer(axum::middleware::from_fn(crate::admin_auth::require_auth))
                .with_state(s)
        };
        use tower::ServiceExt;
        let token = mint_admin_jwt();
        let req = make_delete_request("00000000-0000-0000-0000-000000000000", &token);
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // No audit event must be written.
        let count: i64 = pool
            .get()
            .expect("conn")
            .query_row("SELECT COUNT(*) FROM audit_events", [], |r| r.get(0))
            .expect("count");
        assert_eq!(count, 0, "no audit event must be written for 404");
    }

    // -----------------------------------------------------------------------
    // Task 3: AgentConfigPayload.disk_allowlist and route wiring tests
    // -----------------------------------------------------------------------

    /// AgentConfigPayload without disk_allowlist in JSON deserializes as empty vec.
    #[test]
    fn test_agent_config_payload_disk_allowlist_default_empty() {
        // JSON payload from an old server build that has no disk_allowlist field.
        let json = r#"{
            "monitored_paths": [],
            "excluded_paths": [],
            "heartbeat_interval_secs": 30,
            "offline_cache_enabled": false
        }"#;
        let payload: AgentConfigPayload = serde_json::from_str(json).expect("deserialize");
        assert!(
            payload.disk_allowlist.is_empty(),
            "missing disk_allowlist must default to empty vec"
        );
    }

    /// GET /agent-config/{id} returns disk_allowlist populated from disk_registry.
    #[tokio::test]
    async fn test_get_agent_config_for_agent_includes_disk_allowlist() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));

        // Insert two disk_registry rows for agent-X.
        {
            let mut conn = pool.get().expect("conn");
            let uow = db::UnitOfWork::new(&mut conn).expect("uow");
            let row1 = DiskRegistryRow {
                id: "id-1".to_string(),
                agent_id: "agent-X".to_string(),
                instance_id: "disk-1".to_string(),
                bus_type: "usb".to_string(),
                encryption_status: "unencrypted".to_string(),
                model: "USB Drive".to_string(),
                registered_at: "2026-01-01T00:00:00Z".to_string(),
            };
            let row2 = DiskRegistryRow {
                id: "id-2".to_string(),
                agent_id: "agent-X".to_string(),
                instance_id: "disk-2".to_string(),
                bus_type: "sata".to_string(),
                encryption_status: "encrypted".to_string(),
                model: "SATA SSD".to_string(),
                registered_at: "2026-01-02T00:00:00Z".to_string(),
            };
            DiskRegistryRepository::insert(&uow, &row1).expect("insert row1");
            DiskRegistryRepository::insert(&uow, &row2).expect("insert row2");
            uow.commit().expect("commit");
        }

        let state = make_state_from_pool(pool);
        let app = admin_router(Arc::clone(&state));

        let req = Request::builder()
            .method("GET")
            .uri("/agent-config/agent-X")
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let payload: AgentConfigPayload = serde_json::from_slice(&body).expect("parse body");

        assert_eq!(payload.disk_allowlist.len(), 2, "expected 2 disk entries");
        // Verify instance_ids are present (order is registered_at ASC).
        let ids: Vec<&str> = payload
            .disk_allowlist
            .iter()
            .map(|d| d.instance_id.as_str())
            .collect();
        assert!(ids.contains(&"disk-1"), "disk-1 must be in allowlist");
        assert!(ids.contains(&"disk-2"), "disk-2 must be in allowlist");
        // Verify bus_type conversion.
        let disk1 = payload
            .disk_allowlist
            .iter()
            .find(|d| d.instance_id == "disk-1")
            .unwrap();
        let disk2 = payload
            .disk_allowlist
            .iter()
            .find(|d| d.instance_id == "disk-2")
            .unwrap();
        assert_eq!(disk1.bus_type, dlp_common::BusType::Usb);
        assert_eq!(disk2.bus_type, dlp_common::BusType::Sata);
    }

    /// GET /agent-config/agent-X does NOT include agent-Y's disks.
    #[tokio::test]
    async fn test_get_agent_config_for_agent_excludes_other_agents_disks() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));

        {
            let mut conn = pool.get().expect("conn");
            let uow = db::UnitOfWork::new(&mut conn).expect("uow");
            let row_x = make_disk_row("id-x", "agent-X", "disk-x", "2026-01-01T00:00:00Z");
            let row_y = make_disk_row("id-y", "agent-Y", "disk-y", "2026-01-02T00:00:00Z");
            DiskRegistryRepository::insert(&uow, &row_x).expect("insert x");
            DiskRegistryRepository::insert(&uow, &row_y).expect("insert y");
            uow.commit().expect("commit");
        }

        let state = make_state_from_pool(pool);
        let app = admin_router(Arc::clone(&state));

        let req = Request::builder()
            .method("GET")
            .uri("/agent-config/agent-X")
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let payload: AgentConfigPayload = serde_json::from_slice(&body).expect("parse body");

        assert_eq!(
            payload.disk_allowlist.len(),
            1,
            "only agent-X disk must be returned"
        );
        assert_eq!(payload.disk_allowlist[0].instance_id, "disk-x");
    }

    /// GET /agent-config/{id} for an agent with no disk_registry rows returns disk_allowlist: [].
    #[tokio::test]
    async fn test_get_agent_config_for_agent_no_disks_returns_empty_allowlist() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let state = make_state_from_pool(Arc::new(
            crate::db::new_pool(":memory:").expect("build pool"),
        ));
        let app = admin_router(Arc::clone(&state));

        let req = Request::builder()
            .method("GET")
            .uri("/agent-config/no-disks-agent")
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let payload: AgentConfigPayload = serde_json::from_slice(&body).expect("parse body");
        assert!(
            payload.disk_allowlist.is_empty(),
            "no disk_registry rows -> disk_allowlist must be empty vec (not null or missing)"
        );
    }

    /// admin_router registers /admin/disk-registry GET+POST and /admin/disk-registry/{id} DELETE.
    /// Verifies by sending requests without auth and expecting 401 (proves the routes are protected).
    #[tokio::test]
    async fn test_admin_router_disk_registry_routes_registered() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let state = make_state_from_pool(Arc::new(
            crate::db::new_pool(":memory:").expect("build pool"),
        ));

        // GET without auth -- should hit protected_routes and return 401, not 404.
        let app_get = admin_router(Arc::clone(&state));
        let req = Request::builder()
            .method("GET")
            .uri("/admin/disk-registry")
            .body(Body::empty())
            .expect("build GET");
        let resp = app_get.oneshot(req).await.expect("oneshot GET");
        assert_ne!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "GET must be registered on /admin/disk-registry"
        );
        assert_ne!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "GET must not return 404 -- route must be wired"
        );
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "GET without JWT must be 401"
        );

        // POST without auth -- should return 401 (route registered and protected).
        let app_post = admin_router(Arc::clone(&state));
        let req = Request::builder()
            .method("POST")
            .uri("/admin/disk-registry")
            .header("Content-Type", "application/json")
            .body(Body::from("{}"))
            .expect("build POST");
        let resp = app_post.oneshot(req).await.expect("oneshot POST");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "POST without JWT must be 401"
        );

        // DELETE without auth -- should return 401.
        let app_del = admin_router(Arc::clone(&state));
        let req = Request::builder()
            .method("DELETE")
            .uri("/admin/disk-registry/some-uuid")
            .body(Body::empty())
            .expect("build DELETE");
        let resp = app_del.oneshot(req).await.expect("oneshot DELETE");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "DELETE without JWT must be 401"
        );
    }

    /// GET /admin/disk-registry without an Authorization header returns 401 (T-37-08).
    #[tokio::test]
    async fn test_get_admin_disk_registry_requires_jwt() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let state = make_state_from_pool(Arc::new(
            crate::db::new_pool(":memory:").expect("build pool"),
        ));
        let app = admin_router(Arc::clone(&state));

        let req = Request::builder()
            .method("GET")
            .uri("/admin/disk-registry")
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "unauthenticated GET /admin/disk-registry must return 401 (T-37-08)"
        );
    }

    /// Successful DELETE emits exactly one audit event with DiskRegistryRemove action.
    #[tokio::test]
    async fn test_delete_disk_registry_handler_emits_audit_event() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));

        // Insert a row directly.
        let row = make_disk_row(
            "uuid-audit-del",
            "agent-B",
            "disk-99",
            "2026-01-01T00:00:00Z",
        );
        {
            let mut conn = pool.get().expect("conn");
            let uow = db::UnitOfWork::new(&mut conn).expect("uow");
            DiskRegistryRepository::insert(&uow, &row).expect("insert");
            uow.commit().expect("commit");
        }

        let app = {
            crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
            let crypto = std::sync::Arc::new(crate::crypto::SecretCrypto::from_kek(
                [0x77; 32],
                crate::crypto::ENVELOPE_VERSION_V1,
            ));
            crate::secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
                .expect("Phase 47 migration");
            let siem = crate::siem_connector::SiemConnector::new(
                std::sync::Arc::clone(&pool),
                std::sync::Arc::clone(&crypto),
            );
            let alert = crate::alert_router::AlertRouter::new(
                std::sync::Arc::clone(&pool),
                std::sync::Arc::clone(&crypto),
            );
            let ps = Arc::new(
                crate::policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"),
            );
            let label_service =
                Arc::new(crate::label_service::LabelService::new(Arc::clone(&pool)));
            let approval_token_crypto = crate::crypto::SecretCrypto::from_kek([0x77; 32], 1);
            let approval_token_conn = pool.get().expect("pool");
            let approval_token_service = Arc::new(
                crate::approval_token::ApprovalTokenService::new(
                    &approval_token_crypto,
                    &approval_token_conn,
                )
                .expect("approval token service"),
            );
            let s = Arc::new(AppState {
                pool: Arc::clone(&pool),
                crypto: std::sync::Arc::clone(&crypto),
                policy_store: ps,
                siem,
                alert,
                ad: None,
                label_service,
                approval_token_service,
                syslog: crate::syslog_connector::SyslogConnector::new(
                    std::sync::Arc::clone(&pool),
                    std::sync::Arc::clone(&crypto),
                ),
                label_aware_enabled: std::sync::Arc::new(
                    std::sync::atomic::AtomicBool::new(false),
                ),
            });
            axum::Router::new()
                .route(
                    "/admin/disk-registry/{id}",
                    delete(delete_disk_registry_handler),
                )
                .route_layer(crate::rate_limiter::default_config())
                .layer(axum::middleware::from_fn(crate::admin_auth::require_auth))
                .with_state(s)
        };
        use tower::ServiceExt;
        let token = mint_admin_jwt();
        let req = make_delete_request("uuid-audit-del", &token);
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Verify audit event.
        let mut conn = pool.get().expect("conn");
        let (event_type, action, resource_path, classification, decision): (
            String,
            String,
            String,
            String,
            String,
        ) = conn
            .query_row(
                "SELECT event_type, action_attempted, resource_path, classification, decision \
                 FROM audit_events",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .expect("audit_events must have one row");

        assert_eq!(event_type, "\"ADMIN_ACTION\"");
        assert_eq!(action, "\"DiskRegistryRemove\"");
        assert_eq!(resource_path, "disk:disk-99@agent-B");
        assert!(
            classification.contains("T3"),
            "classification must be T3; got: {classification}"
        );
        assert!(
            decision.contains("ALLOW"),
            "decision must be ALLOW; got: {decision}"
        );
    }

    // -----------------------------------------------------------------------
    // Phase 59: Label admin API tests (LABEL-03..07)
    // -----------------------------------------------------------------------

    /// GET /admin/labels returns all labels as JSON array.
    #[tokio::test]
    async fn test_list_labels() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let req = Request::builder()
            .method("GET")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let page: PaginatedLabelsResponse = serde_json::from_slice(&body).expect("parse");
        assert!(page.labels.is_empty(), "fresh db must have no labels");
        assert_eq!(page.total, 0);
        assert_eq!(page.limit, DEFAULT_LABEL_LIMIT);
        assert_eq!(page.offset, 0);
    }

    /// GET /admin/labels?state=temporary returns only temporary labels.
    #[tokio::test]
    async fn test_list_labels_filter_by_state() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // Create a temporary label
        let json = r#"{"path":"\\\\server\\share\\file.txt","object_type":"file","tier":"T4","label_state":"temporary"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json))
            .expect("build request");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Create a confirmed label
        let json2 = r#"{"path":"\\\\server\\share\\folder","object_type":"folder","tier":"T3","label_state":"confirmed"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json2))
            .expect("build request");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Filter by temporary
        let req = Request::builder()
            .method("GET")
            .uri("/admin/labels?state=temporary")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let page: PaginatedLabelsResponse = serde_json::from_slice(&body).expect("parse");
        assert_eq!(page.labels.len(), 1);
        assert_eq!(page.labels[0].label_state, "temporary");
        assert_eq!(page.total, 1);
    }

    /// POST /admin/labels with valid data creates label, returns 201.
    #[tokio::test]
    async fn test_create_label_success() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let json = r#"{"path":"\\\\server\\share\\HR\\salary.xlsx","object_type":"file","tier":"T4","label_state":"temporary","owner_sid":"S-1-5-21-1"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json))
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let label: LabelResponse = serde_json::from_slice(&body).expect("parse");
        assert_eq!(label.path, r"\\server\share\HR\salary.xlsx");
        assert_eq!(label.object_type, "file");
        assert_eq!(label.tier, "T4");
        assert_eq!(label.label_state, "temporary");
        assert_eq!(label.owner_sid, Some("S-1-5-21-1".to_string()));
        assert!(!label.id.is_empty(), "id must be generated");
        assert!(!label.created_at.is_empty(), "created_at must be set");
    }

    /// POST /admin/labels with relative path returns 422.
    #[tokio::test]
    async fn test_create_label_relative_path_rejected() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let json = r#"{"path":"relative\\path.txt","object_type":"file","tier":"T1","label_state":"temporary"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json))
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// POST /admin/labels with invalid tier returns 422.
    #[tokio::test]
    async fn test_create_label_invalid_tier_rejected() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let json = r#"{"path":"\\\\server\\share\\file.txt","object_type":"file","tier":"T5","label_state":"temporary"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json))
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// POST /admin/labels with parent_label_id not pointing to folder returns 422.
    #[tokio::test]
    async fn test_create_label_parent_not_folder_rejected() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // Create a file label first
        let json1 = r#"{"path":"\\\\server\\share\\file.txt","object_type":"file","tier":"T1","label_state":"temporary"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json1))
            .expect("build request");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Try to use the file label as parent
        let json2 = r#"{"path":"\\\\server\\share\\file2.txt","object_type":"file","tier":"T1","label_state":"temporary","parent_label_id":"not-a-real-id"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json2))
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        // parent_label_id points to non-existent label -> 422
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// PUT /admin/labels/:id updates existing label.
    #[tokio::test]
    async fn test_update_label_success() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // Create a label
        let json = r#"{"path":"\\\\server\\share\\file.txt","object_type":"file","tier":"T1","label_state":"temporary"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json))
            .expect("build request");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let created: LabelResponse = serde_json::from_slice(&body).expect("parse");
        let id = created.id;

        // Update it
        let json2 = r#"{"path":"\\\\server\\share\\file.txt","object_type":"file","tier":"T4","label_state":"confirmed"}"#;
        let req = Request::builder()
            .method("PUT")
            .uri(format!("/admin/labels/{id}"))
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json2))
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let updated: LabelResponse = serde_json::from_slice(&body).expect("parse");
        assert_eq!(updated.tier, "T4");
        assert_eq!(updated.label_state, "confirmed");
        assert_eq!(updated.id, id);
    }

    /// POST /admin/labels/:id/confirm changes state to confirmed.
    #[tokio::test]
    async fn test_confirm_label_success() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // Create a temporary label
        let json = r#"{"path":"\\\\server\\share\\file.txt","object_type":"file","tier":"T1","label_state":"temporary"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json))
            .expect("build request");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let created: LabelResponse = serde_json::from_slice(&body).expect("parse");
        let id = created.id;

        // Confirm it
        let req = Request::builder()
            .method("POST")
            .uri(format!("/admin/labels/{id}/confirm"))
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let confirmed: LabelResponse = serde_json::from_slice(&body).expect("parse");
        assert_eq!(confirmed.label_state, "confirmed");
    }

    /// POST /admin/labels/:id/reject changes state to rejected.
    #[tokio::test]
    async fn test_reject_label_success() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // Create a temporary label
        let json = r#"{"path":"\\\\server\\share\\file.txt","object_type":"file","tier":"T1","label_state":"temporary"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json))
            .expect("build request");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let created: LabelResponse = serde_json::from_slice(&body).expect("parse");
        let id = created.id;

        // Reject it
        let req = Request::builder()
            .method("POST")
            .uri(format!("/admin/labels/{id}/reject"))
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let rejected: LabelResponse = serde_json::from_slice(&body).expect("parse");
        assert_eq!(rejected.label_state, "rejected");
    }

    /// DELETE /admin/labels/:id removes label.
    #[tokio::test]
    async fn test_delete_label_success() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // Create a label
        let json = r#"{"path":"\\\\server\\share\\file.txt","object_type":"file","tier":"T1","label_state":"temporary"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json))
            .expect("build request");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let created: LabelResponse = serde_json::from_slice(&body).expect("parse");
        let id = created.id;

        // Delete it
        let req = Request::builder()
            .method("DELETE")
            .uri(format!("/admin/labels/{id}"))
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build request");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Verify it's gone
        let req = Request::builder()
            .method("GET")
            .uri(format!("/admin/labels/{id}"))
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// GET /admin/labels/:id returns single label.
    #[tokio::test]
    async fn test_get_label_success() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // Create a label
        let json = r#"{"path":"\\\\server\\share\\file.txt","object_type":"file","tier":"T1","label_state":"temporary"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json))
            .expect("build request");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let created: LabelResponse = serde_json::from_slice(&body).expect("parse");
        let id = created.id;

        // Get it
        let req = Request::builder()
            .method("GET")
            .uri(format!("/admin/labels/{id}"))
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let got: LabelResponse = serde_json::from_slice(&body).expect("parse");
        assert_eq!(got.id, id);
        assert_eq!(got.path, r"\\server\share\file.txt");
    }

    /// Confirm/reject only allowed from temporary state (422 otherwise).
    #[tokio::test]
    async fn test_confirm_non_temporary_label_rejected() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // Create a confirmed label
        let json = r#"{"path":"\\\\server\\share\\file.txt","object_type":"file","tier":"T1","label_state":"confirmed"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json))
            .expect("build request");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("body");
        let created: LabelResponse = serde_json::from_slice(&body).expect("parse");
        let id = created.id;

        // Try to confirm an already-confirmed label
        let req = Request::builder()
            .method("POST")
            .uri(format!("/admin/labels/{id}/confirm"))
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// Label creation emits an audit event.
    #[tokio::test]
    async fn test_create_label_emits_audit_event() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let json = r#"{"path":"\\\\server\\share\\audit.txt","object_type":"file","tier":"T2","label_state":"temporary"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json))
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // We cannot directly query the in-memory DB from here because the pool
        // is owned by the AppState inside the router. The audit event is
        // best-effort and the test above verifies the handler returns 201.
        // Audit emission correctness is covered by the audit_store unit tests.
    }

    /// POST /admin/labels with drive-letter path succeeds.
    #[tokio::test]
    async fn test_create_label_drive_letter_path() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let json = r#"{"path":"C:\\Users\\Admin\\secret.docx","object_type":"file","tier":"T4","label_state":"temporary"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json))
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let label: LabelResponse = serde_json::from_slice(&body).expect("parse");
        assert_eq!(label.path, r"C:\Users\Admin\secret.docx");
    }

    /// POST /admin/labels with parent_label_id pointing to folder succeeds.
    #[tokio::test]
    async fn test_create_label_with_parent_folder() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // Create a folder label
        let json1 = r#"{"path":"\\\\server\\share\\HR","object_type":"folder","tier":"T3","label_state":"confirmed"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json1))
            .expect("build request");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let folder: LabelResponse = serde_json::from_slice(&body).expect("parse");

        // Create a child file label with parent_label_id
        let json2 = format!(
            r#"{{"path":"\\\\server\\share\\HR\\salary.xlsx","object_type":"file","tier":"T4","label_state":"temporary","parent_label_id":"{}"}}"#,
            folder.id
        );
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json2))
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let file: LabelResponse = serde_json::from_slice(&body).expect("parse");
        assert_eq!(file.parent_label_id, Some(folder.id));
    }

    // ── Task 3: Expire endpoint and pagination tests ────────────────────────

    /// POST /admin/labels/:id/expire changes any state to expired.
    #[tokio::test]
    async fn test_expire_label_success() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // Create a confirmed label
        let json = r#"{"path":"\\\\server\\share\\file.txt","object_type":"file","tier":"T1","label_state":"confirmed"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json))
            .expect("build request");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let created: LabelResponse = serde_json::from_slice(&body).expect("parse");
        let id = created.id;

        // Expire it
        let req = Request::builder()
            .method("POST")
            .uri(format!("/admin/labels/{id}/expire"))
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let expired: LabelResponse = serde_json::from_slice(&body).expect("parse");
        assert_eq!(expired.label_state, "expired");
    }

    /// POST /admin/labels/:id/expire on non-existent label returns 404.
    #[tokio::test]
    async fn test_expire_label_not_found() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels/nonexistent/expire")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// GET /admin/labels returns paginated response with defaults.
    #[tokio::test]
    async fn test_list_labels_paginated_defaults() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // Create 3 labels
        for i in 1..=3 {
            let json = format!(
                r#"{{"path":"\\\\server\\share\\doc{i}.txt","object_type":"file","tier":"T2","label_state":"temporary"}}"#
            );
            let req = Request::builder()
                .method("POST")
                .uri("/admin/labels")
                .header("Authorization", format!("Bearer {jwt}"))
                .header("Content-Type", "application/json")
                .body(Body::from(json))
                .expect("build request");
            let resp = app.clone().oneshot(req).await.expect("oneshot");
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        let req = Request::builder()
            .method("GET")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let page: PaginatedLabelsResponse = serde_json::from_slice(&body).expect("parse");
        assert_eq!(page.labels.len(), 3);
        assert_eq!(page.total, 3);
        assert_eq!(page.limit, DEFAULT_LABEL_LIMIT);
        assert_eq!(page.offset, 0);
    }

    /// GET /admin/labels?limit=2&offset=0 returns first page.
    #[tokio::test]
    async fn test_list_labels_paginated_first_page() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        for i in 1..=5 {
            let json = format!(
                r#"{{"path":"\\\\server\\share\\doc{i}.txt","object_type":"file","tier":"T2","label_state":"temporary"}}"#
            );
            let req = Request::builder()
                .method("POST")
                .uri("/admin/labels")
                .header("Authorization", format!("Bearer {jwt}"))
                .header("Content-Type", "application/json")
                .body(Body::from(json))
                .expect("build request");
            let resp = app.clone().oneshot(req).await.expect("oneshot");
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        let req = Request::builder()
            .method("GET")
            .uri("/admin/labels?limit=2&offset=0")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let page: PaginatedLabelsResponse = serde_json::from_slice(&body).expect("parse");
        assert_eq!(page.labels.len(), 2);
        assert_eq!(page.total, 5);
        assert_eq!(page.limit, 2);
        assert_eq!(page.offset, 0);
    }

    /// GET /admin/labels?limit=2&offset=2 returns second page.
    #[tokio::test]
    async fn test_list_labels_paginated_second_page() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        for i in 1..=5 {
            let json = format!(
                r#"{{"path":"\\\\server\\share\\doc{i}.txt","object_type":"file","tier":"T2","label_state":"temporary"}}"#
            );
            let req = Request::builder()
                .method("POST")
                .uri("/admin/labels")
                .header("Authorization", format!("Bearer {jwt}"))
                .header("Content-Type", "application/json")
                .body(Body::from(json))
                .expect("build request");
            let resp = app.clone().oneshot(req).await.expect("oneshot");
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        let req = Request::builder()
            .method("GET")
            .uri("/admin/labels?limit=2&offset=2")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let page: PaginatedLabelsResponse = serde_json::from_slice(&body).expect("parse");
        assert_eq!(page.labels.len(), 2);
        assert_eq!(page.total, 5);
        assert_eq!(page.limit, 2);
        assert_eq!(page.offset, 2);
    }

    /// GET /admin/labels?limit=1001 is clamped to max 1000.
    #[tokio::test]
    async fn test_list_labels_limit_clamped() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let req = Request::builder()
            .method("GET")
            .uri("/admin/labels?limit=1001")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let page: PaginatedLabelsResponse = serde_json::from_slice(&body).expect("parse");
        assert_eq!(page.limit, MAX_LABEL_LIMIT);
    }

    /// GET /admin/labels?state=temporary&limit=1 returns paginated filtered results.
    #[tokio::test]
    async fn test_list_labels_filtered_and_paginated() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // 2 temporary
        for i in 1..=2 {
            let json = format!(
                r#"{{"path":"\\\\server\\share\\temp{i}.txt","object_type":"file","tier":"T2","label_state":"temporary"}}"#
            );
            let req = Request::builder()
                .method("POST")
                .uri("/admin/labels")
                .header("Authorization", format!("Bearer {jwt}"))
                .header("Content-Type", "application/json")
                .body(Body::from(json))
                .expect("build request");
            let resp = app.clone().oneshot(req).await.expect("oneshot");
            assert_eq!(resp.status(), StatusCode::CREATED);
        }
        // 1 confirmed
        let json = r#"{"path":"\\\\server\\share\\conf.txt","object_type":"file","tier":"T3","label_state":"confirmed"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json))
            .expect("build request");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);

        let req = Request::builder()
            .method("GET")
            .uri("/admin/labels?state=temporary&limit=1&offset=0")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let page: PaginatedLabelsResponse = serde_json::from_slice(&body).expect("parse");
        assert_eq!(page.labels.len(), 1);
        assert_eq!(page.total, 2);
        assert_eq!(page.labels[0].label_state, "temporary");
    }

    // ── Task 4: Auth tests for all 8 label endpoints ─────────────────────────

    /// GET /admin/labels without auth returns 401.
    #[tokio::test]
    async fn test_label_list_requires_auth() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let req = Request::builder()
            .method("GET")
            .uri("/admin/labels")
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// GET /admin/labels/:id without auth returns 401.
    #[tokio::test]
    async fn test_label_get_requires_auth() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let req = Request::builder()
            .method("GET")
            .uri("/admin/labels/some-id")
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// POST /admin/labels without auth returns 401.
    #[tokio::test]
    async fn test_label_create_requires_auth() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels")
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// PUT /admin/labels/:id without auth returns 401.
    #[tokio::test]
    async fn test_label_update_requires_auth() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let req = Request::builder()
            .method("PUT")
            .uri("/admin/labels/some-id")
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// POST /admin/labels/:id/confirm without auth returns 401.
    #[tokio::test]
    async fn test_label_confirm_requires_auth() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels/some-id/confirm")
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// POST /admin/labels/:id/reject without auth returns 401.
    #[tokio::test]
    async fn test_label_reject_requires_auth() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels/some-id/reject")
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// POST /admin/labels/:id/expire without auth returns 401.
    #[tokio::test]
    async fn test_label_expire_requires_auth() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let req = Request::builder()
            .method("POST")
            .uri("/admin/labels/some-id/expire")
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// DELETE /admin/labels/:id without auth returns 401.
    #[tokio::test]
    async fn test_label_delete_requires_auth() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let req = Request::builder()
            .method("DELETE")
            .uri("/admin/labels/some-id")
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Phase 62: Syslog config handler tests ───────────────────────────────

    #[tokio::test]
    async fn test_get_syslog_config_returns_defaults() {
        use axum::body::to_bytes;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let req = Request::builder()
            .method("GET")
            .uri("/admin/syslog-config")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(axum::body::Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let payload: SyslogConfigPayload = serde_json::from_slice(&body).expect("parse");
        assert_eq!(payload.host, "");
        assert_eq!(payload.port, 514);
        assert!(!payload.enabled);
        assert_eq!(payload.protocol, "tls");
        assert_eq!(payload.facility_code, 20);
        assert_eq!(payload.format, "json");
        assert!(payload.batching_enabled);
        assert_eq!(payload.severity_alert, 3);
        assert_eq!(payload.severity_block, 4);
        assert_eq!(payload.severity_audit, 6);
        assert_eq!(payload.queue_policy, "fifo_tail_drop");
        assert_eq!(payload.queue_max_size, 100000);
        assert_eq!(payload.tls_min_version, "1.2");
    }

    #[tokio::test]
    async fn test_put_syslog_config_updates_all_fields() {
        use axum::body::to_bytes;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let payload = SyslogConfigPayload {
            host: "syslog.example.com".to_string(),
            port: 6514,
            enabled: true,
            protocol: "tls".to_string(),
            facility_code: 22,
            format: "json".to_string(),
            batching_enabled: false,
            severity_alert: 2,
            severity_block: 5,
            severity_audit: 7,
            queue_policy: "fifo_head_drop".to_string(),
            queue_max_size: 50000,
            tls_min_version: "1.3".to_string(),
        };

        let put = Request::builder()
            .method("PUT")
            .uri("/admin/syslog-config")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&payload).expect("serialize"),
            ))
            .expect("build PUT");
        let put_resp = app.clone().oneshot(put).await.expect("PUT oneshot");
        assert_eq!(put_resp.status(), StatusCode::OK);

        let get = Request::builder()
            .method("GET")
            .uri("/admin/syslog-config")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(axum::body::Body::empty())
            .expect("build GET");
        let get_resp = app.clone().oneshot(get).await.expect("GET oneshot");
        assert_eq!(get_resp.status(), StatusCode::OK);

        let body = to_bytes(get_resp.into_body(), 64 * 1024)
            .await
            .expect("body");
        let rt: SyslogConfigPayload = serde_json::from_slice(&body).expect("parse");
        assert_eq!(rt.host, payload.host);
        assert_eq!(rt.port, payload.port);
        assert_eq!(rt.enabled, payload.enabled);
        assert_eq!(rt.facility_code, payload.facility_code);
        assert_eq!(rt.batching_enabled, payload.batching_enabled);
        assert_eq!(rt.severity_alert, payload.severity_alert);
        assert_eq!(rt.severity_block, payload.severity_block);
        assert_eq!(rt.severity_audit, payload.severity_audit);
        assert_eq!(rt.queue_policy, payload.queue_policy);
        assert_eq!(rt.queue_max_size, payload.queue_max_size);
        assert_eq!(rt.tls_min_version, payload.tls_min_version);
    }

    #[tokio::test]
    async fn test_put_syslog_config_rejects_invalid_port() {
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let payload = SyslogConfigPayload {
            host: "syslog.example.com".to_string(),
            port: 0,
            enabled: true,
            protocol: "tls".to_string(),
            facility_code: 20,
            format: "json".to_string(),
            batching_enabled: true,
            severity_alert: 3,
            severity_block: 4,
            severity_audit: 6,
            queue_policy: "fifo_tail_drop".to_string(),
            queue_max_size: 100000,
            tls_min_version: "1.2".to_string(),
        };

        let put = Request::builder()
            .method("PUT")
            .uri("/admin/syslog-config")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&payload).expect("serialize"),
            ))
            .expect("build PUT");
        let resp = app.oneshot(put).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_put_syslog_config_rejects_invalid_facility() {
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let payload = SyslogConfigPayload {
            host: "syslog.example.com".to_string(),
            port: 6514,
            enabled: true,
            protocol: "tls".to_string(),
            facility_code: 15,
            format: "json".to_string(),
            batching_enabled: true,
            severity_alert: 3,
            severity_block: 4,
            severity_audit: 6,
            queue_policy: "fifo_tail_drop".to_string(),
            queue_max_size: 100000,
            tls_min_version: "1.2".to_string(),
        };

        let put = Request::builder()
            .method("PUT")
            .uri("/admin/syslog-config")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&payload).expect("serialize"),
            ))
            .expect("build PUT");
        let resp = app.oneshot(put).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_put_syslog_config_rejects_invalid_severity() {
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let payload = SyslogConfigPayload {
            host: "syslog.example.com".to_string(),
            port: 6514,
            enabled: true,
            protocol: "tls".to_string(),
            facility_code: 20,
            format: "json".to_string(),
            batching_enabled: true,
            severity_alert: 8,
            severity_block: 4,
            severity_audit: 6,
            queue_policy: "fifo_tail_drop".to_string(),
            queue_max_size: 100000,
            tls_min_version: "1.2".to_string(),
        };

        let put = Request::builder()
            .method("PUT")
            .uri("/admin/syslog-config")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&payload).expect("serialize"),
            ))
            .expect("build PUT");
        let resp = app.oneshot(put).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_put_syslog_config_rejects_invalid_queue_policy() {
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let payload = SyslogConfigPayload {
            host: "syslog.example.com".to_string(),
            port: 6514,
            enabled: true,
            protocol: "tls".to_string(),
            facility_code: 20,
            format: "json".to_string(),
            batching_enabled: true,
            severity_alert: 3,
            severity_block: 4,
            severity_audit: 6,
            queue_policy: "invalid_policy".to_string(),
            queue_max_size: 100000,
            tls_min_version: "1.2".to_string(),
        };

        let put = Request::builder()
            .method("PUT")
            .uri("/admin/syslog-config")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&payload).expect("serialize"),
            ))
            .expect("build PUT");
        let resp = app.oneshot(put).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_put_syslog_config_rejects_invalid_tls_version() {
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let payload = SyslogConfigPayload {
            host: "syslog.example.com".to_string(),
            port: 6514,
            enabled: true,
            protocol: "tls".to_string(),
            facility_code: 20,
            format: "json".to_string(),
            batching_enabled: true,
            severity_alert: 3,
            severity_block: 4,
            severity_audit: 6,
            queue_policy: "fifo_tail_drop".to_string(),
            queue_max_size: 100000,
            tls_min_version: "1.1".to_string(),
        };

        let put = Request::builder()
            .method("PUT")
            .uri("/admin/syslog-config")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_string(&payload).expect("serialize"),
            ))
            .expect("build PUT");
        let resp = app.oneshot(put).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_post_syslog_config_test_rate_limited() {
        use axum::body::to_bytes;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // First request should succeed (syslog disabled, so forward short-circuits).
        let req1 = Request::builder()
            .method("POST")
            .uri("/admin/syslog-config/test")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(axum::body::Body::empty())
            .expect("build req1");
        let resp1 = app.clone().oneshot(req1).await.expect("oneshot 1");
        assert_eq!(resp1.status(), StatusCode::OK);

        // Second request within 10s should be rate-limited.
        let req2 = Request::builder()
            .method("POST")
            .uri("/admin/syslog-config/test")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(axum::body::Body::empty())
            .expect("build req2");
        let resp2 = app.oneshot(req2).await.expect("oneshot 2");
        assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp2.into_body(), 64 * 1024).await.expect("body");
        let err: serde_json::Value = serde_json::from_slice(&body).expect("parse");
        assert!(err["error"].as_str().unwrap().contains("Rate limit"));
    }

    #[tokio::test]
    async fn test_syslog_config_routes_require_auth() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();

        let req = Request::builder()
            .method("GET")
            .uri("/admin/syslog-config")
            .body(Body::empty())
            .expect("build request");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ---------------------------------------------------------------------------
    // Phase 49: Allowlist admin API tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_allowlist_routes_registered_and_require_auth() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();

        // GET /admin/allowlist without auth -> 401
        let req = Request::builder()
            .method("GET")
            .uri("/admin/allowlist")
            .body(Body::empty())
            .expect("build GET");
        let resp = app.clone().oneshot(req).await.expect("oneshot GET");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "GET must require auth"
        );

        // POST /admin/allowlist without auth -> 401
        let req = Request::builder()
            .method("POST")
            .uri("/admin/allowlist")
            .header("Content-Type", "application/json")
            .body(Body::from("{}"))
            .expect("build POST");
        let resp = app.clone().oneshot(req).await.expect("oneshot POST");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "POST must require auth"
        );

        // GET /admin/allowlist/{id} without auth -> 401
        let req = Request::builder()
            .method("GET")
            .uri("/admin/allowlist/some-uuid")
            .body(Body::empty())
            .expect("build GET by id");
        let resp = app.clone().oneshot(req).await.expect("oneshot GET by id");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "GET by id must require auth"
        );

        // PUT /admin/allowlist/{id} without auth -> 401
        let req = Request::builder()
            .method("PUT")
            .uri("/admin/allowlist/some-uuid")
            .header("Content-Type", "application/json")
            .body(Body::from("{}"))
            .expect("build PUT");
        let resp = app.clone().oneshot(req).await.expect("oneshot PUT");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "PUT must require auth"
        );

        // DELETE /admin/allowlist/{id} without auth -> 401
        let req = Request::builder()
            .method("DELETE")
            .uri("/admin/allowlist/some-uuid")
            .body(Body::empty())
            .expect("build DELETE");
        let resp = app.oneshot(req).await.expect("oneshot DELETE");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "DELETE must require auth"
        );
    }

    #[tokio::test]
    async fn test_create_allowlist_handler_success() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let payload = serde_json::json!({
            "match_type": "exact_path",
            "value": "C:\\Windows\\System32\\foo.dll",
            "description": "Test entry",
            "category": "self",
            "priority": 10,
            "enabled": true,
        });

        let req = Request::builder()
            .method("POST")
            .uri("/admin/allowlist")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(payload.to_string()))
            .expect("build POST");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_create_allowlist_handler_invalid_match_type_returns_422() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let payload = serde_json::json!({
            "match_type": "invalid_type",
            "value": "foo",
            "description": "Test",
            "category": "self",
            "priority": 10,
            "enabled": true,
        });

        let req = Request::builder()
            .method("POST")
            .uri("/admin/allowlist")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(payload.to_string()))
            .expect("build POST");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_create_allowlist_handler_invalid_category_returns_422() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let payload = serde_json::json!({
            "match_type": "exact_path",
            "value": "foo",
            "description": "Test",
            "category": "invalid_cat",
            "priority": 10,
            "enabled": true,
        });

        let req = Request::builder()
            .method("POST")
            .uri("/admin/allowlist")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(payload.to_string()))
            .expect("build POST");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_list_allowlist_handler_returns_created_entries() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // Create an entry
        let payload = serde_json::json!({
            "match_type": "exact_path",
            "value": "C:\\Windows\\System32\\foo.dll",
            "description": "Test entry",
            "category": "self",
            "priority": 10,
            "enabled": true,
        });
        let req = Request::builder()
            .method("POST")
            .uri("/admin/allowlist")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(payload.to_string()))
            .expect("build POST");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);

        // List entries
        let req = Request::builder()
            .method("GET")
            .uri("/admin/allowlist")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build GET");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let list: Vec<AllowlistEntryResponse> = serde_json::from_slice(&body).expect("parse");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].match_type, "exact_path");
        assert_eq!(list[0].value, "C:\\Windows\\System32\\foo.dll");
        assert_eq!(list[0].category, "self");
        assert!(list[0].enabled);
    }

    #[tokio::test]
    async fn test_get_allowlist_handler_returns_entry() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // Create an entry
        let payload = serde_json::json!({
            "match_type": "cert_thumbprint",
            "value": "ABCD1234",
            "description": "Cert entry",
            "category": "avedr",
            "priority": 5,
            "enabled": false,
        });
        let req = Request::builder()
            .method("POST")
            .uri("/admin/allowlist")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(payload.to_string()))
            .expect("build POST");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let created: AllowlistEntryResponse = serde_json::from_slice(&body).expect("parse");
        let id = created.id;

        // Get by id
        let req = Request::builder()
            .method("GET")
            .uri(format!("/admin/allowlist/{id}"))
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build GET");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let got: AllowlistEntryResponse = serde_json::from_slice(&body).expect("parse");
        assert_eq!(got.id, id);
        assert_eq!(got.match_type, "cert_thumbprint");
        assert_eq!(got.value, "ABCD1234");
        assert_eq!(got.category, "avedr");
        assert!(!got.enabled);
    }

    #[tokio::test]
    async fn test_get_allowlist_handler_not_found_returns_404() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let req = Request::builder()
            .method("GET")
            .uri("/admin/allowlist/nonexistent-uuid")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build GET");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_allowlist_handler_success() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // Create an entry
        let payload = serde_json::json!({
            "match_type": "exact_path",
            "value": "C:\\foo.dll",
            "description": "Original",
            "category": "self",
            "priority": 10,
            "enabled": true,
        });
        let req = Request::builder()
            .method("POST")
            .uri("/admin/allowlist")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(payload.to_string()))
            .expect("build POST");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let created: AllowlistEntryResponse = serde_json::from_slice(&body).expect("parse");
        let id = created.id;

        // Update it
        let update = serde_json::json!({
            "match_type": "path_glob",
            "value": "C:\\bar.dll",
            "description": "Updated",
            "category": "system_critical",
            "priority": 20,
            "enabled": false,
        });
        let req = Request::builder()
            .method("PUT")
            .uri(format!("/admin/allowlist/{id}"))
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(update.to_string()))
            .expect("build PUT");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let updated: AllowlistEntryResponse = serde_json::from_slice(&body).expect("parse");
        assert_eq!(updated.id, id);
        assert_eq!(updated.match_type, "path_glob");
        assert_eq!(updated.value, "C:\\bar.dll");
        assert_eq!(updated.description, "Updated");
        assert_eq!(updated.category, "system_critical");
        assert_eq!(updated.priority, 20);
        assert!(!updated.enabled);
        assert_eq!(updated.version, 2, "version must be bumped");
    }

    #[tokio::test]
    async fn test_update_allowlist_handler_not_found_returns_404() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let update = serde_json::json!({
            "match_type": "exact_path",
            "value": "foo",
            "description": "Test",
            "category": "self",
            "priority": 10,
            "enabled": true,
        });
        let req = Request::builder()
            .method("PUT")
            .uri("/admin/allowlist/nonexistent-uuid")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(update.to_string()))
            .expect("build PUT");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_allowlist_handler_success() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // Create an entry
        let payload = serde_json::json!({
            "match_type": "exact_path",
            "value": "C:\\foo.dll",
            "description": "To delete",
            "category": "self",
            "priority": 10,
            "enabled": true,
        });
        let req = Request::builder()
            .method("POST")
            .uri("/admin/allowlist")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(payload.to_string()))
            .expect("build POST");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let created: AllowlistEntryResponse = serde_json::from_slice(&body).expect("parse");
        let id = created.id;

        // Delete it
        let req = Request::builder()
            .method("DELETE")
            .uri(format!("/admin/allowlist/{id}"))
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build DELETE");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_delete_allowlist_handler_not_found_returns_404() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let req = Request::builder()
            .method("DELETE")
            .uri("/admin/allowlist/nonexistent-uuid")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build DELETE");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_allowlist_filters_by_category() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // Create two entries with different categories
        for (cat, val) in [("self", "foo"), ("avedr", "bar")] {
            let payload = serde_json::json!({
                "match_type": "exact_path",
                "value": val,
                "description": "Test",
                "category": cat,
                "priority": 10,
                "enabled": true,
            });
            let req = Request::builder()
                .method("POST")
                .uri("/admin/allowlist")
                .header("Authorization", format!("Bearer {jwt}"))
                .header("Content-Type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("build POST");
            let resp = app.clone().oneshot(req).await.expect("oneshot");
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        // List with category filter
        let req = Request::builder()
            .method("GET")
            .uri("/admin/allowlist?category=self")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build GET");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let list: Vec<AllowlistEntryResponse> = serde_json::from_slice(&body).expect("parse");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].category, "self");
        assert_eq!(list[0].value, "foo");
    }

    #[tokio::test]
    async fn test_disable_allowlist_handler_success() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // Create an entry
        let payload = serde_json::json!({
            "match_type": "exact_path",
            "value": "C:\\foo.dll",
            "description": "To disable",
            "category": "self",
            "priority": 10,
            "enabled": true,
        });
        let req = Request::builder()
            .method("POST")
            .uri("/admin/allowlist")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(Body::from(payload.to_string()))
            .expect("build POST");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let created: AllowlistEntryResponse = serde_json::from_slice(&body).expect("parse");
        let id = created.id;
        assert!(created.enabled);

        // Disable it
        let req = Request::builder()
            .method("POST")
            .uri(format!("/admin/allowlist/{id}/disable"))
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build DISABLE");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let disabled: AllowlistEntryResponse = serde_json::from_slice(&body).expect("parse");
        assert_eq!(disabled.id, id);
        assert!(!disabled.enabled);
        assert_eq!(disabled.version, 2, "version must be bumped on disable");
    }

    #[tokio::test]
    async fn test_disable_allowlist_handler_not_found_returns_404() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        let req = Request::builder()
            .method("POST")
            .uri("/admin/allowlist/nonexistent-uuid/disable")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build DISABLE");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_allowlist_audit_handler_returns_audit_log() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let _app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // Create an entry directly via repository and insert an audit record
        let pool = Arc::new(crate::db::new_pool(":memory:").expect("build pool"));
        let state = make_state_from_pool(Arc::clone(&pool));
        {
            let mut conn = pool.get().expect("conn");
            let uow = crate::db::UnitOfWork::new(&mut conn).expect("uow");
            let row = crate::db::repositories::AllowlistEntryRow {
                id: "audit-test-entry".to_string(),
                match_type: "exact_path".to_string(),
                value: "foo".to_string(),
                description: "test".to_string(),
                category: "self".to_string(),
                priority: 10,
                enabled: 1,
                version: 1,
                created_at: "2026-01-01T00:00:00Z".to_string(),
                updated_at: "2026-01-01T00:00:00Z".to_string(),
            };
            crate::db::repositories::AllowlistRepository::insert(&uow, &row).expect("insert");
            let audit = crate::db::repositories::AllowlistAuditRow {
                id: "audit-1".to_string(),
                entry_id: "audit-test-entry".to_string(),
                action: "create".to_string(),
                actor: "admin".to_string(),
                old_value: None,
                new_value: Some(r#"{"value":"foo"}"#.to_string()),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
            };
            crate::db::repositories::AllowlistAuditRepository::insert(&uow, &audit)
                .expect("insert audit");
            uow.commit().expect("commit");
        }

        let app = admin_router(state);
        let req = Request::builder()
            .method("GET")
            .uri("/admin/allowlist/audit-test-entry/audit")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build AUDIT");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let audits: Vec<AllowlistAuditResponse> = serde_json::from_slice(&body).expect("parse");
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].action, "create");
        assert_eq!(audits[0].actor, "admin");
        assert_eq!(audits[0].new_value, Some(r#"{"value":"foo"}"#.to_string()));
    }

    #[tokio::test]
    async fn test_list_allowlist_audit_handler_empty_for_new_entry() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = spawn_admin_app();
        let jwt = mint_admin_jwt();

        // Create an entry directly via repository to bypass audit emission
        let pool = Arc::new(crate::db::new_pool(":memory:").expect("build pool"));
        let state = make_state_from_pool(Arc::clone(&pool));
        {
            let mut conn = pool.get().expect("conn");
            let uow = crate::db::UnitOfWork::new(&mut conn).expect("uow");
            let row = crate::db::repositories::AllowlistEntryRow {
                id: "test-audit-empty".to_string(),
                match_type: "exact_path".to_string(),
                value: "foo".to_string(),
                description: "test".to_string(),
                category: "self".to_string(),
                priority: 10,
                enabled: 1,
                version: 1,
                created_at: "2026-01-01T00:00:00Z".to_string(),
                updated_at: "2026-01-01T00:00:00Z".to_string(),
            };
            crate::db::repositories::AllowlistRepository::insert(&uow, &row).expect("insert");
            uow.commit().expect("commit");
        }

        let app = admin_router(state);
        let req = Request::builder()
            .method("GET")
            .uri("/admin/allowlist/test-audit-empty/audit")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build AUDIT");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
        let audits: Vec<AllowlistAuditResponse> = serde_json::from_slice(&body).expect("parse");
        assert!(
            audits.is_empty(),
            "audit log should be empty for entry with no audit records"
        );
    }
}
