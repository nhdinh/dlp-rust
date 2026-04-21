//! Application state machine for the dlp-admin-cli TUI.
//!
//! The [`App`] struct owns all runtime state.  The [`Screen`] enum is
//! the single source of truth for what is rendered and how key events
//! are dispatched.

use crate::client::EngineClient;

// ---------------------------------------------------------------------------
// Status bar
// ---------------------------------------------------------------------------

/// Visual style of the status-bar message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum StatusKind {
    Info,
    Success,
    Error,
}

// ---------------------------------------------------------------------------
// Purpose enums (tell the app what to do when input is confirmed)
// ---------------------------------------------------------------------------

/// What happens when the user confirms a text input.
#[derive(Debug, Clone)]
pub enum InputPurpose {
    GetPolicyById,
    /// Legacy file-path import path; superseded by the structured PolicyCreate
    /// form in Phase 14. Retained for Phase 17 (import/export).
    #[allow(dead_code)]
    CreatePolicyFromFile,
    UpdatePolicyId,
    UpdatePolicyFile {
        id: String,
    },
    DeletePolicyId,
}

/// What happens when the user confirms a yes/no dialog.
#[derive(Debug, Clone)]
pub enum ConfirmPurpose {
    DeletePolicy { id: String },
}

/// What happens when the user confirms a password input.
#[derive(Debug, Clone)]
pub enum PasswordPurpose {
    SetAgentPasswordNew,
    SetAgentPasswordConfirm { first: String },
    VerifyAgentPassword,
    ChangeAdminPasswordCurrent,
    ChangeAdminPasswordNew { current: String },
    ChangeAdminPasswordConfirm { current: String, new_pw: String },
}

// ---------------------------------------------------------------------------
// Conditions builder supporting types
// ---------------------------------------------------------------------------

/// The five ABAC condition attributes available in the conditions builder.
///
/// Used across Step 1 display, Step 2 operator lookup, Step 3 value-picker
/// branching, and `PolicyCondition` construction. A dedicated enum avoids
/// repeated string comparisons and enables exhaustive matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionAttribute {
    /// Data classification tier (T1-T4).
    Classification,
    /// Active Directory group membership (by SID).
    MemberOf,
    /// Device trust level (Managed, Unmanaged, Compliant, Unknown).
    DeviceTrust,
    /// Network location (Corporate, CorporateVpn, Guest, Unknown).
    NetworkLocation,
    /// Access context (Local or SMB).
    AccessContext,
}

/// All condition attributes in display order (Step 1 list).
pub const ATTRIBUTES: [ConditionAttribute; 5] = [
    ConditionAttribute::Classification,
    ConditionAttribute::MemberOf,
    ConditionAttribute::DeviceTrust,
    ConditionAttribute::NetworkLocation,
    ConditionAttribute::AccessContext,
];

impl ConditionAttribute {
    /// Human-readable label for display in the step picker.
    ///
    /// Called by the render function in Plan 02 (`draw_conditions_builder`).
    #[allow(dead_code)] // Used by Plan 02 render.rs draw_conditions_builder.
    pub fn label(self) -> &'static str {
        match self {
            Self::Classification => "Classification",
            Self::MemberOf => "MemberOf",
            Self::DeviceTrust => "DeviceTrust",
            Self::NetworkLocation => "NetworkLocation",
            Self::AccessContext => "AccessContext",
        }
    }
}

/// Identifies which parent screen opened the conditions builder modal.
///
/// Used by the Esc-at-Step-1 handler to reconstruct the parent screen
/// when closing the modal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerScreen {
    /// Opened from the policy creation flow.
    PolicyCreate,
    /// Opened from the policy edit flow (Phase 15).
    PolicyEdit,
}

/// All state for the Policy Create / Edit form.
///
/// Holds form fields and the accumulated conditions list.
/// Using a single struct avoids borrow-split when the conditions
/// builder modal writes into the conditions list.
#[derive(Debug, Clone, Default)]
pub struct PolicyFormState {
    /// Policy name (required).
    pub name: String,
    /// Policy description (optional).
    pub description: String,
    /// Priority as string for text input (parsed to u32 on submit).
    pub priority: String,
    /// Index into the action options list (ALLOW/DENY/AllowWithLog/DenyWithAlert).
    pub action: usize,
    /// Whether the policy is enabled (used by Phase 15 policy edit form).
    pub enabled: bool,
    /// Accumulated conditions from the conditions builder.
    pub conditions: Vec<dlp_common::abac::PolicyCondition>,
    /// Server-side policy ID. Empty for new policies; populated for existing ones
    /// so it can be preserved through the ConditionsBuilder modal round-trip.
    pub id: String,
    /// Boolean composition mode (ALL / ANY / NONE). Defaults to ALL via
    /// `PolicyMode::default()`. In-memory UI state only — never serialized.
    pub mode: dlp_common::abac::PolicyMode,
}

/// Fixed action options for the policy create / edit form.
///
/// Indices match `PolicyFormState.action`. The wire strings are sent verbatim
/// in the POST body; the server's `deserialize_policy_row` accepts them
/// case-insensitively.
pub const ACTION_OPTIONS: [&str; 4] = ["ALLOW", "DENY", "AllowWithLog", "DenyWithAlert"];

// ---------------------------------------------------------------------------
// Policy simulate supporting types
// ---------------------------------------------------------------------------

/// Identifies which menu opened the simulate screen — used to route Esc correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulateCaller {
    MainMenu,
    PolicyMenu,
}

/// The outcome of a simulate submission: no result yet, a successful evaluation,
/// or an error (network or server).
#[derive(Debug, Clone)]
pub enum SimulateOutcome {
    /// No submission made yet, or result was cleared.
    None,
    /// Server returned a decision successfully.
    Success(dlp_common::abac::EvaluateResponse),
    /// Network or server error; message is already prefixed with
    /// "Network error: " or "Server error: ".
    Error(String),
}

/// All form field values for the Policy Simulate screen.
///
/// `groups_raw` stores the comma-separated text buffer; it is split into
/// `Vec<String>` on submit. Other fields store select indices or string values.
#[derive(Debug, Clone, Default)]
pub struct SimulateFormState {
    /// Raw comma-separated SID input (not parsed until submit).
    pub groups_raw: String,
    /// Subject fields.
    pub user_sid: String,
    pub user_name: String,
    /// Select index into SIMULATE_DEVICE_TRUST_OPTIONS (default 1 = Unmanaged).
    pub device_trust: usize,
    /// Select index into SIMULATE_NETWORK_LOCATION_OPTIONS (default 3 = Unknown).
    pub network_location: usize,
    /// Resource fields.
    pub path: String,
    /// Select index into SIMULATE_CLASSIFICATION_OPTIONS (default 0 = T1).
    pub classification: usize,
    /// Environment / action fields.
    /// Select index into SIMULATE_ACTION_OPTIONS (default 0 = READ).
    pub action: usize,
    /// Select index into SIMULATE_ACCESS_CONTEXT_OPTIONS (default 0 = Local).
    pub access_context: usize,
}

/// Fixed select options for the simulate form.
pub const SIMULATE_DEVICE_TRUST_OPTIONS: [&str; 4] =
    ["Managed", "Unmanaged", "Compliant", "Unknown"];
pub const SIMULATE_NETWORK_LOCATION_OPTIONS: [&str; 4] =
    ["Corporate", "CorporateVpn", "Guest", "Unknown"];
pub const SIMULATE_CLASSIFICATION_OPTIONS: [&str; 4] = ["T1", "T2", "T3", "T4"];
pub const SIMULATE_ACTION_OPTIONS: [&str; 6] = ["READ", "WRITE", "COPY", "DELETE", "MOVE", "PASTE"];
pub const SIMULATE_ACCESS_CONTEXT_OPTIONS: [&str; 2] = ["Local", "Smb"];

/// Total editable row count for the simulate form.
pub const SIMULATE_ROW_COUNT: usize = 10;
/// Index of the [Simulate] submit row within editable indices.
#[allow(dead_code)]
pub const SIMULATE_SUBMIT_ROW: usize = 9;

// ---------------------------------------------------------------------------
// Import / Export supporting types
// ---------------------------------------------------------------------------

/// Identifies which menu opened the ImportConfirm screen — used to route Esc correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportCaller {
    PolicyMenu,
}

/// Validation state for the ImportConfirm screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportState {
    /// Awaiting admin confirmation.
    Pending,
    /// Confirmed; import execution is underway (displayed as a spinner/working state).
    InProgress,
    /// Import succeeded; shows the post-import summary.
    Success { created: usize, updated: usize },
    /// Import failed; shows the error message and aborts.
    Error(String),
}

/// Policy record returned by `GET /admin/policies` (server's PolicyResponse shape).
///
/// The authoritative schema for import/export JSON. Imported JSON is deserialized
/// into `Vec<PolicyResponse>` and converted to `PolicyPayload` before POST/PUT.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PolicyResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    /// JSON-encoded conditions array (`Vec<PolicyCondition>` on the wire).
    pub conditions: serde_json::Value,
    pub action: String,
    pub enabled: bool,
    #[serde(default)]
    pub version: i64,
    #[serde(default)]
    pub updated_at: String,
    /// Boolean composition mode for the conditions list. Defaults to ALL
    /// on legacy v0.4.0 exports that omit the field.
    #[serde(default)]
    pub mode: dlp_common::abac::PolicyMode,
}

/// Payload for `POST /admin/policies` and `PUT /admin/policies/{id}`.
///
/// Matches `PolicyPayload` from `dlp-server/src/admin_api.rs`.
/// Dropped from `PolicyResponse`: `version`, `updated_at`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyPayload {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub conditions: serde_json::Value,
    pub action: String,
    pub enabled: bool,
    /// Boolean composition mode for the conditions list.
    #[serde(default)]
    pub mode: dlp_common::abac::PolicyMode,
}

impl From<PolicyResponse> for PolicyPayload {
    fn from(r: PolicyResponse) -> Self {
        Self {
            id: r.id,
            name: r.name,
            description: r.description,
            priority: r.priority,
            conditions: r.conditions,
            action: r.action,
            enabled: r.enabled,
            mode: r.mode,
        }
    }
}

// ---------------------------------------------------------------------------
// Screen enum
// ---------------------------------------------------------------------------

/// Every possible screen in the TUI.  Navigation is a simple state
/// machine: each screen knows which screen to return to on Esc.
#[derive(Debug, Clone)]
pub enum Screen {
    /// Top-level menu.
    MainMenu { selected: usize },
    /// Password Management submenu.
    PasswordMenu { selected: usize },
    /// Policy Management submenu.
    PolicyMenu { selected: usize },
    /// System submenu.
    SystemMenu { selected: usize },
    /// Scrollable policy list.
    PolicyList {
        policies: Vec<serde_json::Value>,
        selected: usize,
    },
    /// Single policy detail (read-only).
    PolicyDetail { policy: serde_json::Value },
    /// Generic text input prompt.
    TextInput {
        prompt: String,
        input: String,
        purpose: InputPurpose,
    },
    /// Password (masked) input prompt.
    PasswordInput {
        prompt: String,
        input: String,
        purpose: PasswordPurpose,
    },
    /// Yes / No confirmation dialog.
    Confirm {
        message: String,
        yes_selected: bool,
        purpose: ConfirmPurpose,
    },
    /// Server status display.
    ServerStatus { health: String, ready: String },
    /// Scrollable agent list.
    AgentList {
        agents: Vec<serde_json::Value>,
        selected: usize,
    },
    /// Informational result screen (press Enter/Esc to dismiss).
    #[allow(dead_code)]
    ResultView { title: String, body: String },
    /// SIEM connector configuration form.
    ///
    /// Navigable list of 9 rows (7 editable fields + Save + Back). When
    /// `editing` is true, keystrokes append to `buffer`; Enter commits
    /// the buffer into the selected field of `config`.
    SiemConfig {
        /// Currently loaded config as a JSON object.
        config: serde_json::Value,
        /// Index of the selected row (0..=8).
        selected: usize,
        /// Whether the selected text field is in edit mode.
        editing: bool,
        /// Buffered input while editing.
        buffer: String,
    },
    /// Alert router configuration form.
    ///
    /// Navigable list of 12 rows (10 editable fields + Save + Back). When
    /// `editing` is true, keystrokes append to `buffer`; Enter commits the
    /// buffer into the selected field of `config`. Row 1 (`smtp_port`) is
    /// the only numeric field; it is parsed as `u16` on commit.
    ///
    /// Editable field order (row index -> JSON key):
    /// 0: smtp_host, 1: smtp_port, 2: smtp_username, 3: smtp_password,
    /// 4: smtp_from, 5: smtp_to, 6: smtp_enabled, 7: webhook_url,
    /// 8: webhook_secret, 9: webhook_enabled. Row 10 = [Save], Row 11 = [Back].
    AlertConfig {
        /// Currently loaded config as a JSON object.
        config: serde_json::Value,
        /// Index of the selected row (0..=11).
        selected: usize,
        /// Whether the selected text field is in edit mode.
        editing: bool,
        /// Buffered input while editing.
        buffer: String,
    },
    /// Conditions Builder modal overlay.
    ///
    /// 3-step sequential picker: Attribute -> Operator -> Value.
    /// Completed conditions accumulate in `pending` and are returned
    /// to the caller via `PolicyFormState`.
    // Constructed by Phase 14 (PolicyCreate) and Phase 15 (PolicyEdit).
    ConditionsBuilder {
        /// Current step: 1, 2, or 3.
        step: u8,
        /// The attribute selected in Step 1 (None until Step 1 completed).
        selected_attribute: Option<ConditionAttribute>,
        /// The operator selected in Step 2 (None until Step 2 completed).
        selected_operator: Option<String>,
        /// Conditions already added this session.
        pending: Vec<dlp_common::abac::PolicyCondition>,
        /// For MemberOf Step 3 only: buffered text input.
        buffer: String,
        /// Whether the pending list area has focus (vs. the step picker).
        pending_focused: bool,
        /// ListState for the pending conditions list.
        pending_state: ratatui::widgets::ListState,
        /// ListState for the step picker (step-appropriate options).
        picker_state: ratatui::widgets::ListState,
        /// Which screen opened this modal (for Esc-at-Step-1 return).
        caller: CallerScreen,
        /// Snapshot of the caller's form state, restored when the modal closes.
        form_snapshot: PolicyFormState,
        /// Index of the condition being edited in the `pending` list, or `None`
        /// for a new condition.
        ///
        /// Set to `Some(i)` when the user presses `'e'` on pending row `i`.
        /// Cleared to `None` after commit (replace path) or when the modal
        /// is freshly opened. The step-3 commit path calls `pending[i] = cond`
        /// when `Some(i)`, and `pending.push(cond)` when `None`.
        edit_index: Option<usize>,
    },
    /// Policy creation multi-field form.
    ///
    /// Row layout (selected index -> field):
    ///   0: Name         (text, required)
    ///   1: Description  (text, optional)
    ///   2: Priority     (text, parsed as u32 at submit)
    ///   3: Action       (select index into ACTION_OPTIONS)
    ///   4: Enabled      (bool toggle — Enter toggles, no edit mode)
    ///   5: [Add Conditions]
    ///   6: Conditions display (read-only summary)
    ///   7: [Submit]
    PolicyCreate {
        /// All form field values and accumulated conditions.
        form: PolicyFormState,
        /// Index of the currently highlighted row (0..=7).
        selected: usize,
        /// Whether the selected text field is in edit mode.
        editing: bool,
        /// Text buffer for the active text field (Name, Description, Priority).
        buffer: String,
        /// Inline validation error displayed below the Submit row.
        /// Cleared on Esc or successful submission.
        validation_error: Option<String>,
    },
    /// Policy edit multi-field form.
    ///
    /// Row layout (selected index -> field):
    ///   0: Name         (text, required)
    ///   1: Description  (text, optional)
    ///   2: Priority     (text, parsed as u32 at submit)
    ///   3: Action       (select index into ACTION_OPTIONS)
    ///   4: Enabled      (bool toggle — Enter toggles, no edit mode)
    ///   5: [Add Conditions]
    ///   6: Conditions display (read-only summary)
    ///   7: [Save]
    PolicyEdit {
        /// Server-side policy ID; used for PUT URL path only — NOT rendered on form.
        #[allow(dead_code)]
        id: String,
        /// All form field values and conditions, pre-populated from GET response.
        form: PolicyFormState,
        /// Index of the currently highlighted row (0..=7).
        selected: usize,
        /// Whether the selected text field is in edit mode.
        editing: bool,
        /// Text buffer for the active text field (Name, Description, Priority).
        buffer: String,
        /// Inline validation error displayed below the [Save] row.
        /// Cleared on Esc or successful submission.
        validation_error: Option<String>,
    },
    /// Policy simulation form.
    ///
    /// Renders a Subject / Resource / Environment multi-field form, submits to
    /// `POST /evaluate` (unauthenticated), and renders the `EvaluateResponse`
    /// inline below the submit row. Reachable from both MainMenu and PolicyMenu.
    ///
    /// Editable row layout (selected index -> field):
    ///   0: User SID            (text)
    ///   1: User Name           (text)
    ///   2: Groups (comma-SIDs)(text)
    ///   3: Device Trust        (select: cycles on Enter)
    ///   4: Network Location    (select: cycles on Enter)
    ///   5: Path                (text)
    ///   6: Classification     (select: cycles on Enter)
    ///   7: Action              (select: cycles on Enter)
    ///   8: Access Context     (select: cycles on Enter)
    ///   9: [Simulate]
    PolicySimulate {
        /// All form field values and select indices.
        form: SimulateFormState,
        /// Index of the currently highlighted editable row (0..=9).
        selected: usize,
        /// Whether the selected text field is in edit mode.
        editing: bool,
        /// Text buffer while editing a field (User SID, User Name, Groups, Path).
        buffer: String,
        /// Inline result block or error.
        result: SimulateOutcome,
        /// Which menu opened this screen (for Esc return destination).
        caller: SimulateCaller,
    },
    /// Import confirmation screen.
    ///
    /// Row layout (render list indices 0..=4):
    ///   0: "Import {N} policies?"              (informational, bold header, skip-nav)
    ///   1: "{conflicting_count} will overwrite" (informational, dark gray, skip-nav)
    ///   2: "{non_conflicting_count} will be created" (informational, dark gray, skip-nav)
    ///   3: [Confirm]   (Enter to proceed)      (actionable)
    ///   4: [Cancel]    (Esc to abort)           (actionable)
    ///
    /// Navigation: Up/Down cycles only between rows 3 and 4 (the actionable rows).
    /// Enter on Confirm -> transitions to InProgress / fires action.
    /// Enter on Cancel / Esc -> returns to PolicyMenu.
    ImportConfirm {
        /// Parsed policies from the imported JSON file.
        policies: Vec<PolicyResponse>,
        /// IDs currently present on the server (for conflict diff).
        existing_ids: Vec<String>,
        /// Number of policies whose IDs are already on the server (-> PUT).
        conflicting_count: usize,
        /// Number of policies with new IDs (-> POST).
        non_conflicting_count: usize,
        /// Selected row index (0..=4); only rows 3 and 4 are actionable.
        selected: usize,
        /// Current validation / outcome state.
        state: ImportState,
        /// Which menu opened this screen.
        caller: ImportCaller,
    },
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

/// Central application state.
pub struct App {
    /// Authenticated HTTP client (holds the JWT).
    pub client: EngineClient,
    /// Tokio runtime for blocking async calls.
    pub rt: tokio::runtime::Runtime,
    /// Current screen.
    pub screen: Screen,
    /// Set to `true` to exit the event loop.
    pub should_quit: bool,
    /// Status bar message shown at the bottom of the screen.
    pub status: Option<(String, StatusKind)>,
}

impl App {
    /// Creates a new `App` starting at the main menu.
    pub fn new(client: EngineClient, rt: tokio::runtime::Runtime) -> Self {
        Self {
            client,
            rt,
            screen: Screen::MainMenu { selected: 0 },
            should_quit: false,
            status: None,
        }
    }

    /// Sets a status-bar message.
    pub fn set_status(&mut self, msg: impl Into<String>, kind: StatusKind) {
        self.status = Some((msg.into(), kind));
    }

    /// Clears the status-bar message.
    #[allow(dead_code)]
    pub fn clear_status(&mut self) {
        self.status = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlp_common::abac::PolicyMode;

    #[test]
    fn test_policy_response_defaults_missing_mode_to_all() {
        let json = r#"{"id":"p","name":"n","description":null,"priority":1,"conditions":[],"action":"ALLOW","enabled":true}"#;
        let got: PolicyResponse = serde_json::from_str(json).expect("deserialize without mode");
        assert_eq!(got.mode, PolicyMode::ALL);
    }

    #[test]
    fn test_policy_response_preserves_explicit_mode_any() {
        let json = r#"{"id":"p","name":"n","description":null,"priority":1,"conditions":[],"action":"ALLOW","enabled":true,"mode":"ANY"}"#;
        let got: PolicyResponse = serde_json::from_str(json).expect("deserialize with mode=ANY");
        assert_eq!(got.mode, PolicyMode::ANY);
    }

    #[test]
    fn test_policy_payload_roundtrips_all_three_modes() {
        for mode in [PolicyMode::ALL, PolicyMode::ANY, PolicyMode::NONE] {
            let payload = PolicyPayload {
                id: "p".into(),
                name: "n".into(),
                description: None,
                priority: 1,
                conditions: serde_json::json!([]),
                action: "DENY".into(),
                enabled: true,
                mode,
            };
            let json = serde_json::to_string(&payload).expect("serialize");
            let expected = match mode {
                PolicyMode::ALL => "\"mode\":\"ALL\"",
                PolicyMode::ANY => "\"mode\":\"ANY\"",
                PolicyMode::NONE => "\"mode\":\"NONE\"",
            };
            assert!(
                json.contains(expected),
                "json `{json}` missing `{expected}`"
            );
            let round_trip: PolicyPayload = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(round_trip.mode, mode);
        }
    }

    #[test]
    fn test_policy_payload_legacy_default_on_missing_mode() {
        let json = r#"{"id":"p","name":"n","description":null,"priority":1,"conditions":[],"action":"ALLOW","enabled":true}"#;
        let got: PolicyPayload = serde_json::from_str(json).expect("legacy deserialize");
        assert_eq!(got.mode, PolicyMode::ALL);
    }

    #[test]
    fn test_policy_response_into_payload_copies_mode() {
        let resp = PolicyResponse {
            id: "p".into(),
            name: "n".into(),
            description: None,
            priority: 1,
            conditions: serde_json::json!([]),
            action: "DENY".into(),
            enabled: true,
            version: 0,
            updated_at: String::new(),
            mode: PolicyMode::NONE,
        };
        let payload: PolicyPayload = resp.into();
        assert_eq!(payload.mode, PolicyMode::NONE);
    }

    #[test]
    fn test_policy_form_state_default_mode_is_all() {
        let form = PolicyFormState::default();
        assert_eq!(form.mode, PolicyMode::ALL);
    }
}

#[cfg(test)]
mod import_export_tests {
    use super::*;

    #[test]
    fn policy_response_to_payload_drops_version_and_updated_at() {
        let response = PolicyResponse {
            id: "test-id".to_string(),
            name: "Test Policy".to_string(),
            description: Some("A test".to_string()),
            priority: 10,
            conditions: serde_json::json!([]),
            action: "DENY".to_string(),
            enabled: true,
            version: 42,
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            mode: dlp_common::abac::PolicyMode::ALL,
        };

        let payload: PolicyPayload = response.into();

        assert_eq!(payload.id, "test-id");
        assert_eq!(payload.name, "Test Policy");
        assert_eq!(payload.description, Some("A test".to_string()));
        assert_eq!(payload.priority, 10);
        assert_eq!(payload.conditions, serde_json::json!([]));
        assert_eq!(payload.action, "DENY");
        assert!(payload.enabled);
    }

    #[test]
    fn policy_response_deserializes_from_server_json() {
        let json = serde_json::json!({
            "id": "policy-abc",
            "name": "Block T4 Exports",
            "description": "Prevent T4 data leaving the network",
            "priority": 1,
            "conditions": [
                { "attribute": "Classification", "operator": "eq", "value": "T4" }
            ],
            "action": "DENY",
            "enabled": true,
            "version": 3,
            "updated_at": "2026-04-01T12:00:00Z"
        });

        let response: PolicyResponse = serde_json::from_value(json).expect("must parse");
        assert_eq!(response.id, "policy-abc");
        assert_eq!(response.name, "Block T4 Exports");
        assert_eq!(response.priority, 1);
        assert_eq!(response.action, "DENY");
        assert!(response.enabled);
        assert!(response.description.is_some());
        assert_eq!(response.conditions.as_array().unwrap().len(), 1);
    }

    #[test]
    fn policy_response_missing_optional_fields_default() {
        // version and updated_at are optional via #[serde(default)].
        let json = serde_json::json!({
            "id": "minimal",
            "name": "Minimal",
            "priority": 5,
            "conditions": [],
            "action": "ALLOW",
            "enabled": false
        });

        let response: PolicyResponse = serde_json::from_value(json).expect("must parse");
        assert_eq!(response.version, 0);
        assert_eq!(response.updated_at, "");
        assert_eq!(response.description, None);
    }

    #[test]
    fn policy_payload_roundtrip() {
        let payload = PolicyPayload {
            id: "roundtrip-test".to_string(),
            name: "Roundtrip".to_string(),
            description: None,
            priority: 99,
            conditions: serde_json::json!([
                { "attribute": "DeviceTrust", "operator": "eq", "value": "Managed" }
            ]),
            action: "AllowWithLog".to_string(),
            enabled: true,
            mode: dlp_common::abac::PolicyMode::ALL,
        };

        let json = serde_json::to_value(&payload).expect("must serialize");
        let deserialized: PolicyPayload = serde_json::from_value(json).expect("must deserialize");

        assert_eq!(deserialized.id, payload.id);
        assert_eq!(deserialized.name, payload.name);
        assert_eq!(deserialized.priority, payload.priority);
        assert_eq!(deserialized.action, payload.action);
        assert_eq!(deserialized.enabled, payload.enabled);
    }
}
