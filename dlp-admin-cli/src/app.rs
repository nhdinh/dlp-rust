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
    CreatePolicyFromFile,
    UpdatePolicyId,
    UpdatePolicyFile { id: String },
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
