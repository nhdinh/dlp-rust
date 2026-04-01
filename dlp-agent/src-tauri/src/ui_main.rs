//! Tauri app setup — command handlers, session management, app lifecycle (T-39).
//!
//! The UI connects to the agent's named pipes immediately on startup and
//! registers its session ID.  All subsequent IPC is handled asynchronously via
//! `tokio` tasks spawned from command handlers.

use std::sync::Arc;

use parking_lot::RwLock;
use tauri::{AppHandle, Manager, State};
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::fmt::format::FmtSpan;

use crate::ipc;

/// Application shared state — holds the session ID.
pub struct UiState {
    pub session_id: u32,
    pub pipe1_connected: Arc<RwLock<bool>>,
}

impl UiState {
    fn new(session_id: u32) -> Self {
        Self {
            session_id,
            pipe1_connected: Arc::new(RwLock::new(false)),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tauri command handlers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the session ID this UI instance is running in.
#[tauri::command]
fn get_session_id(state: State<'_, UiState>) -> u32 {
    state.session_id
}

/// Checks whether the UI is connected to the agent's Pipe 1.
#[tauri::command]
fn is_pipe1_connected(state: State<'_, UiState>) -> bool {
    *state.pipe1_connected.read()
}

// ─────────────────────────────────────────────────────────────────────────────
// App lifecycle
// ─────────────────────────────────────────────────────────────────────────────

/// Initialises logging and spawns all named-pipe tasks.
fn spawn_ipc_tasks(app: &AppHandle, session_id: u32) {
    let pipe1_connected = {
        let state = app.state::<UiState>();
        state.pipe1_connected.clone()
    };

    // Pipe 1 — connect to agent, register session, handle incoming agent messages.
    let session_id_clone = session_id;
    let connected = pipe1_connected.clone();
    tokio::spawn(async move {
        match ipc::pipe1::connect_and_run(session_id_clone).await {
            Ok(()) => {
                debug!(session_id_clone, "Pipe 1: connection closed normally");
            }
            Err(e) => {
                error!(session_id_clone, error = %e, "Pipe 1: connection error");
            }
        }
        *connected.write() = false;
    });

    // Pipe 3 — send UiReady to agent as first message (fire-and-forget).
    let session_id_for_pipe3 = session_id;
    tokio::spawn(async move {
        if let Err(e) = ipc::pipe3::send_ui_ready(session_id_for_pipe3).await {
            debug!(error = %e, "Pipe 3: UiReady failed");
        }
    });

    *pipe1_connected.write() = true;
}

/// Resolves the current process's Windows session ID via `ProcessIdToSessionId`.
fn get_current_session_id() -> u32 {
    // SAFETY: both APIs are stable Windows APIs.
    unsafe {
        use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
        use windows::Win32::System::Threading::GetCurrentProcessId;
        let mut session_id: u32 = 0;
        let pid = GetCurrentProcessId();
        if ProcessIdToSessionId(pid, &mut session_id).is_ok() {
            session_id
        } else {
            warn!("ProcessIdToSessionId failed — defaulting to session 0");
            0
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// App entry point
// ─────────────────────────────────────────────────────────────────────────────

#[cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
pub fn run() {
    // Initialise logging first.
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(Level::INFO.into())
        .from_env_lossy();

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::CLOSE)
        .with_target(true)
        .init();

    let session_id = get_current_session_id();
    info!(session_id, "DLP Agent UI starting");

    let ui_state = UiState::new(session_id);

    tauri::Builder::default()
        .manage(ui_state)
        .invoke_handler(tauri::generate_handler![get_session_id, is_pipe1_connected,])
        .setup(move |app| {
            info!(session_id, "Tauri app setup starting");
            spawn_ipc_tasks(app.handle(), session_id);
            info!(session_id, "Tauri app setup complete");
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("tauri app failed to run");
}
