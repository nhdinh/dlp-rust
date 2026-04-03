//! iced application — session management, IPC task spawning, tray
//! integration.
//!
//! The UI window is hidden by default; the system tray icon is the
//! primary user interaction point.  Named-pipe IPC tasks run on tokio
//! background threads and communicate with the agent via length-prefix
//! JSON frames over Windows named pipes.

use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::fmt::format::FmtSpan;

use crate::ipc;
use crate::tray;

/// Shared application state.
struct UiState {
    session_id: u32,
    pipe1_connected: Arc<RwLock<bool>>,
}

/// Top-level application message.
#[derive(Debug, Clone)]
enum Message {
    /// Periodic tick for polling tray menu events.
    Tick(()),
}

/// Resolves the current process's Windows session ID via
/// `ProcessIdToSessionId`.
fn get_current_session_id() -> u32 {
    // SAFETY: both APIs are stable Windows APIs that do not require
    // special preconditions beyond a valid process ID (guaranteed by
    // GetCurrentProcessId).
    unsafe {
        use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
        use windows::Win32::System::Threading::GetCurrentProcessId;
        let mut session_id: u32 = 0;
        let pid = GetCurrentProcessId();
        if ProcessIdToSessionId(pid, &mut session_id).is_ok() {
            session_id
        } else {
            warn!(
                "ProcessIdToSessionId failed -- defaulting to session 0"
            );
            0
        }
    }
}

/// Spawns all named-pipe IPC tasks on the tokio runtime.
fn spawn_ipc_tasks(
    session_id: u32,
    pipe1_connected: Arc<RwLock<bool>>,
) {
    // Pipe 1 -- bidirectional command pipe.
    let connected = pipe1_connected.clone();
    tokio::spawn(async move {
        match ipc::pipe1::connect_and_run(session_id).await {
            Ok(()) => {
                debug!(session_id, "Pipe 1: connection closed normally")
            }
            Err(e) => {
                error!(
                    session_id,
                    error = %e,
                    "Pipe 1: connection error"
                )
            }
        }
        *connected.write() = false;
    });

    // Pipe 2 -- agent-to-UI event listener.
    tokio::spawn(async move {
        match ipc::pipe2::run_listener().await {
            Ok(()) => debug!("Pipe 2: connection closed normally"),
            Err(e) => {
                error!(error = %e, "Pipe 2: connection error")
            }
        }
    });

    // Pipe 3 -- send UiReady to agent.
    tokio::spawn(async move {
        if let Err(e) = ipc::pipe3::send_ui_ready(session_id).await
        {
            debug!(error = %e, "Pipe 3: UiReady failed");
        }
    });

    *pipe1_connected.write() = true;
}

/// Initialises logging and runs the iced application.
///
/// # Errors
///
/// Returns an error if the iced runtime fails to start.
pub fn run() -> iced::Result {
    // Initialise structured logging.
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

    // Initialise the system tray before entering iced's event loop.
    if let Err(e) = tray::init() {
        error!(error = %e, "failed to init system tray");
    }

    let pipe1_connected = Arc::new(RwLock::new(false));

    // Spawn IPC tasks.  iced with the `tokio` feature shares the same
    // tokio runtime, so these tasks run on iced's async executor.
    spawn_ipc_tasks(session_id, pipe1_connected.clone());

    let state = UiState {
        session_id,
        pipe1_connected,
    };

    iced::application("DLP Agent UI", DlpApp::update, DlpApp::view)
        .subscription(DlpApp::subscription)
        .window_size(iced::Size::new(480.0, 200.0))
        .run_with(move || (DlpApp { state }, iced::Task::none()))
}

/// The iced application struct.
struct DlpApp {
    state: UiState,
}

impl DlpApp {
    /// Handles incoming messages.
    fn update(&mut self, message: Message) -> iced::Task<Message> {
        match message {
            Message::Tick(_) => {
                // Poll tray menu events from the muda receiver.
                if let Ok(event) = muda::MenuEvent::receiver().try_recv()
                {
                    let id = event.id.0.clone();
                    match id.as_str() {
                        "show_portal" => tray::open_portal(),
                        "exit" => {
                            info!("Exit requested via tray");
                            std::process::exit(0);
                        }
                        _ => {}
                    }
                }
                iced::Task::none()
            }
        }
    }

    /// Renders the main window content.
    fn view(&self) -> iced::Element<'_, Message> {
        let status = if *self.state.pipe1_connected.read() {
            "Connected to DLP Agent"
        } else {
            "Disconnected"
        };

        iced::widget::column![
            iced::widget::text("DLP Agent UI").size(18),
            iced::widget::text(format!(
                "Session: {}",
                self.state.session_id
            ))
            .size(14),
            iced::widget::text(format!("Status: {status}")).size(14),
        ]
        .padding(20)
        .spacing(10)
        .into()
    }

    /// Returns a subscription that periodically polls for tray menu
    /// events.
    fn subscription(&self) -> iced::Subscription<Message> {
        iced::time::every(std::time::Duration::from_millis(100))
            .map(|_| Message::Tick(()))
    }
}
