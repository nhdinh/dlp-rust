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
            warn!("ProcessIdToSessionId failed -- defaulting to session 0");
            0
        }
    }
}

/// Spawns all named-pipe IPC tasks on the tokio runtime.
fn spawn_ipc_tasks(session_id: u32, pipe1_connected: Arc<RwLock<bool>>) {
    // Pipe 1 -- bidirectional command pipe.
    let connected = pipe1_connected;
    tokio::spawn(async move {
        // Mark connected BEFORE entering the blocking read loop.
        *connected.write() = true;
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
        if let Err(e) = ipc::pipe3::send_ui_ready(session_id).await {
            debug!(error = %e, "Pipe 3: UiReady failed");
        }
    });
}

/// Log file path for UI crash diagnostics.
///
/// Written to by the panic hook when the process crashes.  Located next
/// to the audit log so it is easy to find.
const CRASH_LOG: &str = r"C:\ProgramData\DLP\logs\dlp-user-ui-crash.log";

/// Installs a panic hook that appends the panic message to a log file.
///
/// Because `windows_subsystem = "windows"` suppresses stderr in release
/// builds, panics would otherwise be completely invisible.
fn install_crash_hook() {
    std::panic::set_hook(Box::new(|info| {
        let msg = format!(
            "[{}] dlp-user-ui PANIC: {}\n",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            info
        );
        // Best-effort write; ignore errors (the directory may not exist).
        let _ = std::fs::create_dir_all(r"C:\ProgramData\DLP\logs");
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(CRASH_LOG)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(msg.as_bytes())
            });
    }));
}

/// Log directory shared with the agent.
const LOG_DIR: &str = r"C:\ProgramData\DLP\logs";

/// Holds the `WorkerGuard` for the non-blocking file writer for the entire
/// process lifetime.  See `dlp-agent::service::LOG_WORKER_GUARD` for the
/// rationale for using `OnceLock` instead of `mem::forget`.
static LOG_WORKER_GUARD: std::sync::OnceLock<tracing_appender::non_blocking::WorkerGuard> =
    std::sync::OnceLock::new();

/// Initialises logging and runs the iced application.
///
/// Logging is set up with two layers:
/// - A rolling daily file at `C:\ProgramData\DLP\logs\dlp-user-ui.log.*`
///   (always active; this is the primary diagnostic output because
///   `windows_subsystem = "windows"` suppresses stderr in release builds).
/// - A stderr layer for interactive/debug use.
///
/// # Errors
///
/// Returns an error if the iced runtime fails to start.
pub fn run() -> iced::Result {
    install_crash_hook();

    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    // Default to INFO; RUST_LOG overrides for development.
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(Level::INFO.into())
        .from_env_lossy();

    let _ = std::fs::create_dir_all(LOG_DIR);

    // Rolling daily log file: C:\ProgramData\DLP\logs\dlp-user-ui.log.<date>
    // This is the only reliable output channel when the UI runs as a
    // `windows_subsystem = "windows"` process (no attached console).
    let file_appender = tracing_appender::rolling::daily(LOG_DIR, "dlp-user-ui.log");
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    let _ = LOG_WORKER_GUARD.set(guard);

    // Two layers: file (always) + stderr (debug/console use only).
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(file_writer)
                .with_span_events(FmtSpan::CLOSE)
                .with_target(true)
                .with_thread_ids(true)
                .with_ansi(false),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_span_events(FmtSpan::CLOSE)
                .with_target(true)
                .with_thread_ids(true),
        )
        .try_init();

    let session_id = get_current_session_id();
    info!(session_id, "DLP Agent UI starting");

    // Initialise the system tray before entering iced's event loop.
    match tray::init() {
        Ok(()) => info!("system tray initialised"),
        Err(e) => error!(error = %e, "failed to init system tray"),
    }

    info!("starting iced application");

    let pipe1_connected = Arc::new(RwLock::new(false));

    let result = iced::application("DLP Agent UI", DlpApp::update, DlpApp::view)
        .subscription(DlpApp::subscription)
        .window_size(iced::Size::new(480.0, 200.0))
        .run_with(move || {
            // Spawn IPC tasks here — inside `run_with` — because the iced
            // tokio runtime is only available after the application starts.
            // Calling `tokio::spawn` before this point panics with
            // "there is no reactor running".
            spawn_ipc_tasks(session_id, pipe1_connected.clone());

            // Start clipboard monitoring — watches for sensitive content
            // pasted into the clipboard and alerts the agent via Pipe 3.
            let _clipboard_stop = crate::clipboard_monitor::start(session_id);

            let state = UiState {
                session_id,
                pipe1_connected,
            };
            (DlpApp { state }, iced::Task::none())
        });

    info!(?result, "iced application exited");
    result
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
                // Apply any pending tray status updates from the Pipe 2 thread.
                tray::apply_pending_status();

                // Poll tray menu events from the muda receiver.
                if let Ok(event) = muda::MenuEvent::receiver().try_recv() {
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
            iced::widget::text(format!("Session: {}", self.state.session_id)).size(14),
            iced::widget::text(format!("Status: {status}")).size(14),
        ]
        .padding(20)
        .spacing(10)
        .into()
    }

    /// Returns a subscription that periodically polls for tray menu
    /// events.
    fn subscription(&self) -> iced::Subscription<Message> {
        iced::time::every(std::time::Duration::from_millis(100)).map(|_| Message::Tick(()))
    }
}
