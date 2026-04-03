//! File system monitor (T-11) using the `notify` crate.
//!
//! Watches all mounted volumes for file system change events and converts
//! them to [`FileAction`] events sent through a Tokio `mpsc` channel.
//!
//! ## Why `notify` over ETW?
//!
//! ETW (`Microsoft-Windows-FileSystem-ETW`) is session-local and requires
//! admin privileges; a session started in one logon session is invisible to
//! processes in another.  The `notify` watcher is a reliable, cross-session
//! approach that works on all Windows configurations without elevation.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::mpsc;

/// Path prefixes to exclude from monitoring (case-insensitive).
///
/// These directories generate high-volume, low-value events that clutter
/// the audit log.  System directories, temp folders, and application
/// caches are excluded since they are not relevant to DLP enforcement.
const EXCLUDED_PREFIXES: &[&str] = &[
    r"c:\windows\",
    r"c:\programdata\",
    r"c:\program files\",
    r"c:\program files (x86)\",
    r"c:\$recycle.bin\",
    r"c:\system volume information\",
    // Per-user application caches and temp directories.
    r"\appdata\local\temp\",
    r"\appdata\local\microsoft\",
    r"\appdata\local\packages\",
    r"\appdata\roaming\code\",
    r"\appdata\roaming\microsoft\",
];

/// Returns `true` if the path should be excluded from monitoring.
///
/// Performs case-insensitive prefix matching against [`EXCLUDED_PREFIXES`].
fn is_excluded(path: &str) -> bool {
    let lower = path.to_lowercase();
    EXCLUDED_PREFIXES.iter().any(|prefix| lower.contains(prefix))
}

/// The file action intercepted from the file system.
#[derive(Debug, Clone)]
pub enum FileAction {
    /// A file was created (or opened if it already existed).
    Created {
        /// The full path to the file.
        path: String,
        /// The PID of the process that performed the operation.
        process_id: u32,
        /// The PID of the related process (may differ for inherited handles).
        related_process_id: u32,
    },
    /// A file was written to.
    Written {
        path: String,
        process_id: u32,
        related_process_id: u32,
        /// Number of bytes written (0 if unavailable).
        byte_count: u32,
    },
    /// A file was deleted.
    Deleted {
        path: String,
        process_id: u32,
        related_process_id: u32,
    },
    /// A file was renamed or moved.
    Moved {
        /// Source path before the rename/move.
        old_path: String,
        /// Destination path after the rename/move.
        new_path: String,
        process_id: u32,
        related_process_id: u32,
    },
    /// A file was read.
    Read {
        path: String,
        process_id: u32,
        related_process_id: u32,
        byte_count: u32,
    },
}

impl FileAction {
    /// Returns the file path involved in this action.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::Created { path, .. }
            | Self::Written { path, .. }
            | Self::Deleted { path, .. }
            | Self::Read { path, .. } => path,
            Self::Moved { new_path, .. } => new_path,
        }
    }

    /// Returns the process ID that initiated this action.
    #[must_use]
    pub fn process_id(&self) -> u32 {
        match self {
            Self::Created { process_id, .. }
            | Self::Written { process_id, .. }
            | Self::Deleted { process_id, .. }
            | Self::Moved { process_id, .. }
            | Self::Read { process_id, .. } => *process_id,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InterceptionEngine
// ─────────────────────────────────────────────────────────────────────────────

/// The file-system interception engine.
///
/// Watches all mounted volumes for file system change events using the
/// `notify` crate.  Events are forwarded through a Tokio `mpsc` channel
/// consumed by the caller.
#[derive(Clone)]
pub struct InterceptionEngine {
    /// Set to `true` by `stop()` to signal the `run()` loop to exit.
    stop_flag: Arc<AtomicBool>,
}

impl InterceptionEngine {
    /// Creates a new interception engine with a fresh stop flag.
    pub fn new() -> Result<Self> {
        Ok(Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Runs the file system monitor using the `notify` crate.
    ///
    /// Watches all mounted volumes for file system change events and converts
    /// them to [`FileAction`] events sent through the channel.  This is a
    /// reliable, cross-session approach that works on all Windows configurations.
    ///
    /// Returns `Ok(())` when [`stop()`](InterceptionEngine::stop) is called.
    pub fn run(&self, tx: mpsc::Sender<FileAction>) -> Result<()> {
        use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
        use std::path::Path;
        use std::sync::mpsc;
        use std::time::Duration;

        let (notify_tx, notify_rx) = mpsc::channel();

        // Watch the root of all mounted volumes (C:\, D:\, etc.) so we catch
        // activity on any drive.  Use a cross-platform RecommendedWatcher.
        let mut watcher: RecommendedWatcher = RecommendedWatcher::new(
            move |res: Result<notify::Event, notify::Error>| {
                if let Ok(event) = res {
                    let _ = notify_tx.send(event);
                }
            },
            Config::default().with_poll_interval(Duration::from_millis(500)),
        )
        .map_err(|e| anyhow::anyhow!("Failed to create file system watcher: {e}"))?;

        // Watch all available drive roots so we capture all file activity.
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:\\", letter as char);
            let path = Path::new(&drive);
            if path.exists() {
                if let Err(e) = watcher.watch(path, RecursiveMode::Recursive) {
                    tracing::warn!(drive = %drive, error = %e, "could not watch drive");
                } else {
                    tracing::debug!(drive = %drive, "watching drive");
                }
            }
        }

        tracing::info!("file system watcher started");
        eprintln!("[DIAG] file monitor: watching all volumes");

        loop {
            // Check stop flag first — use a short timeout so we can also
            // process pending events before exiting.
            match notify_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(event) => {
                    let kind = event.kind;
                    let paths: Vec<_> = event
                        .paths
                        .iter()
                        .map(|p| p.to_string_lossy().to_string())
                        .collect();

                    for path in paths {
                        let action = match kind {
                            notify::EventKind::Create(_) => Some(FileAction::Created {
                                path,
                                process_id: 0,
                                related_process_id: 0,
                            }),
                            notify::EventKind::Modify(_) => Some(FileAction::Written {
                                path,
                                process_id: 0,
                                related_process_id: 0,
                                byte_count: 0,
                            }),
                            notify::EventKind::Remove(_) => Some(FileAction::Deleted {
                                path,
                                process_id: 0,
                                related_process_id: 0,
                            }),
                            _ => None,
                        };

                        if let Some(action) = action {
                            if self.stop_flag.load(Ordering::SeqCst) {
                                tracing::info!(
                                    "stop flag set — exiting file monitor"
                                );
                                return Ok(());
                            }
                            // Skip excluded paths (system dirs, temp, caches).
                            if is_excluded(action.path()) {
                                continue;
                            }
                            // try_send is non-blocking — the watcher must not stall.
                            let _ = tx.clone().try_send(action);
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Check stop flag on timeout.
                    if self.stop_flag.load(Ordering::SeqCst) {
                        tracing::info!("stop flag set — exiting file monitor");
                        return Ok(());
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    tracing::info!("watcher channel disconnected — exiting");
                    return Ok(());
                }
            }
        }
    }

    /// Stops the file system monitor.
    ///
    /// Safe to call from any thread.  The [`run()`](InterceptionEngine::run)
    /// call will return within one poll interval (~500 ms).
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        tracing::debug!("file monitor stop flag set");
    }
}

impl Default for InterceptionEngine {
    fn default() -> Self {
        Self::new().expect("interception engine initialisation always succeeds")
    }
}

impl Drop for InterceptionEngine {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_action_path_created() {
        let action = FileAction::Created {
            path: r"C:\Data\report.xlsx".to_string(),
            process_id: 100,
            related_process_id: 0,
        };
        assert_eq!(action.path(), r"C:\Data\report.xlsx");
        assert_eq!(action.process_id(), 100);
    }

    #[test]
    fn test_file_action_moved_path_returns_new() {
        let action = FileAction::Moved {
            old_path: r"C:\Data\old.txt".to_string(),
            new_path: r"C:\Data\new.txt".to_string(),
            process_id: 200,
            related_process_id: 0,
        };
        assert_eq!(action.path(), r"C:\Data\new.txt");
    }

    #[test]
    fn test_interception_engine_default() {
        let engine = InterceptionEngine::default();
        assert!(!engine.stop_flag.load(Ordering::SeqCst));
    }

    // -- Path exclusion filter tests ----------------------------------------

    #[test]
    fn test_excluded_windows_dir() {
        assert!(is_excluded(r"C:\Windows\System32\config\SYSTEM.LOG2"));
        assert!(is_excluded(r"c:\windows\temp\somefile.tmp"));
    }

    #[test]
    fn test_excluded_program_files() {
        assert!(is_excluded(r"C:\Program Files\SomeApp\data.bin"));
        assert!(is_excluded(r"C:\Program Files (x86)\App\file.dll"));
    }

    #[test]
    fn test_excluded_programdata() {
        assert!(is_excluded(r"C:\ProgramData\DLP\logs\audit.jsonl"));
    }

    #[test]
    fn test_excluded_appdata_temp() {
        assert!(is_excluded(
            r"C:\Users\jsmith\AppData\Local\Temp\tmp1234.dat"
        ));
    }

    #[test]
    fn test_excluded_appdata_vscode() {
        assert!(is_excluded(
            r"C:\Users\jsmith\AppData\Roaming\Code\User\state.vscdb"
        ));
    }

    #[test]
    fn test_not_excluded_user_documents() {
        assert!(!is_excluded(r"C:\Users\jsmith\Documents\report.xlsx"));
    }

    #[test]
    fn test_not_excluded_data_dir() {
        assert!(!is_excluded(r"C:\Data\financials.xlsx"));
    }

    #[test]
    fn test_not_excluded_restricted_dir() {
        assert!(!is_excluded(r"C:\Restricted\secrets.docx"));
    }

    #[test]
    fn test_excluded_recycle_bin() {
        assert!(is_excluded(r"C:\$Recycle.Bin\S-1-5-21\$RXXXX.txt"));
    }
}
