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

use crate::config::AgentConfig;

/// Built-in path prefixes excluded from monitoring (case-insensitive).
///
/// These directories generate high-volume, low-value events that clutter
/// the audit log.  System directories, temp folders, and application
/// caches are excluded since they are not relevant to DLP enforcement.
///
/// User-configured exclusions from [`AgentConfig::excluded_paths`] are
/// merged with this list at runtime.
const BUILTIN_EXCLUDED_PREFIXES: &[&str] = &[
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
/// Checks the path against both the built-in exclusions and any
/// user-configured exclusions.  All comparisons are case-insensitive
/// substring matches.
fn is_excluded(path: &str, custom_exclusions: &[String]) -> bool {
    let lower = path.to_lowercase();
    if BUILTIN_EXCLUDED_PREFIXES
        .iter()
        .any(|prefix| lower.contains(prefix))
    {
        return true;
    }
    custom_exclusions
        .iter()
        .any(|prefix| lower.contains(&prefix.to_lowercase()))
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
/// Watches configured directories for file system change events using the
/// `notify` crate.  Events are forwarded through a Tokio `mpsc` channel
/// consumed by the caller.
///
/// Directories to watch and additional exclusions are controlled by
/// [`AgentConfig`].  When no config is provided, all mounted drives
/// are watched with only built-in exclusions.
#[derive(Clone)]
pub struct InterceptionEngine {
    /// Set to `true` by `stop()` to signal the `run()` loop to exit.
    stop_flag: Arc<AtomicBool>,
    /// Runtime configuration (watch paths + custom exclusions).
    config: AgentConfig,
}

impl InterceptionEngine {
    /// Creates a new interception engine with default configuration
    /// (all drives, built-in exclusions only).
    pub fn new() -> Result<Self> {
        Self::with_config(AgentConfig::default())
    }

    /// Creates a new interception engine with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Agent configuration specifying watched paths and
    ///   custom exclusions.
    pub fn with_config(config: AgentConfig) -> Result<Self> {
        Ok(Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
            config,
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
        use notify::{Config, RecommendedWatcher, Watcher};
        use std::sync::mpsc as std_mpsc;
        use std::time::Duration;

        let (notify_tx, notify_rx) = std_mpsc::channel();

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

        // Watch configured paths (or all drives if none configured).
        let watch_paths = self.config.resolve_watch_paths();
        register_watch_paths(&mut watcher, &watch_paths);

        let mode = if self.config.monitored_paths.is_empty() {
            "all drives"
        } else {
            "configured paths"
        };
        tracing::info!(
            count = watch_paths.len(),
            custom_exclusions = self.config.excluded_paths.len(),
            "file system watcher started ({})", mode
        );

        loop {
            // Use a short timeout so we can check the stop flag between events.
            match notify_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(event) => {
                    if !self.dispatch_event(event, &tx) {
                        return Ok(());
                    }
                }
                Err(std_mpsc::RecvTimeoutError::Timeout) => {}
                Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                    tracing::info!("watcher channel disconnected — exiting");
                    return Ok(());
                }
            }

            if self.stop_flag.load(Ordering::SeqCst) {
                tracing::info!("stop flag set — exiting file monitor");
                return Ok(());
            }
        }
    }

    /// Converts a single `notify` event into [`FileAction`]s and sends them
    /// through the channel.
    ///
    /// Returns `false` if the stop flag is set (caller should exit the loop).
    fn dispatch_event(
        &self,
        event: notify::Event,
        tx: &mpsc::Sender<FileAction>,
    ) -> bool {
        for path_buf in &event.paths {
            let path = path_buf.to_string_lossy().to_string();
            let action = match event_kind_to_action(event.kind, path) {
                Some(a) => a,
                None => continue,
            };

            if is_excluded(action.path(), &self.config.excluded_paths) {
                continue;
            }

            if self.stop_flag.load(Ordering::SeqCst) {
                return false;
            }

            // try_send is non-blocking — the watcher must not stall.
            let _ = tx.try_send(action);
        }
        true
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

/// Registers each path with the watcher, logging success or failure.
fn register_watch_paths(
    watcher: &mut notify::RecommendedWatcher,
    paths: &[std::path::PathBuf],
) {
    use notify::{RecursiveMode, Watcher};

    for path in paths {
        if let Err(e) = watcher.watch(path, RecursiveMode::Recursive) {
            tracing::warn!(path = %path.display(), error = %e, "could not watch path");
        } else {
            tracing::info!(path = %path.display(), "watching path");
        }
    }
}

/// Converts a `notify::EventKind` and file path into a [`FileAction`].
///
/// Returns `None` for event kinds that do not map to a DLP-relevant action
/// (e.g. metadata-only changes, access events).
fn event_kind_to_action(kind: notify::EventKind, path: String) -> Option<FileAction> {
    match kind {
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

    /// No custom exclusions — tests built-in list only.
    const NO_CUSTOM: &[String] = &[];

    #[test]
    fn test_excluded_windows_dir() {
        assert!(is_excluded(r"C:\Windows\System32\config\SYSTEM.LOG2", NO_CUSTOM));
        assert!(is_excluded(r"c:\windows\temp\somefile.tmp", NO_CUSTOM));
    }

    #[test]
    fn test_excluded_program_files() {
        assert!(is_excluded(r"C:\Program Files\SomeApp\data.bin", NO_CUSTOM));
        assert!(is_excluded(r"C:\Program Files (x86)\App\file.dll", NO_CUSTOM));
    }

    #[test]
    fn test_excluded_programdata() {
        assert!(is_excluded(r"C:\ProgramData\DLP\logs\audit.jsonl", NO_CUSTOM));
    }

    #[test]
    fn test_excluded_appdata_temp() {
        assert!(is_excluded(
            r"C:\Users\jsmith\AppData\Local\Temp\tmp1234.dat",
            NO_CUSTOM,
        ));
    }

    #[test]
    fn test_excluded_appdata_vscode() {
        assert!(is_excluded(
            r"C:\Users\jsmith\AppData\Roaming\Code\User\state.vscdb",
            NO_CUSTOM,
        ));
    }

    #[test]
    fn test_not_excluded_user_documents() {
        assert!(!is_excluded(r"C:\Users\jsmith\Documents\report.xlsx", NO_CUSTOM));
    }

    #[test]
    fn test_not_excluded_data_dir() {
        assert!(!is_excluded(r"C:\Data\financials.xlsx", NO_CUSTOM));
    }

    #[test]
    fn test_not_excluded_restricted_dir() {
        assert!(!is_excluded(r"C:\Restricted\secrets.docx", NO_CUSTOM));
    }

    #[test]
    fn test_excluded_recycle_bin() {
        assert!(is_excluded(r"C:\$Recycle.Bin\S-1-5-21\$RXXXX.txt", NO_CUSTOM));
    }

    // -- Custom exclusion tests -----------------------------------------------

    #[test]
    fn test_custom_exclusion_matches() {
        let custom = vec![r"C:\BuildOutput\".to_string()];
        assert!(is_excluded(r"C:\BuildOutput\release\app.exe", &custom));
    }

    #[test]
    fn test_custom_exclusion_case_insensitive() {
        let custom = vec![r"D:\MyCache\".to_string()];
        assert!(is_excluded(r"d:\mycache\temp\data.bin", &custom));
    }

    #[test]
    fn test_custom_exclusion_does_not_affect_non_matching() {
        let custom = vec![r"C:\BuildOutput\".to_string()];
        assert!(!is_excluded(r"C:\Data\report.xlsx", &custom));
    }
}
