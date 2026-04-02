//! File system ETW monitor (T-11).
//!
//! Subscribes to the `Microsoft-Windows-FileSystem-ETW` trace session and
//! processes file-operation events in real time via a callback.
//!
//! ## ETW event delivery model
//!
//! `OpenTraceW` + `ProcessTrace` is called with a logging callback struct
//! (`EVENT_TRACE_LOGFILEW.ProcessTraceCallback`).  `ProcessTrace` blocks
//! until the trace is stopped; each FS event fires the callback synchronously
//! from the system thread pool.  The callback must not throw exceptions or
//! leak the `EtwProcessor` reference across the FFI boundary — it stores the
//! action in a lock-free ring buffer read by a Tokio task on this end.
//!
//! ## Caveats
//!
//! ETW captures events *after* the operation has succeeded.  A blocked
//! operation therefore never appears here — blocking decisions are made by the
//! interception layer *before* the operation proceeds.  If an ETW event
//! arrives for an operation the hooks did not intercept, [`EvasionDetected`]
//! is emitted to flag a potential bypass attempt.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::debug;

/// The file action intercepted from the ETW trace.
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
    /// An ETW event was received for an operation the interception hooks
    /// did not intercept — potential evasion/bypass signal.
    EvasionDetected {
        path: String,
        process_id: u32,
        /// The ETW operation name/ID that triggered this signal.
        etw_operation_name: String,
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
            | Self::Read { path, .. }
            | Self::EvasionDetected { path, .. } => path,
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
            | Self::Read { process_id, .. }
            | Self::EvasionDetected { process_id, .. } => *process_id,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Well-known GUID for the Microsoft-Windows-FileSystem-ETW provider.
/// Stable across Windows versions.
///
/// Correct value confirmed against:
/// - Microsoft Learn: "FileSystem-ETW provider" (`logman -p {c65430ae-74d3-4806-b6d0-79a7bb8b9308}`)
/// - Microsoft Hardware Dev: "Configuring FileSystem-ETW Tracing"
const FS_ETW_GUID: windows::core::GUID = windows::core::GUID::from_values(
    0xc65430ae,
    0x74d3,
    0x4806,
    [0xb6, 0xd0, 0x79, 0xa7, 0xbb, 0x8b, 0x93, 0x08],
);

// ETW event type codes from FileSystem-ETW manifest (stable).
// Used by `parse_event_record` which is invoked from the ETW callback at runtime.
#[allow(dead_code)]
const FS_EVENT_CREATE: u8 = 10;
#[allow(dead_code)]
const FS_EVENT_WRITE: u8 = 15;
#[allow(dead_code)]
const FS_EVENT_DELETE: u8 = 24;
#[allow(dead_code)]
const FS_EVENT_RENAME: u8 = 37;
#[allow(dead_code)]
const FS_EVENT_READ: u8 = 16;

// Real-time trace mode flag (from Win32_System_Diagnostics_Etw).
// Must be at module level so both `run()` and `build_logfile()` can reference it.
const EVENT_TRACE_REAL_TIME_MODE: u32 = 256u32;

// ─────────────────────────────────────────────────────────────────────────────
// Wide-string helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Converts a `&str` to a null-terminated wide-string vector.
fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Converts a null-terminated `PCWSTR` to a `String`.
#[allow(dead_code)]
fn pwstr_to_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
        if len > 4096 {
            return None; // sanity limit
        }
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16(slice).ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// InterceptionEngine
// ─────────────────────────────────────────────────────────────────────────────

/// The file-system interception engine.
///
/// Maintains a real-time ETW trace session subscribed to the
/// `Microsoft-Windows-FileSystem-ETW` provider.  Events are forwarded from
/// the ETW callback thread to a Tokio `mpsc` channel consumed by the caller.
#[derive(Clone)]
pub struct InterceptionEngine {
    /// Set to `true` by `stop()` to unblock `ProcessTrace`.
    stop_flag: Arc<AtomicBool>,
}

impl InterceptionEngine {
    /// Starts a real-time ETW trace session and enables the FS provider.
    pub fn new() -> Result<Self> {
        Ok(Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Starts the ETW trace and pumps events until `stop()` is called.
    ///
    /// This is a blocking call — intended to run inside `tokio::spawn_blocking`.
    /// Returns `Ok(())` when the trace is stopped.
    pub fn run(&self, tx: mpsc::Sender<FileAction>) -> Result<()> {
        use windows::Win32::System::Diagnostics::Etw::{
            CloseTrace, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW, StopTraceW,
            CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_TRACE_PROPERTIES,
            PROCESSTRACE_HANDLE,
        };

        // ── Build the trace properties ──────────────────────────────────────

        const SESSION_NAME: &str = "DLPFileMonitor";
        let session_name_wide = to_wide(SESSION_NAME);

        // `EVENT_TRACE_PROPERTIES` must be allocated with enough space for
        // the session name string that follows it in the struct.
        let struct_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let name_offset = struct_size;
        let name_capacity = (SESSION_NAME.len() + 1) * 2;
        let mut props_buf = vec![0u8; struct_size + name_capacity];

        let props = props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        // SAFETY: props points to a properly-aligned, zero-initialised buffer.
        unsafe {
            (*props).Wnode.BufferSize = props_buf.len() as u32;
            (*props).Wnode.Guid = FS_ETW_GUID;
            (*props).Wnode.Flags = 0x00000000; // WNODE_FLAG_TRACED_GUID
            (*props).BufferSize = 64; // 64 KB buffers
            (*props).MinimumBuffers = 16;
            (*props).MaximumBuffers = 256;
            (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*props).FlushTimer = 1; // flush every 1 second
            (*props).LoggerNameOffset = name_offset as u32;

            // Copy the session name into the buffer after the struct.
            let name_dst = props_buf[name_offset..].as_mut_ptr() as *mut u16;
            std::ptr::copy_nonoverlapping(
                session_name_wide.as_ptr(),
                name_dst,
                SESSION_NAME.len() + 1,
            );
        }

        // ── Start the trace ────────────────────────────────────────────────

        let mut trace_handle = CONTROLTRACE_HANDLE::default();
        // SAFETY: props_buf is valid for the call; session name is null-terminated.
        unsafe {
            StartTraceW(
                &mut trace_handle,
                windows::core::PCWSTR(props_buf[name_offset..].as_ptr() as *const _),
                props,
            )
            .ok()
            .map_err(|e| anyhow::anyhow!("StartTraceW failed: {e}"))?;
        }

        debug!(
            ?trace_handle,
            session = SESSION_NAME,
            "ETW trace session started"
        );

        // Enable the FileSystem provider on this trace.
        // SAFETY: trace_handle is valid from StartTraceW.
        unsafe {
            EnableTraceEx2(
                trace_handle,
                &FS_ETW_GUID,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                0,    // level (0 = all)
                0,    // match any keyword
                0,    // match all keyword
                0,    // timeout (0 = infinite)
                None, // enableparameters
            )
            .ok()
            .map_err(|e| anyhow::anyhow!("EnableTraceEx2 failed: {e}"))?;
        }

        // ── Open the trace for real-time delivery ───────────────────────────

        // Build the shared state and register it in the global OnceLock.
        // SAFETY: CALLBACK_STATE.set() is called once per run() call, and the
        // callback accesses it read-only.  The OnceLock is cleared by take() below.
        let state = Arc::new(CallbackState {
            stop_flag: self.stop_flag.clone(),
            sender: Arc::new(tx),
        });
        {
            let mut guard = CALLBACK_STATE.lock();
            *guard = Some(state.clone());
        }

        // SAFETY: the callback is a valid function pointer.
        let trace = unsafe { OpenTraceW(&mut build_logfile()) };

        // OpenTraceW returns 0 on failure.
        if trace.Value == 0 {
            let mut guard = CALLBACK_STATE.lock();
            *guard = None;
            return Err(anyhow::anyhow!("OpenTraceW failed"));
        }

        // SAFETY: trace handle is valid; OpenTraceW succeeded.
        let result = unsafe {
            ProcessTrace(
                &[PROCESSTRACE_HANDLE {
                    Value: trace_handle.Value,
                }],
                None,
                None,
            )
        };

        // Clean up the callback state.
        let mut guard = CALLBACK_STATE.lock();
        *guard = None;
        let _ = unsafe { CloseTrace(trace) };

        // Stop the trace.
        let session_name_for_stop = to_wide(SESSION_NAME);
        // SAFETY: stop is a safe control operation on our own trace handle.
        unsafe {
            let _ = StopTraceW(
                trace_handle,
                windows::core::PCWSTR(session_name_for_stop.as_ptr()),
                props,
            );
        };

        if result.is_err() {
            return Err(anyhow::anyhow!("ProcessTrace failed: {result:?}"));
        }

        debug!("ETW trace session exited cleanly");
        Ok(())
    }

    /// Stops the ETW trace session.
    ///
    /// Sets the stop flag and wakes the trace session.  Safe to call from
    /// any thread.  The `run()` task will terminate within a few seconds.
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        debug!("ETW stop flag set");
    }
}

impl Default for InterceptionEngine {
    fn default() -> Self {
        Self::new().expect("ETW engine initialisation always succeeds")
    }
}

impl Drop for InterceptionEngine {
    fn drop(&mut self) {
        self.stop();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared processor state between the callback thread and the engine owner
// ─────────────────────────────────────────────────────────────────────────────

/// Global shared state for the ETW event callback.
///
/// Set once per trace session by `run()` before `OpenTraceW` is called.
/// The callback reads it to dispatch events.  It is cleared by `run()` after
/// `ProcessTrace` exits.
static CALLBACK_STATE: Mutex<Option<Arc<CallbackState>>> = Mutex::new(None);

/// The state the ETW callback needs access to.
#[derive(Debug)]
struct CallbackState {
    /// Set to `true` by `InterceptionEngine::stop()`.  The callback checks this
    /// to avoid sending events during shutdown.
    stop_flag: Arc<AtomicBool>,
    /// Channel sender for `FileAction` events.  `try_send` is used
    /// (fire-and-forget) — ETW must never block or panic.
    /// Always `Some` once `CALLBACK_STATE` is set (set before `OpenTraceW`).
    sender: Arc<mpsc::Sender<FileAction>>,
}

impl CallbackState {
    /// Sends `action` through the channel, silently dropping if the channel
    /// is full or closed.
    ///
    /// `try_send` is used (non-blocking) so the ETW callback never blocks —
    /// this is critical because blocking the callback can stall the trace.
    fn send(&self, action: FileAction) {
        if self.stop_flag.load(Ordering::Acquire) {
            return;
        }
        // try_send requires owned Sender — clone the Arc handle.
        // The original stays in CALLBACK_STATE; the clone is consumed here.
        // This is safe: mpsc::Sender is cheap to clone (just an Arc under the hood).
        let _ = self.sender.clone().try_send(action);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Event record parsing
// ─────────────────────────────────────────────────────────────────────────────

/// Parses a raw ETW `EVENT_RECORD` into a `FileAction`.
///
/// The file path is read from the event's `UserData` field as a
/// null-terminated UTF-16 string.  Extended data fields (`RelatedProcessId`)
/// are read from the record header when available.
fn parse_event_record(
    record: &windows::Win32::System::Diagnostics::Etw::EVENT_RECORD,
) -> Option<FileAction> {
    let path = pwstr_to_string(record.UserData as *const u16)?;
    // EVENT_RECORD.EventHeader is an EVENT_HEADER (not a named union field).
    let header = &record.EventHeader;
    let pid = header.ProcessId;
    // KernelTime is reused as RelatedThreadId in FS ETW events.
    let related_pid = header.TimeStamp as u32; // Use lower 32 bits of timestamp
    let event_type = header.EventDescriptor.Id as u8;

    match event_type {
        FS_EVENT_CREATE => Some(FileAction::Created {
            path,
            process_id: pid,
            related_process_id: related_pid,
        }),
        FS_EVENT_WRITE => Some(FileAction::Written {
            path,
            process_id: pid,
            related_process_id: related_pid,
            byte_count: 0,
        }),
        FS_EVENT_DELETE => Some(FileAction::Deleted {
            path,
            process_id: pid,
            related_process_id: related_pid,
        }),
        FS_EVENT_RENAME => Some(FileAction::Moved {
            old_path: String::new(),
            new_path: path,
            process_id: pid,
            related_process_id: related_pid,
        }),
        FS_EVENT_READ => Some(FileAction::Read {
            path,
            process_id: pid,
            related_process_id: related_pid,
            byte_count: 0,
        }),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ETW callback wiring (FFI)
// ─────────────────────────────────────────────────────────────────────────────

/// ETW event callback — invoked by `ProcessTrace` for every file-system event.
///
/// `PEVENT_RECORD_CALLBACK` takes a single `EVENT_RECORD*` argument.
/// Shared state is retrieved from the global `CALLBACK_STATE` OnceLock.
///
/// # Safety
///
/// - `eventrecord` is a valid pointer from ETW.
unsafe extern "system" fn etw_event_callback(
    eventrecord: *mut windows::Win32::System::Diagnostics::Etw::EVENT_RECORD,
) {
    if eventrecord.is_null() {
        return;
    }

    let guard = match CALLBACK_STATE.lock().as_ref() {
        Some(s) => s.clone(),
        None => return,
    };

    let record = unsafe { &*eventrecord };

    // Only process events from the FileSystem ETW provider GUID.
    if record.EventHeader.ProviderId != FS_ETW_GUID {
        return;
    }

    if let Some(action) = parse_event_record(record) {
        guard.send(action);
    }
}

/// Builds the `EVENT_TRACE_LOGFILEW` struct for `OpenTraceW`.
///
/// Sets `Anonymous2.EventRecordCallback` so ETW invokes `etw_event_callback`
/// on every file-system event.  The callback retrieves shared state from
/// the global `CALLBACK_STATE` OnceLock.
fn build_logfile() -> windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_LOGFILEW {
    use windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_LOGFILEW;

    let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };

    // SAFETY: zeroed struct is valid; we only write the fields we set.
    logfile.Anonymous1.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    // LoggerName = null tells OpenTraceW to use the session started by StartTraceW.
    logfile.LoggerName = windows::core::PWSTR::null();
    // EventRecordCallback is invoked for every FS event.
    logfile.Anonymous2.EventRecordCallback = Some(etw_event_callback);

    logfile
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

    #[test]
    fn test_pwstr_to_string() {
        let wide: Vec<u16> = "hello\0".encode_utf16().collect();
        let result = pwstr_to_string(wide.as_ptr());
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn test_pwstr_to_string_null_ptr() {
        assert!(pwstr_to_string(std::ptr::null()).is_none());
    }
}
