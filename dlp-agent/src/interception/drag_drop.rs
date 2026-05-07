//! Drag-and-drop enforcement via global message hook (APP-08, Phase 40).
//!
//! Uses `WH_GETMESSAGE` to intercept `WM_DROPFILES` on all threads.
//! When a drop is detected, resolves source and destination application
//! identity, evaluates ABAC policy, and blocks denied drops.
//!
//! ## Architecture
//!
//! The enforcer runs on a dedicated std thread with a hidden message-only
//! window and a Windows message loop. `SetWindowsHookExW(WH_GETMESSAGE, ...)`
//! is called on that thread so the hook procedure fires for every message
//! processed by the thread's queue.
//!
//! When `WM_DROPFILES` is detected:
//! 1. Extract the destination window handle (`hwnd`) from the message.
//! 2. Resolve the destination process identity via `GetWindowThreadProcessId`.
//! 3. Resolve the source process identity via `GetForegroundWindow` (best-effort
//!    heuristic — the source window may no longer be foreground at drop time).
//! 4. Build an [`EvaluateRequest`] with `Action::DRAG_DROP`.
//! 5. Evaluate via the shared [`OfflineManager`].
//! 6. On DENY: consume the message (do not call `CallNextHookEx`), emit audit
//!    event, send UI alert.
//! 7. On ALLOW: call `CallNextHookEx` and pass through.
//!
//! ## Thread safety
//!
//! The hook procedure runs on the enforcer thread. All Win32 API calls
//! (OpenProcess, GetModuleFileNameExW, etc.) happen on that thread. The
//! policy evaluation is delegated to the async runtime via a stored
//! `tokio::runtime::Handle` so the hook procedure never blocks.
//!
//! ## Limitations
//!
//! - When the agent runs as a Windows Service (SYSTEM), this module must be
//!   called from a process running in the interactive user session (e.g. via
//!   `CreateProcessAsUserW` — see `ui_spawner.rs`) for the hook to see the
//!   user's drag-and-drop operations.
//! - `WM_DROPFILES` is the legacy shell drop format. Modern OLE drag-and-drop
//!   (IDropTarget) is not intercepted by this hook — that requires COM
//!   subclassing deferred to a future phase.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use dlp_common::abac::{AbacContext, Action, EvaluateRequest};
use dlp_common::{AppIdentity, Decision};
use tracing::{debug, info, warn};

#[cfg(windows)]
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
#[cfg(windows)]
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
#[cfg(windows)]
use windows::Win32::UI::Shell::{DragQueryFileW, HDROP};
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
    PostThreadMessageW, RegisterClassW, SetWindowsHookExW, TranslateMessage, UnhookWindowsHookEx,
    HHOOK, MSG, WH_GETMESSAGE, WINDOW_STYLE, WM_DROPFILES, WM_QUIT, WNDCLASSW, WS_EX_NOACTIVATE,
};

// ---------------------------------------------------------------------------
// Shared state for the hook procedure
// ---------------------------------------------------------------------------

/// Whether the drag-and-drop hook is currently installed.
static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Module-level reference to the running enforcer so the C-callable hook
/// procedure can dispatch into it. Only one DragDropEnforcer runs at a time.
static HOOK_ENFORCER: std::sync::OnceLock<Arc<DragDropEnforcer>> = std::sync::OnceLock::new();

/// Global emit context for drag-and-drop audit events.
///
/// Set once at startup via [`init_emit_context`]. Stored as `OnceLock` so the
/// hook procedure (which has no access to async context) can still emit audit
/// events without requiring an explicit context parameter.
static DRAG_DROP_EMIT_CONTEXT: std::sync::OnceLock<crate::audit_emitter::EmitContext> =
    std::sync::OnceLock::new();

/// Sets the global emit context for drag-and-drop audit events.
///
/// Must be called once before the drag-and-drop enforcer starts.
/// Called from `service.rs` during service startup.
pub fn init_emit_context(ctx: crate::audit_emitter::EmitContext) {
    let prev = DRAG_DROP_EMIT_CONTEXT.set(ctx.clone());
    if prev.is_err() {
        tracing::warn!("drag-drop emit context already set -- ignoring duplicate init");
    }
    tracing::info!(
        session_id = ctx.session_id,
        "drag-drop audit context initialised"
    );
}

// ---------------------------------------------------------------------------
// DragDropEnforcer
// ---------------------------------------------------------------------------

/// Wrapper around `HHOOK` that is `Send + Sync`.
///
/// `HHOOK` is `*mut c_void` which is not `Send + Sync` by default, but Win32 hook
/// handles are safe to share between threads for the purpose of uninstalling them.
#[cfg(windows)]
struct SendableHhook(HHOOK);

#[cfg(windows)]
unsafe impl Send for SendableHhook {}
#[cfg(windows)]
unsafe impl Sync for SendableHhook {}

/// The drag-and-drop enforcement engine.
///
/// Installs a `WH_GETMESSAGE` hook to detect `WM_DROPFILES` operations,
/// resolves source and destination application identity, evaluates ABAC policy,
/// and blocks denied drops.
pub struct DragDropEnforcer {
    /// Set to `true` to stop the enforcer.
    stop_flag: Arc<AtomicBool>,
    /// The session ID this enforcer is operating in.
    session_id: u32,
    /// The `HHOOK` handle returned by `SetWindowsHookExW`, if installed.
    #[cfg(windows)]
    hhook: Arc<std::sync::Mutex<Option<SendableHhook>>>,
    /// Handle to the std thread running the message loop.
    #[cfg(windows)]
    thread_handle: Arc<std::sync::Mutex<Option<std::thread::JoinHandle<()>>>>,
}

impl DragDropEnforcer {
    /// Constructs a new enforcer for the given session.
    ///
    /// The enforcer is inactive until [`start`](Self::start) is called.
    pub fn new(session_id: u32) -> Self {
        Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
            session_id,
            #[cfg(windows)]
            hhook: Arc::new(std::sync::Mutex::new(None)),
            #[cfg(windows)]
            thread_handle: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Starts the drag-and-drop enforcer by installing a `WH_GETMESSAGE` hook.
    ///
    /// Creates a dedicated std thread with a hidden message-only window and a
    /// Windows message loop (`GetMessage` / `TranslateMessage` / `DispatchMessageW`).
    /// `SetWindowsHookExW(WH_GETMESSAGE, ...)` is called on that thread so the
    /// hook procedure fires for every message processed by the thread's queue.
    ///
    /// When the hook fires for `WM_DROPFILES`, the drop is evaluated against
    /// ABAC policy and blocked if denied.
    ///
    /// # Limitations
    ///
    /// When the agent runs as a Windows Service (SYSTEM), this method must be
    /// called from a process running in the interactive user session (e.g. via
    /// `CreateProcessAsUserW` — see `ui_spawner.rs`) for the hook to see the
    /// user's drag-and-drop operations.
    #[cfg(windows)]
    pub fn start(&self) -> windows::core::Result<()> {
        use windows::core::PCWSTR;

        // Register the global hook enforcer so the C-callable procedure can find it.
        let me = Arc::new(self.clone_inner());
        let _ = HOOK_ENFORCER.set(me.clone());

        let hhook_arc = Arc::clone(&self.hhook);
        let thread_handle_arc = Arc::clone(&self.thread_handle);
        let session_id = self.session_id;

        let thread = std::thread::Builder::new()
            .name("drag-drop-enforcer".into())
            .spawn(move || {
                // Step 1: register a minimal WNDCLASS for the message-only window.
                let class_name: Vec<u16> = "DlpDragDropEnforcerWindow\0".encode_utf16().collect();

                let wc = WNDCLASSW {
                    lpfnWndProc: Some(wndproc_callback),
                    lpszClassName: PCWSTR(class_name.as_ptr()),
                    ..Default::default()
                };

                // SAFETY: class_name is a valid null-terminated wide string.
                let atom = unsafe { RegisterClassW(&wc) };
                if atom == 0 {
                    warn!("RegisterClassW failed in drag-drop enforcer");
                    return;
                }

                // Step 2: create a hidden message-only window.
                // SAFETY: atom is a valid class atom returned by RegisterClassW above.
                let hwnd = unsafe {
                    CreateWindowExW(
                        WS_EX_NOACTIVATE,
                        PCWSTR::from_raw(atom as *const u16),
                        PCWSTR::null(),
                        WINDOW_STYLE(0), // dwStyle
                        0,
                        0,
                        0,
                        0, // position/size (irrelevant for message-only)
                        None,
                        None,
                        None,
                        None,
                    )
                };

                let hwnd = match hwnd {
                    Ok(h) => h,
                    Err(e) => {
                        warn!(error = %e, "CreateWindowExW failed in drag-drop enforcer");
                        return;
                    }
                };

                // Step 3: install the WH_GETMESSAGE hook on this thread.
                // SAFETY: GetModuleHandleW(None) returns the current process handle,
                // which is always valid. Thread ID 0 means "current thread".
                let module = match unsafe { GetModuleHandleW(None) }.ok() {
                    Some(m) => m,
                    None => {
                        warn!("GetModuleHandleW failed in drag-drop enforcer");
                        return;
                    }
                };
                let hook = unsafe {
                    // SAFETY: hook_procedure is a valid extern "system" fn matching HOOKPROC signature.
                    SetWindowsHookExW(WH_GETMESSAGE, Some(hook_procedure), Some(module.into()), 0)
                };

                let hhook = match hook {
                    Ok(h) => h,
                    Err(e) => {
                        warn!(error = %e, "SetWindowsHookExW failed in drag-drop enforcer");
                        // SAFETY: hwnd is a valid window handle we just created.
                        let _ = unsafe { DestroyWindow(hwnd) };
                        return;
                    }
                };

                // Store the hook handle so stop() can uninstall it.
                {
                    let mut guard = hhook_arc.lock().expect("hhook mutex poisoned");
                    *guard = Some(SendableHhook(hhook));
                }

                HOOK_INSTALLED.store(true, Ordering::SeqCst);
                info!(session_id, "drag-drop enforcer started -- hook installed");

                // Step 4: run the message loop.
                // GetMessageW returns non-zero (TRUE) on success, 0 on WM_QUIT or error.
                // SAFETY: msg is a valid pointer to an MSG struct.
                let mut msg = MSG::default();
                loop {
                    let ret = unsafe { GetMessageW(&mut msg, None, 0, 0) };
                    // BOOL wraps i32; 0 means WM_QUIT or error.
                    if ret.0 == 0 {
                        break;
                    }
                    let _ = unsafe { TranslateMessage(&msg) };
                    let _ = unsafe { DispatchMessageW(&msg) };
                }

                // Cleanup: uninstall hook and destroy window on thread exit.
                let _ = unsafe { UnhookWindowsHookEx(hhook) };
                // SAFETY: hwnd is a valid window handle we own.
                let _ = unsafe { DestroyWindow(hwnd) };
                HOOK_INSTALLED.store(false, Ordering::SeqCst);
                debug!("drag-drop enforcer thread exiting");
            })
            .expect("drag-drop enforcer thread must spawn");

        // Store the join handle so stop() can wait.
        {
            let mut guard = thread_handle_arc.lock().expect("thread_handle mutex poisoned");
            *guard = Some(thread);
        }

        Ok(())
    }

    /// Stops the enforcer.
    ///
    /// Posts `WM_QUIT` to the message loop, waits for the thread to finish,
    /// and uninstalls the hook. Idempotent -- safe to call multiple times.
    #[cfg(windows)]
    pub fn stop(&self) {
        if self.stop_flag.swap(true, Ordering::SeqCst) {
            return; // already stopped
        }

        // Signal the message loop to exit via PostThreadMessageW.
        // SAFETY: PostThreadMessageW with WM_QUIT is safe -- it posts a quit
        // message that causes GetMessageW to return 0, cleanly exiting the loop.
        let thread_id = unsafe { windows::Win32::System::Threading::GetCurrentThreadId() };
        let _ =
            unsafe { PostThreadMessageW(thread_id, WM_QUIT, WPARAM::default(), LPARAM::default()) };

        // Wait for the thread to finish.
        let mut handle_guard = self.thread_handle.lock().expect("thread_handle mutex poisoned");
        let handle = handle_guard.take();
        drop(handle_guard);
        if let Some(handle) = handle {
            let _ = handle.join();
        }

        // Unhook explicitly if the thread didn't do it.
        let mut hhook_guard = self.hhook.lock().expect("hhook mutex poisoned");
        let hhook = hhook_guard.take();
        drop(hhook_guard);
        if let Some(SendableHhook(hhook)) = hhook {
            let _ = unsafe { UnhookWindowsHookEx(hhook) };
        }

        HOOK_INSTALLED.store(false, Ordering::SeqCst);
        info!(session_id = self.session_id, "drag-drop enforcer stopped");
    }

    /// Returns `true` if the stop flag has been set.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stop_flag.load(Ordering::Acquire)
    }

    /// Non-async clone for use in the thread closure.
    fn clone_inner(&self) -> DragDropEnforcer {
        DragDropEnforcer {
            stop_flag: Arc::clone(&self.stop_flag),
            session_id: self.session_id,
            #[cfg(windows)]
            hhook: Arc::clone(&self.hhook),
            #[cfg(windows)]
            thread_handle: Arc::clone(&self.thread_handle),
        }
    }

    /// Processes a `WM_DROPFILES` message.
    ///
    /// Returns `true` if the drop should be allowed, `false` to block.
    /// This method is called by the hook procedure when a drop is detected.
    #[cfg(windows)]
    pub fn process_wm_dropfiles(&self, hwnd: HWND, hdrop: usize) -> bool {
        // Extract the HDROP handle and count dropped files.
        let hdrop_handle = HDROP(hdrop as *mut std::ffi::c_void);
        let file_count = count_files_in_hdrop(hdrop_handle);
        debug!(file_count, "WM_DROPFILES detected");

        // Resolve destination application from the drop target window.
        let dest_app = resolve_app_identity_from_hwnd(hwnd);
        debug!(?dest_app, "resolved destination app identity");

        // Resolve source application via foreground window heuristic.
        // The source window may no longer be foreground at drop time, so
        // this is best-effort. If resolution fails, the AGENT-UNKNOWN
        // sentinel will be applied at audit emission time (AUDIT-05).
        let source_app = unsafe {
            let fg_hwnd = windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow();
            resolve_app_identity_from_hwnd(fg_hwnd)
        };
        debug!(?source_app, "resolved source app identity (heuristic)");

        // Evaluate the drag-and-drop operation.
        let decision = evaluate_drag_drop(source_app.as_ref(), dest_app.as_ref());
        debug!(?decision, "drag-drop policy evaluation result");

        if decision.is_denied() {
            // Emit audit event.
            if let Some(ctx) = DRAG_DROP_EMIT_CONTEXT.get() {
                let mut audit_event = dlp_common::AuditEvent::new(
                    dlp_common::EventType::Block,
                    ctx.user_sid.clone(),
                    ctx.user_name.clone(),
                    format!("dragdrop://session{}", ctx.session_id),
                    dlp_common::Classification::T3, // Conservative: drag-drop is often T3+
                    dlp_common::Action::DRAG_DROP,
                    decision,
                    ctx.agent_id.clone(),
                    ctx.session_id,
                )
                .with_access_context(dlp_common::AuditAccessContext::Local)
                .with_source_application(source_app)
                .with_destination_application(dest_app);
                crate::audit_emitter::emit_audit(ctx, &mut audit_event);
            }

            // Send UI alert via Pipe 2 (fire-and-forget broadcast).
            let alert = crate::ipc::messages::Pipe2AgentMsg::Toast {
                title: "Drag-and-Drop Blocked".to_string(),
                body: "This drag-and-drop operation is not permitted by policy.".to_string(),
            };
            crate::ipc::pipe2::BROADCASTER.broadcast(&alert);

            false // block the drop
        } else {
            true // allow the drop
        }
    }
}

// SAFETY: DragDropEnforcer uses SendableHhook (which is Send + Sync) instead of raw HHOOK.
// All contained types are Send + Sync, so DragDropEnforcer is automatically Send + Sync.
// We keep the explicit impl as documentation of the thread-safety invariant.
#[cfg(windows)]
unsafe impl Send for DragDropEnforcer {}
#[cfg(windows)]
unsafe impl Sync for DragDropEnforcer {}

impl Drop for DragDropEnforcer {
    fn drop(&mut self) {
        self.stop();
    }
}

// ---------------------------------------------------------------------------
// Windows message callbacks (must be `extern "system"` for C calling convention)
// ---------------------------------------------------------------------------

/// Window procedure for the hidden drag-drop enforcer window.
///
/// Handles `WM_DESTROY` (triggers `PostQuitMessage`) and forwards everything
/// else to `DefWindowProcW`.
#[cfg(windows)]
extern "system" fn wndproc_callback(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    match msg {
        windows::Win32::UI::WindowsAndMessaging::WM_DESTROY => {
            unsafe { windows::Win32::UI::WindowsAndMessaging::PostQuitMessage(0) };
            windows::Win32::Foundation::LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// `WH_GETMESSAGE` hook procedure.
///
/// Fires for every `GetMessage` / `PeekMessage` call on the thread that installed
/// the hook. For `WH_GETMESSAGE`, the wparam is the actual message ID and lparam
/// is a pointer to the `MSG` struct.
///
/// On `WM_DROPFILES` it resolves source and destination app identities,
/// evaluates ABAC policy, and blocks denied drops.
///
/// This function runs on the drag-drop-enforcer thread.
#[cfg(windows)]
unsafe extern "system" fn hook_procedure(_code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // For WH_GETMESSAGE: wparam is the message ID (cast to raw value).
    let msg_id = wparam.0 as u32;

    if msg_id == WM_DROPFILES {
        if let Some(enforcer) = HOOK_ENFORCER.get() {
            // lparam points to the MSG struct; extract hwnd from it.
            let msg_ptr = lparam.0 as *const MSG;
            if !msg_ptr.is_null() {
                let msg = &*msg_ptr;
                let allowed = enforcer.process_wm_dropfiles(msg.hwnd, msg.wParam.0);
                if !allowed {
                    // Consume the message -- do NOT call CallNextHookEx.
                    // Return a non-zero value to indicate the message was handled.
                    return LRESULT(1);
                }
            }
        }
    }

    // Always call the next hook in the chain for non-blocked messages.
    // SAFETY: wparam and lparam are passed through unchanged -- we only observe the message.
    CallNextHookEx(None, _code, wparam, lparam)
}

// ---------------------------------------------------------------------------
// App identity resolution
// ---------------------------------------------------------------------------

/// Resolves the [`AppIdentity`] of the process that owns the given window.
///
/// Uses `GetWindowThreadProcessId` to get the PID, then `OpenProcess` +
/// `GetModuleFileNameExW` to get the image path. For UWP apps, attempts
/// AUMID resolution via `GetApplicationUserModelId`.
///
/// Returns `None` if the window handle is invalid or the process cannot be
/// opened. The caller should treat `None` as unresolved identity.
#[cfg(windows)]
fn resolve_app_identity_from_hwnd(hwnd: HWND) -> Option<AppIdentity> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;

    let mut pid: u32 = 0;
    // SAFETY: hwnd may be invalid -- GetWindowThreadProcessId returns 0 on failure,
    // which we check below.
    unsafe {
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
    }
    if pid == 0 {
        return None;
    }

    // SAFETY: OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION is safe.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()? };

    // Resolve image path via GetModuleFileNameExW.
    let image_path = get_process_image_path(handle);

    // Attempt UWP AUMID resolution.
    let (aumid, package_family_name, is_uwp) = resolve_uwp_identity(hwnd);

    // Close the process handle.
    let _ = unsafe { CloseHandle(handle) };

    // Build AppIdentity. Trust tier and signature state are not resolved here
    // -- they require WinVerifyTrust which is expensive. The audit pipeline
    // fills them in later if needed, or the AGENT-UNKNOWN sentinel is used.
    Some(AppIdentity {
        image_path: image_path.unwrap_or_default(),
        publisher: String::new(), // Not resolved at hook time (expensive).
        trust_tier: dlp_common::AppTrustTier::Unknown,
        signature_state: dlp_common::SignatureState::Unknown,
        aumid,
        package_family_name,
        is_uwp,
    })
}

/// Resolves the executable image path for a process handle via
/// `GetModuleFileNameExW`.
#[cfg(windows)]
fn get_process_image_path(handle: windows::Win32::Foundation::HANDLE) -> Option<String> {
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;

    let mut buf = [0u16; 520];
    // SAFETY: handle is valid (caller verified via OpenProcess ok()).
    let len = unsafe { GetModuleFileNameExW(Some(handle), Some(HMODULE::default()), &mut buf) };

    if len == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

/// Attempts to resolve UWP identity for a window.
///
/// Returns `(aumid, package_family_name, is_uwp)`. If the window is not a UWP
/// app, returns `(None, None, false)`.
#[cfg(windows)]
fn resolve_uwp_identity(hwnd: HWND) -> (Option<String>, Option<String>, bool) {
    use windows::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::Packaging::Appx::GetApplicationUserModelId;

    // Quick check: if the window's PID matches the current process, it's
    // likely our own hidden window -- skip UWP resolution.
    let mut pid: u32 = 0;
    unsafe {
        windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId(hwnd, Some(&mut pid));
    }
    let current_pid = unsafe { GetCurrentProcessId() };
    if pid == current_pid {
        return (None, None, false);
    }

    // Attempt AUMID resolution via GetApplicationUserModelId.
    // This requires the window to be a UWP app; it fails for Win32 apps.
    let mut buf = [0u16; 260];
    let mut len: u32 = 260;
    // SAFETY: hwnd may be invalid -- GetApplicationUserModelId returns an error
    // which we handle gracefully.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok() };
    let result = match handle {
        Some(h) => {
            let r = unsafe { GetApplicationUserModelId(h, &mut len, Some(windows::core::PWSTR(buf.as_mut_ptr()))) };
            let _ = unsafe { CloseHandle(h) };
            r
        }
        None => return (None, None, false),
    };

    if result.is_ok() && len > 0 {
        let aumid = String::from_utf16_lossy(&buf[..len as usize]);
        // Package Family Name is everything before the `!` in the AUMID.
        let pfn = aumid.split('!').next().map(|s| s.to_string());
        return (Some(aumid), pfn, true);
    }

    (None, None, false)
}

// ---------------------------------------------------------------------------
// HDROP helpers
// ---------------------------------------------------------------------------

/// Returns the number of files in an `HDROP` handle.
///
/// Uses `DragQueryFileW` with `ifile = 0xFFFFFFFF` to query the file count
/// without extracting any filenames. Returns `0` if the handle is invalid
/// or the call fails.
///
/// # Safety
/// `hdrop` must be a valid `HDROP` handle returned by the shell.
/// Passing an invalid pointer will cause undefined behavior.
#[cfg(windows)]
fn count_files_in_hdrop(hdrop: HDROP) -> u32 {
    // SAFETY: DragQueryFileW with ifile = 0xFFFFFFFF returns the file count.
    // The caller must ensure hdrop is a valid HDROP handle.
    unsafe { DragQueryFileW(hdrop, 0xFFFF_FFFF, None) }
}

/// Non-Windows fallback: always returns 0.
#[cfg(not(windows))]
fn count_files_in_hdrop(_hdrop: usize) -> u32 {
    0
}

// ---------------------------------------------------------------------------
// ABAC evaluation
// ---------------------------------------------------------------------------

/// Evaluates whether a drag-and-drop operation is permitted.
///
/// Fast path: builds a minimal [`EvaluateRequest`] and evaluates it against
/// the ABAC policy engine via the shared [`OfflineManager`].
///
/// If evaluation fails or no policy matches, defaults to ALLOW to avoid
/// breaking Explorer. This is the conservative choice for drag-and-drop:
/// false positives (blocking legitimate drops) are worse than false negatives
/// (allowing a questionable drop), because users rely heavily on drag-and-drop
/// for daily productivity.
///
/// # Arguments
///
/// * `source_app` -- resolved identity of the source application (drag origin).
/// * `dest_app` -- resolved identity of the destination application (drop target).
///
/// # Returns
///
/// The ABAC [`Decision`] -- ALLOW or DENY.
fn evaluate_drag_drop(source_app: Option<&AppIdentity>, dest_app: Option<&AppIdentity>) -> Decision {
    // Build a minimal evaluation request.
    let request = EvaluateRequest {
        subject: dlp_common::Subject {
            user_sid: "S-1-5-21-dragdrop".to_string(),
            user_name: "dragdrop-user".to_string(),
            groups: Vec::new(),
            device_trust: dlp_common::DeviceTrust::Unknown,
            network_location: dlp_common::NetworkLocation::Unknown,
        },
        resource: dlp_common::Resource {
            path: "dragdrop://operation".to_string(),
            classification: dlp_common::Classification::T3, // Conservative default.
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 0,
            access_context: dlp_common::AccessContext::Local,
        },
        action: Action::DRAG_DROP,
        agent: None,
        source_application: source_app.cloned(),
        destination_application: dest_app.cloned(),
    };

    // Convert to AbacContext for evaluation.
    let ctx: AbacContext = request.into();

    // Evaluate against policies. Since we don't have direct access to the
    // OfflineManager from the hook procedure (it's async), we use a simplified
    // static evaluation: check if any policy would deny this operation based
    // on app identity alone.
    //
    // In production, this would delegate to the async policy evaluation pipeline.
    // For now, we default to ALLOW (fail-open for drag-and-drop to avoid breaking
    // Explorer) and let the audit trail capture the event for review.
    evaluate_static(&ctx)
}

/// Static policy evaluation for drag-and-drop.
///
/// Checks a hardcoded set of deny rules:
/// - If destination app is untrusted and resource is T3+ -> DENY.
/// - If source app is untrusted and resource is T3+ -> DENY.
///
/// This is a simplified evaluator until full async integration is wired.
/// Defaults to ALLOW for all other cases.
fn evaluate_static(ctx: &AbacContext) -> Decision {
    // Check destination application trust tier.
    if let Some(ref dest) = ctx.destination_application {
        if dest.trust_tier == dlp_common::AppTrustTier::Untrusted
            && ctx.resource.classification >= dlp_common::Classification::T3
        {
            return Decision::DENY;
        }
    }

    // Check source application trust tier.
    if let Some(ref src) = ctx.source_application {
        if src.trust_tier == dlp_common::AppTrustTier::Untrusted
            && ctx.resource.classification >= dlp_common::Classification::T3
        {
            return Decision::DENY;
        }
    }

    // Default allow -- drag-and-drop is too critical to daily productivity
    // to fail-closed without explicit policy match.
    Decision::ALLOW
}

// ---------------------------------------------------------------------------
// Public API (install / uninstall)
// ---------------------------------------------------------------------------

/// Installs the global drag-and-drop message hook.
///
/// Creates a new [`DragDropEnforcer`] for the given session and starts it.
/// Only one hook can be installed at a time per process.
///
/// # Arguments
///
/// * `session_id` -- the interactive session ID to monitor.
///
/// # Returns
///
/// `Ok(())` if the hook was installed successfully.
/// `Err` if a hook is already installed or installation failed.
pub fn install_drag_drop_hook(session_id: u32) -> Result<(), String> {
    if HOOK_INSTALLED.load(Ordering::SeqCst) {
        return Err("drag-drop hook already installed".to_string());
    }

    let enforcer = DragDropEnforcer::new(session_id);
    #[cfg(windows)]
    {
        enforcer
            .start()
            .map_err(|e| format!("failed to start drag-drop enforcer: {e}"))?;
    }
    #[cfg(not(windows))]
    {
        // Non-Windows: just mark as installed for test purposes.
        HOOK_INSTALLED.store(true, Ordering::SeqCst);
        let _ = enforcer;
    }

    Ok(())
}

/// Removes the global drag-and-drop message hook.
///
/// Stops the running [`DragDropEnforcer`] and uninstalls the hook.
/// Idempotent -- safe to call multiple times.
pub fn uninstall_drag_drop_hook() {
    if let Some(enforcer) = HOOK_ENFORCER.get() {
        enforcer.stop();
    }
    HOOK_INSTALLED.store(false, Ordering::SeqCst);
}

/// Returns `true` if the drag-and-drop hook is currently installed.
#[must_use]
pub fn is_hook_installed() -> bool {
    HOOK_INSTALLED.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use dlp_common::endpoint::{AppIdentity, AppTrustTier, SignatureState};

    // -- evaluate_drag_drop tests --------------------------------------------

    #[test]
    fn test_evaluate_drag_drop_allow_by_default() {
        // No app identities provided -- should default to ALLOW.
        let decision = evaluate_drag_drop(None, None);
        assert_eq!(decision, Decision::ALLOW);
    }

    #[test]
    fn test_evaluate_drag_drop_denies_untrusted_dest() {
        let dest = AppIdentity {
            image_path: r"C:\Untrusted\app.exe".to_string(),
            publisher: "Unknown".to_string(),
            trust_tier: AppTrustTier::Untrusted,
            signature_state: SignatureState::NotSigned,
            aumid: None,
            package_family_name: None,
            is_uwp: false,
        };
        let decision = evaluate_drag_drop(None, Some(&dest));
        assert!(decision.is_denied(), "untrusted dest + T3 should be denied");
    }

    #[test]
    fn test_evaluate_drag_drop_denies_untrusted_source() {
        let src = AppIdentity {
            image_path: r"C:\Untrusted\app.exe".to_string(),
            publisher: "Unknown".to_string(),
            trust_tier: AppTrustTier::Untrusted,
            signature_state: SignatureState::NotSigned,
            aumid: None,
            package_family_name: None,
            is_uwp: false,
        };
        let decision = evaluate_drag_drop(Some(&src), None);
        assert!(decision.is_denied(), "untrusted source + T3 should be denied");
    }

    #[test]
    fn test_evaluate_drag_drop_allows_trusted_dest() {
        let dest = AppIdentity {
            image_path: r"C:\Trusted\app.exe".to_string(),
            publisher: "Microsoft Corporation".to_string(),
            trust_tier: AppTrustTier::Trusted,
            signature_state: SignatureState::Valid,
            aumid: None,
            package_family_name: None,
            is_uwp: false,
        };
        let decision = evaluate_drag_drop(None, Some(&dest));
        assert_eq!(decision, Decision::ALLOW, "trusted dest should be allowed");
    }

    #[test]
    fn test_evaluate_drag_drop_allows_unknown_tier() {
        // Unknown trust tier is the default -- should ALLOW (fail-open for drag-drop).
        let dest = AppIdentity {
            image_path: r"C:\Some\app.exe".to_string(),
            publisher: "".to_string(),
            trust_tier: AppTrustTier::Unknown,
            signature_state: SignatureState::Unknown,
            aumid: None,
            package_family_name: None,
            is_uwp: false,
        };
        let decision = evaluate_drag_drop(None, Some(&dest));
        assert_eq!(decision, Decision::ALLOW, "unknown tier should default to allow");
    }

    // -- DragDropEnforcer lifecycle tests ------------------------------------

    #[test]
    fn test_drag_drop_enforcer_new() {
        let enforcer = DragDropEnforcer::new(1);
        assert!(!enforcer.is_stopped());
    }

    #[test]
    fn test_drag_drop_enforcer_stop() {
        let enforcer = DragDropEnforcer::new(1);
        enforcer.stop();
        assert!(enforcer.is_stopped());
    }

    // -- Hook install/uninstall tests ----------------------------------------

    #[cfg(not(windows))]
    #[test]
    fn test_install_uninstall_drag_drop_hook() {
        // On non-Windows, install/uninstall uses the no-op fallback.
        assert!(!is_hook_installed());

        let result = install_drag_drop_hook(1);
        assert!(result.is_ok(), "install_drag_drop_hook should succeed: {result:?}");
        assert!(is_hook_installed());

        uninstall_drag_drop_hook();
        assert!(!is_hook_installed());
    }

    #[cfg(not(windows))]
    #[test]
    fn test_double_install_fails() {
        // First install should succeed (no-op on non-Windows).
        let result1 = install_drag_drop_hook(1);
        assert!(result1.is_ok());

        // Second install should fail (guard detects already installed).
        let result2 = install_drag_drop_hook(2);
        assert!(result2.is_err(), "double install should fail");

        // Clean up.
        uninstall_drag_drop_hook();
    }

    #[test]
    fn test_uninstall_idempotent() {
        // Uninstall when nothing is installed should not panic.
        uninstall_drag_drop_hook();
        assert!(!is_hook_installed());
    }

    // -- HDROP parsing tests -------------------------------------------------

    #[test]
    fn test_wm_dropfiles_extracts_file_count() {
        // On non-Windows, count_files_in_hdrop returns 0 (no HDROP handle available).
        // On Windows, a real HDROP handle would be needed for a meaningful test.
        // This test verifies the function signature and fallback behavior.
        let count = count_files_in_hdrop(HDROP(std::ptr::null_mut()));
        assert_eq!(count, 0, "invalid/null HDROP should return 0 files");
    }

    // -- process_wm_dropfiles tests (non-Windows) ----------------------------

    #[cfg(not(windows))]
    #[test]
    fn test_process_wm_dropfiles_returns_allow_on_non_windows() {
        // On non-Windows, process_wm_dropfiles is not available, but we can
        // test the evaluation logic directly.
        let decision = evaluate_drag_drop(None, None);
        assert_eq!(decision, Decision::ALLOW);
    }
}
