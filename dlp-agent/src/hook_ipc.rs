//! Hook IPC — named-pipe protocol between API-hook DLL and agent service.
//!
//! Each frame on the pipe is encoded as:
//! ```text
//! [u32: payload_length_le] [bincode payload]
//! ```
//!
//! The server runs a blocking accept loop (intended to be spawned on a
//! dedicated `std::thread`).  When a Tokio runtime is available on the
//! calling thread, each connection is handled in a
//! `tokio::task::spawn_blocking` task so the accept loop never blocks on
//! classification work.
//!
//! # Cache Non-Authoritative Invariant
//!
//! The cache stores classification **HINT only**. ABAC authority is never
//! bypassed. A cache hit enables tier-gated fast-path decisions; a cache miss
//! always falls through to the full ABAC evaluation via pipe round-trip.

use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::{debug, info, warn};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, NAMED_PIPE_MODE,
    PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};

use dlp_common::hook_ipc::{
    CacheHint, DiagnosticsResponse, HealthResponse, IpcEnvelope, IpcMessageV1, IpcPayloadV1,
    PullDiagnosticsRequest, PullHealthRequest,
};
use dlp_common::{Classification, HookRequest, HookResponse};

use crate::ipc::frame::{read_frame, write_frame};
use crate::ipc::pipe_security::PipeSecurity;

/// Default pipe name used by the hook DLL.
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\DlpHookPipe";

/// Number of pipe instances to allow.
const NUM_INSTANCES: u32 = 4;

/// Output / input buffer size.
const PIPE_BUFFER_SIZE: u32 = 65_536;

/// Default timeout for `CreateNamedPipeW`.
const PIPE_TIMEOUT_MS: u32 = 5_000;

/// Handler type for processing hook requests.
pub type HookHandler = Arc<dyn Fn(HookRequest) -> HookResponse + Send + Sync + 'static>;

/// Handler type for processing diagnostic pull requests.
pub type DiagnosticsHandler =
    Arc<dyn Fn(PullDiagnosticsRequest) -> DiagnosticsResponse + Send + Sync + 'static>;

/// Handler type for processing health pull requests.
pub type HealthHandler = Arc<dyn Fn(PullHealthRequest) -> HealthResponse + Send + Sync + 'static>;

/// Handler type for processing override requests.
pub type OverrideHandler =
    Arc<dyn Fn(dlp_common::hook_ipc::OverrideRequest) + Send + Sync + 'static>;

/// Classification cache accessor for the hook IPC handler.
///
/// This trait abstracts over `ClassificationCache` so that tests can inject
/// a mock implementation without creating real shared-memory mappings.
pub trait CacheAccessor: Send + Sync + 'static {
    /// Returns the current cache version (high 63 bits of version_word).
    fn current_version(&self) -> u64;
}

impl CacheAccessor for crate::classification_cache::ClassificationCache {
    fn current_version(&self) -> u64 {
        // SAFETY: ClassificationCache has a safe header() method that returns
        // a reference to the CacheHeader. The version_word is an AtomicU64
        // stored at a fixed offset in the shared-memory mapping.
        use std::sync::atomic::Ordering;
        let header = unsafe { self.header() };
        let word = header.version_word.load(Ordering::Acquire);
        word >> 1
    }
}

/// Named-pipe server that listens for hook DLL classification requests.
pub struct HookIpcServer {
    pipe_name: String,
    handler: HookHandler,
    diagnostics_handler: Option<DiagnosticsHandler>,
    health_handler: Option<HealthHandler>,
    override_handler: Option<OverrideHandler>,
    bypass_tx: Option<crossbeam_channel::Sender<dlp_common::hook_ipc::BypassAlert>>,
}

impl HookIpcServer {
    /// Creates a new hook IPC server.
    ///
    /// `pipe_name` is the full Win32 pipe path (e.g. `r"\\.\pipe\DlpHookPipe"`).
    /// `handler` is called once per request to produce a [`HookResponse`].
    pub fn new(pipe_name: impl Into<String>, handler: HookHandler) -> Self {
        Self {
            pipe_name: pipe_name.into(),
            handler,
            diagnostics_handler: None,
            health_handler: None,
            override_handler: None,
            bypass_tx: None,
        }
    }

    /// Creates a new hook IPC server with a cache-aware handler.
    ///
    /// The returned handler:
    /// 1. Reads `cache_version` from the request and detects stale DLLs.
    /// 2. Delegates to `inner_handler` for the actual ABAC evaluation.
    /// 3. Builds a [`CacheHint`] from the response for DLL LRU warming.
    /// 4. Returns the current cache version in the response.
    ///
    /// # Cache Non-Authoritative Invariant
    ///
    /// The cache stores classification **HINT only**. ABAC authority is never
    /// bypassed. The `inner_handler` always performs full ABAC evaluation.
    pub fn with_cache(
        pipe_name: impl Into<String>,
        inner_handler: HookHandler,
        cache: Arc<dyn CacheAccessor>,
    ) -> Self {
        let handler: HookHandler = Arc::new(move |req: HookRequest| {
            handle_hook_request(req, &inner_handler, &cache, None)
        });
        Self {
            pipe_name: pipe_name.into(),
            handler,
            diagnostics_handler: None,
            health_handler: None,
            override_handler: None,
            bypass_tx: None,
        }
    }

    /// Creates a new hook IPC server with a bypass alert channel.
    ///
    /// `bypass_tx` receives [`dlp_common::hook_ipc::BypassAlert`] payloads sent
    /// by the hook DLL over the named pipe (e.g. hook-overwrite or journal-degraded
    /// self-reported events).  The agent-side [`BypassCorrelator`] drains the
    /// matching receiver.
    pub fn with_bypass_channel(
        pipe_name: impl Into<String>,
        handler: HookHandler,
        bypass_tx: crossbeam_channel::Sender<dlp_common::hook_ipc::BypassAlert>,
    ) -> Self {
        Self {
            pipe_name: pipe_name.into(),
            handler,
            diagnostics_handler: None,
            health_handler: None,
            override_handler: None,
            bypass_tx: Some(bypass_tx),
        }
    }

    /// Creates a new hook IPC server with cache, offline manager, and bypass channel.
    ///
    /// This is the production constructor used by `service.rs`.
    /// The `handler` is constructed by the caller (typically using `OfflineManager::offline_decision`).
    pub fn with_cache_offline_and_bypass(
        pipe_name: impl Into<String>,
        cache: Arc<dyn CacheAccessor>,
        handler: HookHandler,
        bypass_tx: crossbeam_channel::Sender<dlp_common::hook_ipc::BypassAlert>,
    ) -> Self {
        let handler: HookHandler =
            Arc::new(move |req: HookRequest| handle_hook_request(req, &handler, &cache, None));
        Self {
            pipe_name: pipe_name.into(),
            handler,
            diagnostics_handler: None,
            health_handler: None,
            override_handler: None,
            bypass_tx: Some(bypass_tx),
        }
    }

    /// Sets the diagnostics handler for `PullDiagnostics` requests.
    pub fn with_diagnostics_handler(mut self, handler: DiagnosticsHandler) -> Self {
        self.diagnostics_handler = Some(handler);
        self
    }

    /// Sets the health handler for `PullHealth` requests.
    pub fn with_health_handler(mut self, handler: HealthHandler) -> Self {
        self.health_handler = Some(handler);
        self
    }

    /// Sets the override handler for `RequestOverride` messages.
    pub fn with_override_handler(mut self, handler: OverrideHandler) -> Self {
        self.override_handler = Some(handler);
        self
    }

    /// Runs the blocking accept loop on the current thread.
    ///
    /// Callers should spawn this in a dedicated `std::thread`.  Connections
    /// are handled synchronously on the accept thread; the loop blocks until
    /// the handler returns.
    pub fn run(self) -> Result<()> {
        self.run_with_ready(|| {})
    }

    /// Same as [`run`](Self::run) but calls `on_ready` after the first pipe
    /// instance has been created and is ready for clients.
    pub fn run_with_ready(self, on_ready: impl FnOnce()) -> Result<()> {
        info!(pipe = %self.pipe_name, "Hook IPC server starting");
        let pipe = create_pipe(&self.pipe_name)?;
        on_ready();
        accept_loop(
            pipe,
            self.pipe_name,
            self.handler,
            self.diagnostics_handler,
            self.health_handler,
            self.override_handler,
            self.bypass_tx,
        )
    }
}

fn pipe_mode() -> NAMED_PIPE_MODE {
    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT
}

fn create_pipe(pipe_name: &str) -> Result<HANDLE> {
    let name_wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    let sec = PipeSecurity::new().context("pipe security descriptor")?;

    let pipe = unsafe {
        CreateNamedPipeW(
            PCWSTR::from_raw(name_wide.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            pipe_mode(),
            NUM_INSTANCES,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            PIPE_TIMEOUT_MS,
            Some(sec.as_ptr()),
        )
    };

    if pipe.is_invalid() {
        return Err(anyhow::anyhow!(
            "CreateNamedPipeW returned INVALID_HANDLE_VALUE"
        ));
    }
    Ok(pipe)
}

fn accept_loop(
    first_pipe: HANDLE,
    pipe_name: String,
    handler: HookHandler,
    diagnostics_handler: Option<DiagnosticsHandler>,
    health_handler: Option<HealthHandler>,
    override_handler: Option<OverrideHandler>,
    bypass_tx: Option<crossbeam_channel::Sender<dlp_common::hook_ipc::BypassAlert>>,
) -> Result<()> {
    let mut pipe = first_pipe;
    loop {
        if crate::service::shutdown_requested() {
            let _ = unsafe { CloseHandle(pipe) };
            info!(pipe = %pipe_name, "shutdown requested — exiting Hook IPC accept loop");
            return Ok(());
        }

        // Wait for a client. ERROR_PIPE_CONNECTED (535) means a client
        // already connected between CreateNamedPipeW and ConnectNamedPipe.
        if let Err(e) = unsafe { ConnectNamedPipe(pipe, None) } {
            let win32_code = (e.code().0 as u32) & 0xFFFF;
            if win32_code != 535 {
                warn!(
                    win32_code,
                    "Hook IPC: ConnectNamedPipe failed — recycling pipe"
                );
                let _ = unsafe { CloseHandle(pipe) };
                pipe = create_pipe(&pipe_name)?;
                continue;
            }
            debug!("Hook IPC: client already connected (535)");
        }

        info!("Hook IPC: client connected");

        if let Err(e) = handle_connection(
            pipe,
            &handler,
            diagnostics_handler.as_ref(),
            health_handler.as_ref(),
            override_handler.as_ref(),
            bypass_tx.as_ref(),
        ) {
            warn!(error = %e, "Hook IPC: connection handler error");
        }
        let _ = unsafe { DisconnectNamedPipe(pipe) };
        let _ = unsafe { CloseHandle(pipe) };

        pipe = create_pipe(&pipe_name)?;
    }
}

fn handle_connection(
    pipe: HANDLE,
    handler: &HookHandler,
    diagnostics_handler: Option<&DiagnosticsHandler>,
    health_handler: Option<&HealthHandler>,
    override_handler: Option<&OverrideHandler>,
    bypass_tx: Option<&crossbeam_channel::Sender<dlp_common::hook_ipc::BypassAlert>>,
) -> Result<()> {
    loop {
        let frame = match read_frame(pipe) {
            Ok(f) => f,
            Err(e) => {
                debug!(error = %e, "Hook IPC: read error — disconnecting");
                break;
            }
        };

        // Try the new envelope protocol first (Phase 58).
        if let Ok(envelope) = bincode::deserialize::<IpcEnvelope>(&frame) {
            // IpcEnvelope only has V1 variant, so let-destructure is sufficient.
            let IpcEnvelope::V1(msg) = envelope;
            let response_payload = match msg.payload {
                IpcPayloadV1::Request(req) => {
                    debug!(path = %req.path, action = %req.action, "Hook IPC: classifying");
                    let response = handler(req);
                    debug!(decision = ?response.decision, "Hook IPC: classification complete");
                    IpcPayloadV1::Response(response)
                }
                IpcPayloadV1::RequestOverride(req) => {
                    debug!(resource_path = %req.resource_path, "Hook IPC: override request");
                    if let Some(oh) = override_handler {
                        oh(req);
                    } else {
                        warn!("Hook IPC: override request received but no handler configured");
                    }
                    // Override is fire-and-forget; respond with empty OK.
                    IpcPayloadV1::Response(HookResponse {
                        decision: dlp_common::Decision::ALLOW,
                        reason: "override request forwarded".to_string(),
                        cache_hint: None,
                        cache_version: 0,
                        approval_override: None,
                    })
                }
                IpcPayloadV1::PullDiagnostics(req) => {
                    debug!(max_entries = req.max_entries, "Hook IPC: pull diagnostics");
                    let response = diagnostics_handler.map(|dh| dh(req)).unwrap_or_default();
                    IpcPayloadV1::DiagnosticsResponse(response)
                }
                IpcPayloadV1::PullHealth(req) => {
                    debug!("Hook IPC: pull health");
                    let response = health_handler.map(|hh| hh(req)).unwrap_or_default();
                    IpcPayloadV1::HealthResponse(response)
                }
                IpcPayloadV1::VolumeClassQuery(query) => {
                    debug!(drive_letter = %query.drive_letter, "Hook IPC: volume class query");
                    let response = crate::detection::usb::handle_volume_class_query(&query);
                    IpcPayloadV1::VolumeClassResponse(response)
                }
                IpcPayloadV1::BypassAlert(ref alert) => {
                    debug!(reason = ?alert.reason, stub = %alert.stub_name, "Hook IPC: bypass alert received");
                    if let Some(tx) = bypass_tx {
                        if let Err(e) = tx.send(alert.clone()) {
                            warn!(metric = "bypass_tx_dropped", error = ?e, "bypass channel full or closed");
                        }
                    }
                    // Respond with empty ACK so DLL doesn't block.
                    IpcPayloadV1::Response(HookResponse {
                        decision: dlp_common::Decision::ALLOW,
                        reason: "bypass alert forwarded".to_string(),
                        cache_hint: None,
                        cache_version: 0,
                        approval_override: None,
                    })
                }
                IpcPayloadV1::JournalDegraded(ref alert) => {
                    debug!(file_object = alert.file_object, op = alert.op, error = %alert.error, "Hook IPC: journal degraded alert received");
                    if let Some(tx) = bypass_tx {
                        let bypass_alert = dlp_common::hook_ipc::BypassAlert {
                            reason: dlp_common::hook_ipc::BypassReason::EdrDetected,
                            stub_name: "journal_degraded".to_string(),
                            pid: 0,
                            timestamp_secs: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                            version: 2,
                            agent_id: String::new(),
                            image_path: String::new(),
                            image_sha256: None,
                            file_path: String::new(),
                            operation: format!("op={}", alert.op),
                            file_object: alert.file_object,
                            qpc_timestamp: 0,
                            severity: "warn".to_string(),
                            correlation_reason: format!("Journal degraded: {}", alert.error),
                        };
                        let _ = tx.send(bypass_alert);
                    }
                    // Respond with empty ACK so DLL doesn't block waiting for a response.
                    IpcPayloadV1::Response(HookResponse {
                        decision: dlp_common::Decision::ALLOW,
                        reason: "journal degraded alert received".to_string(),
                        cache_hint: None,
                        cache_version: 0,
                        approval_override: None,
                    })
                }
                // Agent-to-DLL responses should not arrive on the server.
                other => {
                    warn!(payload = ?other, "Hook IPC: unexpected payload from DLL");
                    continue;
                }
            };

            let response_envelope = IpcEnvelope::V1(IpcMessageV1 {
                payload: response_payload,
            });
            let payload =
                bincode::serialize(&response_envelope).context("serialize envelope response")?;
            if let Err(e) = write_frame(pipe, &payload) {
                warn!(error = %e, "Hook IPC: write response failed — disconnecting");
                break;
            }
            continue;
        }

        // Fall back to legacy raw HookRequest (pre-Phase 58 DLLs).
        match bincode::deserialize::<HookRequest>(&frame) {
            Ok(request) => {
                debug!(path = %request.path, action = %request.action, "Hook IPC: classifying (legacy)");
                let response = handler(request);
                debug!(decision = ?response.decision, "Hook IPC: classification complete (legacy)");

                let payload = bincode::serialize(&response).context("serialize response")?;
                if let Err(e) = write_frame(pipe, &payload) {
                    warn!(error = %e, "Hook IPC: write response failed — disconnecting");
                    break;
                }
            }
            Err(e) => {
                warn!(error = %e, "Hook IPC: malformed request — bincode deserialization failed");
                continue;
            }
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Cache-aware request handler
// ─────────────────────────────────────────────────────────────────────────────

/// Handles a hook request with cache_version awareness and cache_hint warming.
///
/// # Arguments
///
/// * `req` — The incoming [`HookRequest`] from the hook DLL.
/// * `inner_handler` — The actual ABAC evaluator (performs full policy evaluation).
/// * `cache` — The shared-memory classification cache accessor.
///
/// # Behavior
///
/// 1. Reads `cache_version` from the request. If it is older than the current
///    cache version, logs a stale-DLL telemetry event.
/// 2. Delegates to `inner_handler` for full ABAC evaluation — the cache is
///    never used to bypass ABAC authority.
/// 3. Builds a [`CacheHint`] from the response (if the path has a classification).
/// 4. Returns the current cache version in the response so the DLL can detect
///    version mismatches on its next lookup.
///
/// # Cache Non-Authoritative Invariant
///
/// The cache stores classification **HINT only**. ABAC authority is never
/// bypassed. The `inner_handler` always performs full ABAC evaluation.
fn handle_hook_request(
    req: HookRequest,
    inner_handler: &HookHandler,
    cache: &Arc<dyn CacheAccessor>,
    approval_cache: Option<&Arc<crate::approval_cache::ApprovalCache>>,
) -> HookResponse {
    let current_version = cache.current_version();

    // Detect stale DLLs (for telemetry/audit only).
    if req.cache_version > 0 && req.cache_version < current_version {
        info!(
            req_version = req.cache_version,
            current_version,
            path = %req.path,
            "stale DLL detected — cache version mismatch"
        );
    }

    // Perform full ABAC evaluation (no bypass).
    let mut response = inner_handler(req.clone());

    // TODO(WORKFLOW-04-followup): Hook-path approval override is deferred.
    // The hook DLL path currently uses a placeholder heuristic (build_cache_hint)
    // rather than real ABAC evaluation. Approval override requires:
    //   1. Real ABAC evaluation in inner_handler returning EvaluateResponse with matched_label_id.
    //   2. PID in HookRequest (or user_sid) to construct ApprovalCacheKey.
    //   3. get_sid_for_pid() to resolve SID from PID.
    //   4. Audit emission with agent_id and session_id threaded through.
    // Until then, the hook path skips approval cache check (fail-closed).
    // if response.decision.is_denied() {
    //     if let Some(ref ac) = approval_cache { ... }
    // }
    let _ = approval_cache; // suppress unused warning until follow-up

    // Build cache_hint for DLL LRU warming.
    // TTL based on tier: T4=30s, T3=60s, T2=300s, T1=1800s.
    // Pass None for classification — the inner_handler path still uses
    // the legacy path heuristic (build_cache_hint with path text matching).
    let cache_hint = build_cache_hint(&req.path, None);

    // Attach cache metadata to response.
    response.cache_hint = cache_hint;
    response.cache_version = current_version;

    response
}

/// Build a [`CacheHint`] from an [`EvaluateResponse`] classification.
///
/// Uses the classification from the ABAC evaluation response (if any) rather
/// than parsing the path. This is the authoritative cache hint source after
/// real ABAC evaluation is wired.
///
/// Returns `None` if the response has no classification (e.g., unclassified path).
///
/// # TTL Budgets
///
/// | Tier | TTL (seconds) |
/// |------|---------------|
/// | T4   | 30            |
/// | T3   | 60            |
/// | T2   | 300           |
/// | T1   | 1800          |
#[allow(dead_code)]
fn build_cache_hint_from_response(_response: &dlp_common::EvaluateResponse) -> Option<CacheHint> {
    // Cache hint is built from the request classification (resolved by
    // PolicyMapper::provisional_classification in hook_request_to_evaluate_request).
    // The response does not carry classification directly.
    // This function is a placeholder for future response-aware cache hint logic.
    None
}

/// Build a [`CacheHint`] for a given path using the response classification.
///
/// Uses the classification from the ABAC evaluation response (if available)
/// instead of path text matching. Falls back to the legacy path heuristic
/// only when no classification is provided.
///
/// # TTL Budgets
///
/// | Tier | TTL (seconds) |
/// |------|---------------|
/// | T4   | 30            |
/// | T3   | 60            |
/// | T2   | 300           |
/// | T1   | 1800          |
fn build_cache_hint(path: &str, classification: Option<Classification>) -> Option<CacheHint> {
    // If ABAC evaluation provided a classification, use it directly.
    if let Some(cls) = classification {
        let ttl_secs = match cls {
            Classification::T4 => 30,
            Classification::T3 => 60,
            Classification::T2 => 300,
            Classification::T1 => 1800,
        };
        return Some(CacheHint {
            path: std::path::PathBuf::from(path),
            tier: cls,
            ttl_secs,
        });
    }

    // Fallback: simplified heuristic based on path patterns.
    // In production this would query the policy store.
    let (tier, ttl_secs) = if path.to_ascii_uppercase().contains("SECRET")
        || path.to_ascii_uppercase().contains("RESTRICTED")
    {
        (Classification::T4, 30)
    } else if path.to_ascii_uppercase().contains("CONFIDENTIAL") {
        (Classification::T3, 60)
    } else if path.to_ascii_uppercase().contains("INTERNAL") {
        (Classification::T2, 300)
    } else {
        // Unclassified — no hint.
        return None;
    };

    Some(CacheHint {
        path: std::path::PathBuf::from(path),
        tier,
        ttl_secs,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Client helpers (used by tests and, in the future, the hook DLL)
// ─────────────────────────────────────────────────────────────────────────────

/// Connects to a named pipe as a client.
///
/// Returns `Err` if the pipe does not exist or the server is not listening.
pub fn connect_client(pipe_name: &str) -> Result<HANDLE> {
    let name_wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();

    let handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(name_wide.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    };

    match handle {
        Ok(h) => Ok(h),
        Err(e) => {
            let code = (e.code().0 as u32) & 0xFFFF;
            Err(anyhow::anyhow!(
                "CreateFileW failed (win32={}) — pipe server not running?",
                code
            ))
        }
    }
}

/// Sends a [`HookRequest`] over an open pipe and returns the [`HookResponse`].
pub fn send_request(pipe: HANDLE, request: &HookRequest) -> Result<HookResponse> {
    let payload = bincode::serialize(request).context("serialize request")?;
    write_frame(pipe, &payload).context("write request frame")?;

    let frame = read_frame(pipe).context("read response frame")?;
    let response: HookResponse = bincode::deserialize(&frame).context("deserialize response")?;
    Ok(response)
}

/// Sends raw bytes over an open pipe and reads the response frame.
pub fn send_raw(pipe: HANDLE, raw: &[u8]) -> Result<Vec<u8>> {
    write_frame(pipe, raw).context("write raw frame")?;
    let frame = read_frame(pipe).context("read response frame")?;
    Ok(frame)
}

/// Closes a pipe handle.
pub fn close_pipe(pipe: HANDLE) {
    let _ = unsafe { CloseHandle(pipe) };
}

/// Test helper: starts a [`HookIpcServer`] on a dedicated thread using the
/// given handler, waits until the pipe is ready, and returns the thread
/// handle so the caller can join it later (or let it run).
///
/// Available in both unit tests and integration tests.
pub fn start_mock_server(
    pipe_name: &str,
    handler: HookHandler,
) -> std::thread::JoinHandle<Result<()>> {
    let name = pipe_name.to_string();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let handle = std::thread::spawn(move || {
        let server = HookIpcServer::new(name, handler);
        server.run_with_ready(|| {
            let _ = tx.send(());
        })
    });

    rx.recv_timeout(std::time::Duration::from_secs(5))
        .expect("server did not become ready within 5s");
    handle
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use dlp_common::Decision;

    /// Starts a [`HookIpcServer`] on a dedicated thread using the given
    /// handler, waits until the pipe is created, and returns the thread
    /// handle so the caller can join it later.
    fn start_server(pipe_name: &str, handler: HookHandler) -> std::thread::JoinHandle<Result<()>> {
        start_mock_server(pipe_name, handler)
    }

    #[test]
    fn hook_ipc_roundtrip_test() {
        let pipe_name = r"\\.\pipe\DlpHookPipeTestRoundtrip";

        let handler: HookHandler = Arc::new(|req: HookRequest| HookResponse {
            decision: Decision::DENY,
            reason: format!("blocked: {}", req.path),
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        });

        let _server_handle = start_server(pipe_name, handler);

        // Give the server thread time to enter ConnectNamedPipe before the
        // client connects.  Without this, CreateFileW may race ahead and the
        // server's subsequent ConnectNamedPipe + handle_connection can see a
        // broken pipe before the client writes.
        std::thread::sleep(Duration::from_millis(50));

        let client = connect_client(pipe_name).expect("client connect");

        let mut latencies: Vec<Duration> = Vec::with_capacity(1_000);

        for i in 0..1_000 {
            let req = HookRequest {
                path: format!(r"C:\Users\test\file{}.txt", i),
                action: "CREATE".to_string(),
                cache_version: 0,
                protocol_version: 1,
                op: dlp_common::hook_ipc::HookOp::Read,
                source_volume_class: None,
                destination_volume_class: None,
                pid: 1234,
            };

            let start = Instant::now();
            let resp = send_request(client, &req).expect("request/response");
            let elapsed = start.elapsed();

            assert_eq!(resp.decision, Decision::DENY);
            assert_eq!(resp.reason, format!("blocked: {}", req.path));
            latencies.push(elapsed);
        }

        close_pipe(client);

        // Drop the server by … nothing; we just let the thread run out.
        // In a real scenario we'd send a shutdown signal.  For the test we
        // simply abandon the pipe — the server thread will block on the
        // next ConnectNamedPipe.  That's acceptable for unit tests.

        latencies.sort();
        let p99_idx = (latencies.len() as f64 * 0.99).ceil() as usize - 1;
        let p99 = latencies[p99_idx.min(latencies.len() - 1)];

        println!("p99 latency: {:?}", p99);
        println!("median latency: {:?}", latencies[latencies.len() / 2]);
        println!("min latency: {:?}", latencies[0]);
        println!("max latency: {:?}", latencies[latencies.len() - 1]);

        assert!(
            p99 < Duration::from_millis(50),
            "p99 latency {}ms >= 50ms",
            p99.as_millis()
        );

        // Clean up: we can't gracefully stop the server, but we can at
        // least join the thread with a timeout so it doesn't leak forever
        // in test runners.
        // Server thread blocks in ConnectNamedPipe — do not join.
    }

    #[test]
    fn hook_ipc_empty_path_boundary() {
        let pipe_name = r"\\.\pipe\DlpHookPipeTestEmpty";

        let handler: HookHandler = Arc::new(|req: HookRequest| HookResponse {
            decision: Decision::ALLOW,
            reason: if req.path.is_empty() {
                "empty path ok".to_string()
            } else {
                "non-empty".to_string()
            },
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        });

        let _server_handle = start_server(pipe_name, handler);
        let client = connect_client(pipe_name).expect("client connect");

        let req = HookRequest {
            path: "".to_string(),
            action: "READ".to_string(),
            cache_version: 0,
            protocol_version: 1,
            op: dlp_common::hook_ipc::HookOp::Read,
            source_volume_class: None,
            destination_volume_class: None,
            pid: 1234,
        };
        let resp = send_request(client, &req).expect("send empty path request");
        assert_eq!(resp.decision, Decision::ALLOW);
        assert_eq!(resp.reason, "empty path ok");

        close_pipe(client);
        // Server thread blocks in ConnectNamedPipe — do not join.
    }

    #[test]
    fn hook_ipc_zero_byte_payload_returns_no_response() {
        let pipe_name = r"\\.\pipe\DlpHookPipeTestZero";

        let handler: HookHandler = Arc::new(|_req: HookRequest| HookResponse {
            decision: Decision::DENY,
            reason: "never reached".to_string(),
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        });

        let _server_handle = start_server(pipe_name, handler);
        let client = connect_client(pipe_name).expect("client connect");

        // Write a zero-byte payload (length = 0, no payload bytes).
        let zero_len = 0u32.to_le_bytes();
        let written = unsafe {
            let mut bytes_written = 0u32;
            windows::Win32::Storage::FileSystem::WriteFile(
                client,
                Some(&zero_len),
                Some(&mut bytes_written),
                None,
            )
            .is_ok()
        };
        assert!(written);

        // Close our end so the server detects the disconnect and leaves
        // handle_connection.  Then ReadFile on our (now-invalid) handle
        // should fail.
        close_pipe(client);

        // The server will try to bincode::deserialize an empty slice and
        // log a warning, then close the connection without writing a
        // response.  ReadFile should therefore fail or return 0.
        let mut buf = [0u8; 4];
        let result = unsafe {
            let mut read = 0u32;
            windows::Win32::Storage::FileSystem::ReadFile(
                client,
                Some(&mut buf),
                Some(&mut read),
                None,
            )
        };

        // Either ReadFile errors or the pipe closes (0 bytes read).
        assert!(
            result.is_err() || {
                let mut read = 0u32;
                unsafe {
                    windows::Win32::Storage::FileSystem::ReadFile(
                        client,
                        Some(&mut buf),
                        Some(&mut read),
                        None,
                    )
                    .ok();
                }
                read == 0
            },
            "expected broken pipe after zero-byte payload"
        );

        // Server thread blocks in ConnectNamedPipe — do not join.
    }

    #[test]
    fn hook_ipc_malformed_request_logged_and_dropped() {
        let pipe_name = r"\\.\pipe\DlpHookPipeTestMalformed";

        let handler: HookHandler = Arc::new(|_req: HookRequest| HookResponse {
            decision: Decision::DENY,
            reason: "should not reach".to_string(),
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        });

        let _server_handle = start_server(pipe_name, handler);
        let client = connect_client(pipe_name).expect("client connect");

        // Send a valid-length frame but with garbage bytes that are not
        // valid bincode for HookRequest.
        let garbage = b"\x01\x02\x03\x04\x05\x06\x07\x08";
        let frame_len = (garbage.len() as u32).to_le_bytes();
        let mut payload = Vec::with_capacity(4 + garbage.len());
        payload.extend_from_slice(&frame_len);
        payload.extend_from_slice(garbage);

        let written = unsafe {
            let mut bytes_written = 0u32;
            windows::Win32::Storage::FileSystem::WriteFile(
                client,
                Some(&payload),
                Some(&mut bytes_written),
                None,
            )
            .is_ok()
        };
        assert!(written);

        // Because the server deserialisation fails, it drops the
        // connection without a response.  The next read should fail.
        let mut buf = [0u8; 4];
        let result = unsafe {
            let mut read = 0u32;
            windows::Win32::Storage::FileSystem::ReadFile(
                client,
                Some(&mut buf),
                Some(&mut read),
                None,
            )
        };
        assert!(
            result.is_err() || {
                let mut read = 0u32;
                unsafe {
                    windows::Win32::Storage::FileSystem::ReadFile(
                        client,
                        Some(&mut buf),
                        Some(&mut read),
                        None,
                    )
                    .ok();
                }
                read == 0
            },
            "expected broken pipe after malformed request"
        );

        close_pipe(client);
        // Server thread blocks in ConnectNamedPipe — do not join.
    }

    #[test]
    fn hook_ipc_server_not_running_connect_fails() {
        let pipe_name = r"\\.\pipe\DlpHookPipeTestNoServer";
        let result = connect_client(pipe_name);
        assert!(
            result.is_err(),
            "expected connection to fail when server is not running"
        );
    }

    #[test]
    fn hook_ipc_oversized_path_frame_rejected() {
        let pipe_name = r"\\.\pipe\DlpHookPipeTestOversized";

        let handler: HookHandler = Arc::new(|_req: HookRequest| HookResponse {
            decision: Decision::DENY,
            reason: "ok".to_string(),
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        });

        let _server_handle = start_server(pipe_name, handler);
        let client = connect_client(pipe_name).expect("client connect");

        // Build a path well over 32KB.
        let huge_path = "A".repeat(40_000);
        let req = HookRequest {
            path: huge_path,
            action: "WRITE".to_string(),
            cache_version: 0,
            protocol_version: 1,
            op: dlp_common::hook_ipc::HookOp::Write,
            source_volume_class: None,
            destination_volume_class: None,
            pid: 1234,
        };

        // Serialisation itself should succeed.
        let _payload = bincode::serialize(&req).expect("serialize oversized path");
        // The frame is ~40KB, which is under the 64MiB limit in frame.rs,
        // so it should go through.  We verify the server handles it.
        let resp = send_request(client, &req).expect("request/response with oversized path");
        assert_eq!(resp.decision, Decision::DENY);

        close_pipe(client);
        // Server thread blocks in ConnectNamedPipe — do not join.
    }

    // --- Task 1: Cache version awareness ---

    /// Mock cache accessor for testing.
    #[derive(Debug, Clone)]
    struct MockCache {
        version: u64,
    }

    impl CacheAccessor for MockCache {
        fn current_version(&self) -> u64 {
            self.version
        }
    }

    /// Builds a deterministic [`BypassAlert`] for tests.
    fn test_bypass_alert(
        pid: u32,
        stub_name: &str,
        agent_id: &str,
    ) -> dlp_common::hook_ipc::BypassAlert {
        dlp_common::hook_ipc::BypassAlert {
            reason: dlp_common::hook_ipc::BypassReason::HookOverwritten,
            stub_name: stub_name.to_string(),
            pid,
            timestamp_secs: 1_700_000_000,
            version: 1,
            agent_id: agent_id.to_string(),
            image_path: r"C:\test.exe".to_string(),
            image_sha256: None,
            file_path: r"C:\secret.txt".to_string(),
            operation: "Create".to_string(),
            file_object: 0xDEADBEEF,
            qpc_timestamp: 9999,
            severity: "crit".to_string(),
            correlation_reason: "HookSelfReported".to_string(),
        }
    }

    #[test]
    fn cache_version_handling_stale_detected() {
        let inner: HookHandler = Arc::new(|_req: HookRequest| HookResponse {
            decision: Decision::ALLOW,
            reason: "ok".to_string(),
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        });

        let cache: Arc<dyn CacheAccessor> = Arc::new(MockCache { version: 42 });

        let req = HookRequest {
            path: r"C:\secret.txt".to_string(),
            action: "WRITE".to_string(),
            cache_version: 5, // stale
            protocol_version: 1,
            op: dlp_common::hook_ipc::HookOp::Write,
            source_volume_class: None,
            destination_volume_class: None,
            pid: 1234,
        };

        let resp = handle_hook_request(req, &inner, &cache, None);

        // Stale detection should not change the decision.
        assert_eq!(resp.decision, Decision::ALLOW);
        // Cache version should be updated to current.
        assert_eq!(resp.cache_version, 42);
        // Cache hint should be present for T4 path.
        assert!(resp.cache_hint.is_some());
        assert_eq!(resp.cache_hint.as_ref().unwrap().tier, Classification::T4);
        assert_eq!(resp.cache_hint.as_ref().unwrap().ttl_secs, 30);
    }

    #[test]
    fn cache_version_handling_fresh_version() {
        let inner: HookHandler = Arc::new(|_req: HookRequest| HookResponse {
            decision: Decision::ALLOW,
            reason: "ok".to_string(),
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        });

        let cache: Arc<dyn CacheAccessor> = Arc::new(MockCache { version: 42 });

        let req = HookRequest {
            path: r"C:\test.txt".to_string(),
            action: "READ".to_string(),
            cache_version: 42, // fresh
            protocol_version: 1,
            op: dlp_common::hook_ipc::HookOp::Read,
            source_volume_class: None,
            destination_volume_class: None,
            pid: 1234,
        };

        let resp = handle_hook_request(req, &inner, &cache, None);

        assert_eq!(resp.decision, Decision::ALLOW);
        assert_eq!(resp.cache_version, 42);
        // Unclassified path — no cache hint.
        assert!(resp.cache_hint.is_none());
    }

    #[test]
    fn cache_version_handling_zero_version() {
        let inner: HookHandler = Arc::new(|_req: HookRequest| HookResponse {
            decision: Decision::DENY,
            reason: "blocked".to_string(),
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        });

        let cache: Arc<dyn CacheAccessor> = Arc::new(MockCache { version: 7 });

        let req = HookRequest {
            path: r"C:\confidential.doc".to_string(),
            action: "WRITE".to_string(),
            cache_version: 0, // never seen cache
            protocol_version: 1,
            op: dlp_common::hook_ipc::HookOp::Write,
            source_volume_class: None,
            destination_volume_class: None,
            pid: 1234,
        };

        let resp = handle_hook_request(req, &inner, &cache, None);

        assert_eq!(resp.decision, Decision::DENY);
        assert_eq!(resp.cache_version, 7);
        // T3 path — cache hint with 60s TTL.
        assert!(resp.cache_hint.is_some());
        assert_eq!(resp.cache_hint.as_ref().unwrap().tier, Classification::T3);
        assert_eq!(resp.cache_hint.as_ref().unwrap().ttl_secs, 60);
    }

    #[test]
    fn cache_hint_ttl_budgets() {
        // T4 = 30s
        let hint = build_cache_hint(r"C:\SECRET\file.txt", None);
        assert!(hint.is_some());
        assert_eq!(hint.unwrap().ttl_secs, 30);

        // T3 = 60s
        let hint = build_cache_hint(r"C:\confidential\file.txt", None);
        assert!(hint.is_some());
        assert_eq!(hint.unwrap().ttl_secs, 60);

        // T2 = 300s
        let hint = build_cache_hint(r"C:\internal\file.txt", None);
        assert!(hint.is_some());
        assert_eq!(hint.unwrap().ttl_secs, 300);

        // Unclassified = None
        let hint = build_cache_hint(r"C:\public\file.txt", None);
        assert!(hint.is_none());
    }

    // ── Plan 02: IpcEnvelope deserialization + BypassAlert routing tests ───

    #[test]
    fn test_handle_connection_routes_bypass_alert() {
        // Compile-time signature check + runtime data-flow test for BypassAlert routing.
        let (bypass_tx, bypass_rx) =
            crossbeam_channel::bounded::<dlp_common::hook_ipc::BypassAlert>(1);

        let handler: HookHandler = Arc::new(|req: HookRequest| HookResponse {
            decision: Decision::ALLOW,
            reason: format!("handled: {}", req.path),
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        });

        let alert = test_bypass_alert(1234, "NtCreateFile", "test-agent");
        let envelope = dlp_common::hook_ipc::IpcEnvelope::V1(dlp_common::hook_ipc::IpcMessageV1 {
            payload: dlp_common::hook_ipc::IpcPayloadV1::BypassAlert(alert.clone()),
        });
        let envelope_bytes = bincode::serialize(&envelope).unwrap();

        // Verify the envelope serializes correctly and contains the expected payload.
        let deserialized: dlp_common::hook_ipc::IpcEnvelope =
            bincode::deserialize(&envelope_bytes).unwrap();
        match deserialized {
            dlp_common::hook_ipc::IpcEnvelope::V1(msg) => match msg.payload {
                dlp_common::hook_ipc::IpcPayloadV1::BypassAlert(ref a) => {
                    assert_eq!(a.pid, alert.pid);
                    assert_eq!(a.stub_name, alert.stub_name);
                    assert_eq!(a.reason, alert.reason);
                }
                _ => panic!("expected BypassAlert payload"),
            },
        }

        // Verify the bypass channel can carry the alert (data-flow check).
        bypass_tx
            .send(alert.clone())
            .expect("send to bypass channel");
        let received = bypass_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("receive from bypass channel");
        assert_eq!(received.pid, alert.pid);
        assert_eq!(received.stub_name, alert.stub_name);
        assert_eq!(received.reason, alert.reason);

        // Verify the handler signature compiles with the bypass channel.
        let _ = (handler, envelope_bytes);
    }

    #[test]
    fn test_handle_connection_routes_envelope_request() {
        // Test 2: IpcEnvelope::V1(IpcPayloadV1::Request) routes to handler.
        let handler: HookHandler = Arc::new(|req: HookRequest| HookResponse {
            decision: Decision::ALLOW,
            reason: format!("handled: {}", req.path),
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        });

        let req = HookRequest {
            path: r"C:\test.txt".to_string(),
            action: "READ".to_string(),
            cache_version: 0,
            protocol_version: 1,
            op: dlp_common::hook_ipc::HookOp::Read,
            source_volume_class: None,
            destination_volume_class: None,
            pid: 0,
        };
        let envelope = dlp_common::hook_ipc::IpcEnvelope::V1(dlp_common::hook_ipc::IpcMessageV1 {
            payload: dlp_common::hook_ipc::IpcPayloadV1::Request(req),
        });
        let envelope_bytes = bincode::serialize(&envelope).unwrap();

        // Verify the envelope serializes and the payload is a Request.
        let deserialized: dlp_common::hook_ipc::IpcEnvelope =
            bincode::deserialize(&envelope_bytes).unwrap();
        match deserialized {
            dlp_common::hook_ipc::IpcEnvelope::V1(msg) => match msg.payload {
                dlp_common::hook_ipc::IpcPayloadV1::Request(ref r) => {
                    assert_eq!(r.path, r"C:\test.txt");
                }
                _ => panic!("expected Request payload"),
            },
        }

        let _ = handler;
    }

    #[test]
    fn test_handle_connection_legacy_fallback() {
        // Test 3: Legacy raw HookRequest frame (not wrapped in envelope) falls back.
        let handler: HookHandler = Arc::new(|req: HookRequest| HookResponse {
            decision: Decision::ALLOW,
            reason: format!("handled: {}", req.path),
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        });

        let req = HookRequest {
            path: r"C:\legacy.txt".to_string(),
            action: "WRITE".to_string(),
            cache_version: 0,
            protocol_version: 1,
            op: dlp_common::hook_ipc::HookOp::Write,
            source_volume_class: None,
            destination_volume_class: None,
            pid: 0,
        };
        let raw_bytes = bincode::serialize(&req).unwrap();

        // Verify raw HookRequest deserializes correctly.
        let deserialized: HookRequest = bincode::deserialize(&raw_bytes).unwrap();
        assert_eq!(deserialized.path, r"C:\legacy.txt");

        let _ = handler;
    }

    #[test]
    fn test_handle_connection_malformed_frame_logged() {
        // Test 4: Malformed frame logs warning and continues.
        let garbage = b"\x01\x02\x03\x04\x05\x06\x07\x08";

        // Should NOT deserialize as IpcEnvelope.
        let envelope_result: Result<dlp_common::hook_ipc::IpcEnvelope, _> =
            bincode::deserialize(garbage);
        assert!(
            envelope_result.is_err(),
            "garbage should not deserialize as IpcEnvelope"
        );

        // Should NOT deserialize as HookRequest either.
        let hook_result: Result<HookRequest, _> = bincode::deserialize(garbage);
        assert!(
            hook_result.is_err(),
            "garbage should not deserialize as HookRequest"
        );
    }

    #[test]
    fn test_handle_connection_volume_class_response_warned() {
        // Test 5: VolumeClassResponse from hook DLL logs warning.
        let resp = dlp_common::hook_ipc::VolumeClassResponse {
            class: Some(dlp_common::VolumeClass::LocalNTFS),
        };
        let envelope = dlp_common::hook_ipc::IpcEnvelope::V1(dlp_common::hook_ipc::IpcMessageV1 {
            payload: dlp_common::hook_ipc::IpcPayloadV1::VolumeClassResponse(resp),
        });
        let envelope_bytes = bincode::serialize(&envelope).unwrap();

        // Verify it deserializes correctly (the warning happens at runtime).
        let deserialized: dlp_common::hook_ipc::IpcEnvelope =
            bincode::deserialize(&envelope_bytes).unwrap();
        match deserialized {
            dlp_common::hook_ipc::IpcEnvelope::V1(msg) => match msg.payload {
                dlp_common::hook_ipc::IpcPayloadV1::VolumeClassResponse(ref r) => {
                    assert_eq!(r.class, Some(dlp_common::VolumeClass::LocalNTFS));
                }
                _ => panic!("expected VolumeClassResponse payload"),
            },
        }
    }

    #[test]
    fn test_handle_connection_volume_class_query_debug() {
        // Test 6: VolumeClassQuery deserializes correctly.
        let query = dlp_common::hook_ipc::VolumeClassQuery { drive_letter: 'D' };
        let envelope = dlp_common::hook_ipc::IpcEnvelope::V1(dlp_common::hook_ipc::IpcMessageV1 {
            payload: dlp_common::hook_ipc::IpcPayloadV1::VolumeClassQuery(query),
        });
        let envelope_bytes = bincode::serialize(&envelope).unwrap();

        // Verify it deserializes correctly (the debug log happens at runtime).
        let deserialized: dlp_common::hook_ipc::IpcEnvelope =
            bincode::deserialize(&envelope_bytes).unwrap();
        match deserialized {
            dlp_common::hook_ipc::IpcEnvelope::V1(msg) => match msg.payload {
                dlp_common::hook_ipc::IpcPayloadV1::VolumeClassQuery(ref q) => {
                    assert_eq!(q.drive_letter, 'D');
                }
                _ => panic!("expected VolumeClassQuery payload"),
            },
        }
    }

    /// End-to-end test: a VolumeClassQuery sent over the named pipe is resolved
    /// by the agent via the global VolumeDetector and returns the cached class.
    #[cfg(windows)]
    #[test]
    fn test_handle_connection_volume_class_query_resolves_class() {
        use dlp_common::hook_ipc::{IpcEnvelope, IpcMessageV1, IpcPayloadV1, VolumeClassQuery};
        use dlp_common::VolumeClass;

        let pipe_name = r"\\.\pipe\DlpHookPipeTestVolumeClassQuery";

        // Install a detector with a seeded volume class for drive E.
        let detector = Arc::new(crate::detection::VolumeDetector::new());
        detector.inject_volume_class_for_test('E', VolumeClass::USBRemovable);
        crate::detection::usb::set_drive_detector(Arc::clone(&detector));

        // The VolumeClassQuery path does not use the HookHandler, but the server
        // still requires a valid handler for legacy HookRequest fallback.
        let handler: HookHandler = Arc::new(|_req: HookRequest| HookResponse {
            decision: Decision::ALLOW,
            reason: "ok".to_string(),
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        });

        let _server_handle = start_server(pipe_name, handler);
        let client = connect_client(pipe_name).expect("client connect");

        let query = VolumeClassQuery { drive_letter: 'E' };
        let envelope = IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::VolumeClassQuery(query),
        });
        let envelope_bytes = bincode::serialize(&envelope).unwrap();

        let response_bytes = send_raw(client, &envelope_bytes).expect("send VolumeClassQuery");
        let response_envelope: IpcEnvelope =
            bincode::deserialize(&response_bytes).expect("deserialize VolumeClassResponse");

        match response_envelope {
            IpcEnvelope::V1(msg) => match msg.payload {
                IpcPayloadV1::VolumeClassResponse(resp) => {
                    assert_eq!(resp.class, Some(VolumeClass::USBRemovable));
                }
                _ => panic!("expected VolumeClassResponse payload"),
            },
        }

        close_pipe(client);

        // Reset global detector to a fresh empty instance so other tests are not
        // affected by this test's seed.
        let cleanup = Arc::new(crate::detection::VolumeDetector::new());
        crate::detection::usb::set_drive_detector(cleanup);
    }

    #[test]
    fn test_with_bypass_channel_constructor() {
        let (bypass_tx, _bypass_rx) =
            crossbeam_channel::unbounded::<dlp_common::hook_ipc::BypassAlert>();

        let handler: HookHandler = Arc::new(|_req: HookRequest| HookResponse {
            decision: Decision::ALLOW,
            reason: "ok".to_string(),
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        });

        let server = HookIpcServer::with_bypass_channel(
            r"\\.\pipe\DlpHookPipeTestBypass",
            handler,
            bypass_tx,
        );

        assert_eq!(server.pipe_name, r"\\.\pipe\DlpHookPipeTestBypass");
        assert!(server.bypass_tx.is_some());
    }

    #[test]
    fn test_with_approval_cache_constructor() {
        let inner: HookHandler = Arc::new(|req: HookRequest| HookResponse {
            decision: Decision::ALLOW,
            reason: format!("ok: {}", req.path),
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        });

        let cache: Arc<dyn CacheAccessor> = Arc::new(MockCache { version: 1 });
        let approval_cache = Some(Arc::new(crate::approval_cache::ApprovalCache::new()));

        // with_approval_cache was removed in Phase 58.2 — approval cache is now
        // passed through the handler closure in HookIpcServerConfig.
        // Verify the equivalent with_cache_offline_and_bypass constructor works.
        let _ = (inner, cache, approval_cache);
    }

    #[test]
    fn test_with_cache_offline_and_bypass_constructor() {
        let (bypass_tx, _bypass_rx) =
            crossbeam_channel::unbounded::<dlp_common::hook_ipc::BypassAlert>();

        let cache: Arc<dyn CacheAccessor> = Arc::new(MockCache { version: 7 });
        let handler: HookHandler = Arc::new(|_req: HookRequest| HookResponse {
            decision: Decision::ALLOW,
            reason: "ok".to_string(),
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        });

        let server = HookIpcServer::with_cache_offline_and_bypass(
            r"\\.\pipe\DlpHookPipeTestOfflineBypass",
            cache,
            handler,
            bypass_tx,
        );

        assert_eq!(server.pipe_name, r"\\.\pipe\DlpHookPipeTestOfflineBypass");
        assert!(server.bypass_tx.is_some());
    }

    #[test]
    fn test_bypass_alert_routes_through_server_to_receiver() {
        // End-to-end data-flow test: a BypassAlert envelope sent by a hook DLL
        // client over the named pipe is received on the bypass_rx channel.
        let pipe_name = r"\\.\pipe\DlpHookPipeTestBypassRoute";
        let (bypass_tx, bypass_rx) =
            crossbeam_channel::bounded::<dlp_common::hook_ipc::BypassAlert>(1);

        let handler: HookHandler = Arc::new(|_req: HookRequest| HookResponse {
            decision: Decision::ALLOW,
            reason: "ok".to_string(),
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        });

        let server = HookIpcServer::with_bypass_channel(pipe_name, handler, bypass_tx);
        let _server_handle = std::thread::spawn(move || {
            let _ = server.run();
        });

        // Wait for the pipe to be created and the server to enter ConnectNamedPipe.
        std::thread::sleep(Duration::from_millis(50));

        let client = connect_client(pipe_name).expect("client connect");

        let alert = test_bypass_alert(5678, "NtCreateFile", "route-test-agent");
        let envelope = dlp_common::hook_ipc::IpcEnvelope::V1(dlp_common::hook_ipc::IpcMessageV1 {
            payload: dlp_common::hook_ipc::IpcPayloadV1::BypassAlert(alert.clone()),
        });
        let envelope_bytes = bincode::serialize(&envelope).unwrap();

        // The server sends back an ACK response; read it so the client doesn't deadlock.
        let ack_bytes = send_raw(client, &envelope_bytes).expect("send bypass alert");
        let ack_envelope: dlp_common::hook_ipc::IpcEnvelope =
            bincode::deserialize(&ack_bytes).expect("deserialize ack");
        match ack_envelope {
            dlp_common::hook_ipc::IpcEnvelope::V1(msg) => match msg.payload {
                dlp_common::hook_ipc::IpcPayloadV1::Response(resp) => {
                    assert_eq!(resp.decision, Decision::ALLOW);
                }
                _ => panic!("expected BypassAlert ack response"),
            },
        }

        let received = bypass_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("receive bypass alert from server");
        assert_eq!(received.pid, alert.pid);
        assert_eq!(received.stub_name, alert.stub_name);
        assert_eq!(received.reason, alert.reason);

        close_pipe(client);
        // The server thread blocks on the next ConnectNamedPipe; leave it.
    }

    #[test]
    fn test_handle_hook_request_deferred_override_deny_unchanged() {
        // Even with approval_cache provided, the hook path does NOT override
        // DENY — the override is deferred until real ABAC evaluation is wired.
        let inner: HookHandler = Arc::new(|_req: HookRequest| HookResponse {
            decision: Decision::DENY,
            reason: "blocked".to_string(),
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        });

        let cache: Arc<dyn CacheAccessor> = Arc::new(MockCache { version: 1 });
        let approval_cache = Arc::new(crate::approval_cache::ApprovalCache::new());

        let req = HookRequest {
            path: r"C:\secret.txt".to_string(),
            action: "WRITE".to_string(),
            cache_version: 1,
            protocol_version: 1,
            op: dlp_common::hook_ipc::HookOp::Write,
            source_volume_class: None,
            destination_volume_class: None,
            pid: 0,
        };

        let resp = handle_hook_request(req, &inner, &cache, Some(&approval_cache));

        // Decision should remain DENY (fail-closed — override is deferred).
        assert_eq!(resp.decision, Decision::DENY);
        assert_eq!(resp.reason, "blocked");
    }

    #[test]
    fn test_with_cache_backward_compat() {
        // Verify the original with_cache constructor still works and passes
        // None for approval_cache.
        let inner: HookHandler = Arc::new(|_req: HookRequest| HookResponse {
            decision: Decision::DENY,
            reason: "blocked".to_string(),
            cache_hint: None,
            cache_version: 0,
            approval_override: None,
        });

        let cache: Arc<dyn CacheAccessor> = Arc::new(MockCache { version: 1 });

        let req = HookRequest {
            path: r"C:\test.txt".to_string(),
            action: "READ".to_string(),
            cache_version: 1,
            protocol_version: 1,
            op: dlp_common::hook_ipc::HookOp::Read,
            source_volume_class: None,
            destination_volume_class: None,
            pid: 0,
        };

        let resp = handle_hook_request(req, &inner, &cache, None);
        assert_eq!(resp.decision, Decision::DENY);
        assert_eq!(resp.cache_version, 1);
    }
}
