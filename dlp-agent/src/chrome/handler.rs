//! Chrome Content Analysis pipe server and request handler.
//!
//! Listens on `\\.\pipe\brcm_chrm_cas` for protobuf-framed scan requests from
//! Chrome.  Evaluates source/destination origins against the
//! [`ManagedOriginsCache`] and returns allow/block verdicts.

use std::sync::Arc;

use anyhow::{Context, Result};
use prost::Message;
use tracing::{debug, error, info, warn};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, NAMED_PIPE_MODE,
    PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};

use super::cache::ManagedOriginsCache;
use super::frame::{read_frame, write_frame};
use super::proto::{ContentAnalysisRequest, ContentAnalysisResponse};

/// The Win32 named pipe name for Chrome Content Analysis.
///
/// Chrome connects to this pipe when it needs to scan clipboard content.
/// The name `brcm_chrm_cas` is the documented base name from the Chromium
/// Content Analysis SDK demo.
const CHROME_PIPE_NAME: &str = r"\\.\pipe\brcm_chrm_cas";

/// Number of simultaneous pipe instances to allow.
const NUM_INSTANCES: u32 = 4;

/// Global cache of managed origins — set once at service startup.
///
/// Safety: the cache is read-only after initialization (only `is_managed`
/// is called from the pipe thread).  The pointer is never mutated.
static ORIGINS_CACHE: std::sync::OnceLock<Arc<ManagedOriginsCache>> = std::sync::OnceLock::new();

/// Sets the global origins cache before the pipe server starts.
///
/// Must be called exactly once during service initialization.
pub fn set_origins_cache(cache: Arc<ManagedOriginsCache>) {
    let _ = ORIGINS_CACHE.set(cache);
}

/// Starts the Chrome Content Analysis pipe server.
///
/// Blocks the calling thread indefinitely (or until a fatal error).  This
/// function is intended to be run on a dedicated `std::thread` (not a
/// Tokio task) because `ConnectNamedPipeW` and `ReadFile` are synchronous.
pub fn serve() -> Result<()> {
    info!(pipe = CHROME_PIPE_NAME, "Chrome pipe server starting");
    let first_pipe = create_pipe()?;
    accept_loop(first_pipe)
}

/// Combines the pipe-mode flags into a single `NAMED_PIPE_MODE` value.
fn pipe_mode() -> NAMED_PIPE_MODE {
    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT
}

/// Accept loop: waits for Chrome clients, handles them, then creates a new
/// pipe instance for the next client.
fn accept_loop(first_pipe: HANDLE) -> Result<()> {
    let mut pipe = first_pipe;
    loop {
        if let Err(e) = unsafe { ConnectNamedPipe(pipe, None) } {
            let win32_code = (e.code().0 as u32) & 0xFFFF;
            if win32_code != 535 {
                warn!(win32_code, "ConnectNamedPipe failed — recycling pipe");
                let _ = unsafe { CloseHandle(pipe) };
                pipe = match create_pipe() {
                    Ok(p) => p,
                    Err(e) => {
                        error!(error = %e, "failed to recreate pipe — exiting accept loop");
                        return Err(e);
                    }
                };
                continue;
            }
            debug!("ConnectNamedPipe: client already connected (535)");
        }

        info!(pipe = CHROME_PIPE_NAME, "Chrome client connected");
        let _ = handle_client(pipe);

        // Create a new pipe instance for the next client.
        pipe = match create_pipe() {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "failed to recreate pipe — exiting accept loop");
                return Err(e);
            }
        };
    }
}

/// Creates a new named pipe instance with the standard IPC DACL.
fn create_pipe() -> Result<HANDLE> {
    let name_wide: Vec<u16> =
        CHROME_PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    let sec = crate::ipc::pipe_security::PipeSecurity::new()
        .context("pipe security descriptor")?;

    let pipe = unsafe {
        CreateNamedPipeW(
            PCWSTR::from_raw(name_wide.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            pipe_mode(),
            NUM_INSTANCES,
            65536, // output buffer
            65536, // input buffer
            5000,  // default timeout ms
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

/// Handles a single Chrome client connection.
fn handle_client(pipe: HANDLE) -> Result<()> {
    loop {
        let frame = match read_frame(pipe) {
            Ok(f) => f,
            Err(e) => {
                debug!(error = %e, "Chrome pipe: read error — disconnecting");
                break;
            }
        };

        let request: ContentAnalysisRequest = match Message::decode(&*frame) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "Chrome pipe: malformed protobuf — closing connection");
                break;
            }
        };

        let response = dispatch_request(&request);

        let mut response_bytes = Vec::new();
        if let Err(e) = response.encode(&mut response_bytes) {
            warn!(error = %e, "Chrome pipe: failed to encode response");
            break;
        }

        if let Err(e) = write_frame(pipe, &response_bytes) {
            debug!(error = %e, "Chrome pipe: write error — disconnecting");
            break;
        }
    }

    cleanup_pipe(pipe)?;
    Ok(())
}

/// Closes and disconnects a pipe handle.
fn cleanup_pipe(pipe: HANDLE) -> Result<()> {
    unsafe {
        let _ = DisconnectNamedPipe(pipe);
        let _ = CloseHandle(pipe);
    }
    Ok(())
}

/// Normalises a URL to an origin string for cache matching.
///
/// Extracts `scheme + host`, lowercases both, strips path/query/port.
/// Returns `None` if the URL does not contain `://`.
///
/// # Examples
///
/// ```
/// assert_eq!(
///     to_origin("https://company.sharepoint.com/path?x=1"),
///     Some("https://company.sharepoint.com".to_string())
/// );
/// assert_eq!(
///     to_origin("HTTPS://EXAMPLE.COM/"),
///     Some("https://example.com".to_string())
/// );
/// ```
fn to_origin(url: &str) -> Option<String> {
    let url = url.trim().to_lowercase();
    let scheme_end = url.find("://")?;
    let scheme = &url[..scheme_end];
    let rest = &url[scheme_end + 3..];
    let host_end = rest.find('/').unwrap_or(rest.len());
    let host = &rest[..host_end];
    // Strip port if present (e.g. ":443").
    let host = host.split(':').next().unwrap_or(host);
    Some(format!("{}://{}", scheme, host))
}

/// Dispatches a Chrome ContentAnalysisRequest and returns the response.
///
/// Decision logic (per D-06 from 29-CONTEXT.md):
/// 1. Only process clipboard paste events (`reason == CLIPBOARD_PASTE`).
/// 2. Extract source URL from `request_data.url`.
/// 3. Normalise to origin.
/// 4. If source origin is in the managed-origins cache -> BLOCK.
/// 5. Otherwise -> ALLOW.
///
/// Non-clipboard requests are always allowed (we only care about paste
/// boundary control).
fn dispatch_request(request: &ContentAnalysisRequest) -> ContentAnalysisResponse {
    let mut response = ContentAnalysisResponse {
        request_token: request.request_token.clone(),
        ..Default::default()
    };

    // CLIPBOARD_PASTE = 1 per the proto definition.
    let is_clipboard = request.reason == Some(1);
    if !is_clipboard {
        response.results.push(make_result_allow());
        return response;
    }

    let source_url = request
        .request_data
        .as_ref()
        .and_then(|d| d.url.as_ref());
    let source_origin = source_url.and_then(|u| to_origin(u));

    let should_block = source_origin.as_ref().map_or(false, |origin| {
        ORIGINS_CACHE
            .get()
            .map_or(false, |cache| cache.is_managed(origin))
    });

    if should_block {
        response.results.push(make_result_block());
        emit_chrome_block_audit(&source_origin, None);
    } else {
        response.results.push(make_result_allow());
    }

    response
}

/// Constructs an ALLOW result for the response.
fn make_result_allow() -> super::proto::content_analysis_response::Result {
    use super::proto::content_analysis_response::result::TriggeredRule;
    use super::proto::content_analysis_response::Result;

    Result {
        status: Some(1), // SUCCESS = 1
        triggered_rules: vec![TriggeredRule {
            action: Some(1), // REPORT_ONLY = 1 (allow with audit)
            rule_name: Some("DLP-Allow".to_string()),
            rule_id: Some("dlp-allow".to_string()),
        }],
    }
}

/// Constructs a BLOCK result for the response.
fn make_result_block() -> super::proto::content_analysis_response::Result {
    use super::proto::content_analysis_response::result::TriggeredRule;
    use super::proto::content_analysis_response::Result;

    Result {
        status: Some(1), // SUCCESS = 1 (the verdict itself succeeded)
        triggered_rules: vec![TriggeredRule {
            action: Some(3), // BLOCK = 3
            rule_name: Some("DLP-Block".to_string()),
            rule_id: Some("dlp-block".to_string()),
        }],
    }
}

/// Emits an audit event for a Chrome clipboard block.
///
/// The event carries `source_origin` and `destination_origin` fields.
/// Clipboard content (`text_content`) is NEVER logged.
fn emit_chrome_block_audit(
    source_origin: &Option<String>,
    destination_origin: Option<String>,
) {
    let mut event = dlp_common::AuditEvent::new(
        dlp_common::EventType::Block,
        "CHROME".to_string(),
        "CHROME".to_string(),
        "chrome-clipboard".to_string(),
        dlp_common::Classification::T3,
        dlp_common::Action::PASTE,
        dlp_common::Decision::DENY,
        std::env::var("DLP_AGENT_ID").unwrap_or_else(|_| "AGENT-UNKNOWN".to_string()),
        0, // Chrome events are not tied to a Windows session ID
    )
    .with_source_origin(source_origin.clone())
    .with_destination_origin(destination_origin);

    let ctx = crate::audit_emitter::EmitContext {
        agent_id: std::env::var("DLP_AGENT_ID")
            .unwrap_or_else(|_| "AGENT-UNKNOWN".to_string()),
        session_id: 0,
        user_sid: "CHROME".to_string(),
        user_name: "CHROME".to_string(),
        machine_name: None,
    };

    crate::audit_emitter::emit_audit(&ctx, &mut event);
}
