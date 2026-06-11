//! Chrome Content Analysis pipe server and request handler.
//!
//! Listens on `\\.\pipe\brcm_chrm_cas` for protobuf-framed scan requests from
//! Chrome.  Evaluates source/destination origins against the
//! [`ManagedOriginsCache`] and returns allow/block verdicts.

use std::sync::Arc;

use anyhow::{Context, Result};
use prost::Message;
use tracing::{debug, error, info, warn};

#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
#[cfg(windows)]
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, NAMED_PIPE_MODE,
    PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};

use super::cache::ManagedOriginsCache;
#[cfg(windows)]
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

/// Global policy evaluator callback — set once at service startup.
///
/// The callback takes an `&EvaluateRequest` and returns an `EvaluateResponse`.
/// This is a function pointer (not a closure) so it can be called from the
/// synchronous pipe thread without async runtime access.
static POLICY_EVALUATOR: std::sync::OnceLock<
    fn(&dlp_common::abac::EvaluateRequest) -> dlp_common::abac::EvaluateResponse,
> = std::sync::OnceLock::new();

#[cfg(test)]
// Test-only thread-local override for the policy evaluator.
// When set (non-None), this takes precedence over `POLICY_EVALUATOR`.
// Thread-local storage eliminates race conditions between parallel tests.
thread_local! {
    static TEST_EVALUATOR_OVERRIDE: std::cell::RefCell<
        Option<fn(&dlp_common::abac::EvaluateRequest) -> dlp_common::abac::EvaluateResponse>,
    > = std::cell::RefCell::new(None);
}

/// Sets the global origins cache before the pipe server starts.
///
/// Must be called exactly once during service initialization.
pub fn set_origins_cache(cache: Arc<ManagedOriginsCache>) {
    let _ = ORIGINS_CACHE.set(cache);
}

/// Sets the global policy evaluator callback before the pipe server starts.
///
/// Must be called exactly once during service initialization.
pub fn set_policy_evaluator(
    evaluator: fn(&dlp_common::abac::EvaluateRequest) -> dlp_common::abac::EvaluateResponse,
) {
    let _ = POLICY_EVALUATOR.set(evaluator);
}

/// Checks if the given origin is in the managed-origins cache.
/// Called by the service-layer policy evaluator.
#[must_use]
pub fn origins_cache_is_managed(origin: &str) -> bool {
    ORIGINS_CACHE
        .get()
        .is_some_and(|cache| cache.is_managed(origin))
}

/// Starts the Chrome Content Analysis pipe server.
///
/// Blocks the calling thread indefinitely (or until a fatal error).  This
/// function is intended to be run on a dedicated `std::thread` (not a
/// Tokio task) because `ConnectNamedPipeW` and `ReadFile` are synchronous.
#[cfg(windows)]
pub fn serve() -> Result<()> {
    info!(pipe = CHROME_PIPE_NAME, "Chrome pipe server starting");
    let first_pipe = create_pipe()?;
    accept_loop(first_pipe)
}

/// Combines the pipe-mode flags into a single `NAMED_PIPE_MODE` value.
#[cfg(windows)]
fn pipe_mode() -> NAMED_PIPE_MODE {
    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT
}

/// Accept loop: waits for Chrome clients, handles them, then creates a new
/// pipe instance for the next client.
#[cfg(windows)]
fn accept_loop(first_pipe: HANDLE) -> Result<()> {
    let mut pipe = first_pipe;
    loop {
        if crate::service::shutdown_requested() {
            let _ = unsafe { CloseHandle(pipe) };
            info!(
                pipe = CHROME_PIPE_NAME,
                "shutdown requested — exiting Chrome accept loop"
            );
            return Ok(());
        }

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
#[cfg(windows)]
fn create_pipe() -> Result<HANDLE> {
    let name_wide: Vec<u16> = CHROME_PIPE_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let sec = crate::ipc::pipe_security::PipeSecurity::new().context("pipe security descriptor")?;

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
#[cfg(windows)]
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
#[cfg(windows)]
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
/// ```no_run
/// // to_origin is module-private; examples are illustrative only.
/// // Equivalent unit tests live in the #[cfg(test)] module below.
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
/// Decision logic (Phase 41 — ABAC-evaluated origin policies):
/// 1. Only process clipboard paste events (`reason == CLIPBOARD_PASTE`).
/// 2. Extract source URL from `request_data.url`.
/// 3. Normalise to origin.
/// 4. Build an `EvaluateRequest` with `Action::PASTE` and `source_origin`.
/// 5. Evaluate against ABAC policy via `POLICY_EVALUATOR`.
/// 6. If decision is DENY -> BLOCK and emit audit event.
/// 7. Otherwise -> ALLOW.
///
/// Non-clipboard requests are always allowed (no regression).
///
/// If `POLICY_EVALUATOR` is not set, the handler falls open (ALLOW)
/// to avoid breaking user productivity during startup races (T-41-08).
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

    let source_url = request.request_data.as_ref().and_then(|d| d.url.as_ref());
    let source_origin = source_url.and_then(|u| to_origin(u));

    // Build an EvaluateRequest for ABAC policy evaluation.
    let evaluate_request = dlp_common::abac::EvaluateRequest {
        subject: dlp_common::abac::Subject {
            user_sid: "CHROME".to_string(),
            user_name: "CHROME".to_string(),
            groups: Vec::new(),
            device_trust: dlp_common::abac::DeviceTrust::Unknown,
            network_location: dlp_common::abac::NetworkLocation::Unknown,
            device_health: dlp_common::DeviceHealthStatus::default(),
        },
        resource: dlp_common::abac::Resource {
            path: "chrome://clipboard".to_string(),
            classification: dlp_common::Classification::T3, // Conservative default for clipboard
        },
        environment: dlp_common::abac::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 0,
            access_context: dlp_common::abac::AccessContext::Local,
        },
        action: dlp_common::abac::Action::PASTE,
        agent: None,
        source_application: None,
        destination_application: None,
        source_origin: source_origin.clone(),
        destination_origin: None, // Chrome API v1 does not expose destination origin
    };

    // Evaluate against ABAC policy if evaluator is available.
    // Test override takes precedence for test isolation (thread-local).
    #[cfg(test)]
    let evaluator_opt = TEST_EVALUATOR_OVERRIDE
        .with(|cell| cell.borrow().as_ref().copied())
        .or_else(|| POLICY_EVALUATOR.get().copied());
    #[cfg(not(test))]
    let evaluator_opt = POLICY_EVALUATOR.get().copied();

    let decision = evaluator_opt
        .map(|evaluator| evaluator(&evaluate_request).decision)
        .unwrap_or(dlp_common::abac::Decision::ALLOW); // Fail-open if no evaluator (defensive)

    if decision.is_denied() {
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
fn emit_chrome_block_audit(source_origin: &Option<String>, destination_origin: Option<String>) {
    debug!(
        ?source_origin,
        ?destination_origin,
        "Chrome clipboard block audit: destination_origin is always None because Chrome Content Analysis API v1 does not expose it"
    );
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
        agent_id: std::env::var("DLP_AGENT_ID").unwrap_or_else(|_| "AGENT-UNKNOWN".to_string()),
        session_id: 0,
        user_sid: "CHROME".to_string(),
        user_name: "CHROME".to_string(),
        machine_name: None,
    };

    crate::audit_emitter::emit_audit(&ctx, &mut event);
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // to_origin
    // ------------------------------------------------------------------

    #[test]
    fn test_to_origin_basic_https() {
        assert_eq!(
            to_origin("https://company.sharepoint.com/path?x=1"),
            Some("https://company.sharepoint.com".to_string())
        );
    }

    #[test]
    fn test_to_origin_uppercase_normalised() {
        assert_eq!(
            to_origin("HTTPS://EXAMPLE.COM/"),
            Some("https://example.com".to_string())
        );
    }

    #[test]
    fn test_to_origin_strips_port() {
        assert_eq!(
            to_origin("https://example.com:443/foo"),
            Some("https://example.com".to_string())
        );
    }

    #[test]
    fn test_to_origin_no_scheme_returns_none() {
        assert_eq!(to_origin("example.com/path"), None);
    }

    #[test]
    fn test_to_origin_empty_string_returns_none() {
        assert_eq!(to_origin(""), None);
    }

    // ------------------------------------------------------------------
    // dispatch_request — allow cases
    // ------------------------------------------------------------------

    #[test]
    fn test_dispatch_non_clipboard_allows() {
        let request = ContentAnalysisRequest {
            request_token: Some("tok-1".to_string()),
            analysis_connector: Some(3), // BULK_DATA_ENTRY
            request_data: None,
            tags: vec![],
            reason: Some(2), // DRAG_AND_DROP — not clipboard
            content_data: None,
        };
        let response = dispatch_request(&request);
        assert_eq!(response.request_token, Some("tok-1".to_string()));
        assert_eq!(response.results.len(), 1);
        let rule = &response.results[0].triggered_rules[0];
        assert_eq!(rule.action, Some(1)); // REPORT_ONLY = allow
    }

    #[test]
    fn test_dispatch_clipboard_no_url_allows() {
        let request = ContentAnalysisRequest {
            request_token: Some("tok-2".to_string()),
            analysis_connector: Some(3),
            request_data: Some(super::super::proto::ContentMetaData {
                url: None,
                filename: None,
                digest: None,
                email: None,
                tab_title: None,
            }),
            tags: vec![],
            reason: Some(1), // CLIPBOARD_PASTE
            content_data: None,
        };
        let response = dispatch_request(&request);
        assert_eq!(response.results.len(), 1);
        let rule = &response.results[0].triggered_rules[0];
        assert_eq!(rule.action, Some(1)); // allow
    }

    // ------------------------------------------------------------------
    // Test helpers for evaluator override
    // ------------------------------------------------------------------

    /// RAII guard that sets the thread-local test evaluator override and resets to None on drop.
    struct EvaluatorGuard {
        _priv: (),
    }

    impl EvaluatorGuard {
        fn set(
            evaluator: fn(&dlp_common::abac::EvaluateRequest) -> dlp_common::abac::EvaluateResponse,
        ) -> Self {
            TEST_EVALUATOR_OVERRIDE.with(|cell| {
                *cell.borrow_mut() = Some(evaluator);
            });
            Self { _priv: () }
        }
    }

    impl Drop for EvaluatorGuard {
        fn drop(&mut self) {
            TEST_EVALUATOR_OVERRIDE.with(|cell| {
                *cell.borrow_mut() = None;
            });
        }
    }

    // ------------------------------------------------------------------
    // Mock policy evaluator for tests
    // ------------------------------------------------------------------

    /// Mock evaluator: blocks if source_origin contains "sharepoint.com".
    fn mock_evaluator_block_managed_origin(
        req: &dlp_common::abac::EvaluateRequest,
    ) -> dlp_common::abac::EvaluateResponse {
        if req.source_origin.as_deref() == Some("https://sharepoint.com") {
            dlp_common::abac::EvaluateResponse {
                decision: dlp_common::abac::Decision::DENY,
                matched_policy_id: Some("mock-origin-policy".to_string()),
                reason: "mock: managed origin blocked".to_string(),
                enforcement_mode: None,
                would_have_denied: false,
                matched_label_id: None,
            }
        } else {
            dlp_common::abac::EvaluateResponse {
                decision: dlp_common::abac::Decision::ALLOW,
                matched_policy_id: None,
                reason: "mock: allowed".to_string(),
                enforcement_mode: None,
                would_have_denied: false,
                matched_label_id: None,
            }
        }
    }

    /// Mock evaluator that always allows.
    fn mock_evaluator_always_allow(
        _req: &dlp_common::abac::EvaluateRequest,
    ) -> dlp_common::abac::EvaluateResponse {
        dlp_common::abac::EvaluateResponse {
            decision: dlp_common::abac::Decision::ALLOW,
            matched_policy_id: None,
            reason: "mock: always allow".to_string(),
            enforcement_mode: None,
            would_have_denied: false,
            matched_label_id: None,
        }
    }

    /// Mock evaluator that always denies.
    fn mock_evaluator_always_deny(
        _req: &dlp_common::abac::EvaluateRequest,
    ) -> dlp_common::abac::EvaluateResponse {
        dlp_common::abac::EvaluateResponse {
            decision: dlp_common::abac::Decision::DENY,
            matched_policy_id: Some("mock-deny-all".to_string()),
            reason: "mock: always deny".to_string(),
            enforcement_mode: None,
            would_have_denied: false,
            matched_label_id: None,
        }
    }

    // ------------------------------------------------------------------
    // dispatch_request — ABAC evaluation tests
    // ------------------------------------------------------------------

    #[test]
    fn test_dispatch_abac_evaluator_not_set_allows() {
        // Ensure no evaluator override is active (Guard not created).
        // This test verifies the fail-open behavior when neither
        // POLICY_EVALUATOR nor TEST_EVALUATOR_OVERRIDE is set.
        let request = ContentAnalysisRequest {
            request_token: Some("tok-abac-no-eval".to_string()),
            analysis_connector: Some(3),
            request_data: Some(super::super::proto::ContentMetaData {
                url: Some("https://sharepoint.com/documents/file.xlsx".to_string()),
                filename: None,
                digest: None,
                email: None,
                tab_title: None,
            }),
            tags: vec![],
            reason: Some(1), // CLIPBOARD_PASTE
            content_data: None,
        };
        let response = dispatch_request(&request);
        assert_eq!(response.results.len(), 1);
        let rule = &response.results[0].triggered_rules[0];
        assert_eq!(rule.action, Some(1)); // ALLOW (fail-open when no evaluator)
    }

    #[test]
    fn test_dispatch_abac_denies_via_policy() {
        let _guard = EvaluatorGuard::set(mock_evaluator_always_deny);

        let request = ContentAnalysisRequest {
            request_token: Some("tok-abac-deny".to_string()),
            analysis_connector: Some(3),
            request_data: Some(super::super::proto::ContentMetaData {
                url: Some("https://example.com/page.html".to_string()),
                filename: None,
                digest: None,
                email: None,
                tab_title: None,
            }),
            tags: vec![],
            reason: Some(1), // CLIPBOARD_PASTE
            content_data: None,
        };
        let response = dispatch_request(&request);
        assert_eq!(response.results.len(), 1);
        let rule = &response.results[0].triggered_rules[0];
        assert_eq!(rule.action, Some(3)); // BLOCK = 3
    }

    #[test]
    fn test_dispatch_abac_allows_via_policy() {
        let _guard = EvaluatorGuard::set(mock_evaluator_always_allow);

        let request = ContentAnalysisRequest {
            request_token: Some("tok-abac-allow".to_string()),
            analysis_connector: Some(3),
            request_data: Some(super::super::proto::ContentMetaData {
                url: Some("https://example.com/page.html".to_string()),
                filename: None,
                digest: None,
                email: None,
                tab_title: None,
            }),
            tags: vec![],
            reason: Some(1), // CLIPBOARD_PASTE
            content_data: None,
        };
        let response = dispatch_request(&request);
        assert_eq!(response.results.len(), 1);
        let rule = &response.results[0].triggered_rules[0];
        assert_eq!(rule.action, Some(1)); // ALLOW
    }

    #[test]
    fn test_dispatch_managed_origin_blocks() {
        let _guard = EvaluatorGuard::set(mock_evaluator_block_managed_origin);

        let request = ContentAnalysisRequest {
            request_token: Some("tok-3".to_string()),
            analysis_connector: Some(3),
            request_data: Some(super::super::proto::ContentMetaData {
                url: Some("https://sharepoint.com/documents/file.xlsx".to_string()),
                filename: None,
                digest: None,
                email: None,
                tab_title: None,
            }),
            tags: vec![],
            reason: Some(1), // CLIPBOARD_PASTE
            content_data: None,
        };
        let response = dispatch_request(&request);
        assert_eq!(response.results.len(), 1);
        let rule = &response.results[0].triggered_rules[0];
        assert_eq!(rule.action, Some(3)); // BLOCK = 3
    }

    #[test]
    fn test_dispatch_unmanaged_origin_allows() {
        let _guard = EvaluatorGuard::set(mock_evaluator_block_managed_origin);

        let request = ContentAnalysisRequest {
            request_token: Some("tok-4".to_string()),
            analysis_connector: Some(3),
            request_data: Some(super::super::proto::ContentMetaData {
                url: Some("https://example.com/page.html".to_string()),
                filename: None,
                digest: None,
                email: None,
                tab_title: None,
            }),
            tags: vec![],
            reason: Some(1), // CLIPBOARD_PASTE
            content_data: None,
        };
        let response = dispatch_request(&request);
        assert_eq!(response.results.len(), 1);
        let rule = &response.results[0].triggered_rules[0];
        assert_eq!(rule.action, Some(1)); // allow
    }

    // ------------------------------------------------------------------
    // make_result helpers
    // ------------------------------------------------------------------

    #[test]
    fn test_make_result_allow_has_report_only_action() {
        let result = make_result_allow();
        assert_eq!(result.status, Some(1)); // SUCCESS
        assert_eq!(result.triggered_rules.len(), 1);
        assert_eq!(result.triggered_rules[0].action, Some(1)); // REPORT_ONLY
    }

    #[test]
    fn test_make_result_block_has_block_action() {
        let result = make_result_block();
        assert_eq!(result.status, Some(1)); // SUCCESS
        assert_eq!(result.triggered_rules.len(), 1);
        assert_eq!(result.triggered_rules[0].action, Some(3)); // BLOCK
    }
}
