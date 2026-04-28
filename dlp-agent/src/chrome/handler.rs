//! Chrome Content Analysis request handler.
//!
//! Receives decoded [`ContentAnalysisRequest`] protobuf messages from the
//! Chrome Enterprise Connector pipe, evaluates origin trust via the ABAC
//! policy engine, and returns a [`ContentAnalysisResponse`] verdict.

#[cfg(windows)]
use anyhow::{Context, Result};

#[cfg(windows)]
use crate::chrome::frame;

#[cfg(windows)]
use crate::chrome::proto;

/// Processes a single Chrome Content Analysis request.
///
/// # Arguments
///
/// * `pipe` — Win32 `HANDLE` to the Chrome named pipe.
///
/// # Errors
///
/// Returns an error if the frame cannot be read, the protobuf cannot be
/// decoded, or the response cannot be written back.
#[cfg(windows)]
pub fn handle_request(pipe: windows::Win32::Foundation::HANDLE) -> Result<()> {
    let frame = frame::read_frame(pipe).context("read chrome request frame")?;

    let request: proto::ContentAnalysisRequest =
        prost::Message::decode(&*frame).context("decode ContentAnalysisRequest")?;

    let response = evaluate_request(&request);

    let mut encoded = Vec::new();
    prost::Message::encode(&response, &mut encoded).context("encode ContentAnalysisResponse")?;

    frame::write_frame(pipe, &encoded).context("write chrome response frame")?;

    Ok(())
}

/// Evaluates a Chrome Content Analysis request against ABAC policies.
///
/// Currently returns a default-allow response.  Full ABAC integration
/// (origin trust lookup, policy evaluation, audit logging) is implemented
/// in downstream plans (29-02, 29-03).
#[cfg(windows)]
fn evaluate_request(
    request: &proto::ContentAnalysisRequest,
) -> proto::ContentAnalysisResponse {
    // Default-allow stub — downstream plans wire ABAC evaluation.
    let result = proto::content_analysis_response::Result {
        status: Some(proto::content_analysis_response::result::Status::Success as i32),
        triggered_rules: vec![],
    };

    proto::ContentAnalysisResponse {
        request_token: request.request_token.clone(),
        results: vec![result],
    }
}

#[cfg(not(windows))]
pub fn handle_request(_pipe: ()) -> anyhow::Result<()> {
    Ok(())
}
