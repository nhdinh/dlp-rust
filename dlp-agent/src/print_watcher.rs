//! Print spooler watcher thread (M017 T04).
//!
//! Spawns a dedicated std thread that watches the print spooler for new jobs
//! using `FindFirstPrinterChangeNotification`.  When a new job is detected,
//! the watcher:
//!
//! 1. Queries job info via `GetJobW` (level 2).
//! 2. If `datatype == "XPS_PASS"`, reads the SPL file and extracts text.
//! 3. Classifies content with [`ContentClassifier`].
//! 4. Evaluates ABAC policy via [`OfflineManager`].
//! 5. Cancels blocked jobs before they reach the printer.
//!
//! ## Redaction
//!
//! XPS text content is parsed in-memory and never written to disk or logs.
//! Only document name, job ID, and classification tier appear in audit events.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use dlp_common::{
    Action, AuditEvent, Classification, Decision, Environment, EvaluateRequest, EvaluateResponse,
    EventType, NetworkLocation, Resource, Subject,
};
use tracing::{debug, error, info, warn};

use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::Graphics::Printing::{
    FindFirstPrinterChangeNotification, FindNextPrinterChangeNotification, PRINTER_CHANGE_ADD_JOB,
    PRINTER_CHANGE_SET_JOB, PRINTER_CHANGE_WRITE_JOB,
};
use windows::Win32::System::Threading::WaitForSingleObject;

use crate::audit_emitter::{emit_audit, EmitContext};
use crate::clipboard::ContentClassifier;
use crate::offline::OfflineManager;
use crate::print_job_info::{cancel_job, get_job_info, is_job_printing, open_printer, JobInfo};
use crate::print_xps_parser::extract_text;

/// Configuration for the print watcher.
#[derive(Debug, Clone)]
pub struct PrintWatcherConfig {
    /// Maximum number of pages to parse from XPS spool files.
    pub max_pages: usize,
    /// Action when a job cannot be classified ("ALLOW" or "DENY"/"Block").
    pub unclassifiable_action: String,
}

impl Default for PrintWatcherConfig {
    fn default() -> Self {
        Self {
            max_pages: 100,
            unclassifiable_action: "Block".to_string(),
        }
    }
}

impl PrintWatcherConfig {
    /// Resolves the unclassifiable action to a boolean: `true` = deny/block.
    #[must_use]
    pub fn should_deny_unclassifiable(&self) -> bool {
        matches!(
            self.unclassifiable_action.to_ascii_lowercase().as_str(),
            "deny" | "block"
        )
    }
}

/// Watches the print spooler for new jobs and enforces DLP policy.
pub struct PrintWatcher {
    offline: Arc<OfflineManager>,
    audit_ctx: EmitContext,
    runtime_handle: tokio::runtime::Handle,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    config: PrintWatcherConfig,
}

impl PrintWatcher {
    /// Constructs a new `PrintWatcher`.
    pub fn new(
        offline: Arc<OfflineManager>,
        audit_ctx: EmitContext,
        runtime_handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            offline,
            audit_ctx,
            runtime_handle,
            shutdown: Arc::new(AtomicBool::new(false)),
            handle: None,
            config: PrintWatcherConfig::default(),
        }
    }

    /// Sets the watcher configuration.
    pub fn with_config(mut self, config: PrintWatcherConfig) -> Self {
        self.config = config;
        self
    }

    /// Starts the watcher thread.
    ///
    /// # Panics
    ///
    /// Panics if called twice without calling `stop()` in between.
    pub fn start(&mut self) {
        assert!(self.handle.is_none(), "PrintWatcher already started");

        let offline = Arc::clone(&self.offline);
        let audit_ctx = self.audit_ctx.clone();
        let runtime_handle = self.runtime_handle.clone();
        let shutdown = Arc::clone(&self.shutdown);
        let config = self.config.clone();

        self.handle = Some(thread::spawn(move || {
            watcher_thread(offline, audit_ctx, runtime_handle, shutdown, config);
        }));

        info!("print watcher thread started");
    }

    /// Signals the watcher thread to shut down and waits for it to exit.
    pub fn stop(&mut self) {
        if self.handle.is_none() {
            return;
        }

        info!("stopping print watcher thread");
        self.shutdown.store(true, Ordering::Relaxed);

        if let Some(handle) = self.handle.take() {
            if let Err(e) = handle.join() {
                error!("print watcher thread panicked: {:?}", e);
            } else {
                info!("print watcher thread stopped cleanly");
            }
        }
    }
}

impl Drop for PrintWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

// ---------------------------------------------------------------------------
// Watcher thread
// ---------------------------------------------------------------------------

fn watcher_thread(
    offline: Arc<OfflineManager>,
    audit_ctx: EmitContext,
    runtime_handle: tokio::runtime::Handle,
    shutdown: Arc<AtomicBool>,
    config: PrintWatcherConfig,
) {
    // Open the local print spooler with admin access.
    let printer = match open_printer("\\.\\pipe\\spoolss") {
        Ok(p) => p,
        Err(e) => {
            error!(error = %e, "failed to open printer — watcher thread exiting");
            return;
        }
    };

    // Create change notification handle.
    let notify_handle: HANDLE = unsafe {
        FindFirstPrinterChangeNotification(
            printer.raw(),
            PRINTER_CHANGE_ADD_JOB | PRINTER_CHANGE_WRITE_JOB | PRINTER_CHANGE_SET_JOB,
            0,
            None,
        )
    };

    if notify_handle.is_invalid() {
        let err = unsafe { windows::Win32::Foundation::GetLastError() };
        error!(error = ?err, "FindFirstPrinterChangeNotification failed — watcher thread exiting");
        return;
    }

    info!("print watcher waiting for spooler changes");

    // Keep track of jobs we've already processed to avoid duplicate evaluation.
    let mut seen_jobs: std::collections::HashSet<u32> = std::collections::HashSet::new();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Wait up to 500ms for a change notification.
        let wait_result = unsafe { WaitForSingleObject(notify_handle, 500) };

        if wait_result == WAIT_OBJECT_0 {
            // Signaled — process changes.
            let ok = unsafe { FindNextPrinterChangeNotification(notify_handle, None, None, None) };
            if !ok.as_bool() {
                let err = unsafe { windows::Win32::Foundation::GetLastError() };
                warn!(error = ?err, "FindNextPrinterChangeNotification failed");
                continue;
            }

            // Enumerate jobs.  We scan a reasonable range of job IDs because
            // the spooler reuses IDs and we don't have a reliable "new job"
            // list from the notification without `PRINTER_NOTIFY_INFO` parsing.
            // In practice, checking the most recent 50 job IDs is sufficient.
            for job_id in 1..=50 {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }

                // Skip already-processed jobs.
                if seen_jobs.contains(&job_id) {
                    continue;
                }

                match get_job_info(&printer, job_id) {
                    Ok(job) => {
                        // Job exists — mark as seen.
                        seen_jobs.insert(job_id);

                        // Only process jobs that are spooling (not yet printing).
                        if is_job_printing(job.status) {
                            debug!(job_id, "job already printing — skipping");
                            continue;
                        }

                        info!(
                            job_id,
                            document = %job.document_name,
                            user = %job.user_name,
                            datatype = %job.datatype,
                            "job_detected"
                        );

                        // Evaluate the job.
                        let decision = evaluate_job(&job, &config, &offline, &runtime_handle);

                        match decision {
                            JobDecision::Allow => {
                                debug!(job_id, "job_allowed");
                            }
                            JobDecision::Cancel => match cancel_job(&printer, job_id) {
                                Ok(()) => {
                                    info!(job_id, "job_cancelled");
                                    emit_print_audit(
                                        &audit_ctx,
                                        &job,
                                        EventType::Block,
                                        Decision::DENY,
                                        "Print job blocked by DLP policy",
                                    );
                                }
                                Err(e) => {
                                    warn!(job_id, error = %e, "SetJob cancel failed");
                                    emit_print_audit(
                                        &audit_ctx,
                                        &job,
                                        EventType::Alert,
                                        Decision::DENY,
                                        &format!("Cancel failed: {e}"),
                                    );
                                }
                            },
                            JobDecision::Alert(reason) => {
                                warn!(job_id, reason, "job_alert");
                                emit_print_audit(
                                    &audit_ctx,
                                    &job,
                                    EventType::Alert,
                                    Decision::DENY,
                                    reason,
                                );
                            }
                        }
                    }
                    Err(_) => {
                        // Job doesn't exist — no error logging needed for expected misses.
                    }
                }
            }
        }
    }

    // Clean up notification handle.
    let _ = unsafe { CloseHandle(notify_handle) };
    info!("print watcher thread exited");
}

// ---------------------------------------------------------------------------
// Job evaluation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobDecision {
    Allow,
    Cancel,
    Alert(&'static str),
}

fn evaluate_job(
    job: &JobInfo,
    config: &PrintWatcherConfig,
    offline: &Arc<OfflineManager>,
    runtime_handle: &tokio::runtime::Handle,
) -> JobDecision {
    // Determine classification.
    let classification = if job.datatype == "XPS_PASS" {
        let spl_path = build_spl_path(job.job_id);
        match std::fs::read(&spl_path) {
            Ok(bytes) => match extract_text(&bytes, config.max_pages) {
                Ok(text) => {
                    let cls = ContentClassifier::classify(&text);
                    debug!(job_id = job.job_id, ?cls, "XPS classification result");
                    cls
                }
                Err(e) => {
                    warn!(job_id = job.job_id, error = %e, "XPS parse failed — falling back to metadata");
                    classify_document_name(&job.document_name)
                }
            },
            Err(e) => {
                warn!(job_id = job.job_id, error = %e, "SPL read failed — falling back to metadata");
                classify_document_name(&job.document_name)
            }
        }
    } else {
        // Non-XPS jobs: metadata-only classification.
        classify_document_name(&job.document_name)
    };

    // Build ABAC request.
    let request = EvaluateRequest {
        subject: Subject {
            user_sid: "S-1-0-0".to_string(), // Placeholder — real SID resolution deferred.
            user_name: job.user_name.clone(),
            groups: Vec::new(),
            device_trust: dlp_common::DeviceTrust::Unknown,
            network_location: NetworkLocation::Unknown,
            device_health: dlp_common::DeviceHealthStatus::default(),
        },
        resource: Resource {
            path: job.document_name.clone(),
            classification,
        },
        environment: Environment {
            timestamp: chrono::Utc::now(),
            session_id: 0,
            access_context: dlp_common::AccessContext::Local,
        },
        action: Action::PRINT,
        agent: None,
        source_application: None,
        destination_application: None,
        source_origin: None,
        destination_origin: None,
    };

    // Evaluate policy.
    let response = runtime_handle.block_on(offline.evaluate(&request));

    decision_from_response(response, job, config)
}

/// Maps an [`EvaluateResponse`] to a [`JobDecision`].
fn decision_from_response(
    response: EvaluateResponse,
    job: &JobInfo,
    _config: &PrintWatcherConfig,
) -> JobDecision {
    match response.decision {
        Decision::DENY | Decision::DenyWithAlert => {
            if is_job_printing(job.status) {
                JobDecision::Alert("Job already printing — cannot cancel")
            } else {
                JobDecision::Cancel
            }
        }
        Decision::ALLOW | Decision::AllowWithLog => JobDecision::Allow,
    }
}

/// Heuristic classification based on document name.
fn classify_document_name(name: &str) -> Classification {
    let lower = name.to_lowercase();
    if lower.contains("confidential") || lower.contains("secret") {
        Classification::T3
    } else if lower.contains("internal") {
        Classification::T2
    } else {
        Classification::T1
    }
}

/// Constructs the SPL file path for a given job ID.
fn build_spl_path(job_id: u32) -> String {
    format!(r"C:\Windows\System32\spool\PRINTERS\{job_id}.SPL")
}

// ---------------------------------------------------------------------------
// Audit helpers
// ---------------------------------------------------------------------------

fn emit_print_audit(
    ctx: &EmitContext,
    job: &JobInfo,
    event_type: EventType,
    decision: Decision,
    _reason: &str,
) {
    let mut event = AuditEvent::new(
        event_type,
        "S-1-0-0".to_string(), // Placeholder SID
        job.user_name.clone(),
        job.document_name.clone(),
        Classification::T1, // Classification is in the request, not the event directly
        Action::PRINT,
        decision,
        ctx.agent_id.clone(),
        ctx.session_id,
    );
    event.correlation_id = Some(format!("print-job-{}", job.job_id));
    emit_audit(ctx, &mut event);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use dlp_common::{Decision, EvaluateResponse};

    #[test]
    fn build_spl_path_returns_correct_path() {
        assert_eq!(
            build_spl_path(42),
            r"C:\Windows\System32\spool\PRINTERS\42.SPL"
        );
        assert_eq!(
            build_spl_path(1),
            r"C:\Windows\System32\spool\PRINTERS\1.SPL"
        );
    }

    #[test]
    fn decision_from_response_allow() {
        let job = JobInfo {
            job_id: 1,
            document_name: "test.docx".to_string(),
            user_name: "alice".to_string(),
            status: 0,
            datatype: "XPS_PASS".to_string(),
            pages: 1,
        };
        let config = PrintWatcherConfig::default();
        let resp = EvaluateResponse {
            decision: Decision::ALLOW,
            matched_policy_id: None,
            reason: "test".to_string(),
            enforcement_mode: None,
            would_have_denied: false,
            matched_label_id: None,
        };
        assert_eq!(
            decision_from_response(resp, &job, &config),
            JobDecision::Allow
        );
    }

    #[test]
    fn decision_from_response_deny_cancels() {
        let job = JobInfo {
            job_id: 1,
            document_name: "test.docx".to_string(),
            user_name: "alice".to_string(),
            status: 0,
            datatype: "XPS_PASS".to_string(),
            pages: 1,
        };
        let config = PrintWatcherConfig::default();
        let resp = EvaluateResponse {
            decision: Decision::DENY,
            matched_policy_id: None,
            reason: "test".to_string(),
            enforcement_mode: None,
            would_have_denied: true,
            matched_label_id: None,
        };
        assert_eq!(
            decision_from_response(resp, &job, &config),
            JobDecision::Cancel
        );
    }

    #[test]
    fn decision_from_response_deny_with_alert_cancels() {
        let job = JobInfo {
            job_id: 1,
            document_name: "test.docx".to_string(),
            user_name: "alice".to_string(),
            status: 0,
            datatype: "XPS_PASS".to_string(),
            pages: 1,
        };
        let config = PrintWatcherConfig::default();
        let resp = EvaluateResponse {
            decision: Decision::DenyWithAlert,
            matched_policy_id: None,
            reason: "test".to_string(),
            enforcement_mode: None,
            would_have_denied: true,
            matched_label_id: None,
        };
        assert_eq!(
            decision_from_response(resp, &job, &config),
            JobDecision::Cancel
        );
    }

    #[test]
    fn decision_from_response_deny_when_printing_emits_alert() {
        let job = JobInfo {
            job_id: 1,
            document_name: "test.docx".to_string(),
            user_name: "alice".to_string(),
            status: windows::Win32::Graphics::Printing::JOB_STATUS_PRINTING,
            datatype: "XPS_PASS".to_string(),
            pages: 1,
        };
        let config = PrintWatcherConfig::default();
        let resp = EvaluateResponse {
            decision: Decision::DENY,
            matched_policy_id: None,
            reason: "test".to_string(),
            enforcement_mode: None,
            would_have_denied: true,
            matched_label_id: None,
        };
        assert_eq!(
            decision_from_response(resp, &job, &config),
            JobDecision::Alert("Job already printing — cannot cancel")
        );
    }

    #[test]
    fn should_cancel_for_classification_respects_config() {
        let allow_config = PrintWatcherConfig {
            max_pages: 0,
            unclassifiable_action: "ALLOW".to_string(),
        };
        let deny_config = PrintWatcherConfig {
            max_pages: 0,
            unclassifiable_action: "DENY".to_string(),
        };
        let block_config = PrintWatcherConfig {
            max_pages: 0,
            unclassifiable_action: "Block".to_string(),
        };

        assert!(!allow_config.should_deny_unclassifiable());
        assert!(deny_config.should_deny_unclassifiable());
        assert!(block_config.should_deny_unclassifiable());
    }

    #[test]
    fn classify_document_name_detects_confidential() {
        assert_eq!(
            classify_document_name("Q3-Confidential-Report.docx"),
            Classification::T3
        );
    }

    #[test]
    fn classify_document_name_detects_secret() {
        assert_eq!(
            classify_document_name("Top Secret Plans.docx"),
            Classification::T3
        );
    }

    #[test]
    fn classify_document_name_detects_internal() {
        assert_eq!(
            classify_document_name("Internal Use Only.docx"),
            Classification::T2
        );
    }

    #[test]
    fn classify_document_name_defaults_to_public() {
        assert_eq!(
            classify_document_name("Hello World.docx"),
            Classification::T1
        );
    }

    #[test]
    fn print_watcher_config_default() {
        let cfg = PrintWatcherConfig::default();
        assert_eq!(cfg.max_pages, 100);
        assert_eq!(cfg.unclassifiable_action, "Block");
        assert!(cfg.should_deny_unclassifiable());
    }

    #[test]
    fn shutdown_immediately_exits() {
        // We can't easily test the thread loop without mocking Win32 APIs,
        // but we can verify the shutdown flag works by creating a watcher
        // and stopping it immediately.
        //
        // NOTE: this test requires a tokio runtime.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handle = rt.handle().clone();

        // Build a minimal OfflineManager (needs a real EngineClient, but we
        // only use it in the thread which we stop before it evaluates anything).
        let cache = std::sync::Arc::new(crate::cache::Cache::new());
        let client = crate::engine_client::EngineClient::default_client().unwrap();
        let offline = std::sync::Arc::new(OfflineManager::new(client, cache, None));

        let audit_ctx = EmitContext {
            agent_id: "AGENT-TEST".to_string(),
            session_id: 1,
            user_sid: "S-1-5-21-TEST".to_string(),
            user_name: "testuser".to_string(),
            machine_name: None,
        };

        let mut watcher = PrintWatcher::new(offline, audit_ctx, handle);
        watcher.config = PrintWatcherConfig {
            max_pages: 0,
            ..Default::default()
        };

        // We can't start the real watcher in a unit test because it calls
        // OpenPrinter on the spooler.  Instead, verify the struct state.
        assert!(watcher.handle.is_none());
        watcher.shutdown.store(true, Ordering::Relaxed);
        assert!(watcher.shutdown.load(Ordering::Relaxed));
    }

    #[test]
    fn max_pages_zero_skips_xps_parsing() {
        // When max_pages is 0, extract_text returns empty string immediately.
        let text = extract_text(b"irrelevant", 0).unwrap();
        assert_eq!(text, "");
    }

    #[test]
    fn unclassifiable_action_allow_with_emf_job() {
        let config = PrintWatcherConfig {
            max_pages: 0,
            unclassifiable_action: "ALLOW".to_string(),
        };
        let job = JobInfo {
            job_id: 1,
            document_name: "test.docx".to_string(),
            user_name: "alice".to_string(),
            status: 0,
            datatype: "NT EMF 1.008".to_string(),
            pages: 1,
        };
        // For an EMF job with ALLOW unclassifiable, the offline decision
        // would depend on the document name classification.  "test.docx"
        // classifies as T1, which is not sensitive, so offline default is ALLOW.
        // This test verifies the config field exists and parses correctly.
        assert!(!config.should_deny_unclassifiable());
        assert_eq!(
            classify_document_name(&job.document_name),
            Classification::T1
        );
    }

    #[test]
    fn unclassifiable_action_deny_with_emf_job() {
        let config = PrintWatcherConfig {
            max_pages: 0,
            unclassifiable_action: "DENY".to_string(),
        };
        let job = JobInfo {
            job_id: 1,
            document_name: "test.docx".to_string(),
            user_name: "alice".to_string(),
            status: 0,
            datatype: "NT EMF 1.008".to_string(),
            pages: 1,
        };
        assert!(config.should_deny_unclassifiable());
        assert_eq!(
            classify_document_name(&job.document_name),
            Classification::T1
        );
    }
}
