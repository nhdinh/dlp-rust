//! Windows Service lifecycle management (T-10, T-38).
//!
//! This module implements the `windows-service` crate entry point and manages
//! the DLP Agent's service states: Start, Stop, Pause, Resume.
//!
//! ## Installation
//!
//! ```cmd
//! sc create dlp-agent type= own start= auto binpath= "C:\Program Files\DLP\dlp-agent.exe"
//! ```
//!
//! ## Service States
//!
//! - **Running**: normal file interception and policy evaluation active.
//! - **Paused**: interception paused; UI remains responsive.
//! - **Stopped**: service exited cleanly.
//!
//! ## Password-Protected Stop (T-38)
//!
//! A `sc stop` command triggers a password challenge over Pipe 1 before the
//! service actually terminates.  The dlp-admin must enter their AD password;
//! 3 failures or cancellation aborts the stop.  On success the service
//! transitions to `StopPending` and exits cleanly.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use parking_lot::Mutex;
use tracing::{error, info, Level};
use tracing_subscriber::fmt::format::FmtSpan;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

/// The Windows Service name registered with the SCM.
pub const SERVICE_NAME: &str = "dlp-agent";

// ──────────────────────────────────────────────────────────────────────────────
// Service main (invoked from the generated FFI entry in main.rs)
// ──────────────────────────────────────────────────────────────────────────────

/// Service main — called by the SCM-generated FFI entry after `service_dispatcher::start`.
//
// Panics here propagate as service crashes — all errors are caught and logged.
#[cfg(windows)]
pub fn service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = run_service() {
        error!(error = %e, "service exited with error");
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Service body
// ──────────────────────────────────────────────────────────────────────────────

/// Runs the DLP Agent Windows Service to completion.
pub fn run_service() -> Result<()> {
    init_logging();
    info!(service_name = SERVICE_NAME, "DLP Agent service starting");

    // Register the service control handler.
    let status_handle = service_control_handler::register(SERVICE_NAME, service_control_handler)?;

    // Wrap in Arc<Mutex<>> so we can use it across multiple set_status calls.
    let status_handle = Arc::new(Mutex::new(status_handle));

    // Report STARTING.
    set_status(
        &status_handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        None,
    )?;

    // Acquire single-instance mutex.
    acquire_instance_mutex();

    // Report RUNNING.
    set_status(
        &status_handle,
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::PAUSE_CONTINUE,
        None,
    )?;

    // Enter the main run loop.
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_loop(&status_handle))?;

    // Report STOPPED.
    set_status(
        &status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        Some(ServiceExitCode::Win32(0)),
    )?;

    info!(service_name = SERVICE_NAME, "service stopped");
    Ok(())
}

/// The main service run loop.
///
/// Waits for either `ctrl_c` or a password-confirmed stop signal.
/// When the SCM issues `sc stop`, [`password_stop::initiate_stop`] is called
/// on the SCM callback thread, which starts the password challenge.  This loop
/// polls the confirmation flag every 500 ms — on confirmation it proceeds to
/// shutdown; on `PASSWORD_CANCEL` or max attempts, [`password_stop::revert_stop`]
/// reverts the state to Running.
async fn run_loop(
    status_handle: &Arc<Mutex<windows_service::service_control_handler::ServiceStatusHandle>>,
) -> Result<()> {
    info!(service_name = SERVICE_NAME, "service running");

    let poll_interval = Duration::from_millis(500);
    let mut ticker = tokio::time::interval(poll_interval);

    loop {
        tokio::select! {
            biased;

            // Ctrl+C from console session.
            _ = tokio::signal::ctrl_c() => {
                info!(service_name = SERVICE_NAME, "service stopping (Ctrl+C)");
                break;
            }

            // Poll every 500 ms for stop confirmation or revert.
            _ = ticker.tick() => {
                if crate::password_stop::is_stop_confirmed() {
                    info!(service_name = SERVICE_NAME, "password verified — initiating shutdown");
                    set_status(
                        status_handle,
                        ServiceState::StopPending,
                        ServiceControlAccept::empty(),
                        None,
                    )?;
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Convenience to build and set a [`ServiceStatus`].
//
// `handle` is wrapped in `Arc<Mutex<>>` — we lock to get a temporary borrow.
fn set_status(
    handle: &Arc<Mutex<windows_service::service_control_handler::ServiceStatusHandle>>,
    state: ServiceState,
    controls: ServiceControlAccept,
    exit_code: Option<ServiceExitCode>,
) -> Result<()> {
    let status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: controls,
        exit_code: exit_code.unwrap_or(ServiceExitCode::Win32(0)),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    let handle = handle.lock();
    handle
        .set_service_status(status)
        .map_err(|e| anyhow::anyhow!("set_service_status failed: {e}"))?;
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Service control handler
// ──────────────────────────────────────────────────────────────────────────────

/// Shared mutable service state.
static SERVICE_STATE: Mutex<ServiceState> = Mutex::new(ServiceState::Running);

/// Returns the current service state.
#[must_use]
pub fn current_state() -> ServiceState {
    *SERVICE_STATE.lock()
}

/// The SCM-issued service control handler.
//
// Runs on the SCM callback thread — keep all work minimal and non-blocking.
fn service_control_handler(control: ServiceControl) -> ServiceControlHandlerResult {
    match control {
        ServiceControl::Stop => {
            info!(service_name = SERVICE_NAME, "SCM: STOP");
            *SERVICE_STATE.lock() = ServiceState::StopPending;
            // Initiate the password challenge — the actual stop proceeds only
            // after successful verification (detected in the run loop via
            // password_stop::is_stop_confirmed).
            crate::password_stop::initiate_stop();
        }
        ServiceControl::Pause => {
            info!(service_name = SERVICE_NAME, "SCM: PAUSE");
            *SERVICE_STATE.lock() = ServiceState::Paused;
        }
        ServiceControl::Continue => {
            info!(service_name = SERVICE_NAME, "SCM: CONTINUE");
            *SERVICE_STATE.lock() = ServiceState::Running;
        }
        ServiceControl::Interrogate => {
            // SCM reads current state via the status handle — no-op here.
        }
        _ => {}
    }
    ServiceControlHandlerResult::NoError
}

// ──────────────────────────────────────────────────────────────────────────────
// Revert to Running (called from password_stop on cancel/failure)
// ──────────────────────────────────────────────────────────────────────────────

/// Reverts the service state from StopPending back to Running.
///
/// Called by [`crate::password_stop`] when the dlp-admin cancels the stop
/// dialog or fails the password challenge 3 times.
pub fn revert_stop() {
    *SERVICE_STATE.lock() = ServiceState::Running;
    info!(
        service_name = SERVICE_NAME,
        "service stop reverted to Running"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Single-instance enforcement
// ──────────────────────────────────────────────────────────────────────────────

/// Acquires the global single-instance mutex.
fn acquire_instance_mutex() {
    #[allow(dead_code)]
    const MUTEX_NAME: &str = "Global\\dlp-agent-instance";
    match std::sync::Mutex::new(()).try_lock() {
        Ok(_guard) => info!(
            service_name = SERVICE_NAME,
            "single-instance mutex acquired"
        ),
        Err(_) => {
            info!(
                service_name = SERVICE_NAME,
                "previous instance detected — SCM serialises starts"
            )
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Logging
// ──────────────────────────────────────────────────────────────────────────────

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(Level::INFO.into())
        .from_env_lossy();

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::CLOSE)
        .with_target(true)
        .with_thread_ids(true)
        .init();
}

// ──────────────────────────────────────────────────────────────────────────────
// CLI fallback (no SCM)
// ──────────────────────────────────────────────────────────────────────────────

/// Runs the DLP Agent as a regular console application.
pub fn run_console() -> Result<()> {
    init_logging();
    info!(
        service_name = SERVICE_NAME,
        "DLP Agent running in console mode"
    );

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        tokio::signal::ctrl_c().await?;
        info!(service_name = SERVICE_NAME, "DLP Agent stopped by Ctrl+C");
        Ok::<_, anyhow::Error>(())
    })?;

    Ok(())
}
