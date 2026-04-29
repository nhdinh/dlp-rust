//! DLP Endpoint Agent entry point.
//!
//! Runs exclusively as a Windows Service, started by the Service Control Manager (SCM).
//! `service_dispatcher::start` blocks until the service stops.

use anyhow::Context;

#[cfg(windows)]
use dlp_agent::service::service_main;

// `define_windows_service!` must be in the same module that calls `service_dispatcher::start`
// so the generated `ffi_entry` function is accessible as a local symbol.
#[cfg(windows)]
windows_service::define_windows_service!(ffi_entry, service_main);

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    // Start the Windows Service dispatcher.  `ffi_entry` is the macro-generated FFI entry
    // point visible in this module; `service_main` (in `service.rs`) is imported above.
    windows_service::service_dispatcher::start(dlp_agent::service::SERVICE_NAME, ffi_entry)
        .context("service dispatcher failed")?;

    Ok(())
}

#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("dlp-agent is only supported on Windows");
}
