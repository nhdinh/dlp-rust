//! DLP Endpoint Agent entry point.
//!
//! ## Execution modes
//!
//! - **Service mode** (default): started by the Windows Service Control Manager (SCM).
//!   `service_dispatcher::start` blocks until the service stops.
//!
//! - **Console mode**: run `cargo run -p dlp-agent -- --console` for interactive testing
//!   without installing the service.

use std::env;

use anyhow::Context;

#[cfg(windows)]
use dlp_agent::service::{run_console, service_main};

// `define_windows_service!` must be in the same module that calls `service_dispatcher::start`
// so the generated `ffi_entry` function is accessible as a local symbol.
#[cfg(windows)]
windows_service::define_windows_service!(ffi_entry, service_main);

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    if env::args().any(|a| a == "--console") {
        run_console().context("console mode failed")?;
        return Ok(());
    }

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
