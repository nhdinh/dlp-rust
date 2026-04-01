//! Starts all three named-pipe IPC servers (T-31).
//!
//! Each server runs on its own thread. Threads are named for easier debugging.

use std::thread;

use anyhow::{Context, Result};
use tracing::info;

use super::{pipe1, pipe2, pipe3};

/// Starts all three IPC pipe servers on background threads.
pub fn start_all() -> Result<()> {
    let p1 = thread::Builder::new()
        .name("ipc-pipe1".into())
        .spawn(|| {
            if let Err(e) = pipe1::serve() {
                tracing::error!(error = %e, "Pipe 1 server exited with error");
            }
        })
        .context("failed to spawn Pipe 1 thread")?;

    let p2 = thread::Builder::new()
        .name("ipc-pipe2".into())
        .spawn(|| {
            if let Err(e) = pipe2::serve() {
                tracing::error!(error = %e, "Pipe 2 server exited with error");
            }
        })
        .context("failed to spawn Pipe 2 thread")?;

    let p3 = thread::Builder::new()
        .name("ipc-pipe3".into())
        .spawn(|| {
            if let Err(e) = pipe3::serve() {
                tracing::error!(error = %e, "Pipe 3 server exited with error");
            }
        })
        .context("failed to spawn Pipe 3 thread")?;

    info!(pipe1 = ?p1.thread().id(), pipe2 = ?p2.thread().id(), pipe3 = ?p3.thread().id(), "all IPC pipe servers started");
    Ok(())
}
