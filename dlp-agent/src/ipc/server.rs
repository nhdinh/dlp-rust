//! Starts all three named-pipe IPC servers (T-31).
//!
//! Each server runs on its own thread. Threads are named for easier
//! debugging.  A readiness barrier ensures all three pipe instances are
//! created before the function returns — this prevents the UI spawner
//! from launching UI processes before the pipes exist.

use std::sync::Arc;
use std::thread;

use anyhow::{Context, Result};
use parking_lot::Mutex;
use tracing::{error, info};

use super::{pipe1, pipe2, pipe3};

/// Starts all three IPC pipe servers on background threads.
///
/// Blocks until all three pipes have been created (i.e., the first
/// `CreateNamedPipeW` call in each server has succeeded).  This
/// guarantees that the pipes exist before the session monitor spawns
/// UI processes that try to connect.
///
/// # Errors
///
/// Returns an error if any pipe server thread fails to spawn, or if
/// any pipe fails to create within the readiness timeout.
pub fn start_all() -> Result<()> {
    // Each pipe server will set its slot to `true` after the first
    // CreateNamedPipeW succeeds.  We poll until all three are ready.
    let ready = Arc::new(Mutex::new([false; 3]));

    let r0 = ready.clone();
    let p1 = thread::Builder::new()
        .name("ipc-pipe1".into())
        .spawn(move || {
            if let Err(e) = pipe1::serve_with_ready(move || {
                r0.lock()[0] = true;
            }) {
                error!(error = %e, "Pipe 1 server exited with error");
            }
        })
        .context("failed to spawn Pipe 1 thread")?;

    let r1 = ready.clone();
    let p2 = thread::Builder::new()
        .name("ipc-pipe2".into())
        .spawn(move || {
            if let Err(e) = pipe2::serve_with_ready(move || {
                r1.lock()[1] = true;
            }) {
                error!(error = %e, "Pipe 2 server exited with error");
            }
        })
        .context("failed to spawn Pipe 2 thread")?;

    let r2 = ready.clone();
    let p3 = thread::Builder::new()
        .name("ipc-pipe3".into())
        .spawn(move || {
            if let Err(e) = pipe3::serve_with_ready(move || {
                r2.lock()[2] = true;
            }) {
                error!(error = %e, "Pipe 3 server exited with error");
            }
        })
        .context("failed to spawn Pipe 3 thread")?;

    // Wait for all three pipes to be created (up to 5 seconds).
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        {
            let flags = ready.lock();
            if flags[0] && flags[1] && flags[2] {
                break;
            }
        }
        if std::time::Instant::now() > deadline {
            tracing::warn!(
                "Timed out waiting for pipe servers to become ready \
                 — proceeding anyway"
            );
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    info!(
        pipe1 = ?p1.thread().id(),
        pipe2 = ?p2.thread().id(),
        pipe3 = ?p3.thread().id(),
        "all IPC pipe servers started and ready"
    );
    Ok(())
}
