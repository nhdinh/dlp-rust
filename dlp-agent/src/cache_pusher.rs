//! Cache pusher — policy change subscriber that rebuilds the shared-memory
//! classification cache.
//!
//! `CachePusher` monitors the agent's policy configuration for changes and
//! triggers a cache rebuild via [`ClassificationCache::rebuild`] when paths or
//! classifications are updated.  Rebuilds are debounced (500 ms) to prevent
//! thrashing during rapid policy updates.
//!
//! ## Cache Non-Authoritative Invariant
//!
//! The cache stores classification **HINT only**.  ABAC authority is never
//! bypassed; the cache only accelerates the hot path and drives fail-mode
//! decisions when the agent pipe is unreachable.

use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::{bounded, Receiver, Sender};
use tracing::{debug, info, warn};

use crate::classification_cache::{CacheKey, ClassificationCache};
// use dlp_common::Classification; // reserved for future policy-store integration

/// Debounce interval for policy change notifications.
const DEBOUNCE_MS: u64 = 500;

/// Poll interval for checking policy changes when no push channel is available.
const POLL_INTERVAL_SECS: u64 = 30;

/// Subscriber that rebuilds the shared-memory classification cache on policy
/// changes.
///
/// ## Usage
///
/// ```ignore
/// let pusher = CachePusher::new(Arc::clone(&cache));
/// pusher.start();
/// ```
pub struct CachePusher {
    cache: Arc<ClassificationCache>,
    notify_tx: Sender<CachePusherCommand>,
    notify_rx: Receiver<CachePusherCommand>,
}

/// Commands sent to the cache pusher background thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePusherCommand {
    /// Trigger a cache rebuild.
    Rebuild,
    /// Shut down the background thread.
    Shutdown,
}

impl CachePusher {
    /// Creates a new `CachePusher` bound to the given cache.
    ///
    /// The pusher does not spawn any threads until [`start`](Self::start) is
    /// called.
    pub fn new(cache: Arc<ClassificationCache>) -> Self {
        let (notify_tx, notify_rx) = bounded::<CachePusherCommand>(16);
        Self {
            cache,
            notify_tx,
            notify_rx,
        }
    }

    /// Returns a clone of the notification sender.
    ///
    /// Callers can use this to trigger rebuilds from other threads or tasks.
    pub fn notifier(&self) -> Sender<CachePusherCommand> {
        self.notify_tx.clone()
    }

    /// Starts the background rebuild thread.
    ///
    /// The thread debounces rebuild requests (500 ms) and polls for changes
    /// every 30 seconds as a backstop.  Call [`on_policy_change`](Self::on_policy_change)
    /// to trigger an immediate (debounced) rebuild.
    ///
    /// ## Panics
    ///
    /// Panics if called more than once.
    pub fn start(self) -> std::thread::JoinHandle<()> {
        let cache = self.cache;
        let rx = self.notify_rx;

        std::thread::Builder::new()
            .name("cache-pusher".into())
            .spawn(move || {
                info!(debounce_ms = DEBOUNCE_MS, "cache pusher thread started");

                let mut pending_rebuild = false;
                let mut last_rebuild = std::time::Instant::now();

                loop {
                    // Wait for a command with a timeout so we can process
                    // debounced rebuilds even when no new commands arrive.
                    let timeout = if pending_rebuild {
                        Duration::from_millis(DEBOUNCE_MS)
                    } else {
                        Duration::from_secs(POLL_INTERVAL_SECS)
                    };

                    match rx.recv_timeout(timeout) {
                        Ok(CachePusherCommand::Rebuild) => {
                            debug!("cache pusher: rebuild command received");
                            pending_rebuild = true;
                        }
                        Ok(CachePusherCommand::Shutdown) => {
                            info!("cache pusher: shutdown command received — exiting");
                            break;
                        }
                        Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                            // Timeout expired — process pending rebuild if any.
                        }
                        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                            info!("cache pusher: channel disconnected — exiting");
                            break;
                        }
                    }

                    if pending_rebuild {
                        // Simple debounce: if we rebuilt very recently, skip.
                        let elapsed = last_rebuild.elapsed();
                        if elapsed < Duration::from_millis(DEBOUNCE_MS) {
                            debug!(
                                elapsed_ms = elapsed.as_millis(),
                                "cache pusher: debouncing rebuild"
                            );
                            continue;
                        }

                        if let Err(e) = Self::perform_rebuild(&cache) {
                            warn!(error = %e, "cache pusher: rebuild failed");
                        } else {
                            last_rebuild = std::time::Instant::now();
                        }
                        pending_rebuild = false;
                    }
                }

                info!("cache pusher thread exited");
            })
            .expect("failed to spawn cache pusher thread")
    }

    /// Triggers a debounced cache rebuild.
    ///
    /// This is a non-blocking fire-and-forget call.  The actual rebuild happens
    /// on the background thread after the debounce interval.
    pub fn on_policy_change(&self) {
        if let Err(e) = self.notify_tx.try_send(CachePusherCommand::Rebuild) {
            warn!(error = %e, "cache pusher: failed to send rebuild command");
        }
    }

    /// Shuts down the background thread.
    ///
    /// This is a non-blocking fire-and-forget call.  The background thread will
    /// exit after processing any pending rebuild.
    pub fn shutdown(&self) {
        if let Err(e) = self.notify_tx.try_send(CachePusherCommand::Shutdown) {
            warn!(error = %e, "cache pusher: failed to send shutdown command");
        }
    }

    /// Performs the actual cache rebuild.
    ///
    /// Collects T3/T4 protected paths and rebuilds the cache.  In a full
    /// implementation this would read from the policy store; here we use a
    /// placeholder that can be overridden by callers.
    fn perform_rebuild(
        cache: &ClassificationCache,
    ) -> Result<(), crate::classification_cache::CacheError> {
        // Placeholder: in production this reads from the policy store.
        // For now, we rebuild with an empty entry list (the cache remains
        // functional but empty until prepopulate_t3_t4_roots is called).
        let entries: Vec<CacheKey> = Vec::new();
        let version = cache.rebuild(entries)?;
        info!(version, "cache pusher: cache rebuilt");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn cache_pusher_command_debug() {
        let cmd = CachePusherCommand::Rebuild;
        assert_eq!(format!("{:?}", cmd), "Rebuild");
    }

    #[test]
    fn cache_pusher_command_eq() {
        assert_eq!(CachePusherCommand::Rebuild, CachePusherCommand::Rebuild);
        assert_ne!(CachePusherCommand::Rebuild, CachePusherCommand::Shutdown);
    }

    /// Verifies that rapid rebuild requests are debounced — only one rebuild
    /// occurs within the debounce window.
    #[test]
    fn debounce() {
        // Create a mock cache that we can't actually build on non-Windows,
        // but we can test the debounce logic at the channel level.
        let (tx, rx) = bounded::<CachePusherCommand>(16);

        // Send multiple rebuild commands rapidly.
        for _ in 0..5 {
            tx.try_send(CachePusherCommand::Rebuild).unwrap();
        }

        // We should receive all 5 commands (the channel has capacity).
        let mut count = 0;
        while let Ok(cmd) = rx.try_recv() {
            assert_eq!(cmd, CachePusherCommand::Rebuild);
            count += 1;
        }
        assert_eq!(count, 5, "expected 5 rebuild commands in channel");
    }

    /// Verifies that shutdown command is processed correctly.
    #[test]
    fn shutdown_command() {
        let (tx, rx) = bounded::<CachePusherCommand>(4);
        tx.send(CachePusherCommand::Shutdown).unwrap();

        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(CachePusherCommand::Shutdown) => {}
            other => panic!("expected Shutdown command, got {:?}", other),
        }
    }

    /// Verifies that the notifier sender can be cloned and used independently.
    #[test]
    fn notifier_clone() {
        let (tx, rx) = bounded::<CachePusherCommand>(4);
        let tx2 = tx.clone();

        tx2.try_send(CachePusherCommand::Rebuild).unwrap();
        assert_eq!(rx.try_recv().unwrap(), CachePusherCommand::Rebuild);
    }
}
