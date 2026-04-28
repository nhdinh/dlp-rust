//! Managed origins cache for the Chrome Content Analysis agent.
//!
//! Maintains an in-memory `RwLock<HashSet<String>>` of managed origin
//! strings (e.g. `"https://sharepoint.com"`).  The cache is populated by
//! polling `GET /admin/managed-origins` every 30 seconds.
//!
//! ## Fail-safe behaviour
//!
//! If the server is unreachable, the stale cache is retained.  An origin
//! not present in the cache is treated as *unmanaged* (allowed).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tracing::{debug, info, warn};

#[cfg(windows)]
use crate::server_client::ServerClient;

/// Background poll interval for managed-origins refresh.
const ORIGINS_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// In-memory cache of managed origin strings.
///
/// The cache is replaced atomically on each successful refresh.  Concurrent
/// read access (via [`ManagedOriginsCache::is_managed`]) never blocks
/// writers longer than a single lock acquisition.
#[derive(Debug, Default)]
pub struct ManagedOriginsCache {
    cache: RwLock<HashSet<String>>,
}

impl ManagedOriginsCache {
    /// Constructs a new, empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if the given origin is in the managed-origins list.
    ///
    /// The comparison is case-sensitive exact string match (no wildcard
    /// support in this phase).
    ///
    /// # Arguments
    ///
    /// * `origin` — the origin string to check (e.g. `"https://sharepoint.com"`).
    #[must_use]
    pub fn is_managed(&self, origin: &str) -> bool {
        self.cache.read().contains(origin)
    }
}

#[cfg(windows)]
impl ManagedOriginsCache {
    /// Fetches the current managed-origins list from the server and replaces
    /// the cache.
    ///
    /// On success: atomically replaces the entire set with new entries.
    /// On failure: retains the existing cache (fail-safe).
    ///
    /// # Arguments
    ///
    /// * `client` — Server client used to call `GET /admin/managed-origins`.
    pub async fn refresh(&self, client: &ServerClient) {
        match client.fetch_managed_origins().await {
            Ok(entries) => {
                let new_set: HashSet<String> =
                    entries.into_iter().map(|e| e.origin).collect();
                let count = new_set.len();
                *self.cache.write() = new_set;
                debug!(count, "managed origins cache refreshed");
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "managed origins refresh failed — retaining stale cache"
                );
            }
        }
    }

    /// Spawns a background tokio task that refreshes the cache every
    /// [`ORIGINS_POLL_INTERVAL`] seconds.
    ///
    /// The task performs an immediate refresh on startup, then polls on the
    /// fixed interval.  It respects the `shutdown` channel: on signal it
    /// exits cleanly without a final refresh.
    ///
    /// # Arguments
    ///
    /// * `self_arc` — `Arc`-wrapped cache instance to refresh.
    /// * `client` — Server client cloned into the background task.
    /// * `shutdown` — Watch receiver; task exits when this signals.
    ///
    /// # Returns
    ///
    /// A `JoinHandle` for the background task (detached; join only needed on
    /// shutdown).
    pub fn spawn_poll_task(
        self_arc: Arc<Self>,
        client: ServerClient,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self_arc.refresh(&client).await;
            info!("managed origins cache: initial refresh complete");

            let mut interval = tokio::time::interval(ORIGINS_POLL_INTERVAL);
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        self_arc.refresh(&client).await;
                    }
                    _ = shutdown.changed() => {
                        info!("managed origins poll task shutting down");
                        return;
                    }
                }
            }
        })
    }
}

impl ManagedOriginsCache {
    /// Seeds the cache with a single origin for use in tests.
    ///
    /// This method is always compiled so that integration tests in `tests/`
    /// can call it without a feature flag.
    #[doc(hidden)]
    pub fn seed_for_test(&self, origin: &str) {
        self.cache.write().insert(origin.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_managed_empty_cache_returns_false() {
        let cache = ManagedOriginsCache::new();
        assert!(!cache.is_managed("https://example.com"));
    }

    #[test]
    fn test_is_managed_known_origin_returns_true() {
        let cache = ManagedOriginsCache::new();
        cache.cache.write().insert("https://sharepoint.com".to_string());
        assert!(cache.is_managed("https://sharepoint.com"));
    }

    #[test]
    fn test_is_managed_unknown_origin_returns_false() {
        let cache = ManagedOriginsCache::new();
        cache.cache.write().insert("https://sharepoint.com".to_string());
        assert!(!cache.is_managed("https://example.com"));
    }

    #[test]
    fn test_seed_for_test_inserts_origin() {
        let cache = ManagedOriginsCache::new();
        cache.seed_for_test("https://test.com");
        assert!(cache.is_managed("https://test.com"));
    }

    #[test]
    fn test_concurrent_reads_do_not_deadlock() {
        use std::thread;
        let cache = Arc::new(ManagedOriginsCache::new());
        cache.cache.write().insert("https://a.com".to_string());

        let c1 = Arc::clone(&cache);
        let c2 = Arc::clone(&cache);
        let t1 = thread::spawn(move || c1.is_managed("https://a.com"));
        let t2 = thread::spawn(move || c2.is_managed("https://a.com"));

        assert!(t1.join().expect("thread 1 must not panic"));
        assert!(t2.join().expect("thread 2 must not panic"));
    }
}
