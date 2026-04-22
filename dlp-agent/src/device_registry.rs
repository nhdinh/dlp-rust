//! Device registry cache for the dlp-agent.
//!
//! Maintains an in-memory `RwLock<HashMap>` keyed by `(vid, pid, serial)` that
//! maps to a [`UsbTrustTier`]. The cache is populated by polling
//! `GET /admin/device-registry` every [`REGISTRY_POLL_INTERVAL`] seconds and
//! on every USB device arrival event (D-08, D-09 from 24-CONTEXT.md).
//!
//! ## Fail-safe behavior (D-10)
//!
//! If the server is unreachable, the stale cache is retained. The
//! [`DeviceRegistryCache::trust_tier_for`] method returns [`UsbTrustTier::Blocked`]
//! for any device not present in the cache — default deny per CLAUDE.md section 3.1.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use dlp_common::UsbTrustTier;
use parking_lot::RwLock;
use tracing::{debug, info, warn};

// Only import ServerClient on Windows (where server_client module exists).
#[cfg(windows)]
use crate::server_client::ServerClient;

/// Background poll interval for registry refresh (D-08).
const REGISTRY_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// In-memory USB device trust-tier cache.
///
/// Keyed by `(vid, pid, serial)` — a device identity triple. Values are
/// [`UsbTrustTier`] variants. Phase 26 enforcement reads from this cache
/// at I/O time without making a server call.
///
/// The cache is replaced atomically on each successful refresh. Concurrent
/// read access (via [`DeviceRegistryCache::trust_tier_for`]) never blocks
/// writers longer than a single lock acquisition.
#[derive(Debug, Default)]
pub struct DeviceRegistryCache {
    /// Map from (vid, pid, serial) to trust tier.
    cache: RwLock<HashMap<(String, String, String), UsbTrustTier>>,
}

impl DeviceRegistryCache {
    /// Constructs a new, empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the trust tier for the given device identity triple.
    ///
    /// Returns [`UsbTrustTier::Blocked`] (the default) if the device is not
    /// in the registry — fail-safe default deny (D-10, CLAUDE.md section 3.1).
    ///
    /// # Arguments
    ///
    /// * `vid` - USB Vendor ID hex string (e.g., `"0951"`).
    /// * `pid` - USB Product ID hex string (e.g., `"1666"`).
    /// * `serial` - Device serial number string.
    ///
    /// # Returns
    ///
    /// The [`UsbTrustTier`] for the device, or [`UsbTrustTier::Blocked`] if unknown.
    #[must_use]
    pub fn trust_tier_for(&self, vid: &str, pid: &str, serial: &str) -> UsbTrustTier {
        let key = (vid.to_string(), pid.to_string(), serial.to_string());
        self.cache
            .read()
            .get(&key)
            .copied()
            // Default deny: unknown devices are Blocked (D-10, CLAUDE.md section 3.1).
            .unwrap_or(UsbTrustTier::Blocked)
    }

    /// Fetches the current device registry from the server and replaces the cache.
    ///
    /// On success: atomically replaces the entire map with new entries.
    /// On failure: retains the existing cache (fail-safe, D-10).
    ///
    /// # Arguments
    ///
    /// * `client` - Server client used to call `GET /admin/device-registry`.
    #[cfg(windows)]
    pub async fn refresh(&self, client: &ServerClient) {
        match client.fetch_device_registry().await {
            Ok(entries) => {
                // Build a new map from the server response, filtering out entries
                // with unrecognized trust_tier values (warn and skip — never panic).
                let new_map: HashMap<(String, String, String), UsbTrustTier> = entries
                    .into_iter()
                    .filter_map(|e| {
                        let tier = match e.trust_tier.as_str() {
                            "blocked" => UsbTrustTier::Blocked,
                            "read_only" => UsbTrustTier::ReadOnly,
                            "full_access" => UsbTrustTier::FullAccess,
                            other => {
                                warn!(
                                    trust_tier = %other,
                                    "unknown trust_tier from server — skipping entry"
                                );
                                return None;
                            }
                        };
                        Some(((e.vid, e.pid, e.serial), tier))
                    })
                    .collect();
                let count = new_map.len();
                // Atomic replacement: write lock held only for the swap.
                *self.cache.write() = new_map;
                debug!(count, "device registry cache refreshed");
            }
            Err(e) => {
                // Fail-safe: retain stale cache on server error (D-10).
                warn!(error = %e, "device registry refresh failed — retaining stale cache");
            }
        }
    }

    /// Spawns a background tokio task that refreshes the cache every
    /// [`REGISTRY_POLL_INTERVAL`] seconds.
    ///
    /// The task performs an immediate refresh on startup, then polls on the
    /// fixed interval. It respects the `shutdown` channel: on signal it exits
    /// cleanly without a final refresh.
    ///
    /// # Arguments
    ///
    /// * `self_arc` - `Arc`-wrapped cache instance to refresh.
    /// * `client` - Server client cloned into the background task.
    /// * `shutdown` - Watch receiver; task exits when this signals.
    ///
    /// # Returns
    ///
    /// A `JoinHandle` for the background task (detached; join only needed on shutdown).
    #[cfg(windows)]
    pub fn spawn_poll_task(
        self_arc: Arc<Self>,
        client: ServerClient,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // Perform an immediate refresh on startup before entering the timer loop.
            // This ensures the cache is populated before the first I/O event arrives.
            self_arc.refresh(&client).await;
            info!("device registry cache: initial refresh complete");

            let mut interval = tokio::time::interval(REGISTRY_POLL_INTERVAL);
            // Consume the immediate first tick (we already refreshed above).
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        self_arc.refresh(&client).await;
                    }
                    _ = shutdown.changed() => {
                        info!("device registry poll task shutting down");
                        return;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_tier_for_empty_cache_returns_blocked() {
        // Arrange: empty cache (default)
        let cache = DeviceRegistryCache::new();
        // Act + Assert: unknown device returns Blocked (fail-safe D-10)
        assert_eq!(cache.trust_tier_for("0951", "1666", "ABC"), UsbTrustTier::Blocked);
    }

    #[test]
    fn test_trust_tier_for_known_device_returns_tier() {
        // Arrange: seed a known device
        let cache = DeviceRegistryCache::new();
        cache.cache.write().insert(
            ("0951".to_string(), "1666".to_string(), "ABC".to_string()),
            UsbTrustTier::ReadOnly,
        );
        // Act + Assert: known device returns its tier
        assert_eq!(cache.trust_tier_for("0951", "1666", "ABC"), UsbTrustTier::ReadOnly);
    }

    #[test]
    fn test_trust_tier_for_unknown_device_returns_blocked() {
        // Arrange: seed a device, then look up a different serial
        let cache = DeviceRegistryCache::new();
        cache.cache.write().insert(
            ("0951".to_string(), "1666".to_string(), "ABC".to_string()),
            UsbTrustTier::FullAccess,
        );
        // Act + Assert: different serial -> Blocked (not in cache)
        assert_eq!(cache.trust_tier_for("0951", "1666", "DIFFERENT"), UsbTrustTier::Blocked);
    }

    #[test]
    fn test_concurrent_reads_do_not_deadlock() {
        // Arrange: shared cache with one entry
        use std::thread;
        let cache = Arc::new(DeviceRegistryCache::new());
        cache.cache.write().insert(
            ("vid".to_string(), "pid".to_string(), "ser".to_string()),
            UsbTrustTier::FullAccess,
        );
        // Act: two threads read simultaneously
        let c1 = Arc::clone(&cache);
        let c2 = Arc::clone(&cache);
        let t1 = thread::spawn(move || c1.trust_tier_for("vid", "pid", "ser"));
        let t2 = thread::spawn(move || c2.trust_tier_for("vid", "pid", "ser"));
        // Assert: both threads return the correct tier (no deadlock)
        assert_eq!(t1.join().expect("thread 1 must not panic"), UsbTrustTier::FullAccess);
        assert_eq!(t2.join().expect("thread 2 must not panic"), UsbTrustTier::FullAccess);
    }
}
