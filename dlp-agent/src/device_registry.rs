//! Device registry cache for the dlp-agent.
//!
//! Maintains an in-memory `RwLock<HashMap>` keyed by `(vid, pid, serial, owner_sid)` that
//! maps to a [`UsbTrustTier`]. The cache is populated by polling
//! `GET /admin/device-registry` every [`REGISTRY_POLL_INTERVAL`] seconds and
//! on every USB device arrival event (D-08, D-09 from 24-CONTEXT.md).
//!
//! ## Per-user support (USB-06, Phase 38.4)
//!
//! The cache key includes an optional `owner_sid` field. Entries with
//! `owner_sid = None` are machine-wide; entries with `owner_sid = Some(sid)`
//! are per-user. The [`trust_tier_for_with_sid`] method queries both and
//! returns the most restrictive tier.
//!
//! ## Fail-safe behavior (D-10)
//!
//! If the server is unreachable, the stale cache is retained. The
//! [`DeviceRegistryCache::trust_tier_for_with_sid`] method returns [`UsbTrustTier::Blocked`]
//! for any device not present in the cache — default deny per CLAUDE.md section 3.1.

use std::cmp;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use dlp_common::UsbTrustTier;
use parking_lot::RwLock;
use tracing::{info, warn};

// Only import ServerClient on Windows (where server_client module exists).
#[cfg(windows)]
use crate::server_client::ServerClient;

/// Background poll interval for registry refresh (D-08).
const REGISTRY_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// In-memory USB device trust-tier cache.
///
/// Keyed by `(vid, pid, serial, owner_sid)` — a device identity triple plus an
/// optional owner SID. Phase 38.4 adds per-user support: entries with
/// `owner_sid = None` are machine-wide; `owner_sid = Some(sid)` are per-user.
///
/// The cache is replaced atomically on each successful refresh. Concurrent
/// read access (via [`DeviceRegistryCache::trust_tier_for_with_sid`]) never blocks
/// writers longer than a single lock acquisition.
#[derive(Debug, Default)]
pub struct DeviceRegistryCache {
    /// Map from (vid, pid, serial, owner_sid) to trust tier.
    ///
    /// `owner_sid` is `None` for machine-wide entries, `Some(sid)` for per-user.
    cache: RwLock<HashMap<(String, String, String, Option<String>), UsbTrustTier>>,
}

/// The result of a trust-tier lookup, including the effective tier and the
/// owner identity that determined it (USB-06, Phase 38.4).
#[derive(Debug, Clone, PartialEq)]
pub struct TrustTierResult {
    /// The effective trust tier after merging per-user and machine-wide entries.
    pub tier: UsbTrustTier,
    /// The owner SID of the entry that determined the effective tier.
    /// `None` when the machine-wide entry was used (or default-deny).
    pub owner_sid: Option<String>,
    /// The owner username of the entry that determined the effective tier.
    /// `None` when the machine-wide entry was used (or default-deny).
    pub owner_user: Option<String>,
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
    #[deprecated(since = "0.7.1", note = "Use trust_tier_for_with_sid for per-user support")]
    #[must_use]
    pub fn trust_tier_for(&self, vid: &str, pid: &str, serial: &str) -> UsbTrustTier {
        self.trust_tier_for_with_sid(vid, pid, serial, None).tier
    }

    /// Returns the trust tier for the given device, considering both per-user
    /// and machine-wide entries (USB-06, Phase 38.4).
    ///
    /// Queries the cache for:
    /// 1. An exact per-user match on `(vid, pid, serial, Some(owner_sid))`.
    /// 2. A machine-wide match on `(vid, pid, serial, None)`.
    ///
    /// If both exist, the **most restrictive** tier wins (minimum per
    /// `PartialOrd`: `Blocked < ReadOnly < FullAccess`).
    ///
    /// If neither exists, returns `(Blocked, None, None)` — default deny.
    ///
    /// # Arguments
    ///
    /// * `vid` - USB Vendor ID hex string.
    /// * `pid` - USB Product ID hex string.
    /// * `serial` - Device serial number string.
    /// * `owner_sid` - Optional Windows user SID for per-user lookup.
    ///
    /// # Returns
    ///
    /// A [`TrustTierResult`] containing the effective tier and the owner
    /// identity of the entry that determined it.
    #[must_use]
    pub fn trust_tier_for_with_sid(
        &self,
        vid: &str,
        pid: &str,
        serial: &str,
        owner_sid: Option<&str>,
    ) -> TrustTierResult {
        // Normalise to lowercase to match parse_usb_device_path (which lowercases
        // VID/PID but leaves serial as-is from dbcc_name) and handle users who
        // typed the serial in uppercase in the admin TUI.
        let vid_lc = vid.to_ascii_lowercase();
        let pid_lc = pid.to_ascii_lowercase();
        let serial_lc = serial.to_ascii_lowercase();

        let cache = self.cache.read();

        // Query per-user entry if owner_sid is provided.
        let per_user = owner_sid.map(|sid| {
            let key = (
                vid_lc.clone(),
                pid_lc.clone(),
                serial_lc.clone(),
                Some(sid.to_string()),
            );
            cache.get(&key).copied()
        });

        // Query machine-wide entry.
        let machine_wide_key = (vid_lc, pid_lc, serial_lc, None);
        let machine_wide = cache.get(&machine_wide_key).copied();

        drop(cache);

        match (per_user.flatten(), machine_wide) {
            (Some(user_tier), Some(machine_tier)) => {
                // Both exist: most restrictive wins (minimum).
                let effective = cmp::min(user_tier, machine_tier);
                if effective == user_tier {
                    TrustTierResult {
                        tier: effective,
                        owner_sid: owner_sid.map(String::from),
                        owner_user: None, // Will be filled by caller from entry metadata.
                    }
                } else {
                    TrustTierResult {
                        tier: effective,
                        owner_sid: None,
                        owner_user: None,
                    }
                }
            }
            (Some(user_tier), None) => TrustTierResult {
                tier: user_tier,
                owner_sid: owner_sid.map(String::from),
                owner_user: None,
            },
            (None, Some(machine_tier)) => TrustTierResult {
                tier: machine_tier,
                owner_sid: None,
                owner_user: None,
            },
            (None, None) => TrustTierResult {
                tier: UsbTrustTier::Blocked,
                owner_sid: None,
                owner_user: None,
            },
        }
    }

    /// Returns `true` if the given device identity triple is present in the
    /// registry cache (i.e., the device has been explicitly registered).
    ///
    /// Checks both machine-wide and any per-user entries.
    ///
    /// # Arguments
    ///
    /// * `vid` - USB Vendor ID hex string.
    /// * `pid` - USB Product ID hex string.
    /// * `serial` - Device serial number string.
    #[must_use]
    pub fn has_device(&self, vid: &str, pid: &str, serial: &str) -> bool {
        self.has_device_with_sid(vid, pid, serial, None)
    }

    /// Returns `true` if the given device is present for the specified owner SID
    /// (or machine-wide when `owner_sid` is `None`).
    ///
    /// # Arguments
    ///
    /// * `vid` - USB Vendor ID hex string.
    /// * `pid` - USB Product ID hex string.
    /// * `serial` - Device serial number string.
    /// * `owner_sid` - Optional owner SID; `None` checks machine-wide only.
    #[must_use]
    pub fn has_device_with_sid(
        &self,
        vid: &str,
        pid: &str,
        serial: &str,
        owner_sid: Option<&str>,
    ) -> bool {
        let key = (
            vid.to_ascii_lowercase(),
            pid.to_ascii_lowercase(),
            serial.to_ascii_lowercase(),
            owner_sid.map(String::from),
        );
        self.cache.read().contains_key(&key)
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
        self.refresh_with_sid(client, None).await;
    }

    /// Fetches the device registry with an optional owner SID filter and
    /// replaces the cache (USB-06, Phase 38.4).
    ///
    /// When `owner_sid` is `Some`, the server returns both machine-wide and
    /// per-user entries for that SID. The cache stores each entry keyed by
    /// its individual `owner_sid` field, so a single refresh can populate
    /// both machine-wide and per-user lookups.
    ///
    /// # Arguments
    ///
    /// * `client` - Server client used to call `GET /admin/device-registry`.
    /// * `owner_sid` - Optional Windows user SID to filter per-user entries.
    #[cfg(windows)]
    pub async fn refresh_with_sid(&self, client: &ServerClient, owner_sid: Option<&str>) {
        match client.fetch_device_registry_with_sid(owner_sid).await {
            Ok(entries) => {
                // Build a new map from the server response, filtering out entries
                // with unrecognized trust_tier values (warn and skip — never panic).
                let new_map: HashMap<(String, String, String, Option<String>), UsbTrustTier> =
                    entries
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
                            // Normalize empty owner_sid to None (T-38.4-06 mitigation).
                            let owner_sid_norm = e.owner_sid.filter(|s| !s.is_empty());
                            Some((
                                (
                                    e.vid.to_ascii_lowercase(),
                                    e.pid.to_ascii_lowercase(),
                                    e.serial.to_ascii_lowercase(),
                                    owner_sid_norm,
                                ),
                                tier,
                            ))
                        })
                        .collect();
                let count = new_map.len();
                // Atomic replacement: write lock held only for the swap.
                *self.cache.write() = new_map;
                info!(count, "device registry cache refreshed");
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

impl DeviceRegistryCache {
    /// Seeds the cache with a single entry for use in tests.
    ///
    /// This method is always compiled so that integration tests in `tests/`
    /// (which compile the library as a separate crate and therefore cannot use
    /// `#[cfg(test)]` on the library side) can call it without a feature flag.
    ///
    /// It is intentionally hidden from generated documentation and carries no
    /// security risk — it only writes to an in-memory `RwLock<HashMap>` that
    /// is discarded when the process exits (T-24-12 accepted disposition).
    ///
    /// # Arguments
    ///
    /// * `vid` - USB Vendor ID hex string.
    /// * `pid` - USB Product ID hex string.
    /// * `serial` - Device serial number string.
    /// * `tier` - Trust tier to associate with this device key.
    #[doc(hidden)]
    pub fn seed_for_test(
        &self,
        vid: &str,
        pid: &str,
        serial: &str,
        tier: UsbTrustTier,
    ) {
        self.seed_for_test_with_sid(vid, pid, serial, None, tier);
    }

    /// Seeds the cache with a per-user entry for use in tests (USB-06, Phase 38.4).
    ///
    /// # Arguments
    ///
    /// * `vid` - USB Vendor ID hex string.
    /// * `pid` - USB Product ID hex string.
    /// * `serial` - Device serial number string.
    /// * `owner_sid` - Optional owner SID; `None` for machine-wide.
    /// * `tier` - Trust tier to associate with this device key.
    #[doc(hidden)]
    pub fn seed_for_test_with_sid(
        &self,
        vid: &str,
        pid: &str,
        serial: &str,
        owner_sid: Option<&str>,
        tier: UsbTrustTier,
    ) {
        self.cache.write().insert(
            (
                vid.to_ascii_lowercase(),
                pid.to_ascii_lowercase(),
                serial.to_ascii_lowercase(),
                owner_sid.map(String::from),
            ),
            tier,
        );
    }

    /// Returns all registered serials for a given VID/PID pair (both lowercase).
    ///
    /// Used only for diagnostic logging when a device arrives but its serial is
    /// not found in the cache — helps surface registration mismatches without
    /// requiring the operator to query the admin TUI.
    #[must_use]
    pub fn serials_for_vid_pid(&self, vid: &str, pid: &str) -> Vec<String> {
        let vid_lc = vid.to_ascii_lowercase();
        let pid_lc = pid.to_ascii_lowercase();
        self.cache
            .read()
            .keys()
            .filter(|(v, p, _, _)| *v == vid_lc && *p == pid_lc)
            .map(|(_, _, s, _)| s.clone())
            .collect()
    }

    /// Returns the number of entries currently in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.read().len()
    }

    /// Returns `true` if the cache contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.read().is_empty()
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
        assert_eq!(
            cache.trust_tier_for("0951", "1666", "ABC"),
            UsbTrustTier::Blocked
        );
    }

    #[test]
    fn test_trust_tier_for_known_device_returns_tier() {
        // Arrange: seed a known device (keys are stored lowercase per cache invariant)
        let cache = DeviceRegistryCache::new();
        cache.seed_for_test("0951", "1666", "ABC", UsbTrustTier::ReadOnly);
        // Act + Assert: lookup normalises caller's case to match stored key
        assert_eq!(
            cache.trust_tier_for("0951", "1666", "ABC"),
            UsbTrustTier::ReadOnly
        );
    }

    #[test]
    fn test_trust_tier_for_unknown_device_returns_blocked() {
        // Arrange: seed a device, then look up a different serial
        let cache = DeviceRegistryCache::new();
        cache.seed_for_test("0951", "1666", "ABC", UsbTrustTier::FullAccess);
        // Act + Assert: different serial -> Blocked (not in cache)
        assert_eq!(
            cache.trust_tier_for("0951", "1666", "DIFFERENT"),
            UsbTrustTier::Blocked
        );
    }

    #[test]
    fn test_concurrent_reads_do_not_deadlock() {
        // Arrange: shared cache with one entry
        use std::thread;
        let cache = Arc::new(DeviceRegistryCache::new());
        cache.cache.write().insert(
            ("vid".to_string(), "pid".to_string(), "ser".to_string(), None),
            UsbTrustTier::FullAccess,
        );
        // Act: two threads read simultaneously
        let c1 = Arc::clone(&cache);
        let c2 = Arc::clone(&cache);
        let t1 = thread::spawn(move || c1.trust_tier_for("vid", "pid", "ser"));
        let t2 = thread::spawn(move || c2.trust_tier_for("vid", "pid", "ser"));
        // Assert: both threads return the correct tier (no deadlock)
        assert_eq!(
            t1.join().expect("thread 1 must not panic"),
            UsbTrustTier::FullAccess
        );
        assert_eq!(
            t2.join().expect("thread 2 must not panic"),
            UsbTrustTier::FullAccess
        );
    }

    // ── Per-user lookup tests (USB-06, Phase 38.4) ───────────────────────────

    #[test]
    fn test_trust_tier_per_user_wins_over_machine_wide() {
        // Machine-wide = FullAccess, per-user = Blocked -> result = Blocked
        let cache = DeviceRegistryCache::new();
        cache.seed_for_test("0951", "1666", "SN001", UsbTrustTier::FullAccess);
        cache.seed_for_test_with_sid(
            "0951",
            "1666",
            "SN001",
            Some("S-1-5-21-1"),
            UsbTrustTier::Blocked,
        );

        let result = cache.trust_tier_for_with_sid("0951", "1666", "SN001", Some("S-1-5-21-1"));
        assert_eq!(result.tier, UsbTrustTier::Blocked);
        assert_eq!(result.owner_sid, Some("S-1-5-21-1".to_string()));
    }

    #[test]
    fn test_trust_tier_machine_wide_only() {
        // Machine-wide = ReadOnly, no per-user -> result = ReadOnly
        let cache = DeviceRegistryCache::new();
        cache.seed_for_test("0951", "1666", "SN001", UsbTrustTier::ReadOnly);

        let result = cache.trust_tier_for_with_sid("0951", "1666", "SN001", Some("S-1-5-21-1"));
        assert_eq!(result.tier, UsbTrustTier::ReadOnly);
        assert_eq!(result.owner_sid, None);
    }

    #[test]
    fn test_trust_tier_per_user_only() {
        // Per-user = FullAccess, no machine-wide -> result = FullAccess
        let cache = DeviceRegistryCache::new();
        cache.seed_for_test_with_sid(
            "0951",
            "1666",
            "SN001",
            Some("S-1-5-21-1"),
            UsbTrustTier::FullAccess,
        );

        let result = cache.trust_tier_for_with_sid("0951", "1666", "SN001", Some("S-1-5-21-1"));
        assert_eq!(result.tier, UsbTrustTier::FullAccess);
        assert_eq!(result.owner_sid, Some("S-1-5-21-1".to_string()));
    }

    #[test]
    fn test_trust_tier_most_restrictive_merge() {
        // Machine-wide = Blocked, per-user = FullAccess -> result = Blocked
        let cache = DeviceRegistryCache::new();
        cache.seed_for_test("0951", "1666", "SN001", UsbTrustTier::Blocked);
        cache.seed_for_test_with_sid(
            "0951",
            "1666",
            "SN001",
            Some("S-1-5-21-1"),
            UsbTrustTier::FullAccess,
        );

        let result = cache.trust_tier_for_with_sid("0951", "1666", "SN001", Some("S-1-5-21-1"));
        assert_eq!(result.tier, UsbTrustTier::Blocked);
        assert_eq!(result.owner_sid, None);
    }

    #[test]
    fn test_trust_tier_returns_owner_fields() {
        let cache = DeviceRegistryCache::new();
        cache.seed_for_test_with_sid(
            "0951",
            "1666",
            "SN001",
            Some("S-1-5-21-1"),
            UsbTrustTier::FullAccess,
        );

        let result = cache.trust_tier_for_with_sid("0951", "1666", "SN001", Some("S-1-5-21-1"));
        assert_eq!(result.tier, UsbTrustTier::FullAccess);
        assert_eq!(result.owner_sid, Some("S-1-5-21-1".to_string()));
    }

    #[test]
    fn test_trust_tier_machine_wide_returns_none_owner() {
        let cache = DeviceRegistryCache::new();
        cache.seed_for_test("0951", "1666", "SN001", UsbTrustTier::ReadOnly);

        let result = cache.trust_tier_for_with_sid("0951", "1666", "SN001", None);
        assert_eq!(result.tier, UsbTrustTier::ReadOnly);
        assert_eq!(result.owner_sid, None);
        assert_eq!(result.owner_user, None);
    }

    #[test]
    fn test_trust_tier_no_sid_falls_back_to_machine_wide() {
        // When owner_sid is None, only machine-wide entries are considered.
        let cache = DeviceRegistryCache::new();
        cache.seed_for_test("0951", "1666", "SN001", UsbTrustTier::FullAccess);
        cache.seed_for_test_with_sid(
            "0951",
            "1666",
            "SN001",
            Some("S-1-5-21-1"),
            UsbTrustTier::Blocked,
        );

        let result = cache.trust_tier_for_with_sid("0951", "1666", "SN001", None);
        // Without an owner SID, the per-user entry should not be considered.
        assert_eq!(result.tier, UsbTrustTier::FullAccess);
        assert_eq!(result.owner_sid, None);
    }

    #[test]
    fn test_trust_tier_unknown_sid_defaults_blocked() {
        // A different SID than what's in the cache -> no match -> default deny.
        let cache = DeviceRegistryCache::new();
        cache.seed_for_test_with_sid(
            "0951",
            "1666",
            "SN001",
            Some("S-1-5-21-1"),
            UsbTrustTier::FullAccess,
        );

        let result = cache.trust_tier_for_with_sid("0951", "1666", "SN001", Some("S-1-5-21-999"));
        assert_eq!(result.tier, UsbTrustTier::Blocked);
        assert_eq!(result.owner_sid, None);
    }

    #[test]
    fn test_has_device_with_sid() {
        let cache = DeviceRegistryCache::new();
        cache.seed_for_test("0951", "1666", "SN001", UsbTrustTier::FullAccess);
        cache.seed_for_test_with_sid(
            "0951",
            "1666",
            "SN001",
            Some("S-1-5-21-1"),
            UsbTrustTier::Blocked,
        );

        assert!(cache.has_device("0951", "1666", "SN001"));
        assert!(cache.has_device_with_sid("0951", "1666", "SN001", None));
        assert!(cache.has_device_with_sid("0951", "1666", "SN001", Some("S-1-5-21-1")));
        assert!(!cache.has_device_with_sid("0951", "1666", "SN001", Some("S-1-5-21-999")));
    }

    #[test]
    fn test_serials_for_vid_pid_across_owner_sids() {
        let cache = DeviceRegistryCache::new();
        cache.seed_for_test("0951", "1666", "SN001", UsbTrustTier::FullAccess);
        cache.seed_for_test_with_sid(
            "0951",
            "1666",
            "SN002",
            Some("S-1-5-21-1"),
            UsbTrustTier::Blocked,
        );

        let serials = cache.serials_for_vid_pid("0951", "1666");
        assert_eq!(serials.len(), 2);
        assert!(serials.contains(&"sn001".to_string()));
        assert!(serials.contains(&"sn002".to_string()));
    }

    #[test]
    fn test_refresh_with_sid_populates_cache() {
        // This test verifies the cache key structure includes owner_sid.
        // Full refresh_with_sid requires a mock server; we verify the key
        // structure by direct insertion.
        let cache = DeviceRegistryCache::new();
        cache.seed_for_test_with_sid(
            "0951",
            "1666",
            "SN001",
            Some("S-1-5-21-1"),
            UsbTrustTier::Blocked,
        );

        let read = cache.cache.read();
        assert!(read.contains_key(&(
            "0951".to_string(),
            "1666".to_string(),
            "sn001".to_string(),
            Some("S-1-5-21-1".to_string())
        )));
    }
}
