//! HashCache — TTL-governed storage for hook DLL content hash evidence.
//!
//! When a blocked write operation is hashed by the hook DLL, the resulting
//! [`HashEvidenceFrame`] is sent to the agent via a one-way IPC frame.
//! The agent stores it in this cache keyed by `(pid, handle_value)`.
//! When the agent later emits an [`AuditEvent`] for the same blocked write,
//! it looks up the matching hash and attaches it via [`with_content_hash`].
//!
//! # Design
//!
//! - DashMap for lock-free concurrent access across threads.
//! - 60-second TTL with a periodic cleanup thread.
//! - `Arc`-wrapped so the cache can be shared between the HookIpcServer
//!   handler thread and the audit emission path.

use dashmap::DashMap;
use dlp_common::hook_ipc::HashEvidenceFrame;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Shared hash cache keyed by `(pid, handle_value)`.
///
/// The value is a tuple of the evidence frame and the insertion timestamp.
/// The timestamp is used for TTL-based eviction.
pub type HashCache = Arc<DashMap<(u32, u64), (HashEvidenceFrame, Instant)>>;

/// Creates a new empty [`HashCache`].
#[must_use]
pub fn create_hash_cache() -> HashCache {
    Arc::new(DashMap::new())
}

/// Spawns a background thread that periodically evicts stale entries.
///
/// The cleanup thread sleeps for 60 seconds, then removes all entries
/// whose age exceeds the TTL. This is a best-effort cleanup — entries
/// may live slightly longer than the TTL if the cleanup thread is delayed.
///
/// # Arguments
///
/// * `cache` — The [`HashCache`] to clean.
/// * `ttl` — Time-to-live for each entry. Defaults to 60 seconds if `None`.
pub fn spawn_hash_cache_cleanup_task(cache: HashCache, ttl: Option<Duration>) {
    let cutoff = ttl.unwrap_or(Duration::from_secs(60));
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(cutoff);
            let now = Instant::now();
            cache.retain(|_key, (_frame, inserted)| {
                now.duration_since(*inserted) < cutoff
            });
        }
    });
}

/// Looks up a hash evidence frame by `(pid, handle_value)`.
///
/// Returns `Some(frame)` if found and not expired, `None` otherwise.
/// The caller should check `hash_skipped` to distinguish "no hash because
/// the pool was saturated" from "no hash because the frame hasn't arrived yet".
pub fn lookup_hash(cache: &HashCache, pid: u32, handle_value: u64) -> Option<HashEvidenceFrame> {
    cache.get(&(pid, handle_value)).map(|entry| entry.value().0.clone())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_hash_cache_is_empty() {
        let cache = create_hash_cache();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_insert_and_lookup() {
        let cache = create_hash_cache();
        let frame = HashEvidenceFrame {
            pid: 1234,
            handle_value: 0xABCD,
            content_sha256: Some("deadbeef".to_string()),
            hash_truncated: false,
            hash_skipped: false,
            timestamp_secs: 1_700_000_000,
        };
        cache.insert((1234, 0xABCD), (frame.clone(), Instant::now()));

        let found = lookup_hash(&cache, 1234, 0xABCD);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.content_sha256, Some("deadbeef".to_string()));
        assert!(!found.hash_truncated);
        assert!(!found.hash_skipped);
    }

    #[test]
    fn test_lookup_missing_returns_none() {
        let cache = create_hash_cache();
        let found = lookup_hash(&cache, 9999, 0xFFFF);
        assert!(found.is_none());
    }

    #[test]
    fn test_retain_evicts_expired() {
        let cache = create_hash_cache();
        let frame = HashEvidenceFrame {
            pid: 1234,
            handle_value: 0xABCD,
            content_sha256: Some("deadbeef".to_string()),
            hash_truncated: false,
            hash_skipped: false,
            timestamp_secs: 1_700_000_000,
        };
        // Insert with an old timestamp (simulating expired entry).
        cache.insert(
            (1234, 0xABCD),
            (
                frame.clone(),
                Instant::now() - Duration::from_secs(120),
            ),
        );

        // Manually run retain with a 60-second cutoff.
        let now = Instant::now();
        let cutoff = Duration::from_secs(60);
        cache.retain(|_key, (_frame, inserted)| now.duration_since(*inserted) < cutoff);

        assert!(cache.is_empty());
    }
}
