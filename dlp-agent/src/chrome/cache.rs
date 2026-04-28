//! Chrome policy decision cache.
//!
//! Caches allow/block verdicts keyed by origin URL to avoid redundant
//! ABAC evaluations for repeated Chrome Content Analysis requests.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

/// Default TTL for cached Chrome policy decisions.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(60);

/// Cached verdict with expiration timestamp.
#[derive(Debug, Clone, PartialEq)]
struct CacheEntry {
    verdict: bool,
    expires_at: Instant,
}

/// Thread-safe LRU-like cache for Chrome origin trust decisions.
///
/// Entries expire after `ttl` seconds; stale entries are evicted on read.
#[derive(Debug, Clone)]
pub struct ChromeCache {
    inner: Arc<RwLock<HashMap<String, CacheEntry>>>,
    ttl: Duration,
}

impl Default for ChromeCache {
    fn default() -> Self {
        Self::new(DEFAULT_CACHE_TTL)
    }
}

impl ChromeCache {
    /// Creates a new cache with the specified TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    /// Returns the cached verdict for `key`, or `None` if missing or expired.
    pub fn get(&self, key: &str) -> Option<bool> {
        let mut guard = self.inner.write();
        if let Some(entry) = guard.get(key) {
            if entry.expires_at > Instant::now() {
                return Some(entry.verdict);
            }
            // Evict stale entry.
            guard.remove(key);
        }
        None
    }

    /// Stores a verdict for `key` with the cache's TTL.
    pub fn insert(&self, key: String, verdict: bool) {
        let entry = CacheEntry {
            verdict,
            expires_at: Instant::now() + self.ttl,
        };
        self.inner.write().insert(key, entry);
    }

    /// Clears all cached entries.
    pub fn clear(&self) {
        self.inner.write().clear();
    }

    /// Returns the number of active (non-expired) entries.
    ///
    /// Note: this performs a full sweep to evict stale entries.
    pub fn len(&self) -> usize {
        let now = Instant::now();
        let mut guard = self.inner.write();
        guard.retain(|_, entry| entry.expires_at > now);
        guard.len()
    }

    /// Returns `true` if the cache contains no active entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_hit_and_miss() {
        let cache = ChromeCache::new(Duration::from_secs(60));
        assert_eq!(cache.get("https://example.com"), None);

        cache.insert("https://example.com".to_string(), true);
        assert_eq!(cache.get("https://example.com"), Some(true));
        assert_eq!(cache.get("https://other.com"), None);
    }

    #[test]
    fn test_cache_expiration() {
        let cache = ChromeCache::new(Duration::from_millis(10));
        cache.insert("https://example.com".to_string(), false);
        assert_eq!(cache.get("https://example.com"), Some(false));

        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(cache.get("https://example.com"), None);
    }

    #[test]
    fn test_cache_clear() {
        let cache = ChromeCache::new(Duration::from_secs(60));
        cache.insert("https://a.com".to_string(), true);
        cache.insert("https://b.com".to_string(), false);
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.get("https://a.com"), None);
    }
}
