//! Policy decision cache (T-17).
//!
//! Caches [`EvaluateResponse`] results keyed by `(resource_hash, subject_hash)`.
//! Each entry has a TTL (default 60 s); expired entries are lazily evicted on
//! access.  On cache miss for a T3/T4 resource, the cache fails closed
//! (DENY) rather than allowing the operation.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

use dlp_common::{Classification, Decision, EvaluateResponse};
use parking_lot::RwLock;
use tracing::debug;

/// Default TTL for cached decisions.
const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// An entry in the decision cache.
#[derive(Debug)]
struct CacheEntry {
    response: EvaluateResponse,
    expires_at: Instant,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// A composite cache key combining resource and subject identity hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheKey {
    resource_hash: u64,
    subject_hash: u64,
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.resource_hash);
        state.write_u64(self.subject_hash);
    }
}

/// The policy decision cache.
///
/// Thread-safe via `RwLock`.  Entries are keyed by a composite of the
/// resource path hash and the subject SID hash.
///
/// ## Fail-closed for T3/T4
///
/// When [`Cache::get`] returns `None` for a sensitive resource (T3 or T4),
/// the caller **must** deny the operation rather than falling back to
/// [`Decision::ALLOW`].
pub struct Cache {
    inner: RwLock<HashMap<CacheKey, CacheEntry>>,
    ttl: Duration,
}

impl Cache {
    /// Constructs an empty cache with the default TTL.
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_TTL)
    }

    /// Constructs an empty cache with a custom TTL.
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    /// Looks up a cached decision.
    ///
    /// Returns `Some(response)` if the entry exists and is not expired.
    /// Returns `None` if the entry is absent or expired.
    /// Expired entries are lazily removed.
    pub fn get(&self, resource_path: &str, user_sid: &str) -> Option<EvaluateResponse> {
        let key = CacheKey {
            resource_hash: hash_str(resource_path),
            subject_hash: hash_str(user_sid),
        };

        let mut guard = self.inner.write();

        // Remove expired entries lazily on access.
        guard.retain(|_, entry| !entry.is_expired());

        guard.remove(&key).filter(|e| !e.is_expired()).map(|e| {
            debug!(
                resource_path,
                user_sid,
                decision = ?e.response.decision,
                "cache hit"
            );
            e.response
        })
    }

    /// Stores a decision in the cache.
    pub fn insert(&self, resource_path: &str, user_sid: &str, response: EvaluateResponse) {
        let key = CacheKey {
            resource_hash: hash_str(resource_path),
            subject_hash: hash_str(user_sid),
        };

        let entry = CacheEntry {
            response,
            expires_at: Instant::now().checked_add(self.ttl).unwrap(),
        };

        self.inner.write().insert(key, entry);
        debug!(resource_path, user_sid, "cached decision");
    }

    /// Returns the number of cached entries (including expired ones not yet evicted).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Returns `true` if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clears all entries from the cache.
    pub fn clear(&self) {
        self.inner.write().clear();
    }

    /// Evicts all expired entries.
    pub fn evict_expired(&self) {
        self.inner.write().retain(|_, entry| !entry.is_expired());
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hash helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Fowler–Noll–Vo (FNV-1a) hash for strings — fast, well-distributed.
fn hash_str(s: &str) -> u64 {
    // FNV-1a 64-bit
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

// ─────────────────────────────────────────────────────────────────────────────
// Fail-closed helper
// ─────────────────────────────────────────────────────────────────────────────

/// Returns a fail-closed [`EvaluateResponse`] for a sensitive resource
/// when no cached or engine decision is available.
///
/// This function implements the **fail-closed for T3/T4 on cache miss** policy
/// defined in T-17.
pub fn fail_closed_response(classification: Classification) -> EvaluateResponse {
    if classification.is_sensitive() {
        debug!(
            ?classification,
            "cache miss on sensitive resource — failing closed"
        );
        EvaluateResponse {
            decision: Decision::DENY,
            matched_policy_id: None,
            reason: "Fail-closed: no cached decision for sensitive resource".to_string(),
        }
    } else {
        EvaluateResponse {
            decision: Decision::ALLOW,
            matched_policy_id: None,
            reason: "Cache miss: default allow for non-sensitive resource".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlp_common::Decision;

    fn make_response(decision: Decision) -> EvaluateResponse {
        EvaluateResponse {
            decision,
            matched_policy_id: None,
            reason: "test".to_string(),
        }
    }

    #[test]
    fn test_cache_insert_get() {
        let cache = Cache::new();
        cache.insert(
            r"C:\Data\file.txt",
            "S-1-5-21-123",
            make_response(Decision::ALLOW),
        );
        let result = cache.get(r"C:\Data\file.txt", "S-1-5-21-123");
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, Decision::ALLOW);
    }

    #[test]
    fn test_cache_miss() {
        let cache = Cache::new();
        let result = cache.get(r"C:\Data\file.txt", "S-1-5-21-999");
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_clear() {
        let cache = Cache::new();
        cache.insert(
            r"C:\Data\file.txt",
            "S-1-5-21-123",
            make_response(Decision::ALLOW),
        );
        assert!(!cache.is_empty());
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_len() {
        let cache = Cache::new();
        assert_eq!(cache.len(), 0);
        cache.insert(r"C:\Data\a.txt", "S-1", make_response(Decision::ALLOW));
        cache.insert(r"C:\Data\b.txt", "S-1", make_response(Decision::DENY));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_fail_closed_t3() {
        let resp = fail_closed_response(Classification::T3);
        assert!(resp.decision.is_denied());
    }

    #[test]
    fn test_fail_closed_t4() {
        let resp = fail_closed_response(Classification::T4);
        assert!(resp.decision.is_denied());
    }

    #[test]
    fn test_fail_closed_t1_allows() {
        let resp = fail_closed_response(Classification::T1);
        assert!(!resp.decision.is_denied());
    }

    #[test]
    fn test_hash_str_deterministic() {
        let h1 = hash_str("hello");
        let h2 = hash_str("hello");
        let h3 = hash_str("world");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }
}
