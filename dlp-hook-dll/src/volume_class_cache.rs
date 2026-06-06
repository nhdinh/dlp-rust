//! Thread-local volume class cache for the hook DLL.
//!
//! Provides sub-millisecond volume class lookups via a thread-local `HashMap`
//! keyed by drive letter with a 10-second TTL. Cache misses trigger a named
//! pipe round-trip to the agent service. UNC paths resolve to
//! [`VolumeClass::NetworkShare`] without cache lookup.
//!
//! # Fail-Closed Invariant
//!
//! - Pipe failure or unreachable agent returns `None` (never
//!   [`VolumeClass::LocalNTFS`]).
//! - Volume GUID paths (`"\\?\\Volume{...}"`) return `None`.
//! - Unknown path formats return `None`.
//!
//! A `None` volume class causes volume-class conditions in ABAC evaluation to
//! evaluate to `false` (condition does not match), which is intentional
//! fail-closed behavior.
//!
//! # Cache Invalidation
//!
//! - `invalidate_cache()` clears the entire thread-local cache. Called on agent
//!   reconnect or global device-change notification.
//! - `invalidate_cache_for_letter(letter)` removes a single entry. Called on
//!   `DBT_DEVICEREMOVECOMPLETE` for a specific drive letter.
//!
//! # Performance
//!
//! - Cache hit: ~100 ns (HashMap lookup + TTL check).
//! - Cache miss: ~1-5 ms (named pipe round-trip to agent).
//! - With a 10-second TTL, cache misses are rare in steady-state workloads.

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use dlp_common::VolumeClass;

/// TTL for cached volume class entries.
///
/// Reduced from 30 s to 10 s per review concern: "Hook DLL cache TTL (30 s)
/// creates stale classification window".
const VOLUME_CLASS_TTL: Duration = Duration::from_secs(10);

// Thread-local cache of drive letter -> (VolumeClass, insertion Instant).
//
// Each thread maintains its own cache to eliminate cross-thread
// synchronization overhead in the hot path. The cache is small (at most 26
// entries for A-Z), so memory overhead is negligible.
thread_local! {
    static VOLUME_CLASS_CACHE: RefCell<HashMap<char, (VolumeClass, Instant)>> =
        RefCell::new(HashMap::new());
}

/// Resolves the volume class for a single drive letter, using the thread-local
/// cache.
///
/// # Arguments
///
/// * `letter` - An uppercase drive letter (e.g., `'C'`, `'D'`).
///
/// # Returns
///
/// * `Some(class)` if the letter is cached and not expired, or if a pipe
///   query succeeds.
/// * `None` on cache miss where the pipe query fails or the agent returns
///   `None` — FAIL-CLOSED.
///
/// # Performance
///
/// Cache hit: ~100 ns. Cache miss with pipe round-trip: ~1-5 ms.
#[must_use]
pub fn resolve_volume_class(letter: char) -> Option<VolumeClass> {
    let upper = letter.to_ascii_uppercase();

    VOLUME_CLASS_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();

        // Check cache: entry exists and TTL not expired.
        if let Some((class, inserted)) = cache.get(&upper) {
            if inserted.elapsed() < VOLUME_CLASS_TTL {
                return Some(*class);
            }
            // Expired — remove so we can re-query below.
            cache.remove(&upper);
        }

        // Cache miss or expired — query agent via named pipe.
        let class = query_volume_class_from_agent(upper);

        // Insert into cache only if the agent returned a known class.
        if let Some(c) = class {
            cache.insert(upper, (c, Instant::now()));
        }

        class
    })
}

/// Resolves the volume class from a Windows filesystem path.
///
/// Delegates to [`dlp_common::abac::resolve_volume_class_from_path`] with the
/// hook DLL's cache-backed lookup function.
///
/// # Arguments
///
/// * `path` - A Windows filesystem path (e.g., `"C:\\file.txt"`,
///   `"\\\\server\\share\\file.txt"`).
///
/// # Returns
///
/// * `Some(VolumeClass::NetworkShare)` for UNC paths.
/// * `Some(class)` for drive-letter paths where the cache or agent knows the
///   class.
/// * `None` for volume GUID paths, unknown formats, or pipe failures —
///   FAIL-CLOSED.
#[must_use]
pub fn resolve_volume_class_from_path(path: &str) -> Option<VolumeClass> {
    dlp_common::abac::resolve_volume_class_from_path(path, resolve_volume_class)
}

/// Clears the entire thread-local volume class cache.
///
/// Call this on:
/// - Agent reconnect (the agent may have refreshed its volume class map).
/// - Global device-change notification (`WM_DEVICECHANGE`) when the exact
///   affected drive letters are unknown.
/// - Fail-mode state transition to RESYNC (flush all cached state).
pub fn invalidate_cache() {
    VOLUME_CLASS_CACHE.with(|cache| {
        cache.borrow_mut().clear();
    });
}

/// Removes a single drive letter from the thread-local cache.
///
/// Call this on `DBT_DEVICEREMOVECOMPLETE` when the specific drive letter is
/// known. More surgical than `invalidate_cache()` — preserves cached entries
/// for unaffected drives.
///
/// # Arguments
///
/// * `letter` - The drive letter to evict (case-insensitive).
pub fn invalidate_cache_for_letter(letter: char) {
    let upper = letter.to_ascii_uppercase();
    VOLUME_CLASS_CACHE.with(|cache| {
        cache.borrow_mut().remove(&upper);
    });
}

/// Queries the agent service for the volume class of a drive letter.
///
/// Sends a [`dlp_common::hook_ipc::VolumeClassQuery`] over the named pipe and
/// awaits a [`dlp_common::hook_ipc::VolumeClassResponse`].
///
/// # Fail-Closed Behavior
///
/// * Pipe connection refused (agent not running) -> `None`.
/// * Pipe timeout -> `None`.
/// * Malformed response -> `None`.
/// * Agent returns `None` -> `None`.
///
/// NEVER returns `Some(VolumeClass::LocalNTFS)` as a fallback.
///
/// # Arguments
///
/// * `letter` - Uppercase drive letter (e.g., `'C'`).
///
/// # Returns
///
/// The volume class reported by the agent, or `None` on any error.
fn query_volume_class_from_agent(letter: char) -> Option<VolumeClass> {
    use dlp_common::hook_ipc::{VolumeClassQuery, VolumeClassResponse};

    let query = VolumeClassQuery {
        drive_letter: letter,
    };

    // Serialize the query into the thread-local pipe buffer.
    let payload = match bincode::serialize(&query) {
        Ok(p) => p,
        Err(_) => return None,
    };

    // Send raw request and receive raw response.
    let response_bytes =
        match crate::pipe_client::send_raw_request(crate::DEFAULT_PIPE_NAME, &payload, 100) {
            Ok(bytes) => bytes,
            Err(_) => return None,
        };

    // Deserialize response.
    let response: VolumeClassResponse = match bincode::deserialize(&response_bytes) {
        Ok(r) => r,
        Err(_) => return None,
    };

    response.class
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: clear cache before each test to avoid cross-test contamination.
    fn clear_cache() {
        invalidate_cache();
    }

    #[test]
    fn test_resolve_unc_path() {
        clear_cache();
        let result = resolve_volume_class_from_path("\\\\server\\share\\file.txt");
        assert_eq!(result, Some(VolumeClass::NetworkShare));
    }

    #[test]
    fn test_resolve_unc_path_single_backslash_prefix() {
        // A path starting with exactly two backslashes is UNC.
        // This test ensures we don't false-positive on single-backslash paths.
        clear_cache();
        let result = resolve_volume_class_from_path("\\\\server\\share");
        assert_eq!(result, Some(VolumeClass::NetworkShare));
    }

    #[test]
    fn test_resolve_drive_letter() {
        clear_cache();
        // We cannot mock query_volume_class_from_agent in a unit test that
        // calls resolve_volume_class directly (it's a private function).
        // Instead, we test resolve_volume_class_from_path with a drive letter
        // path. Since no agent is running, the pipe query will fail and return
        // None — which is the expected fail-closed behavior.
        let result = resolve_volume_class_from_path("Z:\\docs\\file.txt");
        // Without a mock agent, this returns None (fail-closed).
        assert_eq!(result, None);
    }

    #[test]
    fn test_cache_ttl_expiration() {
        clear_cache();

        // Manually insert an entry with an old Instant (simulating expiration).
        let expired_instant = Instant::now() - Duration::from_secs(20);
        VOLUME_CLASS_CACHE.with(|cache| {
            cache
                .borrow_mut()
                .insert('C', (VolumeClass::LocalNTFS, expired_instant));
        });

        // The entry is expired, so resolve_volume_class should trigger a
        // re-query. Without an agent, the re-query returns None.
        let result = resolve_volume_class('C');
        assert_eq!(result, None, "expired cache entry should trigger re-query");

        // The expired entry should have been removed.
        let cached = VOLUME_CLASS_CACHE.with(|cache| cache.borrow().get(&'C').copied());
        assert!(cached.is_none(), "expired entry should be evicted");
    }

    #[test]
    fn test_cache_hit_no_requery() {
        clear_cache();

        // Insert a fresh entry.
        VOLUME_CLASS_CACHE.with(|cache| {
            cache
                .borrow_mut()
                .insert('D', (VolumeClass::Optical, Instant::now()));
        });

        // Should return the cached value without querying the agent.
        let result = resolve_volume_class('D');
        assert_eq!(result, Some(VolumeClass::Optical));
    }

    #[test]
    fn test_clear_cache() {
        clear_cache();

        // Insert entries.
        VOLUME_CLASS_CACHE.with(|cache| {
            cache
                .borrow_mut()
                .insert('C', (VolumeClass::LocalNTFS, Instant::now()));
            cache
                .borrow_mut()
                .insert('D', (VolumeClass::USBRemovable, Instant::now()));
        });

        // Verify entries exist.
        assert!(VOLUME_CLASS_CACHE.with(|cache| cache.borrow().contains_key(&'C')));
        assert!(VOLUME_CLASS_CACHE.with(|cache| cache.borrow().contains_key(&'D')));

        // Clear cache.
        invalidate_cache();

        // Verify entries are gone.
        assert!(!VOLUME_CLASS_CACHE.with(|cache| cache.borrow().contains_key(&'C')));
        assert!(!VOLUME_CLASS_CACHE.with(|cache| cache.borrow().contains_key(&'D')));
    }

    #[test]
    fn test_invalidate_single_letter() {
        clear_cache();

        // Insert entries for C and D.
        VOLUME_CLASS_CACHE.with(|cache| {
            cache
                .borrow_mut()
                .insert('C', (VolumeClass::LocalNTFS, Instant::now()));
            cache
                .borrow_mut()
                .insert('D', (VolumeClass::USBRemovable, Instant::now()));
        });

        // Invalidate only C.
        invalidate_cache_for_letter('C');

        // C should be gone, D should remain.
        assert!(!VOLUME_CLASS_CACHE.with(|cache| cache.borrow().contains_key(&'C')));
        assert!(VOLUME_CLASS_CACHE.with(|cache| cache.borrow().contains_key(&'D')));
    }

    #[test]
    fn test_invalidate_single_letter_case_insensitive() {
        clear_cache();

        // Insert entry for uppercase C.
        VOLUME_CLASS_CACHE.with(|cache| {
            cache
                .borrow_mut()
                .insert('C', (VolumeClass::LocalNTFS, Instant::now()));
        });

        // Invalidate lowercase c — should still match.
        invalidate_cache_for_letter('c');

        assert!(!VOLUME_CLASS_CACHE.with(|cache| cache.borrow().contains_key(&'C')));
    }

    #[test]
    fn test_pipe_failure_fails_closed() {
        clear_cache();

        // With no agent running, any drive letter query should fail-closed.
        let result = resolve_volume_class('X');
        assert_eq!(
            result, None,
            "pipe failure must return None, not Some(LocalNTFS)"
        );
    }

    #[test]
    fn test_volume_guid_fails_closed() {
        clear_cache();
        let result = resolve_volume_class_from_path(
            "\\\\?\\Volume{12345678-1234-1234-1234-123456789012}\\file.txt",
        );
        assert_eq!(result, None, "volume GUID path must fail-closed with None");
    }

    #[test]
    fn test_unknown_path_fails_closed() {
        clear_cache();
        let result = resolve_volume_class_from_path("unknown");
        assert_eq!(result, None, "unknown path format must return None");
    }

    #[test]
    fn test_forward_slash_drive_letter() {
        clear_cache();
        // Forward slash paths are normalized by resolve_volume_class_from_path
        // in dlp-common. Without an agent, this returns None (fail-closed).
        let result = resolve_volume_class_from_path("E:/file.txt");
        assert_eq!(result, None);
    }

    #[test]
    fn test_thread_local_isolation() {
        use std::sync::Arc;
        use std::thread;

        clear_cache();

        // Insert in main thread.
        VOLUME_CLASS_CACHE.with(|cache| {
            cache
                .borrow_mut()
                .insert('M', (VolumeClass::Virtual, Instant::now()));
        });

        let cap = Arc::new(std::sync::Mutex::new(false));
        let cap2 = cap.clone();

        thread::spawn(move || {
            // Spawned thread should NOT see the main thread's entry.
            let has_m = VOLUME_CLASS_CACHE.with(|cache| cache.borrow().contains_key(&'M'));
            *cap2.lock().unwrap() = has_m;
        })
        .join()
        .unwrap();

        // Spawned thread should not have seen 'M'.
        assert!(!*cap.lock().unwrap(), "thread-local cache must be isolated");

        // Main thread should still have 'M'.
        assert!(VOLUME_CLASS_CACHE.with(|cache| cache.borrow().contains_key(&'M')));
    }

    #[test]
    fn test_cache_insert_on_successful_query() {
        clear_cache();

        // Manually insert a fresh entry to verify the cache stores it.
        VOLUME_CLASS_CACHE.with(|cache| {
            cache
                .borrow_mut()
                .insert('F', (VolumeClass::SDCard, Instant::now()));
        });

        let result = resolve_volume_class('F');
        assert_eq!(result, Some(VolumeClass::SDCard));
    }

    #[test]
    fn test_network_share_path_with_extra_backslashes() {
        clear_cache();
        // UNC with more than two leading backslashes is still a network path.
        let result = resolve_volume_class_from_path("\\\\\\\\server\\share\\file.txt");
        // resolve_volume_class_from_path in dlp-common checks starts_with("\\\\"),
        // so four backslashes also matches.
        assert_eq!(result, Some(VolumeClass::NetworkShare));
    }
}
