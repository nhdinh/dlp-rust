//! Thread-local volume class cache for the hook DLL.
//!
//! Resolves volume class from Windows paths at trampoline time without WMI
//! queries in the hot path. Uses a per-thread cache keyed by drive letter
//! with a 10-second TTL. Cache misses trigger a named pipe query to the
//! agent service.
//!
//! # Design
//!
//! - `thread_local!` with `RefCell<HashMap<char, (VolumeClass, Instant)>>`
//!   eliminates cross-thread synchronization (per D-08).
//! - UNC paths resolve to `NetworkShare` immediately without cache lookup.
//! - Volume GUID paths return `None` (fail-closed).
//! - Cache invalidation on `DBT_DEVICEREMOVECOMPLETE` via
//!   [`invalidate_cache_for_letter`].
//!
//! # Fail-Closed Invariant
//!
//! If the pipe is unreachable, the drive letter is unknown, or any error
//! occurs during classification, the function returns `None` — NEVER
//! `LocalNTFS`. A `None` volume class causes volume-class ABAC conditions
//! to evaluate to `false`, which for a DENY policy means the condition does
//! not match. This is intentional fail-closed behavior.

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use dlp_common::hook_ipc::{IpcEnvelope, IpcMessageV1, IpcPayloadV1, VolumeClassQuery};
use dlp_common::VolumeClass;

/// TTL for cached volume class entries.
///
/// Reduced from 30s to 10s per review feedback: "Hook DLL cache TTL (30s)
/// creates stale classification window".
const VOLUME_CLASS_TTL: Duration = Duration::from_secs(10);

// Thread-local cache of drive letter -> (VolumeClass, insertion Instant).
// Each thread maintains its own cache, eliminating Mutex/RwLock overhead
// in the hot path. The cache is small (one entry per mounted drive) and
// expires quickly (10s).
// Exposed for test pre-warming; normal callers use `resolve_volume_class`.
thread_local! {
    pub(crate) static VOLUME_CLASS_CACHE: RefCell<HashMap<char, (VolumeClass, Instant)>> =
        RefCell::new(HashMap::new());
}

/// Resolve the volume class for a given drive letter.
///
/// # Arguments
///
/// * `letter` - The drive letter (e.g., `'C'`, `'D'`). Case-insensitive;
///   always normalized to uppercase before cache lookup.
///
/// # Returns
///
/// * `Some(VolumeClass)` if the drive is known (cached or agent-resolved).
/// * `None` on cache miss + pipe failure, unknown drive, or any error.
///
/// # Fail-Closed
///
/// Returns `None` on ANY error — never defaults to `LocalNTFS`.
#[must_use]
pub fn resolve_volume_class(letter: char) -> Option<VolumeClass> {
    let letter = letter.to_ascii_uppercase();

    VOLUME_CLASS_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();

        // Check cache: if entry exists and not expired, return it.
        if let Some((class, inserted)) = cache.get(&letter) {
            if inserted.elapsed() < VOLUME_CLASS_TTL {
                return Some(*class);
            }
            // Expired — remove stale entry.
            cache.remove(&letter);
        }

        // Cache miss or expired: query agent via named pipe.
        match query_volume_class_from_agent(letter) {
            Some(class) => {
                cache.insert(letter, (class, Instant::now()));
                Some(class)
            }
            None => None,
        }
    })
}

/// Resolve the volume class from a Windows filesystem path.
///
/// Delegates to [`dlp_common::abac::resolve_volume_class_from_path`] with
/// [`resolve_volume_class`] as the lookup callback.
///
/// # Arguments
///
/// * `path` - A Windows filesystem path (e.g., `"C:\\file.txt"`,
///   `"\\\\server\\share\\file.txt"`).
///
/// # Returns
///
/// * `Some(VolumeClass::NetworkShare)` for UNC paths (no cache lookup).
/// * `Some(class)` from cache or agent for drive-letter paths.
/// * `None` for volume GUID paths, unknown formats, or lookup failures.
///
/// # Fail-Closed
///
/// Returns `None` on ANY unclassifiable path — never defaults to `LocalNTFS`.
#[must_use]
pub fn resolve_volume_class_from_path(path: &str) -> Option<VolumeClass> {
    dlp_common::abac::resolve_volume_class_from_path(path, resolve_volume_class)
}

/// Invalidate the entire thread-local volume class cache.
///
/// Called on device-change notification (e.g., `DBT_DEVICEREMOVECOMPLETE`
/// for an unknown drive) or agent reconnect. Clears all cached entries so
/// subsequent lookups re-query the agent.
pub fn invalidate_cache() {
    VOLUME_CLASS_CACHE.with(|cache| {
        cache.borrow_mut().clear();
    });
}

/// Invalidate the cache entry for a single drive letter.
///
/// Called when `DBT_DEVICEREMOVECOMPLETE` is received for a specific drive
/// letter. Removes only that entry, preserving cached entries for other
/// drives.
///
/// # Arguments
///
/// * `letter` - The drive letter to invalidate (case-insensitive).
pub fn invalidate_cache_for_letter(letter: char) {
    let letter = letter.to_ascii_uppercase();
    VOLUME_CLASS_CACHE.with(|cache| {
        cache.borrow_mut().remove(&letter);
    });
}

/// Query the agent service for the volume class of a drive letter.
///
/// Sends a [`VolumeClassQuery`] over the named pipe and awaits a
/// [`VolumeClassResponse`]. The pipe round-trip is approximately 1-5ms,
/// which is acceptable for cache misses (rare with a 10s TTL).
///
/// # Arguments
///
/// * `letter` - The drive letter to classify.
///
/// # Returns
///
/// * `Some(VolumeClass)` if the agent responds with a known class.
/// * `None` if the pipe is unreachable, the agent has no entry, or any
///   error occurs.
///
/// # Fail-Closed
///
/// Returns `None` on ANY error — never defaults to `LocalNTFS`.
fn query_volume_class_from_agent(letter: char) -> Option<VolumeClass> {
    let query = VolumeClassQuery {
        drive_letter: letter,
    };
    let envelope = IpcEnvelope::V1(IpcMessageV1 {
        payload: IpcPayloadV1::VolumeClassQuery(query),
    });

    // Serialize the envelope into a temporary buffer.
    let payload = match bincode::serialize(&envelope) {
        Ok(p) => p,
        Err(_) => return None,
    };

    // Send raw request and receive raw response.
    let response_bytes = match crate::pipe_client::send_raw_request(
        crate::DEFAULT_PIPE_NAME,
        &payload,
        100, // 100ms timeout for volume class query
    ) {
        Ok(bytes) => bytes,
        Err(_) => return None,
    };

    // Deserialize the response envelope.
    let response_envelope: IpcEnvelope = match bincode::deserialize(&response_bytes) {
        Ok(e) => e,
        Err(_) => return None,
    };

    match response_envelope {
        IpcEnvelope::V1(IpcMessageV1 {
            payload: IpcPayloadV1::VolumeClassResponse(resp),
        }) => resp.class,
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_unc_path() {
        let result = resolve_volume_class_from_path("\\\\server\\share\\file.txt");
        assert_eq!(result, Some(VolumeClass::NetworkShare));
    }

    #[test]
    fn test_resolve_drive_letter() {
        // Pre-warm the cache with a known value by directly inserting.
        VOLUME_CLASS_CACHE.with(|cache| {
            cache
                .borrow_mut()
                .insert('D', (VolumeClass::Optical, Instant::now()));
        });

        let result = resolve_volume_class_from_path("D:\\docs\\file.txt");
        assert_eq!(result, Some(VolumeClass::Optical));
    }

    #[test]
    fn test_cache_ttl_expiration() {
        // Insert an entry with an old Instant (simulating expiration).
        let old_instant = Instant::now() - Duration::from_secs(20);
        VOLUME_CLASS_CACHE.with(|cache| {
            cache
                .borrow_mut()
                .insert('E', (VolumeClass::USBRemovable, old_instant));
        });

        // The entry is expired, so resolve_volume_class should re-query.
        // Since there's no agent, it returns None — but the key point is
        // that the expired entry was removed and a re-query was attempted.
        let result = resolve_volume_class('E');
        // Without a mock agent, the pipe query fails -> None.
        assert_eq!(result, None);

        // Verify the expired entry was removed from cache.
        VOLUME_CLASS_CACHE.with(|cache| {
            assert!(!cache.borrow().contains_key(&'E'));
        });
    }

    #[test]
    fn test_clear_cache() {
        // Insert entries for multiple drives.
        VOLUME_CLASS_CACHE.with(|cache| {
            let mut c = cache.borrow_mut();
            c.insert('C', (VolumeClass::LocalNTFS, Instant::now()));
            c.insert('D', (VolumeClass::Optical, Instant::now()));
        });

        invalidate_cache();

        // All entries should be gone.
        VOLUME_CLASS_CACHE.with(|cache| {
            assert!(cache.borrow().is_empty());
        });
    }

    #[test]
    fn test_invalidate_single_letter() {
        // Insert entries for C and D.
        VOLUME_CLASS_CACHE.with(|cache| {
            let mut c = cache.borrow_mut();
            c.insert('C', (VolumeClass::LocalNTFS, Instant::now()));
            c.insert('D', (VolumeClass::Optical, Instant::now()));
        });

        invalidate_cache_for_letter('C');

        // C should be gone, D should remain.
        VOLUME_CLASS_CACHE.with(|cache| {
            let c = cache.borrow();
            assert!(!c.contains_key(&'C'));
            assert!(c.contains_key(&'D'));
        });
    }

    #[test]
    fn test_pipe_failure_fails_closed() {
        // Query a drive letter with no agent running — should return None.
        let result = resolve_volume_class('Z');
        assert_eq!(result, None, "pipe failure must return None, not LocalNTFS");
    }

    #[test]
    fn test_volume_guid_fails_closed() {
        let result = resolve_volume_class_from_path(
            "\\\\?\\Volume{12345678-1234-1234-1234-123456789012}\\file.txt",
        );
        assert_eq!(result, None, "volume GUID path must fail-closed with None");
    }

    #[test]
    fn test_case_insensitive_letter() {
        // Insert uppercase, query lowercase.
        VOLUME_CLASS_CACHE.with(|cache| {
            cache
                .borrow_mut()
                .insert('F', (VolumeClass::Virtual, Instant::now()));
        });

        let result = resolve_volume_class('f');
        assert_eq!(result, Some(VolumeClass::Virtual));
    }

    #[test]
    fn test_invalidate_case_insensitive() {
        VOLUME_CLASS_CACHE.with(|cache| {
            cache
                .borrow_mut()
                .insert('G', (VolumeClass::SDCard, Instant::now()));
        });

        invalidate_cache_for_letter('g');

        VOLUME_CLASS_CACHE.with(|cache| {
            assert!(!cache.borrow().contains_key(&'G'));
        });
    }
}
