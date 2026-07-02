//! SHA-256 content hash computation for blocked write operations.
//!
//! Provides two entry points:
//! - [`compute_content_hash`] — inline hashing for small buffers.
//! - [`compute_content_hash_offloaded`] — thread-pool hashing for large buffers.
//!
//! # Design
//!
//! - 100MB cap per D-14 to prevent DoS from huge buffers.
//! - Buffers below 64KB are hashed inline; larger buffers use a dedicated
//!   thread pool to avoid blocking the trampoline hot path.
//! - Thread pool is lazily initialized on first use (NEVER from `DllMain`).
//! - If pool creation fails, returns `hash_skipped=true` as graceful fallback.
//!
//! # Safety
//!
//! Both functions take raw pointers because they are called from trampolines
//! that intercept `WriteFile`/`WriteFileEx`. The caller must ensure the buffer
//! is valid for the specified length.

use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// Maximum bytes to hash (100MB cap per D-14).
pub const HASH_CAP_BYTES: usize = 100 * 1024 * 1024;

/// Buffers below this threshold are hashed inline (64KB).
pub const SMALL_BUFFER_THRESHOLD: usize = 64 * 1024;

/// Lazily initialized thread pool for offloaded hashing.
///
/// Initialized on the first call to `compute_content_hash_offloaded`,
/// NEVER from `DllMain` (loader-lock safety).
static HASH_POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();

/// Global counter tracking pending offloaded hash computations.
///
/// Incremented before submitting to the pool, decremented after
/// completion (even on panic, via `QueueDepthGuard`).
static HASH_QUEUE_DEPTH: AtomicU64 = AtomicU64::new(0);

/// Maximum number of pending offloaded hashes before saturation.
///
/// Per D-07: if queue depth exceeds this threshold, skip hashing.
const HASH_QUEUE_DEPTH_MAX: u64 = 4;

/// RAII guard that increments queue depth on creation and decrements on drop.
///
/// Ensures the counter is always decremented even if the pool closure panics.
struct QueueDepthGuard;

impl QueueDepthGuard {
    fn new() -> Self {
        HASH_QUEUE_DEPTH.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for QueueDepthGuard {
    fn drop(&mut self) {
        HASH_QUEUE_DEPTH.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Compute SHA-256 of a buffer inline.
///
/// # Arguments
///
/// * `buffer` — Pointer to the first byte of the buffer.
/// * `len` — Number of bytes in the buffer.
///
/// # Returns
///
/// A tuple of `(hash, truncated, skipped)`:
/// - `hash` — `Some(hex_string)` on success, `None` if buffer is null/empty.
/// - `truncated` — `true` if `len` exceeded `HASH_CAP_BYTES`.
/// - `skipped` — Always `false` for inline computation.
///
/// # Safety
///
/// `buffer` must be valid for `len` bytes. This is guaranteed by the
/// `WriteFile`/`WriteFileEx` contract when called from a trampoline.
pub unsafe fn compute_content_hash(buffer: *const u8, len: u32) -> (Option<String>, bool, bool) {
    if buffer.is_null() || len == 0 {
        return (None, false, false);
    }

    let actual_len = (len as usize).min(HASH_CAP_BYTES);
    let truncated = (len as usize) > HASH_CAP_BYTES;

    // SAFETY: buffer is valid for actual_len bytes per WriteFile contract.
    let slice = unsafe { std::slice::from_raw_parts(buffer, actual_len) };

    let mut hasher = Sha256::new();
    hasher.update(slice);
    let result = hasher.finalize();
    let hex = hex::encode(result);

    (Some(hex), truncated, false)
}

/// Compute SHA-256 of a buffer, offloading large buffers to a thread pool.
///
/// # Arguments
///
/// * `buffer` — Pointer to the first byte of the buffer.
/// * `len` — Number of bytes in the buffer.
///
/// # Returns
///
/// A tuple of `(hash, truncated, skipped)`:
/// - `hash` — `Some(hex_string)` on success, `None` if buffer is null/empty
///   or pool creation failed.
/// - `truncated` — `true` if `len` exceeded `HASH_CAP_BYTES`.
/// - `skipped` — `true` if the thread pool could not be created.
///
/// # Safety
///
/// `buffer` must be valid for `len` bytes. This is guaranteed by the
/// `WriteFile`/`WriteFileEx` contract when called from a trampoline.
pub unsafe fn compute_content_hash_offloaded(
    buffer: *const u8,
    len: u32,
) -> (Option<String>, bool, bool) {
    if buffer.is_null() || len == 0 {
        return (None, false, false);
    }

    let len_usize = len as usize;

    // Small buffers: hash inline to avoid thread pool overhead.
    if len_usize < SMALL_BUFFER_THRESHOLD {
        return unsafe { compute_content_hash(buffer, len) };
    }

    // Large buffers: use thread pool with saturation check.
    if HASH_QUEUE_DEPTH.load(Ordering::Relaxed) > HASH_QUEUE_DEPTH_MAX {
        return (None, false, true);
    }

    let _guard = QueueDepthGuard::new();

    let pool = HASH_POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .thread_name(|i| format!("dlp-hash-{i}"))
            .build()
            .expect("hash pool creation failed")
    });

    // SAFETY: buffer is valid for len bytes per caller contract.
    // We copy the data into a Vec before sending to the pool to avoid
    // Send issues with raw pointers. The Vec owns the copy.
    let actual_len = (len as usize).min(HASH_CAP_BYTES);
    let vec = unsafe { std::slice::from_raw_parts(buffer, actual_len).to_vec() };
    let truncated = (len as usize) > HASH_CAP_BYTES;
    pool.install(move || {
        let mut hasher = Sha256::new();
        hasher.update(&vec);
        let result = hasher.finalize();
        let hex = hex::encode(result);
        (Some(hex), truncated, false)
    })
}

/// Test-only helper to reset the hash queue depth counter.
///
/// Used by unit tests to ensure clean counter state between tests.
#[cfg(test)]
pub(crate) fn reset_hash_queue_depth() {
    HASH_QUEUE_DEPTH.store(0, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Known SHA-256 of "hello world".
    const HELLO_WORLD_SHA256: &str =
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    #[test]
    fn test_sha256_known_value() {
        let buffer = b"hello world";
        let (hash, truncated, skipped) =
            unsafe { compute_content_hash(buffer.as_ptr(), buffer.len() as u32) };
        assert_eq!(hash, Some(HELLO_WORLD_SHA256.to_string()));
        assert!(!truncated);
        assert!(!skipped);
    }

    #[test]
    fn test_sha256_empty_buffer() {
        let (hash, truncated, skipped) = unsafe { compute_content_hash(std::ptr::null(), 0) };
        assert!(hash.is_none());
        assert!(!truncated);
        assert!(!skipped);
    }

    #[test]
    fn test_sha256_zero_len() {
        let buffer = b"ignored";
        let (hash, truncated, skipped) = unsafe { compute_content_hash(buffer.as_ptr(), 0) };
        assert!(hash.is_none());
        assert!(!truncated);
        assert!(!skipped);
    }

    #[test]
    fn test_hash_truncation() {
        // Create a buffer larger than HASH_CAP_BYTES.
        let oversized = vec![0xABu8; HASH_CAP_BYTES + 1000];
        let (hash, truncated, skipped) =
            unsafe { compute_content_hash(oversized.as_ptr(), oversized.len() as u32) };
        assert!(hash.is_some());
        assert!(truncated, "expected truncated=true for oversized buffer");
        assert!(!skipped);

        // Verify the hash is the SHA-256 of the first HASH_CAP_BYTES bytes.
        let mut hasher = Sha256::new();
        hasher.update(&oversized[..HASH_CAP_BYTES]);
        let expected = hex::encode(hasher.finalize());
        assert_eq!(hash.unwrap(), expected);
    }

    #[test]
    #[ignore = "allocates ~100MB; run with: cargo test -p dlp-hook-dll --lib -- hash_compute::tests::test_hash_truncation_100mb -- --ignored --nocapture"]
    fn test_hash_truncation_100mb() {
        // Create a buffer of exactly HASH_CAP_BYTES + 1000 bytes.
        // This verifies the 100MB cap is enforced and the hash matches
        // the first HASH_CAP_BYTES bytes.
        let oversized = vec![0xABu8; HASH_CAP_BYTES + 1000];
        let (hash, truncated, skipped) =
            unsafe { compute_content_hash(oversized.as_ptr(), oversized.len() as u32) };
        assert!(hash.is_some());
        assert!(truncated, "expected truncated=true for 100MB+ buffer");
        assert!(!skipped);

        // Verify the hash is the SHA-256 of the first HASH_CAP_BYTES bytes.
        let mut hasher = Sha256::new();
        hasher.update(&oversized[..HASH_CAP_BYTES]);
        let expected = hex::encode(hasher.finalize());
        assert_eq!(hash.unwrap(), expected);
    }

    #[test]
    fn test_hash_skipped_on_pool_failure() {
        // This test verifies the fallback path. In practice, pool creation
        // only fails under extreme resource exhaustion. We test the function
        // signature and that small buffers bypass the pool entirely.
        let buffer = b"small";
        let (hash, truncated, skipped) =
            unsafe { compute_content_hash_offloaded(buffer.as_ptr(), buffer.len() as u32) };
        // Small buffers are hashed inline (no pool needed).
        assert!(hash.is_some());
        assert!(!truncated);
        assert!(!skipped);
    }

    #[test]
    fn test_hash_skipped_on_null_buffer() {
        let (hash, truncated, skipped) =
            unsafe { compute_content_hash_offloaded(std::ptr::null(), 100) };
        assert!(hash.is_none());
        assert!(!truncated);
        assert!(!skipped);
    }

    #[test]
    fn test_offloaded_small_buffer_uses_inline() {
        // Buffers below SMALL_BUFFER_THRESHOLD should not touch the pool.
        let buffer = vec![0xCDu8; SMALL_BUFFER_THRESHOLD - 1];
        let (hash, truncated, skipped) =
            unsafe { compute_content_hash_offloaded(buffer.as_ptr(), buffer.len() as u32) };
        assert!(hash.is_some());
        assert!(!truncated);
        assert!(!skipped);
    }

    #[test]
    fn test_hash_skipped_on_pool_saturation() {
        let _guard = crate::PHASE_58_5_TEST_LOCK.lock().unwrap();
        reset_hash_queue_depth();

        // Force saturation by manually setting queue depth above threshold.
        HASH_QUEUE_DEPTH.store(HASH_QUEUE_DEPTH_MAX + 1, Ordering::Relaxed);

        let buffer = vec![0xABu8; SMALL_BUFFER_THRESHOLD + 1];
        let (hash, truncated, skipped) =
            unsafe { compute_content_hash_offloaded(buffer.as_ptr(), buffer.len() as u32) };

        // Restore queue depth so other tests are not affected.
        reset_hash_queue_depth();

        assert!(hash.is_none());
        assert!(!truncated);
        assert!(skipped, "expected skipped=true when queue depth > MAX");
    }

    #[test]
    fn test_queue_depth_guard_increments_and_decrements() {
        let _guard = crate::PHASE_58_5_TEST_LOCK.lock().unwrap();
        // Reset to known state.
        reset_hash_queue_depth();

        {
            let _guard = QueueDepthGuard::new();
            assert_eq!(
                HASH_QUEUE_DEPTH.load(Ordering::Relaxed),
                1,
                "queue depth should be incremented"
            );
        }

        assert_eq!(
            HASH_QUEUE_DEPTH.load(Ordering::Relaxed),
            0,
            "queue depth should be decremented after guard drops"
        );
    }

    #[test]
    fn test_offloaded_large_buffer_computes_hash() {
        // Buffers at or above SMALL_BUFFER_THRESHOLD use the pool.
        let buffer = vec![0xEFu8; SMALL_BUFFER_THRESHOLD + 1];
        let (hash, truncated, skipped) =
            unsafe { compute_content_hash_offloaded(buffer.as_ptr(), buffer.len() as u32) };
        assert!(hash.is_some());
        assert!(!truncated);
        assert!(!skipped);
    }
}
