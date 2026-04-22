//! Integration tests for [`dlp_agent::device_registry::DeviceRegistryCache`] behavior.
//!
//! These tests verify the trust-tier lookup contract without starting the
//! Windows service or making any network calls. They run on all platforms
//! (the `DeviceRegistryCache` struct and its `trust_tier_for` / `seed_for_test`
//! methods are unconditionally compiled).

use dlp_agent::device_registry::DeviceRegistryCache;
use dlp_common::UsbTrustTier;

// ---------------------------------------------------------------------------
// Test 9: Empty cache returns Blocked for any lookup (fail-safe default deny)
// ---------------------------------------------------------------------------

/// Test 9: A freshly constructed `DeviceRegistryCache` with no entries
/// returns [`UsbTrustTier::Blocked`] for any `(vid, pid, serial)` triple,
/// implementing the fail-safe default-deny policy (D-10, CLAUDE.md §3.1).
#[test]
fn test_empty_cache_returns_blocked() {
    // Arrange: empty cache (no seeded entries)
    let cache = DeviceRegistryCache::new();

    // Act + Assert: unknown device returns Blocked
    assert_eq!(
        cache.trust_tier_for("0951", "1666", "ABC"),
        UsbTrustTier::Blocked,
        "empty cache must return Blocked (default deny)"
    );
}

// ---------------------------------------------------------------------------
// Test 10: After seeding, trust_tier_for returns the seeded tier
// ---------------------------------------------------------------------------

/// Test 10: After seeding the cache with a specific `(vid, pid, serial)` →
/// `ReadOnly` mapping, `trust_tier_for` returns `ReadOnly` for that exact key.
#[test]
fn test_seeded_cache_returns_correct_tier() {
    // Arrange: seed a single entry
    let cache = DeviceRegistryCache::new();
    cache.seed_for_test("0951", "1666", "ABC", UsbTrustTier::ReadOnly);

    // Act + Assert: exact key returns the seeded tier
    assert_eq!(
        cache.trust_tier_for("0951", "1666", "ABC"),
        UsbTrustTier::ReadOnly,
        "cache must return the seeded tier for the exact key"
    );
}

// ---------------------------------------------------------------------------
// Test 11: Wrong serial returns Blocked (different serial is a different key)
// ---------------------------------------------------------------------------

/// Test 11: With a `FullAccess` entry seeded for serial `"ABC"`, looking up
/// serial `"DIFFERENT"` returns [`UsbTrustTier::Blocked`] — the three-tuple
/// key `(vid, pid, serial)` must match exactly.
#[test]
fn test_wrong_serial_returns_blocked() {
    // Arrange: seed a FullAccess entry for serial "ABC"
    let cache = DeviceRegistryCache::new();
    cache.seed_for_test("0951", "1666", "ABC", UsbTrustTier::FullAccess);

    // Act + Assert: different serial is not in the cache -> Blocked
    assert_eq!(
        cache.trust_tier_for("0951", "1666", "DIFFERENT"),
        UsbTrustTier::Blocked,
        "a different serial must return Blocked (not in registry)"
    );
}
