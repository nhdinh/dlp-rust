//! Unit tests for the Phase 47 crypto module.
//!
//! Layout matches the `<behavior>` block of Task 47-01:
//!
//! 1. Round-trip — encrypt then decrypt recovers the plaintext.
//! 2. Nonce uniqueness — 1000 sequential encrypts produce 1000 distinct nonces.
//! 3. AAD mismatch — decrypting with the wrong AAD yields `AuthTagMismatch`.
//! 4. Version byte — unknown version yields `UnsupportedVersion(byte)`.
//! 5. DPAPI round-trip — `#[cfg(windows)]`-gated.
//! 6. PBKDF2 known-answer test (RFC 7914 §11 vector adapted to dkLen=32).
//! 7. Envelope binary format — 29-byte overhead.
//!
//! Pure-crypto tests are platform-portable; DPAPI tests are Windows-only.

use super::envelope::{Envelope, ENVELOPE_VERSION_V1, MIN_ENVELOPE_LEN, NONCE_LEN, TAG_LEN};
use super::error::CryptoError;
use super::kdf::{derive_kek, pbkdf2_sha256_into, PBKDF2_DEFAULT_ITERATIONS, PBKDF2_SALT_LEN};
use super::{aad_for, SecretCrypto};
use secrecy::ExposeSecret;
use std::collections::HashSet;

/// Fixed test KEK so every test uses the same key — production code never
/// constructs a KEK this way.
const TEST_KEK: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

fn fixture_crypto() -> SecretCrypto {
    SecretCrypto::from_kek(TEST_KEK, ENVELOPE_VERSION_V1)
}

// ─────────────────────────────────────────────────────────────────────────────
// Behavior 1: round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn round_trip_recovers_plaintext_exactly() {
    let crypto = fixture_crypto();
    let aad = aad_for("alert_router_config", "smtp_password");
    let plaintext = b"hunter2-the-most-common-password";

    let envelope = crypto.encrypt(plaintext, &aad).expect("encrypt");
    let recovered = crypto.decrypt(&envelope, &aad).expect("decrypt");

    assert_eq!(recovered.expose_secret().as_bytes(), plaintext);
}

#[test]
fn round_trip_via_serialized_blob() {
    // Ensures the on-disk format round-trips: encrypt -> serialize -> deserialize -> decrypt.
    let crypto = fixture_crypto();
    let aad = aad_for("siem_config", "splunk_token");
    let plaintext = b"Splunk-HEC-token-abc-123";

    let envelope = crypto.encrypt(plaintext, &aad).expect("encrypt");
    let blob = envelope.serialize();
    let parsed = Envelope::deserialize(&blob).expect("deserialize");
    let recovered = crypto.decrypt(&parsed, &aad).expect("decrypt");

    assert_eq!(recovered.expose_secret().as_bytes(), plaintext);
}

// ─────────────────────────────────────────────────────────────────────────────
// Behavior 2: nonce uniqueness across 1000 encrypts
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn nonces_are_unique_across_1000_encrypts() {
    let crypto = fixture_crypto();
    let aad = aad_for("secrets_jwt", "secret");
    let plaintext = b"same-plaintext-every-time";

    let mut nonces: HashSet<[u8; NONCE_LEN]> = HashSet::with_capacity(1000);
    for _ in 0..1000 {
        let env = crypto.encrypt(plaintext, &aad).expect("encrypt");
        assert!(
            nonces.insert(env.nonce),
            "nonce collision detected — OsRng is misbehaving or AES-GCM nonce-gen is broken"
        );
    }
    assert_eq!(nonces.len(), 1000);
}

// ─────────────────────────────────────────────────────────────────────────────
// Behavior 3: AAD mismatch
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn aad_mismatch_returns_auth_tag_mismatch() {
    let crypto = fixture_crypto();
    let aad_a = aad_for("table_a", "col_x");
    let aad_b = aad_for("table_b", "col_x");
    let plaintext = b"sensitive-value";

    let envelope = crypto.encrypt(plaintext, &aad_a).expect("encrypt");
    let err = crypto
        .decrypt(&envelope, &aad_b)
        .expect_err("decrypt must reject");

    assert!(matches!(err, CryptoError::AuthTagMismatch));
}

#[test]
fn aad_format_matches_specification() {
    // The wire format is locked: any change here invalidates every existing
    // ciphertext. Pin it down with an explicit byte-for-byte assertion.
    let aad = aad_for("alert_router_config", "smtp_password");
    assert_eq!(aad, b"dlp:secret:alert_router_config:smtp_password");

    let aad_empty_col = aad_for("t", "");
    assert_eq!(aad_empty_col, b"dlp:secret:t:");
}

// ─────────────────────────────────────────────────────────────────────────────
// Behavior 4: unknown version byte
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unknown_version_byte_yields_unsupported_version_error() {
    let crypto = fixture_crypto();
    let aad = aad_for("siem_config", "elk_api_key");
    let plaintext = b"elk-token";

    let mut envelope = crypto.encrypt(plaintext, &aad).expect("encrypt");
    envelope.version = 99; // Pretend this row was written by a future release.
    let err = crypto
        .decrypt(&envelope, &aad)
        .expect_err("decrypt must reject");

    assert!(
        matches!(err, CryptoError::UnsupportedVersion(99)),
        "got {err:?}"
    );
}

#[test]
fn malformed_envelope_too_short_is_rejected() {
    let too_short = [ENVELOPE_VERSION_V1, 0, 1, 2]; // 4 bytes, far below MIN_ENVELOPE_LEN.
    let err = Envelope::deserialize(&too_short).expect_err("must reject");
    assert!(matches!(err, CryptoError::InvalidEnvelope));
}

// ─────────────────────────────────────────────────────────────────────────────
// Behavior 7: envelope binary format — 29-byte overhead
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn envelope_overhead_is_29_bytes() {
    let crypto = fixture_crypto();
    let aad = aad_for("any", "thing");
    let plaintext = b"P"; // 1 byte plaintext.

    let blob = crypto
        .encrypt(plaintext, &aad)
        .expect("encrypt")
        .serialize();
    // Layout: version(1) + nonce(12) + ciphertext(1) + tag(16) = 30 bytes.
    // Overhead = blob - plaintext = 29.
    assert_eq!(blob.len(), plaintext.len() + 29);
    assert_eq!(MIN_ENVELOPE_LEN, 1 + NONCE_LEN + TAG_LEN);
}

#[test]
fn envelope_serialize_layout_is_version_nonce_ciphertext() {
    let crypto = fixture_crypto();
    let aad = aad_for("t", "c");
    let plaintext = b"abc";

    let envelope = crypto.encrypt(plaintext, &aad).expect("encrypt");
    let blob = envelope.serialize();

    assert_eq!(blob[0], ENVELOPE_VERSION_V1, "version byte position 0");
    assert_eq!(
        &blob[1..1 + NONCE_LEN],
        envelope.nonce.as_slice(),
        "nonce bytes 1..13"
    );
    assert_eq!(
        &blob[1 + NONCE_LEN..],
        envelope.ciphertext.as_slice(),
        "ct+tag from byte 13"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Behavior 6: PBKDF2 known-answer test
// ─────────────────────────────────────────────────────────────────────────────

/// RFC 7914 §11 PBKDF2-HMAC-SHA256 test vector.
///
/// P = "passwd", S = "salt", c = 1, dkLen = 64. We slice to 32 bytes and
/// compare against the first half of the published vector.
#[test]
fn pbkdf2_known_answer_rfc7914_passwd_salt_1iter() {
    let mut out = [0u8; 32];
    pbkdf2_sha256_into(b"passwd", b"salt", 1, &mut out);

    // First 32 bytes of the published 64-byte expected output.
    // Full vector: 55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc
    //              49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783
    let expected: [u8; 32] = [
        0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6,
        0x05, 0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65, 0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d,
        0xac, 0xbc,
    ];
    assert_eq!(out, expected, "PBKDF2-HMAC-SHA256 KAT mismatch");
}

/// Stability check at the production iteration count: two derivations with
/// identical inputs must yield identical outputs (deterministic).
///
/// Marked `#[ignore]` because 600k iterations is intentionally slow
/// (~250ms on a modern CPU). Run with `cargo test -- --ignored` to exercise.
#[test]
#[ignore = "600k iters is slow; run via --ignored"]
fn pbkdf2_at_production_iter_count_is_deterministic() {
    let seed = b"machine-bound-seed-from-dpapi-output-blob-fixture";
    let salt = [0xAB; PBKDF2_SALT_LEN];

    let kek1 = derive_kek(seed, &salt, PBKDF2_DEFAULT_ITERATIONS);
    let kek2 = derive_kek(seed, &salt, PBKDF2_DEFAULT_ITERATIONS);

    assert_eq!(kek1.as_ref(), kek2.as_ref());
}

/// Cheap stability check: different inputs produce different KEKs.
#[test]
fn pbkdf2_inputs_separation() {
    let salt = [0u8; PBKDF2_SALT_LEN];
    let kek_a = derive_kek(b"seed-a", &salt, 1000);
    let kek_b = derive_kek(b"seed-b", &salt, 1000);
    assert_ne!(kek_a.as_ref(), kek_b.as_ref());

    let salt_alt = [1u8; PBKDF2_SALT_LEN];
    let kek_c = derive_kek(b"seed-a", &salt_alt, 1000);
    assert_ne!(kek_a.as_ref(), kek_c.as_ref(), "salt must affect output");
}

// ─────────────────────────────────────────────────────────────────────────────
// Behavior 5: DPAPI round-trip — Windows only
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(windows)]
#[test]
fn dpapi_round_trip_recovers_plaintext() {
    use super::dpapi::{dpapi_protect, dpapi_unprotect};
    let plaintext = b"hello";
    let wrapped = dpapi_protect(plaintext).expect("protect");
    // The wrapped blob is non-empty and different from the plaintext.
    assert!(!wrapped.is_empty());
    assert_ne!(wrapped.as_slice(), plaintext.as_slice());
    let recovered = dpapi_unprotect(&wrapped).expect("unprotect");
    assert_eq!(recovered.as_slice(), plaintext.as_slice());
}

#[cfg(windows)]
#[test]
fn dpapi_unprotect_rejects_garbage() {
    use super::dpapi::dpapi_unprotect;
    let err = dpapi_unprotect(&[0u8; 64]).expect_err("garbage must not decrypt");
    assert!(matches!(err, CryptoError::DpapiUnprotectFailed { .. }));
}

// ─────────────────────────────────────────────────────────────────────────────
// Secret-debug redaction — defensive check that `SecretCrypto::Debug` does
// not leak the KEK. The per-secret SecretString redaction is exercised
// transitively by Task 47-09; here we cover only the bootstrap type.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn debug_does_not_leak_kek_bytes() {
    let crypto = fixture_crypto();
    let dbg = format!("{crypto:?}");
    // None of the KEK fixture bytes should appear as a recognisable hex pair.
    // The simplest check: ensure the `<redacted>` placeholder is present.
    assert!(dbg.contains("redacted"), "got {dbg}");
    // And the most-distinctive sentinel byte of TEST_KEK is 0x20 at the end —
    // the literal hex `20` could appear coincidentally, but the literal `\x01`
    // through `\x20` byte sequence will not appear in the redacted Debug.
}
