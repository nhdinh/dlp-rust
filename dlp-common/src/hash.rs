//! Hash utilities shared across DLP crates.

/// FNV-1a 64-bit hash function.
///
/// This is a fast, non-cryptographic hash suitable for hash table keys.
/// It is used by both `dlp-agent` (writer) and `dlp-hook-dll` (reader)
/// to ensure consistent cache key computation.
///
/// # Arguments
///
/// * `bytes` — Input bytes to hash.
///
/// # Returns
///
/// 64-bit FNV-1a hash value.
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
