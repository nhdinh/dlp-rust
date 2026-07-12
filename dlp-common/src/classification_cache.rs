//! Shared-memory classification cache ABI types.
//!
//! These structs define the binary layout of the shared-memory mapping used
//! between the dlp-agent (writer) and dlp-hook-dll (reader). They are
//! `#[repr(C)]` with explicit sizes and alignment to guarantee ABI stability
//! across 32/64-bit boundaries and compiler versions.
//!
//! # Invariant
//!
//! Both crates MUST use these exact types — never duplicate the definitions.
//! The static assertions below verify size and alignment at compile time.

use std::sync::atomic::AtomicU64;

// ---------------------------------------------------------------------------
// Shared-memory ABI structs
// ---------------------------------------------------------------------------

/// Shared-memory cache header — 128 bytes, 8-byte aligned.
///
/// All offset and size fields use `u64` (not `usize`) for 32/64-bit
/// compatibility. The layout is little-endian only (x86/x64 Windows).
///
/// # Sequence-Lock Protocol
///
/// - `version_word` is **odd** while the writer is building the inactive buffer.
/// - `version_word` is **even** when the buffer is stable and safe to read.
/// - High 63 bits = monotonic version number; low bit = active buffer (0 or 1).
#[repr(C, align(8))]
pub struct CacheHeader {
    /// Atomic version word: [63:1] = version, [0] = active buffer.
    /// Odd while writing; even when stable.
    pub version_word: AtomicU64,
    /// Magic number — must equal `CACHE_MAGIC`.
    pub magic: u64,
    /// Layout version — must equal `CACHE_LAYOUT_VERSION`.
    pub layout_version: u32,
    /// Size of this header in bytes (128).
    pub header_size: u32,
    /// Total size of the shared-memory mapping.
    pub total_size: u64,
    /// Offset to the root-prefix table from start of mapping.
    pub prefix_table_offset: u64,
    /// Number of prefix entries in the prefix table.
    pub prefix_count: u64,
    /// Offset to hash table (buffer 0).
    pub hash_table_offset_0: u64,
    /// Offset to hash table (buffer 1).
    pub hash_table_offset_1: u64,
    /// Number of hash slots per buffer.
    pub hash_slots: u64,
    /// Wall-clock seconds (Unix epoch) when this buffer was built.
    pub created_at_epoch_secs: u64,
    /// Simple XOR checksum of all header fields (excluding version_word and
    /// checksum itself).
    pub checksum: u64,
    /// Offset to operator-extended allowlist entries from start of mapping.
    pub allowlist_offset: u64,
    /// Number of allowlist entries.
    pub allowlist_count: u64,
    /// Reserved for forward compatibility.
    ///
    /// `_reserved[0]` carries the **global enforcement mode byte**, written by
    /// the agent and read by the DLL on the cache-hit fast-path:
    /// - `0` = Block
    /// - `1` = Audit
    /// - `2` = AuditAndBlock
    /// - `3` = PerPolicy
    ///
    /// `_reserved[1..24]` remain zeroed/reserved for forward compatibility.
    /// The byte is inside the checksummed region (`compute_checksum` folds
    /// `_reserved` on both writer and reader), so it is integrity-protected.
    pub _reserved: [u8; 24],
}

/// Root-prefix entry for directory-level classification.
///
/// Prefixes are sorted by `prefix_len` descending (longest first) so that
/// longest-prefix matching works with a simple linear scan.
#[repr(C)]
pub struct PrefixEntry {
    /// Length of the prefix in bytes.
    pub prefix_len: u16,
    /// UTF-8 path prefix (MAX_PATH = 260 bytes).
    pub prefix: [u8; 260],
    /// Classification tier (1–4, matching `Classification`).
    pub tier: u8,
    /// TTL in seconds.
    pub ttl_secs: u16,
    /// Padding to align to 272 bytes.
    pub _pad: [u8; 6],
}

/// Per-file hash entry using FNV-1a 64-bit.
#[repr(C)]
pub struct HashEntry {
    /// FNV-1a 64-bit hash of the path.
    pub hash: u64,
    /// Classification tier (1–4).
    pub tier: u8,
    /// Padding to align ttl_secs to 2 bytes.
    pub _pad1: u8,
    /// TTL in seconds.
    pub ttl_secs: u16,
    /// Padding to align to 16 bytes total.
    pub _pad2: [u8; 4],
}

// ---------------------------------------------------------------------------
// Static assertions — compile-time ABI verification
// ---------------------------------------------------------------------------

const _: () = assert!(
    std::mem::size_of::<CacheHeader>() == 128,
    "CacheHeader must be exactly 128 bytes"
);

const _: () = assert!(
    std::mem::align_of::<CacheHeader>() == 8,
    "CacheHeader must be 8-byte aligned"
);

const _: () = assert!(
    std::mem::size_of::<PrefixEntry>() == 272,
    "PrefixEntry must be exactly 272 bytes"
);

const _: () = assert!(
    std::mem::size_of::<HashEntry>() == 16,
    "HashEntry must be exactly 16 bytes"
);
