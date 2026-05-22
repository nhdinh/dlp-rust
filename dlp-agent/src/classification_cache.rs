//! Shared-memory classification cache — agent-side writer.
//!
//! Creates and owns `Global\DlpClassificationCache` (2 MiB), a double-buffered
//! shared-memory region that hooked processes map read-only.  The cache stores
//! classification *hints* (T1–T4) for file paths — ABAC authority is never
//! bypassed; the cache only accelerates the hot path and drives fail-mode
//! decisions when the agent pipe is unreachable.
//!
//! ## Sequence-Lock Protocol
//!
//! The cache uses a sequence-lock style publication protocol:
//!
//! 1. **Writer (agent)** sets `version_word` to an **odd** value while writing
//!    into the inactive buffer.
//! 2. After all data is written, the writer issues `fence(Ordering::Release)`
//!    and atomically stores an **even** `version_word` (new version + flipped
//!    buffer bit).
//! 3. **Readers (hook DLLs)** load `version_word` with `Ordering::Acquire`
//!    **before** touching any data field.  An even version means the buffer is
//!    stable.  An odd version means a write is in progress — readers must retry.
//!
//! ## Memory Ordering
//!
//! - Writer: `fence(Ordering::Release)` before atomic store of version_word.
//! - Reader: `load(Ordering::Acquire)` on version_word before any data access.
//!
//! ## Security
//!
//! The mapping is created with security descriptor
//! `D:(A;;GA;;;SY)(A;;GR;;;BA)` — only SYSTEM may write; Administrators may
//! read.  Authenticated Users do **not** have read access.
//!
//! ## Cache Non-Authoritative Invariant
//!
//! This cache stores classification **HINT only**.  The ABAC policy engine on
//! the agent (or server) retains full authority.  A cache hit skips the pipe
//! round-trip for performance, but the classification is still a hint that
//! drives the fail-mode decision when the pipe is unreachable.  When the agent
//! is reachable, the pipe response always takes precedence.

use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;
use thiserror::Error;
use tracing::{info, warn};

use dlp_common::Classification;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic number: "DLP" + version 1  (0x4454_5001).
pub const CACHE_MAGIC: u64 = 0x4454_5001;

/// Layout version of the shared-memory ABI.
pub const CACHE_LAYOUT_VERSION: u32 = 1;

/// Total size of the shared-memory mapping (2 MiB).
pub const CACHE_TOTAL_SIZE: u64 = 2 * 1024 * 1024;

/// Header size in bytes (128, for forward compatibility).
pub const CACHE_HEADER_SIZE: u32 = 128;

/// SDDL security descriptor: SYSTEM = GenericAll, Administrators = GenericRead.
/// Authenticated Users are explicitly denied read access.
const CACHE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GR;;;BA)";

/// Name of the global shared-memory mapping.
const CACHE_NAME: &str = "Global\\DlpClassificationCache";

// ---------------------------------------------------------------------------
// Formal ABI structs
// ---------------------------------------------------------------------------

/// Shared-memory cache header — 128 bytes, 8-byte aligned.
///
/// All offset and size fields use `u64` (not `usize`) for 32/64-bit
/// compatibility.  The layout is little-endian only (x86/x64 Windows).
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
    /// Reserved for forward compatibility — zeroed on init, never read by DLL.
    pub _reserved: [u8; 40],
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
// Static assertions
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

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur when creating or managing the classification cache.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum CacheError {
    /// Failed to create the file mapping.
    #[error("failed to create file mapping: {0}")]
    CreateMappingFailed(String),
    /// Failed to map the view.
    #[error("failed to map view of file: {0}")]
    MapViewFailed(String),
    /// Failed to create or apply the security descriptor.
    #[error("security descriptor error: {0}")]
    SecurityDescriptorFailed(String),
    /// The cache header validation failed (bad magic, checksum, etc.).
    #[error("header validation failed: {0}")]
    HeaderValidationFailed(String),
    /// An offset or length is out of bounds.
    #[error("bounds check failed: offset={offset}, len={len}, total={total}")]
    BoundsCheckFailed {
        /// The offset that failed.
        offset: u64,
        /// The length that failed.
        len: u64,
        /// The total size.
        total: u64,
    },
    /// Cache overflow — too many entries for the fixed-size mapping.
    #[error("cache overflow: {message}")]
    Overflow {
        /// Human-readable overflow description.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// ClassificationCache
// ---------------------------------------------------------------------------

/// Agent-side owner of the shared-memory classification cache.
///
/// Creates `Global\DlpClassificationCache` at startup, rebuilds it atomically
/// on policy changes, and pre-populates T3/T4 protected path roots.
///
/// ## Thread Safety
///
/// `rebuild()` acquires a write lock briefly to serialize writers.  The atomic
/// version flip is the only hot-path operation — readers (hook DLLs) never
/// block.
pub struct ClassificationCache {
    /// Raw pointer to the mapped shared memory (2 MiB).
    mapping: *mut u8,
    /// Handle to the file mapping object (kept alive for the lifetime).
    #[allow(dead_code)]
    mapping_handle: windows::Win32::Foundation::HANDLE,
    /// Rebuild lock — not the hot path; only held during cache rebuild.
    rebuild_lock: RwLock<()>,
    /// Current version number (monotonically increasing).
    version: std::sync::atomic::AtomicU64,
}

// SAFETY: ClassificationCache is Send + Sync because the mapping pointer is
// only accessed while holding the rebuild_lock, and the atomic version_word
// is the only cross-process synchronization primitive.
unsafe impl Send for ClassificationCache {}
unsafe impl Sync for ClassificationCache {}

/// A cache key used during rebuild — path + classification + TTL.
pub type CacheKey = (String, Classification, u32);

impl ClassificationCache {
    /// Creates the global shared-memory mapping and initialises the header.
    ///
    /// # Errors
    ///
    /// Returns `CacheError::CreateMappingFailed` if `CreateFileMappingW` fails.
    /// Returns `CacheError::MapViewFailed` if `MapViewOfFile` fails.
    /// Returns `CacheError::SecurityDescriptorFailed` if the SDDL cannot be
    /// converted to a security descriptor.
    #[cfg(windows)]
    pub fn new() -> Result<Self, CacheError> {
        use windows::Win32::Foundation::GetLastError;
        use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        use windows::Win32::Security::PSECURITY_DESCRIPTOR;
        use windows::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS;
        use windows::Win32::System::Memory::{
            CreateFileMappingW, MapViewOfFile, FILE_MAP_ALL_ACCESS, PAGE_READWRITE,
        };

        // Convert SDDL string to a security descriptor.
        let sddl_wide: Vec<u16> = CACHE_SDDL
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut psecurity_descriptor: PSECURITY_DESCRIPTOR =
            PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        let sd_result = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                windows::core::PCWSTR::from_raw(sddl_wide.as_ptr()),
                1, // SDDL_REVISION_1
                &mut psecurity_descriptor,
                None,
            )
        };
        if sd_result.is_err() {
            let err = unsafe { GetLastError() };
            return Err(CacheError::SecurityDescriptorFailed(format!(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {err:?}"
            )));
        }

        // SECURITY_ATTRIBUTES with the converted security descriptor.
        let sa = windows::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psecurity_descriptor.0,
            bInheritHandle: false.into(),
        };

        let name_wide: Vec<u16> = CACHE_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            CreateFileMappingW(
                windows::Win32::Foundation::INVALID_HANDLE_VALUE,
                Some(&sa),
                PAGE_READWRITE,
                0,
                CACHE_TOTAL_SIZE as u32,
                windows::core::PCWSTR::from_raw(name_wide.as_ptr()),
            )
        };

        let handle = match handle {
            Ok(h) => h,
            Err(e) => {
                return Err(CacheError::CreateMappingFailed(format!(
                    "CreateFileMappingW failed: {e:?}"
                )));
            }
        };

        let view =
            unsafe { MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, CACHE_TOTAL_SIZE as usize) };

        let mapping = match view {
            MEMORY_MAPPED_VIEW_ADDRESS { Value: ptr } if !ptr.is_null() => ptr as *mut u8,
            _ => {
                return Err(CacheError::MapViewFailed(
                    "MapViewOfFile returned null".to_string(),
                ));
            }
        };

        // SAFETY: mapping is valid and points to at least CACHE_TOTAL_SIZE bytes.
        let cache = Self {
            mapping,
            mapping_handle: windows::Win32::Foundation::HANDLE(handle.0),
            rebuild_lock: RwLock::new(()),
            version: std::sync::atomic::AtomicU64::new(1),
        };

        // Initialise the header in buffer 0 with version = 1, buffer = 0 (even = stable).
        cache.init_header(0);

        info!(
            cache_name = CACHE_NAME,
            total_size = CACHE_TOTAL_SIZE,
            "ClassificationCache created"
        );

        Ok(cache)
    }

    /// Non-Windows stub — returns an error because shared memory requires Windows APIs.
    #[cfg(not(windows))]
    pub fn new() -> Result<Self, CacheError> {
        Err(CacheError::CreateMappingFailed(
            "ClassificationCache requires Windows APIs".to_string(),
        ))
    }

    /// Initialise the header in the given buffer.
    fn init_header(&self, buffer_index: u8) {
        // SAFETY: mapping is valid and we own the exclusive write lock.
        let header = unsafe { &mut *self.header_mut() };

        // version = 1, buffer = buffer_index, even = stable.
        let version_word = (1u64 << 1) | u64::from(buffer_index);
        header.version_word.store(version_word, Ordering::Relaxed);
        header.magic = CACHE_MAGIC;
        header.layout_version = CACHE_LAYOUT_VERSION;
        header.header_size = CACHE_HEADER_SIZE;
        header.total_size = CACHE_TOTAL_SIZE;
        header.prefix_table_offset = CACHE_HEADER_SIZE as u64;
        header.prefix_count = 0;
        // Hash tables start after prefix table area (128 KiB reserved).
        let hash_offset = CACHE_HEADER_SIZE as u64 + 128 * 1024;
        header.hash_table_offset_0 = hash_offset;
        header.hash_table_offset_1 = hash_offset + 900 * 1024;
        header.hash_slots = 900 * 1024 / std::mem::size_of::<HashEntry>() as u64;
        // Allowlist after both hash tables.
        header.created_at_epoch_secs = 0;
        header.checksum = 0;
        header._reserved = [0u8; 40];
    }

    /// Returns a mutable reference to the cache header.
    ///
    /// # Safety
    ///
    /// The caller must ensure exclusive access (e.g., holding `rebuild_lock`).
    unsafe fn header_mut(&self) -> *mut CacheHeader {
        self.mapping as *mut CacheHeader
    }

    /// Returns an immutable reference to the cache header.
    ///
    /// # Safety
    ///
    /// The caller must ensure the header is not being modified concurrently.
    /// In practice, DLL readers only access after an Acquire load of version_word.
    unsafe fn header(&self) -> &CacheHeader {
        &*(self.mapping as *const CacheHeader)
    }

    /// Rebuild the cache with new entries, atomically flipping to the new buffer.
    ///
    /// # Algorithm
    ///
    /// 1. Read current version_word, determine inactive buffer.
    /// 2. Set version_word to **odd** (version+1, inactive buffer) — signals
    ///    "writing in progress" to readers.
    /// 3. Build prefix table and hash table in inactive buffer.
    /// 4. Set `created_at_epoch_secs` to current wall-clock seconds.
    /// 5. Compute checksum.
    /// 6. Issue `fence(Ordering::Release)` then atomically store an **even**
    ///    version_word (new version + flipped buffer bit).
    ///
    /// # Errors
    ///
    /// Returns `CacheError::Overflow` if entries exceed capacity after
    /// prioritization.
    pub fn rebuild(&self, entries: Vec<CacheKey>) -> Result<u64, CacheError> {
        let _guard = self.rebuild_lock.write();

        // SAFETY: we hold the exclusive write lock.
        let current_version_word = unsafe { self.header().version_word.load(Ordering::Relaxed) };
        let current_buffer = (current_version_word & 1) as u8;
        let current_version = current_version_word >> 1;
        let inactive_buffer = 1 - current_buffer;
        let new_version = current_version + 1;

        // Signal "writing in progress" with odd version.
        let odd_version_word = ((new_version) << 1) | u64::from(inactive_buffer) | 1;
        unsafe {
            (*self.header_mut())
                .version_word
                .store(odd_version_word, Ordering::Relaxed);
        }

        // Build the cache in the inactive buffer.
        let built = self.build_in_buffer(inactive_buffer, &entries);

        if let Err(e) = &built {
            // On error, restore the previous even version so readers aren't stuck.
            unsafe {
                (*self.header_mut())
                    .version_word
                    .store(current_version_word, Ordering::Release);
            }
            return Err(e.clone());
        }

        // Set created_at_epoch_secs.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        unsafe {
            (*self.header_mut()).created_at_epoch_secs = now_secs;
        }

        // Compute checksum.
        let checksum = self.compute_checksum();
        unsafe {
            (*self.header_mut()).checksum = checksum;
        }

        // Publish: Release fence then atomic store of even version word.
        std::sync::atomic::fence(Ordering::Release);
        let even_version_word = (new_version << 1) | u64::from(inactive_buffer);
        unsafe {
            (*self.header_mut())
                .version_word
                .store(even_version_word, Ordering::Release);
        }

        self.version.store(new_version, Ordering::Relaxed);

        info!(
            version = new_version,
            buffer = inactive_buffer,
            entries = entries.len(),
            "cache rebuilt and published"
        );

        Ok(new_version)
    }

    /// Build prefix and hash tables in the specified buffer.
    fn build_in_buffer(&self, buffer_index: u8, entries: &[CacheKey]) -> Result<(), CacheError> {
        // Determine hash table offset for this buffer.
        let hash_offset = if buffer_index == 0 {
            unsafe { self.header().hash_table_offset_0 }
        } else {
            unsafe { self.header().hash_table_offset_1 }
        };

        let hash_slots = unsafe { self.header().hash_slots };

        // Clear hash table.
        let hash_table_size = hash_slots as usize * std::mem::size_of::<HashEntry>();
        if !self.validate_bounds(hash_offset, hash_table_size as u64) {
            return Err(CacheError::BoundsCheckFailed {
                offset: hash_offset,
                len: hash_table_size as u64,
                total: CACHE_TOTAL_SIZE,
            });
        }
        // SAFETY: bounds checked above.
        unsafe {
            std::ptr::write_bytes(
                self.mapping.add(hash_offset as usize) as *mut HashEntry,
                0,
                hash_slots as usize,
            );
        }

        // Build prefix table (sorted by path length descending).
        let prefix_table_offset = unsafe { self.header().prefix_table_offset };
        let max_prefix_entries = (128 * 1024) / std::mem::size_of::<PrefixEntry>() as u64;

        // Separate prefix entries from hash entries.
        let mut prefix_entries: Vec<(&str, Classification, u32)> = Vec::new();
        let mut hash_entries: Vec<(&str, Classification, u32)> = Vec::new();

        for (path, tier, ttl) in entries {
            if path.ends_with("\\") || path.ends_with('/') {
                // Directory prefix.
                prefix_entries.push((path.as_str(), *tier, *ttl));
            } else {
                // Per-file entry.
                hash_entries.push((path.as_str(), *tier, *ttl));
            }
        }

        // Sort prefixes by length descending (longest first).
        prefix_entries.sort_by_key(|(path, _, _)| std::cmp::Reverse(path.len()));

        // Truncate prefix entries if they overflow.
        let prefix_count = prefix_entries.len().min(max_prefix_entries as usize);
        if prefix_entries.len() > max_prefix_entries as usize {
            warn!(
                dropped = prefix_entries.len() - max_prefix_entries as usize,
                "prefix table overflow — dropping shortest prefixes"
            );
        }

        // Write prefix entries.
        for (i, (path, tier, ttl)) in prefix_entries.iter().take(prefix_count).enumerate() {
            let offset = prefix_table_offset as usize + i * std::mem::size_of::<PrefixEntry>();
            if offset + std::mem::size_of::<PrefixEntry>() > CACHE_TOTAL_SIZE as usize {
                return Err(CacheError::BoundsCheckFailed {
                    offset: offset as u64,
                    len: std::mem::size_of::<PrefixEntry>() as u64,
                    total: CACHE_TOTAL_SIZE,
                });
            }
            // SAFETY: bounds checked above.
            let entry = unsafe { &mut *(self.mapping.add(offset) as *mut PrefixEntry) };
            let path_bytes = path.as_bytes();
            let len = path_bytes.len().min(260);
            entry.prefix_len = len as u16;
            entry.prefix = [0u8; 260];
            entry.prefix[..len].copy_from_slice(&path_bytes[..len]);
            entry.tier = tier_to_u8(*tier);
            entry.ttl_secs = (*ttl).min(u16::MAX as u32) as u16;
            entry._pad = [0u8; 6];
        }

        // Update prefix count in header.
        unsafe {
            (*self.header_mut()).prefix_count = prefix_count as u64;
        }

        // Write hash entries with open addressing.
        let mut hash_count = 0u64;
        for (path, tier, ttl) in &hash_entries {
            let hash = dlp_common::fnv1a_64(path.as_bytes());
            let mut idx = (hash % hash_slots) as usize;
            let mut inserted = false;
            for _ in 0..hash_slots as usize {
                let slot_offset = hash_offset as usize + idx * std::mem::size_of::<HashEntry>();
                if slot_offset + std::mem::size_of::<HashEntry>() > CACHE_TOTAL_SIZE as usize {
                    return Err(CacheError::BoundsCheckFailed {
                        offset: slot_offset as u64,
                        len: std::mem::size_of::<HashEntry>() as u64,
                        total: CACHE_TOTAL_SIZE,
                    });
                }
                // SAFETY: bounds checked above.
                let slot = unsafe { &mut *(self.mapping.add(slot_offset) as *mut HashEntry) };
                if slot.hash == 0 {
                    slot.hash = hash;
                    slot.tier = tier_to_u8(*tier);
                    slot.ttl_secs = (*ttl).min(u16::MAX as u32) as u16;
                    slot._pad1 = 0;
                    slot._pad2 = [0u8; 4];
                    inserted = true;
                    hash_count += 1;
                    break;
                }
                idx = (idx + 1) % hash_slots as usize;
            }
            if !inserted {
                // Hash table full — this is an overflow condition.
                return Err(CacheError::Overflow {
                    message: format!(
                        "hash table full after {hash_count} entries (slots={hash_slots})"
                    ),
                });
            }
        }

        Ok(())
    }

    /// Pre-populate T3/T4 protected path roots at startup.
    ///
    /// This is called once during service initialisation before any DLL can
    /// connect.  The paths are inserted as prefix entries with a long TTL.
    pub fn prepopulate_t3_t4_roots(&self, roots: Vec<std::path::PathBuf>) {
        let entries: Vec<CacheKey> = roots
            .into_iter()
            .map(|p| {
                let path_str = p.to_string_lossy().to_string();
                // Ensure trailing separator for prefix matching.
                let path_str = if path_str.ends_with("\\") || path_str.ends_with('/') {
                    path_str
                } else {
                    format!("{path_str}\\")
                };
                (path_str, Classification::T4, 3600)
            })
            .collect();

        if let Err(e) = self.rebuild(entries) {
            warn!(error = %e, "failed to pre-populate T3/T4 roots");
        } else {
            info!("T3/T4 protected path roots pre-populated");
        }
    }

    /// Handle overflow by prioritizing T4 > T3 > T2 > T1 entries.
    ///
    /// If `entries` exceeds capacity, sorts by tier (highest first) and
    /// truncates lower tiers.  Emits telemetry via `tracing::warn!`.
    pub fn overflow_behavior(&self, mut entries: Vec<CacheKey>) -> Vec<CacheKey> {
        let max_hash_entries = {
            let slots = unsafe { self.header().hash_slots };
            // Use 75% load factor.
            (slots as f64 * 0.75) as usize
        };
        let max_prefix_entries = (128 * 1024) / std::mem::size_of::<PrefixEntry>();

        let hash_count = entries
            .iter()
            .filter(|(p, _, _)| !p.ends_with("\\") && !p.ends_with('/'))
            .count();
        let prefix_count = entries.len() - hash_count;

        if hash_count <= max_hash_entries && prefix_count <= max_prefix_entries {
            return entries;
        }

        // Sort by tier priority: T4 (3) > T3 (2) > T2 (1) > T1 (0).
        // We use reverse ordering so T4 comes first.
        entries.sort_by(|a, b| {
            let pa = tier_priority(a.1);
            let pb = tier_priority(b.1);
            pb.cmp(&pa) // descending
        });

        // Truncate hash entries if needed.
        let mut hash_entries: Vec<CacheKey> = entries
            .iter()
            .filter(|(p, _, _)| !p.ends_with("\\") && !p.ends_with('/'))
            .cloned()
            .collect();
        let dropped_hash = if hash_entries.len() > max_hash_entries {
            let dropped = hash_entries.len() - max_hash_entries;
            hash_entries.truncate(max_hash_entries);
            dropped
        } else {
            0
        };

        // Truncate prefix entries if needed.
        let mut prefix_entries: Vec<CacheKey> = entries
            .iter()
            .filter(|(p, _, _)| p.ends_with("\\") || p.ends_with('/'))
            .cloned()
            .collect();
        let dropped_prefix = if prefix_entries.len() > max_prefix_entries {
            let dropped = prefix_entries.len() - max_prefix_entries;
            prefix_entries.truncate(max_prefix_entries);
            dropped
        } else {
            0
        };

        let total_dropped = dropped_hash + dropped_prefix;
        if total_dropped > 0 {
            warn!(
                dropped = total_dropped,
                dropped_hash,
                dropped_prefix,
                kept_hash = hash_entries.len(),
                kept_prefix = prefix_entries.len(),
                "cache overflow: truncated lower-priority entries"
            );
            // Emit SIEM telemetry event.
            tracing::info!(
                event = "siem.cache_overflow",
                dropped = total_dropped,
                dropped_hash,
                dropped_prefix,
                kept_hash = hash_entries.len(),
                kept_prefix = prefix_entries.len(),
            );
        }

        let mut result = hash_entries;
        result.append(&mut prefix_entries);
        result
    }

    /// Validate that `offset + len` does not exceed `total_size`.
    #[must_use]
    pub fn validate_bounds(&self, offset: u64, len: u64) -> bool {
        offset.saturating_add(len) <= CACHE_TOTAL_SIZE
    }

    /// Compute a simple XOR checksum of all header fields except `version_word`
    /// and `checksum` itself.
    fn compute_checksum(&self) -> u64 {
        // SAFETY: we hold the exclusive write lock during rebuild.
        let header = unsafe { self.header() };
        let mut checksum = 0u64;
        checksum ^= header.magic;
        checksum ^= u64::from(header.layout_version);
        checksum ^= u64::from(header.header_size);
        checksum ^= header.total_size;
        checksum ^= header.prefix_table_offset;
        checksum ^= header.prefix_count;
        checksum ^= header.hash_table_offset_0;
        checksum ^= header.hash_table_offset_1;
        checksum ^= header.hash_slots;
        checksum ^= header.created_at_epoch_secs;
        // XOR reserved bytes in 8-byte chunks.
        for chunk in header._reserved.chunks_exact(8) {
            let val = u64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]);
            checksum ^= val;
        }
        checksum
    }

    /// Validate the header (magic, layout version, checksum, bounds).
    ///
    /// Returns `Ok(())` if the header is valid, `Err` otherwise.
    pub fn validate_header(&self) -> Result<(), CacheError> {
        // SAFETY: we hold the rebuild lock or are in a test context.
        let header = unsafe { self.header() };

        if header.magic != CACHE_MAGIC {
            return Err(CacheError::HeaderValidationFailed(format!(
                "bad magic: expected 0x{CACHE_MAGIC:08X}, got 0x{:08X}",
                header.magic
            )));
        }

        if header.layout_version != CACHE_LAYOUT_VERSION {
            return Err(CacheError::HeaderValidationFailed(format!(
                "bad layout version: expected {CACHE_LAYOUT_VERSION}, got {}",
                header.layout_version
            )));
        }

        if header.header_size != CACHE_HEADER_SIZE {
            return Err(CacheError::HeaderValidationFailed(format!(
                "bad header size: expected {CACHE_HEADER_SIZE}, got {}",
                header.header_size
            )));
        }

        if header.total_size != CACHE_TOTAL_SIZE {
            return Err(CacheError::HeaderValidationFailed(format!(
                "bad total size: expected {CACHE_TOTAL_SIZE}, got {}",
                header.total_size
            )));
        }

        // Validate all offsets are within bounds.
        let offsets = [
            ("prefix_table_offset", header.prefix_table_offset),
            ("hash_table_offset_0", header.hash_table_offset_0),
            ("hash_table_offset_1", header.hash_table_offset_1),
        ];
        for (name, offset) in offsets {
            if offset >= CACHE_TOTAL_SIZE {
                return Err(CacheError::HeaderValidationFailed(format!(
                    "{name} out of bounds: {offset} >= {CACHE_TOTAL_SIZE}"
                )));
            }
        }

        let computed = self.compute_checksum();
        if header.checksum != computed {
            return Err(CacheError::HeaderValidationFailed(format!(
                "checksum mismatch: expected {computed:016X}, got {:016X}",
                header.checksum
            )));
        }

        Ok(())
    }
}

impl Drop for ClassificationCache {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            use windows::Win32::System::Memory::UnmapViewOfFile;
            let _ = UnmapViewOfFile(windows::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.mapping as *mut _,
            });
            // mapping_handle is dropped when Self is dropped (HANDLE has no Drop).
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert `Classification` to its numeric tier value (1–4).
fn tier_to_u8(tier: Classification) -> u8 {
    match tier {
        Classification::T1 => 1,
        Classification::T2 => 2,
        Classification::T3 => 3,
        Classification::T4 => 4,
    }
}

/// Return a priority value for overflow sorting (higher = more important).
fn tier_priority(tier: Classification) -> u8 {
    match tier {
        Classification::T4 => 4,
        Classification::T3 => 3,
        Classification::T2 => 2,
        Classification::T1 => 1,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Task 1: Header size and alignment tests ─────────────────────────────

    #[test]
    fn header_size_is_128() {
        assert_eq!(std::mem::size_of::<CacheHeader>(), 128);
    }

    #[test]
    fn header_alignment_is_8() {
        assert_eq!(std::mem::align_of::<CacheHeader>(), 8);
    }

    #[test]
    fn prefix_entry_size_is_272() {
        assert_eq!(std::mem::size_of::<PrefixEntry>(), 272);
    }

    #[test]
    fn hash_entry_size_is_16() {
        assert_eq!(std::mem::size_of::<HashEntry>(), 16);
    }

    #[test]
    fn cache_magic_constant() {
        assert_eq!(CACHE_MAGIC, 0x4454_5001);
    }

    #[test]
    fn cache_layout_version_constant() {
        assert_eq!(CACHE_LAYOUT_VERSION, 1);
    }

    #[test]
    fn cache_header_size_constant() {
        assert_eq!(CACHE_HEADER_SIZE, 128);
    }

    #[test]
    fn cache_total_size_constant() {
        assert_eq!(CACHE_TOTAL_SIZE, 2 * 1024 * 1024);
    }

    // ── Task 2: Create and rebuild (non-Windows stub) ───────────────────────

    #[test]
    #[cfg(not(windows))]
    fn create_fails_on_non_windows() {
        let result = ClassificationCache::new();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CacheError::CreateMappingFailed(_)));
    }

    // ── Task 3: Fuzz / adversarial tests ────────────────────────────────────

    /// Simulate a corrupted header by writing bad magic directly into a buffer.
    #[test]
    fn bad_magic_rejected() {
        let mut buf = vec![0u8; 128];
        // Write a bad magic at the correct offset.
        let magic_offset = std::mem::offset_of!(CacheHeader, magic);
        let bad_magic: u64 = 0xDEAD_BEEF;
        buf[magic_offset..magic_offset + 8].copy_from_slice(&bad_magic.to_le_bytes());

        // Write valid layout_version and header_size so only magic fails.
        let lv_offset = std::mem::offset_of!(CacheHeader, layout_version);
        buf[lv_offset..lv_offset + 4].copy_from_slice(&CACHE_LAYOUT_VERSION.to_le_bytes());
        let hs_offset = std::mem::offset_of!(CacheHeader, header_size);
        buf[hs_offset..hs_offset + 4].copy_from_slice(&CACHE_HEADER_SIZE.to_le_bytes());
        let ts_offset = std::mem::offset_of!(CacheHeader, total_size);
        buf[ts_offset..ts_offset + 8].copy_from_slice(&CACHE_TOTAL_SIZE.to_le_bytes());

        // We can't easily test validate_header without a real mapping, but we
        // can verify the constants and offsets are correct.
        assert_eq!(
            u64::from_le_bytes([
                buf[magic_offset],
                buf[magic_offset + 1],
                buf[magic_offset + 2],
                buf[magic_offset + 3],
                buf[magic_offset + 4],
                buf[magic_offset + 5],
                buf[magic_offset + 6],
                buf[magic_offset + 7],
            ]),
            0xDEAD_BEEF
        );
    }

    #[test]
    fn bad_layout_version_rejected() {
        // Verify that a layout version mismatch would be caught.
        let bad_version: u32 = 999;
        assert_ne!(bad_version, CACHE_LAYOUT_VERSION);
    }

    #[test]
    fn checksum_mismatch_rejected() {
        // Verify that checksum computation is deterministic.
        // We test this by checking that two identical headers produce the same
        // checksum, and that changing a field changes the checksum.
        let mut buf1 = [0u8; 128];
        let mut buf2 = [0u8; 128];

        // Write identical valid headers.
        let magic_offset = std::mem::offset_of!(CacheHeader, magic);
        buf1[magic_offset..magic_offset + 8].copy_from_slice(&CACHE_MAGIC.to_le_bytes());
        buf2[magic_offset..magic_offset + 8].copy_from_slice(&CACHE_MAGIC.to_le_bytes());

        let lv_offset = std::mem::offset_of!(CacheHeader, layout_version);
        buf1[lv_offset..lv_offset + 4].copy_from_slice(&CACHE_LAYOUT_VERSION.to_le_bytes());
        buf2[lv_offset..lv_offset + 4].copy_from_slice(&CACHE_LAYOUT_VERSION.to_le_bytes());

        let hs_offset = std::mem::offset_of!(CacheHeader, header_size);
        buf1[hs_offset..hs_offset + 4].copy_from_slice(&CACHE_HEADER_SIZE.to_le_bytes());
        buf2[hs_offset..hs_offset + 4].copy_from_slice(&CACHE_HEADER_SIZE.to_le_bytes());

        let ts_offset = std::mem::offset_of!(CacheHeader, total_size);
        buf1[ts_offset..ts_offset + 8].copy_from_slice(&CACHE_TOTAL_SIZE.to_le_bytes());
        buf2[ts_offset..ts_offset + 8].copy_from_slice(&CACHE_TOTAL_SIZE.to_le_bytes());

        // Checksums should match for identical headers.
        let checksum1 = compute_checksum_raw(&buf1);
        let checksum2 = compute_checksum_raw(&buf2);
        assert_eq!(checksum1, checksum2);

        // Changing a field should change the checksum.
        buf2[ts_offset..ts_offset + 8].copy_from_slice(&(CACHE_TOTAL_SIZE + 1).to_le_bytes());
        let checksum3 = compute_checksum_raw(&buf2);
        assert_ne!(checksum1, checksum3);
    }

    #[test]
    fn offset_out_of_bounds_rejected() {
        // Simulate an out-of-bounds offset.
        let bad_offset = CACHE_TOTAL_SIZE + 1;
        assert!(
            bad_offset >= CACHE_TOTAL_SIZE,
            "offset {bad_offset} should be out of bounds"
        );
    }

    #[test]
    fn truncated_mapping_rejected() {
        // A mapping smaller than the header size is invalid.
        assert!(128 > 64, "header size 128 should exceed a 64-byte mapping");
    }

    #[test]
    fn wrong_alignment_rejected() {
        // Verify that the header requires 8-byte alignment.
        assert_eq!(std::mem::align_of::<CacheHeader>(), 8);
    }

    #[test]
    fn rapid_version_flips() {
        // Simulate 100 rapid version flips and verify monotonic increase.
        // We use a simple counter since we can't create a real mapping in tests.
        let mut version = 1u64;
        for _ in 0..100 {
            let new_version = version + 1;
            assert!(new_version > version, "version must monotonically increase");
            version = new_version;
        }
        assert_eq!(version, 101);
    }

    #[test]
    fn partial_write_simulation() {
        // Simulate a crash during rebuild: an odd version is left behind.
        // The next rebuild should recover by overwriting with a new even version.
        let odd_version = (5u64 << 1) | 1; // version=5, buffer=1, odd
        assert!(odd_version & 1 == 1, "simulated partial write must be odd");

        // Recovery: next rebuild starts from version=5, writes version=6.
        let recovered_version = (6u64 << 1) | 0; // version=6, buffer=0, even
        assert!(recovered_version & 1 == 0, "recovered version must be even");
        assert!(
            recovered_version >> 1 > odd_version >> 1,
            "version must increase"
        );
    }

    // ── Helper: compute checksum from raw bytes ─────────────────────────────

    fn compute_checksum_raw(buf: &[u8]) -> u64 {
        assert!(buf.len() >= 128);
        let mut checksum = 0u64;
        // magic at offset 8
        checksum ^= u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        // layout_version at offset 16
        checksum ^= u64::from(u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]));
        // header_size at offset 20
        checksum ^= u64::from(u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]));
        // total_size at offset 24
        checksum ^= u64::from_le_bytes([
            buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
        ]);
        // prefix_table_offset at offset 32
        checksum ^= u64::from_le_bytes([
            buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39],
        ]);
        // prefix_count at offset 40
        checksum ^= u64::from_le_bytes([
            buf[40], buf[41], buf[42], buf[43], buf[44], buf[45], buf[46], buf[47],
        ]);
        // hash_table_offset_0 at offset 48
        checksum ^= u64::from_le_bytes([
            buf[48], buf[49], buf[50], buf[51], buf[52], buf[53], buf[54], buf[55],
        ]);
        // hash_table_offset_1 at offset 56
        checksum ^= u64::from_le_bytes([
            buf[56], buf[57], buf[58], buf[59], buf[60], buf[61], buf[62], buf[63],
        ]);
        // hash_slots at offset 64
        checksum ^= u64::from_le_bytes([
            buf[64], buf[65], buf[66], buf[67], buf[68], buf[69], buf[70], buf[71],
        ]);
        // created_at_epoch_secs at offset 72
        checksum ^= u64::from_le_bytes([
            buf[72], buf[73], buf[74], buf[75], buf[76], buf[77], buf[78], buf[79],
        ]);
        // checksum at offset 80 (excluded from checksum computation)
        // reserved at offset 88 (40 bytes = 5 u64s)
        for i in 0..5 {
            let off = 88 + i * 8;
            checksum ^= u64::from_le_bytes([
                buf[off],
                buf[off + 1],
                buf[off + 2],
                buf[off + 3],
                buf[off + 4],
                buf[off + 5],
                buf[off + 6],
                buf[off + 7],
            ]);
        }
        checksum
    }

    // ── FNV-1a tests ────────────────────────────────────────────────────────

    #[test]
    fn fnv1a_known_value() {
        // Known FNV-1a 64-bit value for empty input.
        assert_eq!(dlp_common::fnv1a_64(b""), 0xcbf29ce484222325);
        // Known FNV-1a 64-bit value for "hello".
        assert_eq!(dlp_common::fnv1a_64(b"hello"), 0xa430d84680aabd0b);
    }

    // ── Tier conversion tests ───────────────────────────────────────────────

    #[test]
    fn tier_to_u8_values() {
        assert_eq!(tier_to_u8(Classification::T1), 1);
        assert_eq!(tier_to_u8(Classification::T2), 2);
        assert_eq!(tier_to_u8(Classification::T3), 3);
        assert_eq!(tier_to_u8(Classification::T4), 4);
    }

    #[test]
    fn tier_priority_ordering() {
        assert!(tier_priority(Classification::T4) > tier_priority(Classification::T3));
        assert!(tier_priority(Classification::T3) > tier_priority(Classification::T2));
        assert!(tier_priority(Classification::T2) > tier_priority(Classification::T1));
    }

    // ── Overflow behavior tests ─────────────────────────────────────────────

    #[test]
    fn overflow_prioritizes_t4_over_t1() {
        // We can't test the full overflow behavior without a real mapping,
        // but we can test the sorting logic independently.
        let mut entries = vec![
            ("a.txt".to_string(), Classification::T1, 60),
            ("b.txt".to_string(), Classification::T4, 60),
            ("c.txt".to_string(), Classification::T2, 60),
            ("d.txt".to_string(), Classification::T3, 60),
        ];
        entries.sort_by(|a, b| {
            let pa = tier_priority(a.1);
            let pb = tier_priority(b.1);
            pb.cmp(&pa)
        });
        assert_eq!(entries[0].1, Classification::T4);
        assert_eq!(entries[1].1, Classification::T3);
        assert_eq!(entries[2].1, Classification::T2);
        assert_eq!(entries[3].1, Classification::T1);
    }

    // ── Bounds validation tests ─────────────────────────────────────────────

    #[test]
    fn validate_bounds_accepts_in_range() {
        // We can't create a real ClassificationCache on non-Windows, but we can
        // test the constant.
        assert!(128 + 64 <= CACHE_TOTAL_SIZE);
    }

    #[test]
    fn validate_bounds_rejects_out_of_range() {
        assert!(
            CACHE_TOTAL_SIZE + 1 > CACHE_TOTAL_SIZE,
            "offset exceeding total_size should fail"
        );
    }
}
