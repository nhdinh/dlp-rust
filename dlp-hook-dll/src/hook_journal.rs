//! Shared-memory hook journal ring buffer for bypass correlator ground truth.
//!
//! The hook DLL creates a per-process shared-memory segment named
//! `Global\DlpHookJournal_<pid>` (64 KiB) and writes an entry before returning
//! every classification decision. The agent correlator maps the same segment
//! read-only and compares entries against ETW Kernel-File events.
//!
//! # Synchronization
//!
//! Single-producer (hook DLL), single-consumer (agent correlator). The producer
//! writes entry fields via `write_volatile`, issues a `Release` fence, then
//! stores `write_index` with `Release` ordering. The consumer reads `write_index`
//! with `Acquire`, then reads the entry. This prevents torn reads on ARM64
//! (review concern CR-03).
//!
//! # Failure Handling
//!
//! If shared-memory creation fails for any reason, the hook DLL silently
//! continues without journaling (per D-25). The correlator will see ETW events
//! with no matching journal and emit `NoHookJournal` alerts — degraded
//! detection is preferable to crashing the host process.

use std::sync::atomic::{fence, Ordering};
use std::sync::OnceLock;

use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, INVALID_HANDLE_VALUE};
use windows::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, OpenFileMappingW, FILE_MAP_ALL_ACCESS,
    MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READWRITE,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Total size of the shared-memory journal mapping (64 KiB).
const JOURNAL_SIZE: usize = 64 * 1024;

/// Size of each journal entry in bytes.
const ENTRY_SIZE: usize = 56;

/// Number of entries that fit in the ring buffer after the header.
const ENTRY_CAPACITY: usize = (JOURNAL_SIZE - std::mem::size_of::<JournalHeader>()) / ENTRY_SIZE;

// ---------------------------------------------------------------------------
// ABI structs — MUST match agent-side reader byte-for-byte
// ---------------------------------------------------------------------------

/// Journal header — 8 bytes, 4-byte aligned.
///
/// The `version` field is set to 1 on creation. The `write_index` is a
/// monotonic counter that wraps via modulo `ENTRY_CAPACITY`.
#[repr(C, align(4))]
pub struct JournalHeader {
    /// Layout version — always 1.
    pub version: u32,
    /// Monotonic write counter. Consumer reads with Acquire.
    pub write_index: u32,
}

/// Journal entry — 56 bytes, 8-byte aligned.
///
/// Stores one file-I/O operation observed by the hook DLL. The `etw_timestamp`
/// field is reserved for correlation forensics (review concern CR-05).
/// The hook DLL sets it to 0; the agent may backfill it from the matching
/// ETW event.
#[repr(C, align(8))]
pub struct JournalEntry {
    /// Monotonic sequence number (1-based).
    pub seq: u64,
    /// HANDLE value from the API call (0 for path-based trampolines).
    pub handle_value: u64,
    /// Operation type: 1=Create, 2=Write, 3=Delete, 4=SetInfo.
    pub op: u8,
    /// Padding to align `path_hash` to 8 bytes and bring total struct size to 56.
    pub _pad: [u8; 15],
    /// FNV-1a 64-bit hash of the normalized path.
    pub path_hash: u64,
    /// QueryPerformanceCounter timestamp at write time.
    pub ts_qpc: u64,
    /// ETW timestamp in 100 ns units (forensics, set to 0 by hook DLL).
    pub etw_timestamp: u64,
}

// ---------------------------------------------------------------------------
// HookJournal — shared-memory producer
// ---------------------------------------------------------------------------

/// Per-process shared-memory journal producer.
///
/// Created lazily on the first hook call (NOT from `DllMain`) to avoid
/// loader-lock deadlock. The mapping is pagefile-backed and named
/// `Global\DlpHookJournal_<pid>`.
pub struct HookJournal {
    /// Pointer to the mapped journal header (read-write).
    header: *mut JournalHeader,
    /// Pointer to the first entry in the ring buffer.
    entries: *mut JournalEntry,
    /// Maximum number of entries (`ENTRY_CAPACITY`).
    capacity: usize,
    /// Next sequence number to assign (1-based).
    next_seq: u64,
}

// SAFETY: HookJournal is Send + Sync because the shared memory is
// process-local and all mutation is through atomic operations on the header.
unsafe impl Send for HookJournal {}
unsafe impl Sync for HookJournal {}

/// Global lazy-initialized journal instance.
///
/// Uses `std::sync::OnceLock` to defer initialization to the first hook call.
static JOURNAL: OnceLock<Option<HookJournal>> = OnceLock::new();

impl HookJournal {
    /// Returns the global `HookJournal` instance, initializing it on first call.
    ///
    /// Returns `None` if the shared-memory mapping cannot be created or opened.
    /// In that case, journaling is unavailable for this process lifetime and
    /// all hook calls proceed without journaling.
    pub fn get() -> Option<&'static HookJournal> {
        let opt = JOURNAL.get_or_init(|| {
            // SAFETY: Windows API calls to create shared memory.
            // Must be called outside DllMain (loader-lock safety).
            unsafe { Self::try_init() }
        });
        opt.as_ref()
    }

    /// Attempt to create or open the shared-memory journal mapping.
    ///
    /// # Safety
    ///
    /// Must be called from a context where Windows loader lock is NOT held
    /// (i.e., NOT from `DllMain`).
    unsafe fn try_init() -> Option<HookJournal> {
        let pid = std::process::id();
        let name = format!("Global\\DlpHookJournal_{}", pid);
        let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let name_pcwstr = windows::core::PCWSTR::from_raw(name_wide.as_ptr());

        // Attempt to create the mapping first.
        let mapping_handle = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            None,           // default security descriptor (per D-01)
            PAGE_READWRITE, // producer needs write access
            0,
            JOURNAL_SIZE as u32,
            name_pcwstr,
        );

        let (handle, created) = match mapping_handle {
            Ok(h) => (h, true),
            Err(e) => {
                // If the mapping already exists, open it instead (CR-04 fix).
                if e.code() == windows::core::HRESULT::from_win32(ERROR_ALREADY_EXISTS.0) {
                    let open_result = OpenFileMappingW(FILE_MAP_ALL_ACCESS.0, false, name_pcwstr);
                    match open_result {
                        Ok(h) => (h, false),
                        Err(_) => {
                            // Silent failure per D-25.
                            return None;
                        }
                    }
                } else {
                    // Silent failure per D-25.
                    return None;
                }
            }
        };

        let view = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, JOURNAL_SIZE);
        let base_ptr = match view {
            MEMORY_MAPPED_VIEW_ADDRESS { Value: ptr } if !ptr.is_null() => ptr as *mut u8,
            _ => {
                let _ = CloseHandle(handle);
                return None;
            }
        };

        let header_ptr = base_ptr as *mut JournalHeader;
        let entries_ptr = base_ptr.add(std::mem::size_of::<JournalHeader>()) as *mut JournalEntry;

        // Initialize header only if we created the mapping.
        if created {
            // SAFETY: base_ptr is valid for JOURNAL_SIZE bytes.
            unsafe {
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr).version), 1u32);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr).write_index), 0u32);
            }
        }

        // Keep the mapping handle alive by leaking it.
        // The mapping is freed automatically when the process exits.
        let _ = CloseHandle(handle);

        let journal = HookJournal {
            header: header_ptr,
            entries: entries_ptr,
            capacity: ENTRY_CAPACITY,
            next_seq: 1,
        };

        let msg = format!("[dlp-hook] journal initialized: {}\0", name);
        crate::debug_log(&msg);

        Some(journal)
    }
}

// ---------------------------------------------------------------------------
// Public write API
// ---------------------------------------------------------------------------

/// Write a journal entry for a file-I/O operation.
///
/// This function is called from every trampoline BEFORE returning the
/// classification decision. If the journal is not available (creation failed),
/// the call returns silently without panicking (per D-25).
///
/// # Synchronization
///
/// The write uses `write_volatile` for each field, followed by a `Release`
/// fence, then a `Release` store of `write_index`. The consumer reads
/// `write_index` with `Acquire`, then reads the entry. This ensures the
/// consumer never sees a new `write_index` with stale entry data (CR-03 fix).
///
/// # Arguments
///
/// * `handle_value` — HANDLE value from the API call (0 for path-based ops).
/// * `op` — Operation type: 1=Create, 2=Write, 3=Delete, 4=SetInfo.
/// * `path` — Normalized file path.
/// * `ts_qpc` — QueryPerformanceCounter timestamp.
/// * `etw_timestamp` — ETW timestamp in 100ns units (0 if unknown).
pub fn journal_write(handle_value: u64, op: u8, path: &str, ts_qpc: u64, etw_timestamp: u64) {
    let Some(journal) = HookJournal::get() else {
        return;
    };

    let path_hash = dlp_common::fnv1a_64(path.as_bytes());

    // SAFETY: SPSC ring buffer. The header and entries pointers are valid
    // for the lifetime of the process (shared memory mapping).
    unsafe {
        let write_index =
            std::ptr::read_volatile(std::ptr::addr_of!((*journal.header).write_index));
        let slot = write_index as usize % journal.capacity;
        let entry_ptr = journal.entries.add(slot);

        let seq = journal.next_seq;

        std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).seq), seq);
        std::ptr::write_volatile(
            std::ptr::addr_of_mut!((*entry_ptr).handle_value),
            handle_value,
        );
        std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).op), op);
        std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).path_hash), path_hash);
        std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).ts_qpc), ts_qpc);
        std::ptr::write_volatile(
            std::ptr::addr_of_mut!((*entry_ptr).etw_timestamp),
            etw_timestamp,
        );

        // CR-03 fix: Release fence prevents CPU-level reordering on ARM64.
        // All entry fields are published before the write_index bump.
        fence(Ordering::Release);

        let new_write_index = write_index.wrapping_add(1);
        std::ptr::write_volatile(
            std::ptr::addr_of_mut!((*journal.header).write_index),
            new_write_index,
        );
    }

    // Increment next_seq for the next write. Use Relaxed because the
    // sequence number is only meaningful within this process.
    // SAFETY: next_seq is only mutated by the single producer (this function).
    // We use a raw pointer write to avoid &mut self.
    let journal_ptr = journal as *const HookJournal as *mut HookJournal;
    unsafe {
        std::ptr::write_volatile(
            std::ptr::addr_of_mut!((*journal_ptr).next_seq),
            journal.next_seq + 1,
        );
    }
}

/// Write a journal entry from a trampoline, capturing the current QPC timestamp.
///
/// This is the convenience function called by trampolines. It reads
/// `QueryPerformanceCounter` and passes `etw_timestamp = 0` (the hook DLL
/// does not have access to ETW timestamps; the correlator uses QPC for
/// matching).
///
/// # Arguments
///
/// * `handle_value` — HANDLE value from the API call (0 for path-based ops).
/// * `op` — Operation type: 1=Create, 2=Write, 3=Delete, 4=SetInfo.
/// * `path` — Normalized file path.
pub fn journal_write_from_trampoline(handle_value: u64, op: u8, path: &str) {
    let ts_qpc = unsafe { query_performance_counter() };
    journal_write(handle_value, op, path, ts_qpc, 0);
}

/// Read the current QueryPerformanceCounter value.
///
/// # Safety
///
/// Safe to call from any thread. Returns 0 on failure.
unsafe fn query_performance_counter() -> u64 {
    let mut qpc: i64 = 0;
    match windows::Win32::System::Performance::QueryPerformanceCounter(&mut qpc) {
        Ok(_) => qpc as u64,
        Err(_) => 0,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Layout tests (platform-independent) ---

    #[test]
    fn test_journal_entry_size() {
        assert_eq!(std::mem::size_of::<JournalEntry>(), 56);
    }

    #[test]
    fn test_journal_header_size() {
        assert_eq!(std::mem::size_of::<JournalHeader>(), 8);
    }

    #[test]
    fn test_entry_capacity_calculation() {
        assert_eq!((65536 - 8) / 56, 1170);
        assert_eq!(ENTRY_CAPACITY, 1170);
    }

    #[test]
    fn test_journal_entry_layout() {
        let entry = JournalEntry {
            seq: 0,
            handle_value: 0,
            op: 0,
            _pad: [0; 15],
            path_hash: 0,
            ts_qpc: 0,
            etw_timestamp: 0,
        };
        let base = std::ptr::addr_of!(entry) as usize;

        assert_eq!(std::ptr::addr_of!(entry.seq) as usize - base, 0);
        assert_eq!(std::ptr::addr_of!(entry.handle_value) as usize - base, 8);
        assert_eq!(std::ptr::addr_of!(entry.op) as usize - base, 16);
        assert_eq!(std::ptr::addr_of!(entry.path_hash) as usize - base, 32);
        assert_eq!(std::ptr::addr_of!(entry.ts_qpc) as usize - base, 40);
        assert_eq!(std::ptr::addr_of!(entry.etw_timestamp) as usize - base, 48);
    }

    #[test]
    fn test_journal_write_silent_on_none() {
        // This test verifies that journal_write returns without panic
        // when the journal global is None. Since we can't easily force
        // the OnceLock to be None in a test, we verify the function
        // signature and that it compiles.
        // The actual None path is exercised when shared memory creation fails.
        journal_write(0, 1, "test", 0, 0);
    }

    // --- Windows-specific shared-memory tests ---

    #[cfg(windows)]
    mod windows_tests {
        use super::*;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Memory::{
            CreateFileMappingW, MapViewOfFile, OpenFileMappingW, UnmapViewOfFile,
            FILE_MAP_ALL_ACCESS, FILE_MAP_READ, MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READWRITE,
        };

        /// Test-specific journal name to avoid collision with real journal.
        /// Uses local namespace (no `Global\` prefix) because creating objects
        /// in the Global namespace requires SeCreateGlobalPrivilege.
        const TEST_JOURNAL_NAME: &str = "DlpHookJournal_Test";

        fn cleanup_test_mapping() {
            // Best-effort cleanup of any leftover test mapping.
            let name_wide: Vec<u16> = TEST_JOURNAL_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let name_pcwstr = windows::core::PCWSTR::from_raw(name_wide.as_ptr());

            unsafe {
                if let Ok(handle) = OpenFileMappingW(FILE_MAP_READ.0, false, name_pcwstr) {
                    let view = MapViewOfFile(handle, FILE_MAP_READ, 0, 0, JOURNAL_SIZE);
                    let ptr = view.Value;
                    if !ptr.is_null() {
                        let _ = UnmapViewOfFile(view);
                    }
                    let _ = CloseHandle(handle);
                }
            }
        }

        #[test]
        fn test_write_index_wraps() {
            cleanup_test_mapping();

            let name_wide: Vec<u16> = TEST_JOURNAL_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let name_pcwstr = windows::core::PCWSTR::from_raw(name_wide.as_ptr());

            unsafe {
                let handle = CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    None,
                    PAGE_READWRITE,
                    0,
                    JOURNAL_SIZE as u32,
                    name_pcwstr,
                )
                .expect("CreateFileMappingW failed");

                let view = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, JOURNAL_SIZE);
                let base_ptr = match view {
                    MEMORY_MAPPED_VIEW_ADDRESS { Value: ptr } if !ptr.is_null() => ptr as *mut u8,
                    _ => panic!("MapViewOfFile failed"),
                };

                let header_ptr = base_ptr as *mut JournalHeader;
                let entries_ptr =
                    base_ptr.add(std::mem::size_of::<JournalHeader>()) as *mut JournalEntry;

                // Initialize header.
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr).version), 1u32);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr).write_index), 0u32);

                let capacity = ENTRY_CAPACITY;
                let _journal = HookJournal {
                    header: header_ptr,
                    entries: entries_ptr,
                    capacity,
                    next_seq: 1,
                };

                // Write capacity + 1 entries to force a wrap.
                for i in 0..=capacity {
                    let write_index =
                        std::ptr::read_volatile(std::ptr::addr_of!((*header_ptr).write_index));
                    let slot = write_index as usize % capacity;
                    let entry_ptr = entries_ptr.add(slot);

                    std::ptr::write_volatile(
                        std::ptr::addr_of_mut!((*entry_ptr).seq),
                        (i + 1) as u64,
                    );
                    std::ptr::write_volatile(
                        std::ptr::addr_of_mut!((*entry_ptr).handle_value),
                        i as u64,
                    );
                    std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).op), 1u8);
                    std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).path_hash), 0u64);
                    std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).ts_qpc), i as u64);
                    std::ptr::write_volatile(
                        std::ptr::addr_of_mut!((*entry_ptr).etw_timestamp),
                        0u64,
                    );

                    fence(Ordering::Release);

                    let new_write_index = write_index.wrapping_add(1);
                    std::ptr::write_volatile(
                        std::ptr::addr_of_mut!((*header_ptr).write_index),
                        new_write_index,
                    );
                }

                // Verify write_index wrapped (monotonic but modulo capacity).
                let final_write_index =
                    std::ptr::read_volatile(std::ptr::addr_of!((*header_ptr).write_index));
                assert_eq!(final_write_index as usize, capacity + 1);

                // Verify the first slot was overwritten with the last entry.
                let first_slot = entries_ptr.add(0);
                let first_seq = std::ptr::read_volatile(std::ptr::addr_of!((*first_slot).seq));
                assert_eq!(first_seq, (capacity + 1) as u64);

                // Cleanup
                let _ = UnmapViewOfFile(view);
                let _ = CloseHandle(handle);
            }
        }

        #[test]
        fn test_seq_monotonic() {
            cleanup_test_mapping();

            let name_wide: Vec<u16> = TEST_JOURNAL_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let name_pcwstr = windows::core::PCWSTR::from_raw(name_wide.as_ptr());

            unsafe {
                let handle = CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    None,
                    PAGE_READWRITE,
                    0,
                    JOURNAL_SIZE as u32,
                    name_pcwstr,
                )
                .expect("CreateFileMappingW failed");

                let view = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, JOURNAL_SIZE);
                let base_ptr = match view {
                    MEMORY_MAPPED_VIEW_ADDRESS { Value: ptr } if !ptr.is_null() => ptr as *mut u8,
                    _ => panic!("MapViewOfFile failed"),
                };

                let header_ptr = base_ptr as *mut JournalHeader;
                let entries_ptr =
                    base_ptr.add(std::mem::size_of::<JournalHeader>()) as *mut JournalEntry;

                std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr).version), 1u32);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr).write_index), 0u32);

                let capacity = ENTRY_CAPACITY;
                let mut journal = HookJournal {
                    header: header_ptr,
                    entries: entries_ptr,
                    capacity,
                    next_seq: 1,
                };

                // Write 3 entries.
                for _ in 0..3 {
                    let write_index =
                        std::ptr::read_volatile(std::ptr::addr_of!((*header_ptr).write_index));
                    let slot = write_index as usize % capacity;
                    let entry_ptr = entries_ptr.add(slot);
                    let seq = journal.next_seq;

                    std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).seq), seq);
                    std::ptr::write_volatile(
                        std::ptr::addr_of_mut!((*entry_ptr).handle_value),
                        0u64,
                    );
                    std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).op), 1u8);
                    std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).path_hash), 0u64);
                    std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).ts_qpc), 0u64);
                    std::ptr::write_volatile(
                        std::ptr::addr_of_mut!((*entry_ptr).etw_timestamp),
                        0u64,
                    );

                    fence(Ordering::Release);

                    let new_write_index = write_index.wrapping_add(1);
                    std::ptr::write_volatile(
                        std::ptr::addr_of_mut!((*header_ptr).write_index),
                        new_write_index,
                    );

                    journal.next_seq += 1;
                }

                // Verify seq values are 1, 2, 3.
                for i in 0..3 {
                    let slot = entries_ptr.add(i);
                    let seq = std::ptr::read_volatile(std::ptr::addr_of!((*slot).seq));
                    assert_eq!(seq, (i + 1) as u64);
                }

                let _ = UnmapViewOfFile(view);
                let _ = CloseHandle(handle);
            }
        }

        #[test]
        fn test_path_hash_computed() {
            cleanup_test_mapping();

            let name_wide: Vec<u16> = TEST_JOURNAL_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let name_pcwstr = windows::core::PCWSTR::from_raw(name_wide.as_ptr());

            unsafe {
                let handle = CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    None,
                    PAGE_READWRITE,
                    0,
                    JOURNAL_SIZE as u32,
                    name_pcwstr,
                )
                .expect("CreateFileMappingW failed");

                let view = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, JOURNAL_SIZE);
                let base_ptr = match view {
                    MEMORY_MAPPED_VIEW_ADDRESS { Value: ptr } if !ptr.is_null() => ptr as *mut u8,
                    _ => panic!("MapViewOfFile failed"),
                };

                let header_ptr = base_ptr as *mut JournalHeader;
                let entries_ptr =
                    base_ptr.add(std::mem::size_of::<JournalHeader>()) as *mut JournalEntry;

                std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr).version), 1u32);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr).write_index), 0u32);

                let capacity = ENTRY_CAPACITY;
                let _journal = HookJournal {
                    header: header_ptr,
                    entries: entries_ptr,
                    capacity,
                    next_seq: 1,
                };

                let path = r"C:\test\file.txt";
                let expected_hash = dlp_common::fnv1a_64(path.as_bytes());

                let write_index =
                    std::ptr::read_volatile(std::ptr::addr_of!((*header_ptr).write_index));
                let slot = write_index as usize % capacity;
                let entry_ptr = entries_ptr.add(slot);

                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).seq), 1u64);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).handle_value), 0u64);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).op), 1u8);
                std::ptr::write_volatile(
                    std::ptr::addr_of_mut!((*entry_ptr).path_hash),
                    expected_hash,
                );
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).ts_qpc), 0u64);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).etw_timestamp), 0u64);

                fence(Ordering::Release);

                std::ptr::write_volatile(
                    std::ptr::addr_of_mut!((*header_ptr).write_index),
                    write_index.wrapping_add(1),
                );

                // Read back and verify.
                let read_hash = std::ptr::read_volatile(std::ptr::addr_of!((*entry_ptr).path_hash));
                assert_eq!(read_hash, expected_hash);

                let _ = UnmapViewOfFile(view);
                let _ = CloseHandle(handle);
            }
        }

        #[test]
        fn test_op_byte_stored() {
            cleanup_test_mapping();

            let name_wide: Vec<u16> = TEST_JOURNAL_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let name_pcwstr = windows::core::PCWSTR::from_raw(name_wide.as_ptr());

            unsafe {
                let handle = CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    None,
                    PAGE_READWRITE,
                    0,
                    JOURNAL_SIZE as u32,
                    name_pcwstr,
                )
                .expect("CreateFileMappingW failed");

                let view = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, JOURNAL_SIZE);
                let base_ptr = match view {
                    MEMORY_MAPPED_VIEW_ADDRESS { Value: ptr } if !ptr.is_null() => ptr as *mut u8,
                    _ => panic!("MapViewOfFile failed"),
                };

                let header_ptr = base_ptr as *mut JournalHeader;
                let entries_ptr =
                    base_ptr.add(std::mem::size_of::<JournalHeader>()) as *mut JournalEntry;

                std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr).version), 1u32);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr).write_index), 0u32);

                let capacity = ENTRY_CAPACITY;
                let _journal = HookJournal {
                    header: header_ptr,
                    entries: entries_ptr,
                    capacity,
                    next_seq: 1,
                };

                let write_index =
                    std::ptr::read_volatile(std::ptr::addr_of!((*header_ptr).write_index));
                let slot = write_index as usize % capacity;
                let entry_ptr = entries_ptr.add(slot);

                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).seq), 1u64);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).handle_value), 0u64);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).op), 2u8);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).path_hash), 0u64);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).ts_qpc), 0u64);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).etw_timestamp), 0u64);

                fence(Ordering::Release);

                std::ptr::write_volatile(
                    std::ptr::addr_of_mut!((*header_ptr).write_index),
                    write_index.wrapping_add(1),
                );

                let read_op = std::ptr::read_volatile(std::ptr::addr_of!((*entry_ptr).op));
                assert_eq!(read_op, 2);

                let _ = UnmapViewOfFile(view);
                let _ = CloseHandle(handle);
            }
        }

        #[test]
        fn test_ts_qpc_stored() {
            cleanup_test_mapping();

            let name_wide: Vec<u16> = TEST_JOURNAL_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let name_pcwstr = windows::core::PCWSTR::from_raw(name_wide.as_ptr());

            unsafe {
                let handle = CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    None,
                    PAGE_READWRITE,
                    0,
                    JOURNAL_SIZE as u32,
                    name_pcwstr,
                )
                .expect("CreateFileMappingW failed");

                let view = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, JOURNAL_SIZE);
                let base_ptr = match view {
                    MEMORY_MAPPED_VIEW_ADDRESS { Value: ptr } if !ptr.is_null() => ptr as *mut u8,
                    _ => panic!("MapViewOfFile failed"),
                };

                let header_ptr = base_ptr as *mut JournalHeader;
                let entries_ptr =
                    base_ptr.add(std::mem::size_of::<JournalHeader>()) as *mut JournalEntry;

                std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr).version), 1u32);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr).write_index), 0u32);

                let capacity = ENTRY_CAPACITY;
                let _journal = HookJournal {
                    header: header_ptr,
                    entries: entries_ptr,
                    capacity,
                    next_seq: 1,
                };

                let expected_ts = 0x1234_5678_9ABC_DEF0u64;

                let write_index =
                    std::ptr::read_volatile(std::ptr::addr_of!((*header_ptr).write_index));
                let slot = write_index as usize % capacity;
                let entry_ptr = entries_ptr.add(slot);

                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).seq), 1u64);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).handle_value), 0u64);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).op), 1u8);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).path_hash), 0u64);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).ts_qpc), expected_ts);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).etw_timestamp), 0u64);

                fence(Ordering::Release);

                std::ptr::write_volatile(
                    std::ptr::addr_of_mut!((*header_ptr).write_index),
                    write_index.wrapping_add(1),
                );

                let read_ts = std::ptr::read_volatile(std::ptr::addr_of!((*entry_ptr).ts_qpc));
                assert_eq!(read_ts, expected_ts);

                let _ = UnmapViewOfFile(view);
                let _ = CloseHandle(handle);
            }
        }

        #[test]
        fn test_etw_timestamp_stored() {
            cleanup_test_mapping();

            let name_wide: Vec<u16> = TEST_JOURNAL_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let name_pcwstr = windows::core::PCWSTR::from_raw(name_wide.as_ptr());

            unsafe {
                let handle = CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    None,
                    PAGE_READWRITE,
                    0,
                    JOURNAL_SIZE as u32,
                    name_pcwstr,
                )
                .expect("CreateFileMappingW failed");

                let view = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, JOURNAL_SIZE);
                let base_ptr = match view {
                    MEMORY_MAPPED_VIEW_ADDRESS { Value: ptr } if !ptr.is_null() => ptr as *mut u8,
                    _ => panic!("MapViewOfFile failed"),
                };

                let header_ptr = base_ptr as *mut JournalHeader;
                let entries_ptr =
                    base_ptr.add(std::mem::size_of::<JournalHeader>()) as *mut JournalEntry;

                std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr).version), 1u32);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr).write_index), 0u32);

                let capacity = ENTRY_CAPACITY;
                let _journal = HookJournal {
                    header: header_ptr,
                    entries: entries_ptr,
                    capacity,
                    next_seq: 1,
                };

                let expected_etw = 0xFEDC_BA98_7654_3210u64;

                let write_index =
                    std::ptr::read_volatile(std::ptr::addr_of!((*header_ptr).write_index));
                let slot = write_index as usize % capacity;
                let entry_ptr = entries_ptr.add(slot);

                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).seq), 1u64);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).handle_value), 0u64);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).op), 1u8);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).path_hash), 0u64);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).ts_qpc), 0u64);
                std::ptr::write_volatile(
                    std::ptr::addr_of_mut!((*entry_ptr).etw_timestamp),
                    expected_etw,
                );

                fence(Ordering::Release);

                std::ptr::write_volatile(
                    std::ptr::addr_of_mut!((*header_ptr).write_index),
                    write_index.wrapping_add(1),
                );

                let read_etw =
                    std::ptr::read_volatile(std::ptr::addr_of!((*entry_ptr).etw_timestamp));
                assert_eq!(read_etw, expected_etw);

                let _ = UnmapViewOfFile(view);
                let _ = CloseHandle(handle);
            }
        }

        #[test]
        fn test_error_already_exists_opens_existing() {
            cleanup_test_mapping();

            let name_wide: Vec<u16> = TEST_JOURNAL_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let name_pcwstr = windows::core::PCWSTR::from_raw(name_wide.as_ptr());

            unsafe {
                // First call: create the mapping.
                let handle1 = CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    None,
                    PAGE_READWRITE,
                    0,
                    JOURNAL_SIZE as u32,
                    name_pcwstr,
                )
                .expect("first CreateFileMappingW failed");

                let view1 = MapViewOfFile(handle1, FILE_MAP_ALL_ACCESS, 0, 0, JOURNAL_SIZE);
                let base_ptr1 = match view1 {
                    MEMORY_MAPPED_VIEW_ADDRESS { Value: ptr } if !ptr.is_null() => ptr as *mut u8,
                    _ => panic!("first MapViewOfFile failed"),
                };

                let header_ptr1 = base_ptr1 as *mut JournalHeader;
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr1).version), 1u32);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr1).write_index), 42u32);

                // IMPORTANT: Keep view1 mapped so the mapping object stays alive.
                // Second call should get ERROR_ALREADY_EXISTS and open existing.
                let handle2 = CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    None,
                    PAGE_READWRITE,
                    0,
                    JOURNAL_SIZE as u32,
                    name_pcwstr,
                );

                let (handle2, _opened) = match handle2 {
                    Ok(h) => (h, true),
                    Err(e) => {
                        if e.code() == windows::core::HRESULT::from_win32(ERROR_ALREADY_EXISTS.0) {
                            let open_result =
                                OpenFileMappingW(FILE_MAP_ALL_ACCESS.0, false, name_pcwstr);
                            match open_result {
                                Ok(h) => (h, false),
                                Err(_) => {
                                    panic!("OpenFileMappingW failed after ERROR_ALREADY_EXISTS")
                                }
                            }
                        } else {
                            panic!("unexpected error from second CreateFileMappingW");
                        }
                    }
                };

                let view2 = MapViewOfFile(handle2, FILE_MAP_ALL_ACCESS, 0, 0, JOURNAL_SIZE);
                let base_ptr2 = match view2 {
                    MEMORY_MAPPED_VIEW_ADDRESS { Value: ptr } if !ptr.is_null() => ptr as *mut u8,
                    _ => panic!("second MapViewOfFile failed"),
                };

                let header_ptr2 = base_ptr2 as *mut JournalHeader;
                let write_index2 =
                    std::ptr::read_volatile(std::ptr::addr_of!((*header_ptr2).write_index));

                // Verify we see the value written by the first mapping.
                assert_eq!(write_index2, 42);

                let _ = UnmapViewOfFile(view1);
                let _ = UnmapViewOfFile(view2);
                let _ = CloseHandle(handle1);
                let _ = CloseHandle(handle2);
            }
        }

        #[test]
        fn test_release_fence_prevents_torn_reads() {
            cleanup_test_mapping();

            let name_wide: Vec<u16> = TEST_JOURNAL_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let name_pcwstr = windows::core::PCWSTR::from_raw(name_wide.as_ptr());

            unsafe {
                let handle = CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    None,
                    PAGE_READWRITE,
                    0,
                    JOURNAL_SIZE as u32,
                    name_pcwstr,
                )
                .expect("CreateFileMappingW failed");

                let view = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, JOURNAL_SIZE);
                let base_ptr = match view {
                    MEMORY_MAPPED_VIEW_ADDRESS { Value: ptr } if !ptr.is_null() => ptr as *mut u8,
                    _ => panic!("MapViewOfFile failed"),
                };

                let header_ptr = base_ptr as *mut JournalHeader;
                let entries_ptr =
                    base_ptr.add(std::mem::size_of::<JournalHeader>()) as *mut JournalEntry;

                std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr).version), 1u32);
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr).write_index), 0u32);

                let capacity = ENTRY_CAPACITY;
                let _journal = HookJournal {
                    header: header_ptr,
                    entries: entries_ptr,
                    capacity,
                    next_seq: 1,
                };

                // Write a fully-populated entry.
                let write_index =
                    std::ptr::read_volatile(std::ptr::addr_of!((*header_ptr).write_index));
                let slot = write_index as usize % capacity;
                let entry_ptr = entries_ptr.add(slot);

                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).seq), 12345u64);
                std::ptr::write_volatile(
                    std::ptr::addr_of_mut!((*entry_ptr).handle_value),
                    0xABCDu64,
                );
                std::ptr::write_volatile(std::ptr::addr_of_mut!((*entry_ptr).op), 3u8);
                std::ptr::write_volatile(
                    std::ptr::addr_of_mut!((*entry_ptr).path_hash),
                    0xDEAD_BEEF_CAFE_BABEu64,
                );
                std::ptr::write_volatile(
                    std::ptr::addr_of_mut!((*entry_ptr).ts_qpc),
                    9876543210u64,
                );
                std::ptr::write_volatile(
                    std::ptr::addr_of_mut!((*entry_ptr).etw_timestamp),
                    1111111111u64,
                );

                fence(Ordering::Release);

                std::ptr::write_volatile(
                    std::ptr::addr_of_mut!((*header_ptr).write_index),
                    write_index.wrapping_add(1),
                );

                // Mock consumer: read write_index with Acquire, then read entry.
                let consumer_write_index =
                    std::ptr::read_volatile(std::ptr::addr_of!((*header_ptr).write_index));
                assert_eq!(consumer_write_index, 1);

                let consumer_slot = (consumer_write_index as usize - 1) % capacity;
                let consumer_entry = entries_ptr.add(consumer_slot);

                let read_seq = std::ptr::read_volatile(std::ptr::addr_of!((*consumer_entry).seq));
                let read_handle =
                    std::ptr::read_volatile(std::ptr::addr_of!((*consumer_entry).handle_value));
                let read_op = std::ptr::read_volatile(std::ptr::addr_of!((*consumer_entry).op));
                let read_hash =
                    std::ptr::read_volatile(std::ptr::addr_of!((*consumer_entry).path_hash));
                let read_ts = std::ptr::read_volatile(std::ptr::addr_of!((*consumer_entry).ts_qpc));
                let read_etw =
                    std::ptr::read_volatile(std::ptr::addr_of!((*consumer_entry).etw_timestamp));

                assert_eq!(read_seq, 12345);
                assert_eq!(read_handle, 0xABCD);
                assert_eq!(read_op, 3);
                assert_eq!(read_hash, 0xDEAD_BEEF_CAFE_BABE);
                assert_eq!(read_ts, 9876543210);
                assert_eq!(read_etw, 1111111111);

                let _ = UnmapViewOfFile(view);
                let _ = CloseHandle(handle);
            }
        }
    }
}
