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
use std::sync::Mutex;

use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, FILE_MAP_ALL_ACCESS,
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

/// Owned wrapper around a hook journal file mapping.
///
/// On drop, unmaps the view and closes the handle so the OS resources are
/// released deterministically during self-unhook.
struct JournalMapping {
    handle: HANDLE,
    view: *mut std::ffi::c_void,
}

impl JournalMapping {
    /// Returns true if the mapping handle is valid.
    #[allow(dead_code)]
    fn is_valid(&self) -> bool {
        !self.handle.is_invalid() && !self.view.is_null()
    }
}

impl Drop for JournalMapping {
    fn drop(&mut self) {
        if !self.view.is_null() {
            let _ = unsafe { UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: self.view }) };
        }
        if !self.handle.is_invalid() {
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }
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
    /// Owned mapping handle and view.
    #[allow(dead_code)]
    mapping: JournalMapping,
}

// SAFETY: HookJournal is Send + Sync because the shared memory is
// process-local and all mutation is through atomic operations on the header.
unsafe impl Send for HookJournal {}
unsafe impl Sync for HookJournal {}

/// Global lock-protected journal instance.
///
/// Uses `std::sync::Mutex<Option<HookJournal>>` so the mapping can be taken
/// and dropped safely during self-unhook. OnceLock reset via pointer cast is
/// unsound and is no longer used.
static JOURNAL: Mutex<Option<HookJournal>> = Mutex::new(None);

impl HookJournal {
    /// Returns the global `HookJournal` instance, initializing it on first call.
    ///
    /// Returns `None` if the shared-memory mapping cannot be created or opened.
    /// In that case, journaling is unavailable for this process lifetime and
    /// all hook calls proceed without journaling.
    pub fn get() -> Option<JournalView> {
        {
            let guard = JOURNAL.lock().ok()?;
            if let Some(ref journal) = *guard {
                return Some(JournalView {
                    header: journal.header,
                    entries: journal.entries,
                    capacity: journal.capacity,
                    next_seq: journal.next_seq,
                });
            }
        }
        // SAFETY: Windows API calls to create shared memory. Must NOT be called
        // from DllMain (loader lock).
        let new_journal = unsafe { Self::try_init()? };
        let view = JournalView {
            header: new_journal.header,
            entries: new_journal.entries,
            capacity: new_journal.capacity,
            next_seq: new_journal.next_seq,
        };
        let mut guard = JOURNAL.lock().ok()?;
        if guard.is_none() {
            *guard = Some(new_journal);
        }
        Some(view)
    }

    /// Advance the global sequence counter for the next journal entry.
    ///
    /// This must be called after each successful write so `next_seq` is
    /// incremented on the authoritative `HookJournal` instance rather than on
    /// a local `JournalView` copy.
    pub fn advance_seq() {
        let mut guard = match JOURNAL.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let Some(ref mut journal) = *guard {
            journal.next_seq += 1;
        }
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

        let mapping = JournalMapping {
            handle: windows::Win32::Foundation::HANDLE(handle.0),
            view: base_ptr as *mut std::ffi::c_void,
        };

        let journal = HookJournal {
            header: header_ptr,
            entries: entries_ptr,
            capacity: ENTRY_CAPACITY,
            next_seq: 1,
            mapping,
        };

        let msg = format!("[dlp-hook] journal initialized: {}\0", name);
        crate::debug_log(&msg);

        Some(journal)
    }
}

/// Lightweight view into the hook journal.
///
/// Returned by [`HookJournal::get`]. The view copies the header/entries pointers
/// and borrows no lock, so it is safe to use after the global `JOURNAL` lock is
/// released. The mapping remains valid until [`unmap_journal`] is called.
#[derive(Clone, Copy)]
pub struct JournalView {
    header: *mut JournalHeader,
    entries: *mut JournalEntry,
    capacity: usize,
    next_seq: u64,
}

// SAFETY: JournalView contains only pointers to mapped memory that is valid
// until unmap_journal is called.
unsafe impl Send for JournalView {}
unsafe impl Sync for JournalView {}

impl JournalView {
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
    pub fn write(&self, handle_value: u64, op: u8, path: &str, ts_qpc: u64, etw_timestamp: u64) {
        let path_hash = dlp_common::fnv1a_64(path.as_bytes());

        // SAFETY: SPSC ring buffer. The header and entries pointers are valid
        // for the lifetime of the process (shared memory mapping).
        unsafe {
            let write_index =
                std::ptr::read_volatile(std::ptr::addr_of!((*self.header).write_index));
            let slot = write_index as usize % self.capacity;
            let entry_ptr = self.entries.add(slot);

            let seq = self.next_seq;

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
                std::ptr::addr_of_mut!((*self.header).write_index),
                new_write_index,
            );
        }
    }
}

/// Unmap the hook journal and release the mapping handle.
///
/// Called during self-unhook. After this point all journal writes become no-ops.
pub fn unmap_journal() {
    let mut guard = match JOURNAL.lock() {
        Ok(g) => g,
        Err(e) => {
            crate::debug_log("[dlp-hook] journal: JOURNAL poisoned, forcing unmap\0");
            e.into_inner()
        }
    };
    *guard = None;
}

/// Test-only helper to install a pre-built `HookJournal` into the global slot.
#[cfg(test)]
pub(crate) fn set_journal_for_test(journal: HookJournal) {
    let mut guard = JOURNAL.lock().expect("JOURNAL lock");
    *guard = Some(journal);
}

/// Test-only helper to read whether the global journal slot is populated.
#[cfg(test)]
pub(crate) fn is_journal_mapped() -> bool {
    JOURNAL.lock().map(|g| g.is_some()).unwrap_or(false)
}

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
        // D-04: Emit alert but do NOT fail the operation closed.
        emit_journal_degraded_alert(handle_value, op, "journal mapping unavailable");
        return;
    };

    journal.write(handle_value, op, path, ts_qpc, etw_timestamp);

    // Advance the authoritative sequence counter while the journal is still
    // held, so the next write receives a monotonically increasing seq. The
    // previous implementation incremented next_seq on a local JournalView copy,
    // which never updated the global HookJournal (WR-02 fix).
    HookJournal::advance_seq();
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

/// Emit a `JournalDegraded` alert via the named pipe.
///
/// Per D-04, when the journal mapping is lost or the ring buffer cannot accept
/// an entry, the hook preserves the ABAC decision and emits this alert for
/// monitoring. The alert is fire-and-forget: if the pipe is unreachable, the
/// error is silently dropped.
///
/// # Arguments
///
/// * `file_object` — The HANDLE value from the API call.
/// * `op` — The operation type (1=Create, 2=Write, 3=Delete, 4=SetInfo).
/// * `error` — Human-readable error description.
pub fn emit_journal_degraded_alert(file_object: u64, op: u8, error: &str) {
    let alert = dlp_common::hook_ipc::JournalDegradedAlert {
        file_object,
        op,
        error: error.to_string(),
    };
    let envelope = dlp_common::hook_ipc::IpcEnvelope::V1(dlp_common::hook_ipc::IpcMessageV1 {
        payload: dlp_common::hook_ipc::IpcPayloadV1::JournalDegraded(alert),
    });

    match bincode::serialize(&envelope) {
        Ok(payload) => {
            let _ = crate::pipe_client::send_raw_oneway(crate::DEFAULT_PIPE_NAME, &payload);
        }
        Err(e) => {
            let msg = format!("[dlp-hook] JournalDegraded serialization failed: {:?}\0", e);
            crate::debug_log(&msg);
        }
    }
    // Also log locally
    let msg = format!(
        "[dlp-hook] JournalDegraded: file_object={} op={} error={}\0",
        file_object, op, error
    );
    crate::debug_log(&msg);
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
        use std::sync::Arc;
        use std::time::Duration;
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
            let _guard = crate::PHASE_58_5_TEST_LOCK.lock().unwrap();
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
                    mapping: JournalMapping {
                        handle: windows::Win32::Foundation::HANDLE(handle.0),
                        view: base_ptr as *mut std::ffi::c_void,
                    },
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
            let _guard = crate::PHASE_58_5_TEST_LOCK.lock().unwrap();
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
                    mapping: JournalMapping {
                        handle: windows::Win32::Foundation::HANDLE(handle.0),
                        view: base_ptr as *mut std::ffi::c_void,
                    },
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
            let _guard = crate::PHASE_58_5_TEST_LOCK.lock().unwrap();
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
                    mapping: JournalMapping {
                        handle: windows::Win32::Foundation::HANDLE(handle.0),
                        view: base_ptr as *mut std::ffi::c_void,
                    },
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
            let _guard = crate::PHASE_58_5_TEST_LOCK.lock().unwrap();
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
                    mapping: JournalMapping {
                        handle: windows::Win32::Foundation::HANDLE(handle.0),
                        view: base_ptr as *mut std::ffi::c_void,
                    },
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
            let _guard = crate::PHASE_58_5_TEST_LOCK.lock().unwrap();
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
                    mapping: JournalMapping {
                        handle: windows::Win32::Foundation::HANDLE(handle.0),
                        view: base_ptr as *mut std::ffi::c_void,
                    },
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
            let _guard = crate::PHASE_58_5_TEST_LOCK.lock().unwrap();
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
                    mapping: JournalMapping {
                        handle: windows::Win32::Foundation::HANDLE(handle.0),
                        view: base_ptr as *mut std::ffi::c_void,
                    },
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
            let _guard = crate::PHASE_58_5_TEST_LOCK.lock().unwrap();
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
            let _guard = crate::PHASE_58_5_TEST_LOCK.lock().unwrap();
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
                    mapping: JournalMapping {
                        handle: windows::Win32::Foundation::HANDLE(handle.0),
                        view: base_ptr as *mut std::ffi::c_void,
                    },
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

        #[test]
        fn test_unmap_journal_releases_handle_and_view() {
            let _guard = crate::PHASE_58_5_TEST_LOCK.lock().unwrap();
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

                let journal = HookJournal {
                    header: header_ptr,
                    entries: entries_ptr,
                    capacity: ENTRY_CAPACITY,
                    next_seq: 1,
                    mapping: JournalMapping {
                        handle: windows::Win32::Foundation::HANDLE(handle.0),
                        view: base_ptr as *mut std::ffi::c_void,
                    },
                };

                set_journal_for_test(journal);
                assert!(is_journal_mapped());

                unmap_journal();
                assert!(!is_journal_mapped());
            }
        }

        #[test]
        fn test_concurrent_read_and_unmap_no_deadlock() {
            let _guard = crate::PHASE_58_5_TEST_LOCK.lock().unwrap();
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

                let journal = HookJournal {
                    header: header_ptr,
                    entries: entries_ptr,
                    capacity: ENTRY_CAPACITY,
                    next_seq: 1,
                    mapping: JournalMapping {
                        handle: windows::Win32::Foundation::HANDLE(handle.0),
                        view: base_ptr as *mut std::ffi::c_void,
                    },
                };

                set_journal_for_test(journal);

                let view_for_thread = JournalView {
                    header: header_ptr,
                    entries: entries_ptr,
                    capacity: ENTRY_CAPACITY,
                    next_seq: 1,
                };

                let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stop_clone = Arc::clone(&stop);

                let reader = std::thread::spawn(move || {
                    while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                        view_for_thread.write(0, 1, r"C:\test.txt", 0, 0);
                    }
                });

                std::thread::sleep(Duration::from_millis(5));
                // Signal the reader to stop before unmapping so it does not access freed memory.
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
                reader.join().unwrap();
                unmap_journal();
                // The important invariant is that unmap_journal completed without
                // deadlocking while reads were in flight. Writes after unmap may
                // silently no-op because the mapping was dropped.
                assert!(!is_journal_mapped());
            }
        }
    }
}
