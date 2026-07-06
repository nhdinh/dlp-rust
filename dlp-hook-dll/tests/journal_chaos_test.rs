//! Concurrency stress test for the hook journal mapping lifecycle.
//!
//! Verifies that `unmap_journal` does not deadlock while a reader thread is
//! actively writing entries.

use dlp_hook_dll::{
    is_journal_mapped, set_journal_for_test, unmap_journal, HookJournal, JournalEntry,
    JournalHeader, JournalView,
};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_ALL_ACCESS,
    MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READWRITE,
};

const TEST_JOURNAL_NAME: &str = "DlpHookJournal_ChaosTest";
const JOURNAL_SIZE: usize = 64 * 1024;

fn cleanup_test_mapping() {
    let name_wide: Vec<u16> = TEST_JOURNAL_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let name_pcwstr = windows::core::PCWSTR::from_raw(name_wide.as_ptr());

    unsafe {
        if let Ok(handle) = windows::Win32::System::Memory::OpenFileMappingW(
            FILE_MAP_ALL_ACCESS.0,
            false,
            name_pcwstr,
        ) {
            let view = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, JOURNAL_SIZE);
            let ptr = view.Value;
            if !ptr.is_null() {
                let _ = UnmapViewOfFile(view);
            }
            let _ = CloseHandle(handle);
        }
    }
}

#[test]
#[serial_test::serial]
fn test_concurrent_read_and_unmap_no_deadlock() {
    let _guard = dlp_hook_dll::PHASE_58_5_TEST_LOCK.lock();
    dlp_hook_dll::reset_for_test();
    cleanup_test_mapping();

    let name_wide: Vec<u16> = TEST_JOURNAL_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let name_pcwstr = windows::core::PCWSTR::from_raw(name_wide.as_ptr());

    unsafe {
        let handle = CreateFileMappingW(
            windows::Win32::Foundation::INVALID_HANDLE_VALUE,
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
        let entries_ptr = base_ptr.add(std::mem::size_of::<JournalHeader>()) as *mut JournalEntry;

        std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr).version), 1u32);
        std::ptr::write_volatile(std::ptr::addr_of_mut!((*header_ptr).write_index), 0u32);

        let journal = HookJournal::new_for_test(
            header_ptr,
            entries_ptr,
            dlp_hook_dll::ENTRY_CAPACITY,
            1,
            windows::Win32::Foundation::HANDLE(handle.0),
            base_ptr as *mut std::ffi::c_void,
        );

        set_journal_for_test(journal);

        let view_for_thread =
            JournalView::new_for_test(header_ptr, entries_ptr, dlp_hook_dll::ENTRY_CAPACITY, 1);

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);

        let reader = std::thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                view_for_thread.write(0, 1, r"C:\test.txt", 0, 0);
            }
        });

        std::thread::sleep(Duration::from_millis(5));
        stop.store(true, Ordering::Relaxed);
        reader.join().unwrap();
        unmap_journal();
        assert!(!is_journal_mapped());
    }
}
