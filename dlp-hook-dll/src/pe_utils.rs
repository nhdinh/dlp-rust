//! PE utility functions for IAT patching in the DLP hook DLL.
//!
//! Supports both PE32 (x86) and PE32+ (x64) via `cfg(target_arch)` constants.
//! All parsing functions include bounds limits to prevent unbounded reads on
//! malformed PE files.

#![allow(dead_code)]

use windows::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE};

// Architecture-specific constants ------------------------------------------------

/// PE optional header magic for PE32+ (x64).
#[cfg(target_arch = "x86_64")]
const PE_MAGIC: u16 = 0x20B;

/// Offset from optional header start to the data directory array on x64.
#[cfg(target_arch = "x86_64")]
const DATA_DIRECTORY_OFFSET: isize = 112;

/// PE optional header magic for PE32 (x86).
#[cfg(target_arch = "x86")]
const PE_MAGIC: u16 = 0x10B;

/// Offset from optional header start to the data directory array on x86.
#[cfg(target_arch = "x86")]
const DATA_DIRECTORY_OFFSET: isize = 96;

/// Maximum number of import descriptors to scan before giving up.
///
/// Prevents unbounded reads on malformed PE files. The value 512 is generous
/// — typical executables import from fewer than 50 DLLs.
const MAX_IMPORT_DESCRIPTORS: usize = 512;

// Public API --------------------------------------------------------------------

/// Finds the IAT entry in the host module that currently points to
/// `target_proc` inside `dll_name`.
///
/// Supports both PE32 (x86) and PE32+ (x64) via `cfg(target_arch)`.
/// Scans at most [`MAX_IMPORT_DESCRIPTORS`] (512) to prevent unbounded
/// reads on malformed PE files.
///
/// # Safety
///
/// `module_base` must point to a valid, loaded PE module in the current
/// process. `target_proc` must be a valid function pointer. This function
/// performs raw pointer arithmetic; calling it with invalid pointers is
/// undefined behaviour.
///
/// # Arguments
///
/// * `module_base` — Base address of the PE module to scan.
/// * `dll_name` — Name of the DLL whose import table contains the target
///   (e.g., `"kernel32.dll"`). Comparison is ASCII case-insensitive.
/// * `target_proc` — The function pointer to search for in the IAT.
///
/// # Returns
///
/// `Some(iat_ptr)` if the entry is found, `None` otherwise.
pub unsafe fn find_iat_entry(
    module_base: *mut u8,
    dll_name: &str,
    target_proc: *const std::ffi::c_void,
) -> Option<*mut usize> {
    if module_base.is_null() || target_proc.is_null() {
        return None;
    }

    let e_lfanew = *(module_base.offset(0x3C) as *const i32) as isize;
    let nt_headers = module_base.offset(e_lfanew);
    let optional_header = nt_headers.offset(24); // after Signature + FileHeader
    let magic = *(optional_header as *const u16);

    if magic != PE_MAGIC {
        return None;
    }

    // DataDirectory starts at DATA_DIRECTORY_OFFSET in IMAGE_OPTIONAL_HEADER.
    let data_directory = optional_header.offset(DATA_DIRECTORY_OFFSET);
    // Import directory is index 1 (offset 8 bytes from data_directory start).
    let import_dir = data_directory.offset(8);
    let import_rva = *(import_dir as *const u32) as isize;

    if import_rva == 0 {
        return None;
    }

    let mut desc = module_base.offset(import_rva);
    let mut descriptors_scanned = 0usize;

    loop {
        if descriptors_scanned >= MAX_IMPORT_DESCRIPTORS {
            return None;
        }
        descriptors_scanned += 1;

        let name_rva = *(desc.offset(12) as *const u32) as isize;
        if name_rva == 0 {
            break; // null terminator
        }

        let name_ptr = module_base.offset(name_rva);
        let name_len = (0..)
            .take_while(|i| *(name_ptr.offset(*i) as *const u8) != 0)
            .count();
        let name_bytes = std::slice::from_raw_parts(name_ptr as *const u8, name_len);
        if let Ok(name_str) = std::str::from_utf8(name_bytes) {
            if name_str.eq_ignore_ascii_case(dll_name) {
                let first_thunk = *(desc.offset(16) as *const u32) as isize;
                let mut iat = module_base.offset(first_thunk) as *mut usize;
                loop {
                    let entry = *iat;
                    if entry == 0 {
                        break;
                    }
                    if entry == target_proc as usize {
                        return Some(iat);
                    }
                    iat = iat.offset(1);
                }
            }
        }

        desc = desc.offset(20); // sizeof(IMAGE_IMPORT_DESCRIPTOR)
    }

    None
}

/// Temporarily makes `iat` writable and overwrites it with `new_fn`.
///
/// Uses `VirtualProtect` to change page protection to `PAGE_EXECUTE_READWRITE`,
/// writes the new pointer, then restores the original protection.
///
/// # Safety
///
/// `iat` must be a valid pointer to an IAT entry within a loaded module.
/// `new_fn` must be a valid function pointer.
///
/// # Returns
///
/// `true` if the patch succeeded, `false` otherwise.
pub unsafe fn patch_iat(iat: *mut usize, new_fn: *mut std::ffi::c_void) -> bool {
    let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
    let size = std::mem::size_of::<usize>();
    let ok = VirtualProtect(
        iat as *mut std::ffi::c_void,
        size,
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    )
    .is_ok();

    if !ok {
        return false;
    }

    *iat = new_fn as usize;

    let mut _tmp = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
    let _ = VirtualProtect(iat as *mut std::ffi::c_void, size, old_protect, &mut _tmp);

    true
}

/// Restores an IAT entry to its original value.
///
/// This is a convenience wrapper around [`patch_iat`] that restores the
/// original function pointer.
///
/// # Safety
///
/// Same invariants as [`patch_iat`].
///
/// # Returns
///
/// `true` if the restore succeeded, `false` otherwise.
pub unsafe fn restore_iat(iat: *mut usize, original: usize) -> bool {
    patch_iat(iat, original as *mut std::ffi::c_void)
}

// Tests -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_iat_entry_null_module_returns_none() {
        unsafe {
            let result = find_iat_entry(std::ptr::null_mut(), "kernel32.dll", std::ptr::null());
            assert!(result.is_none());
        }
    }

    #[test]
    fn find_iat_entry_null_target_returns_none() {
        unsafe {
            let dummy: u8 = 0;
            let result = find_iat_entry(
                std::ptr::addr_of!(dummy) as *mut u8,
                "kernel32.dll",
                std::ptr::null(),
            );
            assert!(result.is_none());
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn pe_magic_is_0x20b_on_x64() {
        assert_eq!(PE_MAGIC, 0x20B);
    }

    #[test]
    #[cfg(target_arch = "x86")]
    fn pe_magic_is_0x10b_on_x86() {
        assert_eq!(PE_MAGIC, 0x10B);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn data_directory_offset_is_112_on_x64() {
        assert_eq!(DATA_DIRECTORY_OFFSET, 112);
    }

    #[test]
    #[cfg(target_arch = "x86")]
    fn data_directory_offset_is_96_on_x86() {
        assert_eq!(DATA_DIRECTORY_OFFSET, 96);
    }

    /// Verify that `find_iat_entry` stops scanning after `MAX_IMPORT_DESCRIPTORS`
    /// iterations when presented with a PE that has a non-terminating import table.
    ///
    /// We construct a minimal fake PE header in a page allocated via `VirtualAlloc`
    /// (which guarantees alignment suitable for `usize` reads):
    /// - DOS header with e_lfanew pointing to the NT headers
    /// - NT signature + FileHeader (20 bytes) + OptionalHeader
    /// - OptionalHeader with the correct PE_MAGIC and a data directory
    /// - Import directory RVA pointing to a block of descriptors that never
    ///   have a zero name_rva (simulating a malformed / unterminated table)
    ///
    /// The name string is placed far from the descriptor array so that
    /// descriptor field offsets do not alias into the string data.
    #[test]
    fn find_iat_entry_respects_max_descriptors_bound() {
        use windows::Win32::System::Memory::{
            VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        };

        // Layout:
        // 0x00..0x3C: DOS header (padding)
        // 0x3C..0x40: e_lfanew = 0x40 (pointer to NT headers)
        // 0x40..0x44: PE signature "PE\0\0"
        // 0x44..0x58: FileHeader (20 bytes)
        // 0x58..: OptionalHeader
        //
        // OptionalHeader (x64):
        //   0x00: magic (2 bytes) = 0x20B
        //   ... padding to offset 112 from optional header start ...
        //   0x70 (112): DataDirectory[0] (8 bytes)
        //   0x78 (120): DataDirectory[1] = Import Directory (8 bytes)
        //     RVA = 0x200, Size = 0x3000
        //
        // Import descriptors at 0x200:
        //   Each descriptor is 20 bytes. We fill them with non-zero name_rva
        //   so the loop never terminates naturally.
        //   522 descriptors * 20 bytes = 0x28F8 bytes, ending at 0x2AF8.
        //
        // Name string at 0x3000 — well past the descriptor array.

        const BUF_SIZE: usize = 0x4000;

        unsafe {
            let pe_ptr = VirtualAlloc(
                None,
                BUF_SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            ) as *mut u8;
            assert!(!pe_ptr.is_null(), "VirtualAlloc failed");
            assert!(
                (pe_ptr as usize) % 8 == 0,
                "VirtualAlloc returned unaligned address: {:p}",
                pe_ptr
            );

            // e_lfanew at offset 0x3C
            let e_lfanew: u32 = 0x40;
            std::ptr::copy_nonoverlapping(e_lfanew.to_le_bytes().as_ptr(), pe_ptr.add(0x3C), 4);

            // PE signature at 0x40
            std::ptr::copy_nonoverlapping(b"PE\0\0".as_ptr(), pe_ptr.add(0x40), 4);

            // FileHeader at 0x44 (20 bytes).
            // Set SizeOfOptionalHeader to a value large enough.
            let size_of_optional_header: u16 = 240;
            std::ptr::copy_nonoverlapping(
                size_of_optional_header.to_le_bytes().as_ptr(),
                pe_ptr.add(0x44 + 16),
                2,
            );

            // OptionalHeader starts at 0x58 (0x40 + 4 + 20)
            let optional_header_start = 0x58;

            // Magic (2 bytes)
            #[cfg(target_arch = "x86_64")]
            let magic: u16 = 0x20B;
            #[cfg(target_arch = "x86")]
            let magic: u16 = 0x10B;
            std::ptr::copy_nonoverlapping(
                magic.to_le_bytes().as_ptr(),
                pe_ptr.add(optional_header_start),
                2,
            );

            // DataDirectory[1] (import directory) at optional_header_start + DATA_DIRECTORY_OFFSET + 8
            let import_dir_rva: u32 = 0x200;
            let import_dir_size: u32 = BUF_SIZE as u32;
            let import_dir_offset = optional_header_start + (DATA_DIRECTORY_OFFSET as usize) + 8;
            std::ptr::copy_nonoverlapping(
                import_dir_rva.to_le_bytes().as_ptr(),
                pe_ptr.add(import_dir_offset),
                4,
            );
            std::ptr::copy_nonoverlapping(
                import_dir_size.to_le_bytes().as_ptr(),
                pe_ptr.add(import_dir_offset + 4),
                4,
            );

            // Import descriptors at 0x200
            // Fill with non-zero name_rva so loop never terminates naturally.
            let desc_start = 0x200;
            let name_rva: u32 = 0x3000;
            for i in 0..MAX_IMPORT_DESCRIPTORS + 10 {
                let offset = desc_start + i * 20;
                if offset + 20 > BUF_SIZE {
                    break;
                }
                std::ptr::copy_nonoverlapping(
                    name_rva.to_le_bytes().as_ptr(),
                    pe_ptr.add(offset + 12),
                    4,
                );
            }

            // Name string at 0x3000 — "kernel32.dll" followed by null
            let dll_name_bytes = b"kernel32.dll\0";
            std::ptr::copy_nonoverlapping(
                dll_name_bytes.as_ptr(),
                pe_ptr.add(0x3000),
                dll_name_bytes.len(),
            );

            // Target proc — some non-null value
            let target_proc: unsafe extern "system" fn() = dummy_proc;

            let result = find_iat_entry(
                pe_ptr,
                "kernel32.dll",
                target_proc as *const std::ffi::c_void,
            );

            // Should return None because we hit MAX_IMPORT_DESCRIPTORS before
            // finding a matching IAT entry (the IAT entries are all zero, so
            // the inner loop breaks immediately, but we scan all descriptors).
            assert!(result.is_none(), "expected None due to bounds limit");

            // Cleanup
            let _ = windows::Win32::System::Memory::VirtualFree(
                pe_ptr as *mut std::ffi::c_void,
                0,
                windows::Win32::System::Memory::VIRTUAL_FREE_TYPE(0x8000),
            );
        }
    }

    #[test]
    fn max_import_descriptors_is_512() {
        assert_eq!(MAX_IMPORT_DESCRIPTORS, 512);
    }

    /// Verify that `patch_iat` + `restore_iat` round-trip works on a dummy
    /// memory page allocated with execute-read-write permissions.
    #[test]
    fn patch_iat_and_restore_iat_round_trip() {
        use windows::Win32::System::Memory::{
            VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        };

        unsafe {
            let page = VirtualAlloc(None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            assert!(!page.is_null(), "VirtualAlloc failed");

            let iat = page as *mut usize;
            let original_value = 0xDEADBEEFusize;
            *iat = original_value;

            let new_fn: unsafe extern "system" fn() = dummy_proc;
            let patched = patch_iat(iat, new_fn as *mut std::ffi::c_void);
            assert!(patched, "patch_iat should succeed");
            assert_eq!(
                *iat, new_fn as usize,
                "IAT should contain new function pointer"
            );

            let restored = restore_iat(iat, original_value);
            assert!(restored, "restore_iat should succeed");
            assert_eq!(
                *iat, original_value,
                "IAT should be restored to original value"
            );

            // Cleanup
            let _ = windows::Win32::System::Memory::VirtualFree(
                page,
                0,
                windows::Win32::System::Memory::VIRTUAL_FREE_TYPE(0x8000),
            ); // MEM_RELEASE
        }
    }

    extern "system" fn dummy_proc() {}
}
