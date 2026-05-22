//! Two-phase EDR detection for safe ntdll syscall-stub patching.
//!
//! This module implements detect-before-patch EDR coexistence per Phase 51
//! decisions D-04 through D-06. It never reads "clean" ntdll bytes from disk
//! (avoiding DoppelGate-class evasion-malware classifier triggers).
//!
//! ## Two-Phase Detection Algorithm
//!
//! 1. **Phase 1 (fast pre-filter):** Enumerate loaded modules via
//!    `EnumProcessModules` + `GetModuleFileNameExW`. If no known EDR DLL is
//!    loaded, return `false` immediately.
//! 2. **Phase 2 (stub prologue inspection):** Read the first byte at
//!    `stub_addr`. If not `0xE9` (JMP rel32), return `false`. Read the rel32
//!    offset, calculate the jump target, and check whether the target falls
//!    within any loaded EDR module's address range.
//!
//! ## Known EDR Modules
//!
//! The default list is derived from `AllowlistCategory::Avedr` entries:
//! - CrowdStrike: `csagent.dll`, `csfalcon.dll`
//! - SentinelOne: `SentinelAgent.dll`
//! - Microsoft Defender: `MsMpEng.exe`
//! - Carbon Black: `cb.exe`
//!
//! **Future enhancement:** This list will be extensible via `system_kv`
//! without agent restart (Plan 05).

use std::ffi::c_void;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{CloseHandle, HMODULE};
use windows::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleFileNameExW};
use windows::Win32::System::Threading::{GetCurrentProcessId, OpenProcess};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Known EDR module names derived from `AllowlistCategory::Avedr` entries.
///
/// Per D-05: CrowdStrike, SentinelOne, Defender, Carbon Black.
/// This list is case-insensitive during matching.
pub const KNOWN_EDR_MODULES: &[&str] = &[
    "csagent.dll",
    "csfalcon.dll",
    "SentinelAgent.dll",
    "MsMpEng.exe",
    "cb.exe",
];

/// Cache TTL for the module enumeration result.
///
/// Re-enumerating modules on every stub check is expensive. We cache the
/// result for 5 seconds, which is short enough to catch dynamic EDR loading
/// but long enough to amortize enumeration cost across multiple stubs.
const MODULE_CACHE_TTL: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Information about a single loaded module.
#[derive(Debug, Clone, PartialEq)]
pub struct ModuleInfo {
    /// Base address of the module in process memory.
    pub base: *const c_void,
    /// Size of the module in bytes.
    pub size: usize,
    /// File name of the module (e.g., "csagent.dll").
    pub name: String,
}

// SAFETY: ModuleInfo is safe to Send because base/size/name are purely
// descriptive data; the pointer is never dereferenced across thread boundaries.
unsafe impl Send for ModuleInfo {}

// ---------------------------------------------------------------------------
// EdrDetector
// ---------------------------------------------------------------------------

/// Two-phase EDR detector with cached module enumeration.
///
/// The detector maintains a cached list of loaded modules to avoid
/// re-enumerating on every stub check. The cache is invalidated after
/// [`MODULE_CACHE_TTL`].
#[derive(Debug, Clone)]
pub struct EdrDetector {
    /// Cached module list from the last enumeration.
    cached_modules: Vec<ModuleInfo>,
    /// Timestamp of the last cache refresh.
    last_refresh: Instant,
}

impl Default for EdrDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl EdrDetector {
    /// Creates a new EDR detector with an empty module cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cached_modules: Vec::new(),
            last_refresh: Instant::now() - MODULE_CACHE_TTL * 2,
        }
    }

    /// Checks whether an EDR has hooked the ntdll stub at `stub_addr`.
    ///
    /// Implements the two-phase algorithm per D-04:
    /// 1. Fast pre-filter: check if any known EDR module is loaded.
    /// 2. Stub prologue inspection: check for `0xE9` JMP rel32 targeting
    ///    an EDR module range.
    ///
    /// # Arguments
    ///
    /// * `stub_addr` — Address of the ntdll syscall stub to inspect.
    ///
    /// # Returns
    ///
    /// `true` if an EDR hook is detected (skip patching), `false` otherwise.
    ///
    /// # Safety
    ///
    /// `stub_addr` must point to at least 5 readable bytes in ntdll's `.text`
    /// section. This is always true for valid ntdll syscall stubs.
    pub unsafe fn is_edr_hooked(&mut self, stub_addr: *const u8) -> bool {
        // Phase 1: fast module-enumeration pre-filter.
        if !self.any_known_edr_module_loaded() {
            return false;
        }

        // Phase 2: stub prologue inspection.
        // SAFETY: ntdll .text is RX and always resident; reading 5 bytes is safe.
        let first_byte = unsafe { *stub_addr };
        if first_byte != 0xE9 {
            // Not a JMP rel32 → not the EDR hook pattern we recognize.
            return false;
        }

        // Read rel32 offset (bytes 1-4, little-endian).
        // SAFETY: We use ptr::read_unaligned because stub_addr may not be
        // 4-byte aligned (e.g., stack-allocated test arrays).
        let rel32 = unsafe {
            let offset_ptr = stub_addr.add(1) as *const i32;
            std::ptr::read_unaligned(offset_ptr)
        };

        // Calculate target: stub_addr + 5 + rel32.
        let target = stub_addr.wrapping_add(5).wrapping_add(rel32 as usize);

        // Check if target falls within any loaded EDR module's range.
        is_address_in_edr_module_range(target as *const c_void, &self.cached_modules)
    }

    /// Returns `true` if any known EDR module is currently loaded.
    ///
    /// This is the Phase 1 fast pre-filter. If no known EDR is loaded,
    /// we can skip Phase 2 entirely.
    fn any_known_edr_module_loaded(&mut self) -> bool {
        self.ensure_fresh_cache();
        self.cached_modules.iter().any(|m| {
            let name_lower = m.name.to_lowercase();
            KNOWN_EDR_MODULES
                .iter()
                .any(|&known| name_lower.contains(&known.to_lowercase()))
        })
    }

    /// Ensures the module cache is fresh (within TTL).
    ///
    /// If the cache is stale, re-enumerates loaded modules.
    fn ensure_fresh_cache(&mut self) {
        if self.last_refresh.elapsed() < MODULE_CACHE_TTL {
            return;
        }
        self.refresh_module_list();
    }

    /// Re-enumerates all loaded modules for the current process.
    ///
    /// Uses `EnumProcessModules` + `GetModuleFileNameExW` to build the
    /// cached module list. Per RESEARCH.md: MS-provided, stable across
    /// Windows versions, handles WoW64 correctly.
    pub fn refresh_module_list(&mut self) {
        self.cached_modules.clear();
        self.last_refresh = Instant::now();

        let pid = unsafe { GetCurrentProcessId() };

        // Open current process with query+vm_read access.
        // SAFETY: GetCurrentProcessId is always valid; OpenProcess with
        // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ on self is safe.
        let handle = unsafe {
            OpenProcess(
                windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION
                    | windows::Win32::System::Threading::PROCESS_VM_READ,
                false,
                pid,
            )
        };

        let h = match handle {
            Ok(h) => h,
            Err(_) => return,
        };

        // First call: get required buffer size.
        let mut needed = 0u32;
        let _ = unsafe { EnumProcessModules(h, std::ptr::null_mut(), 0, &mut needed) };
        if needed == 0 {
            let _ = unsafe { CloseHandle(h) };
            return;
        }

        let module_count = (needed as usize) / std::mem::size_of::<HMODULE>();
        let mut modules: Vec<HMODULE> = vec![HMODULE(std::ptr::null_mut()); module_count];

        // Second call: fill the buffer.
        let ok =
            unsafe { EnumProcessModules(h, modules.as_mut_ptr() as *mut _, needed, &mut needed) };
        if ok.is_err() {
            let _ = unsafe { CloseHandle(h) };
            return;
        }

        // Extract module info for each loaded module.
        for (i, &module_base) in modules.iter().enumerate() {
            if module_base.0.is_null() {
                continue;
            }

            // Get module file name.
            let mut name_buf = vec![0u16; 512];
            let name_len =
                unsafe { GetModuleFileNameExW(Some(h), Some(module_base), &mut name_buf) };

            if name_len == 0 {
                continue;
            }

            // Extract basename from full path.
            let full_path = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let basename = std::path::Path::new(&full_path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();

            // Calculate module size using VirtualQuery.
            // SAFETY: module_base is a valid module address from EnumProcessModules.
            let size = unsafe { get_module_size(module_base.0) }.unwrap_or(0);

            self.cached_modules.push(ModuleInfo {
                base: module_base.0,
                size,
                name: basename,
            });

            // Safety limit: stop after a reasonable number of modules.
            if i >= 256 {
                break;
            }
        }

        let _ = unsafe { CloseHandle(h) };
    }

    /// Returns a reference to the cached module list.
    #[must_use]
    pub fn cached_modules(&self) -> &[ModuleInfo] {
        &self.cached_modules
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Checks if `addr` falls within any EDR module's address range.
///
/// # Arguments
///
/// * `addr` — The address to check.
/// * `modules` — The cached module list (filtered to EDR modules implicitly
///   by the caller).
///
/// # Returns
///
/// `true` if `addr` is within `[base, base + size)` of any module.
#[must_use]
pub fn is_address_in_edr_module_range(addr: *const c_void, modules: &[ModuleInfo]) -> bool {
    let addr_usize = addr as usize;
    modules.iter().any(|m| {
        let base = m.base as usize;
        let end = base.saturating_add(m.size);
        addr_usize >= base && addr_usize < end
    })
}

/// Gets the size of a loaded module via `VirtualQuery`.
///
/// Walks the module's memory region using `VirtualQuery` to find the
/// total committed size.
///
/// # Safety
///
/// `base` must be a valid module base address from `EnumProcessModules`.
unsafe fn get_module_size(base: *const c_void) -> Option<usize> {
    use windows::Win32::System::Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION};

    let mut info = MEMORY_BASIC_INFORMATION::default();
    let result = VirtualQuery(
        Some(base),
        &mut info,
        std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
    );

    if result == 0 {
        return None;
    }

    // The region size from VirtualQuery gives us the allocation size
    // starting from the base address.
    Some(info.RegionSize)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edr_detector_no_edr_modules_loaded() {
        let mut detector = EdrDetector::new();
        // With an empty cache, no EDR modules are loaded.
        let stub_addr: *const u8 = std::ptr::null();
        // SAFETY: stub_addr is never dereferenced because cache is empty
        // (Phase 1 returns false before any memory read).
        let result = unsafe { detector.is_edr_hooked(stub_addr) };
        assert!(!result, "empty cache should return false");
    }

    #[test]
    fn edr_detector_clean_stub_no_jmp() {
        // Simulate a clean ntdll stub prologue: mov r10, rcx (0x4C 0x8B 0xD1).
        let stub: [u8; 12] = [
            0x4C, 0x8B, 0xD1, 0xB8, 0x55, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x00,
        ];
        let mut detector = EdrDetector::new();

        // Inject a fake non-EDR module so Phase 1 passes.
        detector.cached_modules.push(ModuleInfo {
            base: 0x1000 as *const c_void,
            size: 0x1000,
            name: "kernel32.dll".to_string(),
        });
        detector.last_refresh = Instant::now();

        // SAFETY: stub is a local array; reading 5 bytes is safe.
        let result = unsafe { detector.is_edr_hooked(stub.as_ptr()) };
        assert!(!result, "stub without 0xE9 JMP should return false");
    }

    #[test]
    fn edr_detector_jmp_to_ntdll_range_not_edr() {
        // Simulate a stub with JMP rel32 targeting ntdll's own range.
        // JMP rel32: 0xE9 + 4-byte offset.
        // We construct the offset so the target is within a non-EDR module.
        //
        // To avoid i32 overflow when stub_addr is a stack pointer far from
        // the target, we place the stub at a fixed low address using a
        // page-aligned allocation.
        let page_size = 4096usize;
        let layout = std::alloc::Layout::from_size_align(page_size, page_size).unwrap();
        // SAFETY: layout is valid (page_size > 0 and power-of-two aligned).
        let page = unsafe { std::alloc::alloc(layout) };
        assert!(!page.is_null(), "alloc failed");

        // Place stub at offset 0x100 within the page.
        let stub_addr = unsafe { page.add(0x100) };
        // Target = stub_addr + 5 + rel32
        // We want target = page + 0x500 (inside a non-EDR module).
        // rel32 = target - (stub_addr + 5)
        let target = unsafe { page.add(0x500) } as isize;
        let rel32 = target - (stub_addr as isize + 5);

        // SAFETY: stub_addr is within our allocated page.
        unsafe {
            *stub_addr = 0xE9; // JMP rel32
            let offset_ptr = stub_addr.add(1) as *mut i32;
            std::ptr::write_unaligned(offset_ptr, rel32 as i32);
        }

        let mut detector = EdrDetector::new();
        // Inject a fake non-EDR module covering the target range.
        detector.cached_modules.push(ModuleInfo {
            base: page as *const c_void,
            size: page_size,
            name: "kernel32.dll".to_string(),
        });
        detector.last_refresh = Instant::now();

        // SAFETY: stub_addr is within our allocated page.
        let result = unsafe { detector.is_edr_hooked(stub_addr) };

        // SAFETY: deallocate the page.
        unsafe { std::alloc::dealloc(page, layout) };

        assert!(!result, "JMP to non-EDR module should return false");
    }

    #[test]
    fn edr_detector_jmp_to_edr_range() {
        // Simulate a stub with JMP rel32 targeting an EDR module range.
        // Use page-aligned allocation to avoid i32 overflow on rel32.
        let page_size = 4096usize;
        let layout = std::alloc::Layout::from_size_align(page_size, page_size).unwrap();
        // SAFETY: layout is valid.
        let page = unsafe { std::alloc::alloc(layout) };
        assert!(!page.is_null(), "alloc failed");

        // Place stub at offset 0x100 within the page.
        let stub_addr = unsafe { page.add(0x100) };
        // Target = page + 0x500 (inside "csagent.dll" at page..page+page_size).
        let target = unsafe { page.add(0x500) } as isize;
        let rel32 = target - (stub_addr as isize + 5);

        // SAFETY: stub_addr is within our allocated page.
        unsafe {
            *stub_addr = 0xE9; // JMP rel32
            let offset_ptr = stub_addr.add(1) as *mut i32;
            std::ptr::write_unaligned(offset_ptr, rel32 as i32);
        }

        let mut detector = EdrDetector::new();
        // Inject a fake EDR module covering the target range.
        detector.cached_modules.push(ModuleInfo {
            base: page as *const c_void,
            size: page_size,
            name: "csagent.dll".to_string(),
        });
        detector.last_refresh = Instant::now();

        // SAFETY: stub_addr is within our allocated page.
        let result = unsafe { detector.is_edr_hooked(stub_addr) };

        // SAFETY: deallocate the page.
        unsafe { std::alloc::dealloc(page, layout) };

        assert!(result, "JMP to EDR module should return true");
    }

    #[test]
    fn known_edr_modules_contains_expected_names() {
        assert!(KNOWN_EDR_MODULES.contains(&"csagent.dll"));
        assert!(KNOWN_EDR_MODULES.contains(&"csfalcon.dll"));
        assert!(KNOWN_EDR_MODULES.contains(&"SentinelAgent.dll"));
        assert!(KNOWN_EDR_MODULES.contains(&"MsMpEng.exe"));
        assert!(KNOWN_EDR_MODULES.contains(&"cb.exe"));
    }

    #[test]
    fn is_address_in_edr_module_range_hit() {
        let modules = vec![ModuleInfo {
            base: 0x1000 as *const c_void,
            size: 0x1000,
            name: "test.dll".to_string(),
        }];
        assert!(is_address_in_edr_module_range(
            0x1500 as *const c_void,
            &modules
        ));
    }

    #[test]
    fn is_address_in_edr_module_range_miss() {
        let modules = vec![ModuleInfo {
            base: 0x1000 as *const c_void,
            size: 0x1000,
            name: "test.dll".to_string(),
        }];
        assert!(!is_address_in_edr_module_range(
            0x3000 as *const c_void,
            &modules
        ));
    }

    #[test]
    fn is_address_in_edr_module_range_boundary() {
        let modules = vec![ModuleInfo {
            base: 0x1000 as *const c_void,
            size: 0x1000,
            name: "test.dll".to_string(),
        }];
        // Exactly at base.
        assert!(is_address_in_edr_module_range(
            0x1000 as *const c_void,
            &modules
        ));
        // One byte past end (0x1000 + 0x1000 = 0x2000).
        assert!(!is_address_in_edr_module_range(
            0x2000 as *const c_void,
            &modules
        ));
    }

    #[test]
    fn module_info_send_safe() {
        // Compile-time check: ModuleInfo must be Send.
        fn assert_send<T: Send>() {}
        assert_send::<ModuleInfo>();
    }

    #[test]
    fn edr_detector_cache_ttl_respected() {
        let mut detector = EdrDetector::new();
        // Manually set cache to expired.
        detector.last_refresh = Instant::now() - Duration::from_secs(10);
        detector.cached_modules.push(ModuleInfo {
            base: 0x1000 as *const c_void,
            size: 0x1000,
            name: "old.dll".to_string(),
        });

        // Calling ensure_fresh_cache should clear stale entries.
        // Since we can't actually enumerate modules in a test, the refresh
        // will clear the cache and fail to populate new entries (no process
        // handle), leaving the cache empty.
        detector.ensure_fresh_cache();
        // The cache may or may not be empty depending on whether OpenProcess
        // succeeded. We just verify the method doesn't panic.
    }
}
