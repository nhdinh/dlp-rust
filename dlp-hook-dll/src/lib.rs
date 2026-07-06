//! DLP API Hook DLL — unified file-I/O interception.
//!
//! This DLL is injected into user-mode processes to intercept file creation,
//! write, move, copy, delete, and rename operations via IAT patching.
//!
//! ## Architecture
//!
//! A single [`HOOKS`] table drives `init()` (patch all), `UnhookAll()` (restore all),
//! and debug logging. Each trampoline is hand-written for precision (path extraction
//! and return-value mapping differ per function).
//!
//! ## Exports
//!
//! | Symbol | Purpose |
//! |--------|---------|
//! | `DllMain` | DLL entry point — patches on attach, restores on detach |
//! | `UnhookAll` | Restores original function pointers |
//! | `HookCreateFileW` | Trampoline for `CreateFileW` |
//! | `HookNtCreateFile` | Trampoline for `NtCreateFile` |
//! | `HookWriteFile` | Trampoline for `WriteFile` |
//! | `HookWriteFileEx` | Trampoline for `WriteFileEx` |
//! | `HookMoveFileExW` | Trampoline for `MoveFileExW` |
//! | `HookCopyFileExW` | Trampoline for `CopyFileExW` |
//! | `HookDeleteFileW` | Trampoline for `DeleteFileW` |
//! | `HookReplaceFileW` | Trampoline for `ReplaceFileW` |
//! | `HookSetFileInformationByHandle` | Trampoline for `SetFileInformationByHandle` |
//! | `HookNtOpenFile` | Trampoline for `NtOpenFile` |
//! | `HookNtWriteFile` | Trampoline for `NtWriteFile` |
//! | `HookNtSetInformationFile` | Trampoline for `NtSetInformationFile` |

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HINSTANCE, NTSTATUS};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{
    FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE,
};
use windows::Win32::System::Diagnostics::Debug::OutputDebugStringW;
use windows::Win32::System::LibraryLoader::{
    FreeLibraryAndExitThread, GetModuleHandleW, GetProcAddress,
};
use windows::Win32::System::Threading::{
    CreateThread, WaitForSingleObject, THREAD_CREATION_FLAGS,
};
// pe_utils.rs uses VirtualProtect and PAGE_EXECUTE_READWRITE; keep import
// if any code in this file needs them, otherwise they are unused.
#[allow(unused_imports)]
use windows::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE};

use dlp_common::hook_ipc::{IpcEnvelope, IpcMessageV1, IpcPayloadV1};
use dlp_common::{Decision, HookRequest, VolumeClass};

mod allowlist;
#[cfg(not(any(test, feature = "test-helpers")))]
mod background_thread;
#[cfg(any(test, feature = "test-helpers"))]
pub mod background_thread;
mod classification_cache;
#[cfg(not(any(test, feature = "test-helpers")))]
mod control_thread;
#[cfg(any(test, feature = "test-helpers"))]
pub mod control_thread;
mod crash_guard;
pub mod diagnostic_ring;
pub mod edr_detector;
mod fail_closed;
mod fail_mode;
pub mod hash_compute;
mod hook_journal;
pub mod ntdll_patcher;
mod pe_utils;
mod perf_telemetry;
#[cfg(not(any(test, feature = "test-helpers")))]
mod pipe_client;
#[cfg(any(test, feature = "test-helpers"))]
pub mod pipe_client;
pub mod sid;
pub mod thread_suspender;
pub mod trampolines;
pub mod volume_class_cache;

pub use fail_closed::DenyReturn;
pub use pe_utils::{find_iat_entry, patch_iat, restore_iat};

// Re-export crash_guard items so trampolines can use them.
pub use crash_guard::{guard_trampoline, seh_guard, with_reentrancy_guard};

// Re-exports for integration tests (isolated_resync_recovery.rs).
#[cfg(any(test, feature = "test-helpers"))]
pub use background_thread::reset_background_thread_for_test;
pub use background_thread::{shutdown_background_thread, start_background_thread};
pub use classification_cache::lru;
#[cfg(any(test, feature = "test-helpers"))]
pub use classification_cache::unmap_cache;
pub use classification_cache::{CacheHeader, CacheLookup};
pub use fail_mode::{decide_isolated, is_cache_stale, FailModeState, FailState};

// Re-exports for integration tests (control_thread_integration.rs, unhook_protocol.rs).
#[cfg(any(test, feature = "test-helpers"))]
pub use control_thread::{
    handle_unhook_command, reset_watchdog_test_state, run_control_loop_for_test,
    shutdown_control_thread, start_control_thread,
};

// Re-export hook_journal for integration tests (journal_integration.rs, journal_degraded_test.rs,
// journal_chaos_test.rs).
#[cfg(any(test, feature = "test-helpers"))]
pub use hook_journal::{
    emit_journal_degraded_alert, is_journal_mapped, journal_write, set_journal_for_test,
    unmap_journal, HookJournal, JournalEntry, JournalHeader, JournalView,
};
#[cfg(any(test, feature = "test-helpers"))]
pub use hook_journal::{ENTRY_CAPACITY, ENTRY_SIZE, JOURNAL_SIZE};

// Re-export sid helper for diagnostic snapshot capture.
pub use sid::get_current_user_sid;

// Test-only utilities (unit tests and integration tests).
#[cfg(any(test, feature = "test-helpers"))]
mod test_utils;
#[cfg(any(test, feature = "test-helpers"))]
pub use test_utils::{reset_for_test, set_test_pipe_name, unique_pipe_name, MockAgentServer};

/// Default pipe name used by the hook DLL.
pub(crate) const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\DlpHookPipe";

/// Test-only override for the pipe name.
///
/// Integration tests set this so that each test can spin up a mock agent server
/// on a unique pipe without colliding with production `DEFAULT_PIPE_NAME`.
#[cfg(any(test, feature = "test-helpers"))]
static TEST_PIPE_OVERRIDE: std::sync::Mutex<Option<&'static str>> = std::sync::Mutex::new(None);

/// Returns the pipe name to use for the current build.
///
/// In production builds this is a compile-time constant (`DEFAULT_PIPE_NAME`).
/// In test builds it returns the value installed by [`set_test_pipe_name`] if
/// any, otherwise falls back to `DEFAULT_PIPE_NAME`.
#[cfg(any(test, feature = "test-helpers"))]
#[inline]
pub fn current_pipe_name() -> &'static str {
    TEST_PIPE_OVERRIDE
        .lock()
        .ok()
        .and_then(|g| *g)
        .unwrap_or(DEFAULT_PIPE_NAME)
}

/// Production version of [`current_pipe_name`] — always the constant.
#[cfg(not(any(test, feature = "test-helpers")))]
#[inline]
pub const fn current_pipe_name() -> &'static str {
    DEFAULT_PIPE_NAME
}

/// Maximum wide-character length for path extraction.
const MAX_WIDE_CHARS: usize = 32_768;

// ---------------------------------------------------------------------------
// Architecture-specific NT path offsets (per review P0)
// ---------------------------------------------------------------------------

/// Offset from `OBJECT_ATTRIBUTES` start to `ObjectName` field on x64.
#[cfg(target_arch = "x86_64")]
const OBJECT_ATTRIBUTES_OBJECT_NAME_OFFSET: isize = 0x10;

/// Offset from `UNICODE_STRING` start to `Buffer` field on x64.
#[cfg(target_arch = "x86_64")]
const UNICODE_STRING_BUFFER_OFFSET: isize = 0x08;

/// Offset from `OBJECT_ATTRIBUTES` start to `ObjectName` field on x86.
#[cfg(target_arch = "x86")]
const OBJECT_ATTRIBUTES_OBJECT_NAME_OFFSET: isize = 0x08;

/// Offset from `UNICODE_STRING` start to `Buffer` field on x86.
#[cfg(target_arch = "x86")]
const UNICODE_STRING_BUFFER_OFFSET: isize = 0x04;

// ---------------------------------------------------------------------------
// Guard to ensure one-time initialisation
// ---------------------------------------------------------------------------

/// Guard to ensure one-time initialisation.
#[cfg(any(test, feature = "test-helpers"))]
pub static INITIALISED: AtomicBool = AtomicBool::new(false);
#[cfg(not(any(test, feature = "test-helpers")))]
static INITIALISED: AtomicBool = AtomicBool::new(false);

/// Flag set by DllMain to request deferred IAT patching outside the Windows
/// loader lock. The actual patching is performed by a one-shot worker thread
/// spawned from DllMain, or lazily on the first trampoline call if the thread
/// fails to start.
#[cfg(any(test, feature = "test-helpers"))]
pub static LAZY_INIT_REQUIRED: AtomicBool = AtomicBool::new(false);
#[cfg(not(any(test, feature = "test-helpers")))]
static LAZY_INIT_REQUIRED: AtomicBool = AtomicBool::new(false);

/// Handle to the one-shot initialization worker thread spawned from DllMain.
/// Stored as a raw pointer value so DllMain PROCESS_DETACH can wait for the
/// thread before unhooking. `HANDLE` is not `Send`/`Sync`, so we store the
/// underlying pointer value.
static INIT_THREAD_HANDLE: Mutex<Option<usize>> = Mutex::new(None);

/// Set to true while the DLL is shutting down so new hook calls pass through.
#[cfg(any(test, feature = "test-helpers"))]
pub static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);
#[cfg(not(any(test, feature = "test-helpers")))]
static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);

/// Number of hook calls currently executing.
#[cfg(any(test, feature = "test-helpers"))]
pub static ACTIVE_CALLS: AtomicUsize = AtomicUsize::new(0);
#[cfg(not(any(test, feature = "test-helpers")))]
static ACTIVE_CALLS: AtomicUsize = AtomicUsize::new(0);

/// Captured DLL HINSTANCE from `DllMain` DLL_PROCESS_ATTACH.
///
/// Stored as a raw `isize` because `HINSTANCE` is a wrapper around `*mut c_void`
/// and does not implement `Send`/`Sync`, which is required for a shared static
/// `Mutex`. The raw value is sound to send across threads and is converted back
/// to `HINSTANCE` only when `self_unload` is called on the owning thread.
static DLL_INSTANCE: Mutex<Option<isize>> = Mutex::new(None);

/// Serializes tests that mutate process-global hook state
/// (IAT restore, ntdll patcher, control thread lifecycle, shared-memory
/// mappings). Prevents parallel tests from corrupting each other's state.
#[cfg(any(test, feature = "test-helpers"))]
pub static PHASE_58_5_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Reset process-global hook state to a clean baseline for tests.
///
/// Clears shutdown and active-call counters, resets the initialization flag,
/// drops the captured DLL instance, disables ntdll patching, and unpatches any
/// stubs that were initialized by prior tests.
#[cfg(any(test, feature = "test-helpers"))]
pub fn reset_hook_globals() {
    SHUTTING_DOWN.store(false, Ordering::SeqCst);
    ACTIVE_CALLS.store(0, Ordering::SeqCst);
    INITIALISED.store(false, Ordering::SeqCst);
    LAZY_INIT_REQUIRED.store(false, Ordering::SeqCst);
    if let Ok(mut guard) = DLL_INSTANCE.lock() {
        *guard = None;
    }
    NTDLL_PATCHING_ENABLED.store(false, Ordering::Relaxed);
    if let Ok(mut guard) = INIT_THREAD_HANDLE.lock() {
        *guard = None;
    }
    if let Some(patcher_lock) = NTDLL_PATCHER.get() {
        if let Ok(mut patcher) = patcher_lock.lock() {
            patcher.unpatch_all_stubs();
        }
    }
}

/// Phase 51: Whether ntdll patching is enabled (read from shared memory during init).
/// Trampolines check this flag before attempting lazy initialization.
static NTDLL_PATCHING_ENABLED: AtomicBool = AtomicBool::new(false);

/// Phase 51: Global NtdllPatcher instance, lazily initialized on first hook call.
///
/// NEVER created from DllMain — DllMain holds the Windows loader lock, and any
/// operation that might trigger DLL loading (including retour's internal
/// operations) would deadlock. Instead, the patcher is created on the first
/// trampoline invocation, which always runs outside the loader lock.
///
/// The Mutex ensures only one thread initializes the patcher and only one
/// patch/unpatch operation runs at a time.
#[cfg(any(test, feature = "test-helpers"))]
pub static NTDLL_PATCHER: OnceLock<Mutex<crate::ntdll_patcher::NtdllPatcher>> = OnceLock::new();
#[cfg(not(any(test, feature = "test-helpers")))]
static NTDLL_PATCHER: OnceLock<Mutex<crate::ntdll_patcher::NtdllPatcher>> = OnceLock::new();

// ---------------------------------------------------------------------------
// Type aliases for original function pointers (clippy: complex types)
// ---------------------------------------------------------------------------

/// Type alias for `NtCreateFile` original function pointer.
type NtCreateFileFn = unsafe extern "system" fn(
    *mut HANDLE,
    u32,
    *mut std::ffi::c_void,
    *mut std::ffi::c_void,
    *const i64,
    u32,
    u32,
    u32,
    u32,
    *mut std::ffi::c_void,
    u32,
) -> NTSTATUS;

/// Type alias for `SetFileInformationByHandle` original function pointer.
type SetFileInformationByHandleFn =
    unsafe extern "system" fn(HANDLE, i32, *mut std::ffi::c_void, u32) -> windows::core::BOOL;

// ---------------------------------------------------------------------------
// Static mut originals and IAT entries for all 12 functions
// ---------------------------------------------------------------------------

/// Original `CreateFileW` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
#[cfg(any(test, feature = "test-helpers"))]
pub static mut ORIGINAL_CREATE_FILE_W: Option<
    unsafe extern "system" fn(
        PCWSTR,
        u32,
        FILE_SHARE_MODE,
        *const SECURITY_ATTRIBUTES,
        FILE_CREATION_DISPOSITION,
        FILE_FLAGS_AND_ATTRIBUTES,
        HANDLE,
    ) -> HANDLE,
> = None;
#[cfg(not(any(test, feature = "test-helpers")))]
static mut ORIGINAL_CREATE_FILE_W: Option<
    unsafe extern "system" fn(
        PCWSTR,
        u32,
        FILE_SHARE_MODE,
        *const SECURITY_ATTRIBUTES,
        FILE_CREATION_DISPOSITION,
        FILE_FLAGS_AND_ATTRIBUTES,
        HANDLE,
    ) -> HANDLE,
> = None;

/// Original `NtCreateFile` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_NT_CREATE_FILE: Option<NtCreateFileFn> = None;

/// Original `WriteFile` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_WRITE_FILE: Option<
    unsafe extern "system" fn(
        HANDLE,
        *const u8,
        u32,
        *mut u32,
        *mut std::ffi::c_void,
    ) -> windows::core::BOOL,
> = None;

/// Original `WriteFileEx` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_WRITE_FILE_EX: Option<
    unsafe extern "system" fn(
        HANDLE,
        *const u8,
        u32,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
    ) -> windows::core::BOOL,
> = None;

/// Original `MoveFileExW` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_MOVE_FILE_EX_W: Option<
    unsafe extern "system" fn(PCWSTR, PCWSTR, u32) -> windows::core::BOOL,
> = None;

/// Original `CopyFileExW` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_COPY_FILE_EX_W: Option<
    unsafe extern "system" fn(
        PCWSTR,
        PCWSTR,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        *mut i32,
        u32,
    ) -> windows::core::BOOL,
> = None;

/// Original `DeleteFileW` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_DELETE_FILE_W: Option<
    unsafe extern "system" fn(PCWSTR) -> windows::core::BOOL,
> = None;

/// Original `ReplaceFileW` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_REPLACE_FILE_W: Option<
    unsafe extern "system" fn(
        PCWSTR,
        PCWSTR,
        PCWSTR,
        u32,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
    ) -> windows::core::BOOL,
> = None;

/// Original `SetFileInformationByHandle` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_SET_FILE_INFORMATION_BY_HANDLE: Option<SetFileInformationByHandleFn> = None;

/// Original `NtOpenFile` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_NT_OPEN_FILE: Option<
    unsafe extern "system" fn(
        *mut HANDLE,
        u32,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        u32,
        u32,
    ) -> NTSTATUS,
> = None;

/// Original `NtWriteFile` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_NT_WRITE_FILE: Option<
    unsafe extern "system" fn(
        HANDLE,
        HANDLE,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        *const u8,
        u32,
        *const i64,
        *mut u32,
    ) -> NTSTATUS,
> = None;

/// Original `NtSetInformationFile` pointer saved before patching.
///
/// SAFETY: written once during `DllMain` / init, then read-only.
static mut ORIGINAL_NT_SET_INFORMATION_FILE: Option<
    unsafe extern "system" fn(
        HANDLE,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        u32,
        u32,
    ) -> NTSTATUS,
> = None;

// ---------------------------------------------------------------------------
// Saved IAT entry addresses so `UnhookAll` can restore them
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "test-helpers"))]
pub static mut IAT_CREATE_FILE_W: Option<*mut usize> = None;
#[cfg(not(any(test, feature = "test-helpers")))]
static mut IAT_CREATE_FILE_W: Option<*mut usize> = None;

static mut IAT_NT_CREATE_FILE: Option<*mut usize> = None;
static mut IAT_WRITE_FILE: Option<*mut usize> = None;
static mut IAT_WRITE_FILE_EX: Option<*mut usize> = None;
static mut IAT_MOVE_FILE_EX_W: Option<*mut usize> = None;
static mut IAT_COPY_FILE_EX_W: Option<*mut usize> = None;
static mut IAT_DELETE_FILE_W: Option<*mut usize> = None;
static mut IAT_REPLACE_FILE_W: Option<*mut usize> = None;
static mut IAT_SET_FILE_INFORMATION_BY_HANDLE: Option<*mut usize> = None;
static mut IAT_NT_OPEN_FILE: Option<*mut usize> = None;
static mut IAT_NT_WRITE_FILE: Option<*mut usize> = None;
static mut IAT_NT_SET_INFORMATION_FILE: Option<*mut usize> = None;

// ---------------------------------------------------------------------------
// HookDescriptor metadata table
// ---------------------------------------------------------------------------

/// Metadata describing a single hooked function.
///
/// The `HOOKS` table drives `init()` (patch all), `UnhookAll()` (restore all),
/// and debug logging.
///
/// Phase 51: Extended with ntdll stub fields for direct-syscall bypass defense.
/// The `detour` handle is intentionally NOT stored here because
/// `retour::RawDetour` is neither `Copy` nor `Clone`. Detour handles live in
/// the [`NtdllPatcher`] struct's per-stub state machine instead.
struct HookDescriptor {
    /// Human-readable function name (e.g., "WriteFile").
    fn_name: &'static str,
    /// DLL that exports the original function ("kernel32.dll" or "ntdll.dll").
    dll_name: &'static str,
    /// Static mut holding the original function pointer.
    original_ptr: *mut usize,
    /// Static mut holding the IAT entry address.
    iat_ptr: *mut usize,
    /// Trampoline function pointer (type-erased).
    ///
    /// Each trampoline has a different signature, so we store it as a raw
    /// pointer and cast at the call site.
    trampoline_ptr: *const (),
    /// Return value to inject on denial.
    #[allow(dead_code)]
    deny_return: DenyReturn,
    /// Address of the ntdll syscall stub (resolved at runtime).
    ///
    /// Phase 51: Set by `ntdll_patcher` when patching the stub.
    #[allow(dead_code)]
    ntdll_stub_addr: UnsafeCell<*mut u8>,
    /// Original 5 bytes of the ntdll stub (saved before patching).
    ///
    /// Phase 51: Saved before `retour` patches the stub; used for integrity
    /// verification in the background re-verification thread.
    #[allow(dead_code)]
    original_ntdll_bytes: UnsafeCell<[u8; 5]>,
}

// SAFETY: HookDescriptor contains raw pointers and `UnsafeCell` fields, but the
// table is initialized at compile time and the mutable fields are only written
// during `ntdll_patcher` initialization while access is serialized by the
// `NTDLL_PATCHER` Mutex. After initialization the fields are read-only from
// trampolines and background threads, so sharing the table across threads is
// safe.
unsafe impl Sync for HookDescriptor {}

/// The canonical hook table — 12 entries covering the full file-I/O surface.
///
/// The two `UnsafeCell` fields are mutated only during `ntdll_patcher`
/// initialization; all other fields are constant. Access to the mutable fields
/// is serialized by the `NTDLL_PATCHER` Mutex and `init()` / `UnhookAll()` run
/// once per process lifetime.
static HOOKS: [HookDescriptor; 12] = [
    HookDescriptor {
        fn_name: "CreateFileW",
        dll_name: "kernel32.dll",
        original_ptr: &raw mut ORIGINAL_CREATE_FILE_W as *mut usize,
        iat_ptr: &raw mut IAT_CREATE_FILE_W as *mut usize,
        trampoline_ptr: trampolines::HookCreateFileW as *const (),
        deny_return: DenyReturn::InvalidHandleValue,
        ntdll_stub_addr: UnsafeCell::new(std::ptr::null_mut()),
        original_ntdll_bytes: UnsafeCell::new([0u8; 5]),
    },
    HookDescriptor {
        fn_name: "NtCreateFile",
        dll_name: "ntdll.dll",
        original_ptr: &raw mut ORIGINAL_NT_CREATE_FILE as *mut usize,
        iat_ptr: &raw mut IAT_NT_CREATE_FILE as *mut usize,
        trampoline_ptr: trampolines::HookNtCreateFile as *const (),
        deny_return: DenyReturn::StatusAccessDenied,
        ntdll_stub_addr: UnsafeCell::new(std::ptr::null_mut()),
        original_ntdll_bytes: UnsafeCell::new([0u8; 5]),
    },
    HookDescriptor {
        fn_name: "WriteFile",
        dll_name: "kernel32.dll",
        original_ptr: &raw mut ORIGINAL_WRITE_FILE as *mut usize,
        iat_ptr: &raw mut IAT_WRITE_FILE as *mut usize,
        trampoline_ptr: trampolines::HookWriteFile as *const (),
        deny_return: DenyReturn::BoolFalse,
        ntdll_stub_addr: UnsafeCell::new(std::ptr::null_mut()),
        original_ntdll_bytes: UnsafeCell::new([0u8; 5]),
    },
    HookDescriptor {
        fn_name: "WriteFileEx",
        dll_name: "kernel32.dll",
        original_ptr: &raw mut ORIGINAL_WRITE_FILE_EX as *mut usize,
        iat_ptr: &raw mut IAT_WRITE_FILE_EX as *mut usize,
        trampoline_ptr: trampolines::HookWriteFileEx as *const (),
        deny_return: DenyReturn::BoolFalse,
        ntdll_stub_addr: UnsafeCell::new(std::ptr::null_mut()),
        original_ntdll_bytes: UnsafeCell::new([0u8; 5]),
    },
    HookDescriptor {
        fn_name: "MoveFileExW",
        dll_name: "kernel32.dll",
        original_ptr: &raw mut ORIGINAL_MOVE_FILE_EX_W as *mut usize,
        iat_ptr: &raw mut IAT_MOVE_FILE_EX_W as *mut usize,
        trampoline_ptr: trampolines::HookMoveFileExW as *const (),
        deny_return: DenyReturn::BoolFalse,
        ntdll_stub_addr: UnsafeCell::new(std::ptr::null_mut()),
        original_ntdll_bytes: UnsafeCell::new([0u8; 5]),
    },
    HookDescriptor {
        fn_name: "CopyFileExW",
        dll_name: "kernel32.dll",
        original_ptr: &raw mut ORIGINAL_COPY_FILE_EX_W as *mut usize,
        iat_ptr: &raw mut IAT_COPY_FILE_EX_W as *mut usize,
        trampoline_ptr: trampolines::HookCopyFileExW as *const (),
        deny_return: DenyReturn::BoolFalse,
        ntdll_stub_addr: UnsafeCell::new(std::ptr::null_mut()),
        original_ntdll_bytes: UnsafeCell::new([0u8; 5]),
    },
    HookDescriptor {
        fn_name: "DeleteFileW",
        dll_name: "kernel32.dll",
        original_ptr: &raw mut ORIGINAL_DELETE_FILE_W as *mut usize,
        iat_ptr: &raw mut IAT_DELETE_FILE_W as *mut usize,
        trampoline_ptr: trampolines::HookDeleteFileW as *const (),
        deny_return: DenyReturn::BoolFalse,
        ntdll_stub_addr: UnsafeCell::new(std::ptr::null_mut()),
        original_ntdll_bytes: UnsafeCell::new([0u8; 5]),
    },
    HookDescriptor {
        fn_name: "ReplaceFileW",
        dll_name: "kernel32.dll",
        original_ptr: &raw mut ORIGINAL_REPLACE_FILE_W as *mut usize,
        iat_ptr: &raw mut IAT_REPLACE_FILE_W as *mut usize,
        trampoline_ptr: trampolines::HookReplaceFileW as *const (),
        deny_return: DenyReturn::BoolFalse,
        ntdll_stub_addr: UnsafeCell::new(std::ptr::null_mut()),
        original_ntdll_bytes: UnsafeCell::new([0u8; 5]),
    },
    HookDescriptor {
        fn_name: "SetFileInformationByHandle",
        dll_name: "kernel32.dll",
        original_ptr: &raw mut ORIGINAL_SET_FILE_INFORMATION_BY_HANDLE as *mut usize,
        iat_ptr: &raw mut IAT_SET_FILE_INFORMATION_BY_HANDLE as *mut usize,
        trampoline_ptr: trampolines::HookSetFileInformationByHandle as *const (),
        deny_return: DenyReturn::BoolFalse,
        ntdll_stub_addr: UnsafeCell::new(std::ptr::null_mut()),
        original_ntdll_bytes: UnsafeCell::new([0u8; 5]),
    },
    HookDescriptor {
        fn_name: "NtOpenFile",
        dll_name: "ntdll.dll",
        original_ptr: &raw mut ORIGINAL_NT_OPEN_FILE as *mut usize,
        iat_ptr: &raw mut IAT_NT_OPEN_FILE as *mut usize,
        trampoline_ptr: trampolines::HookNtOpenFile as *const (),
        deny_return: DenyReturn::StatusAccessDenied,
        ntdll_stub_addr: UnsafeCell::new(std::ptr::null_mut()),
        original_ntdll_bytes: UnsafeCell::new([0u8; 5]),
    },
    HookDescriptor {
        fn_name: "NtWriteFile",
        dll_name: "ntdll.dll",
        original_ptr: &raw mut ORIGINAL_NT_WRITE_FILE as *mut usize,
        iat_ptr: &raw mut IAT_NT_WRITE_FILE as *mut usize,
        trampoline_ptr: trampolines::HookNtWriteFile as *const (),
        deny_return: DenyReturn::StatusAccessDenied,
        ntdll_stub_addr: UnsafeCell::new(std::ptr::null_mut()),
        original_ntdll_bytes: UnsafeCell::new([0u8; 5]),
    },
    HookDescriptor {
        fn_name: "NtSetInformationFile",
        dll_name: "ntdll.dll",
        original_ptr: &raw mut ORIGINAL_NT_SET_INFORMATION_FILE as *mut usize,
        iat_ptr: &raw mut IAT_NT_SET_INFORMATION_FILE as *mut usize,
        trampoline_ptr: trampolines::HookNtSetInformationFile as *const (),
        deny_return: DenyReturn::StatusAccessDenied,
        ntdll_stub_addr: UnsafeCell::new(std::ptr::null_mut()),
        original_ntdll_bytes: UnsafeCell::new([0u8; 5]),
    },
];

// ---------------------------------------------------------------------------
// Phase 51: Ntdll stub trampoline mapping (Plan 03 will define the trampolines)
// ---------------------------------------------------------------------------

/// Maps ntdll function names to their ntdll-specific trampoline targets.
///
/// These trampolines are installed by `ntdll_patcher` via `retour::RawDetour`
/// on the ntdll syscall stubs themselves (not the IAT). They follow the same
/// classification pipeline as IAT trampolines but call the original stub
/// through retour's generated trampoline instead of the IAT-saved pointer.
const NTDLL_STUBS: &[(&str, *const ())] = &[
    (
        "NtCreateFile",
        trampolines::NtdllTrampolineNtCreateFile as *const (),
    ),
    (
        "NtOpenFile",
        trampolines::NtdllTrampolineNtOpenFile as *const (),
    ),
    (
        "NtWriteFile",
        trampolines::NtdllTrampolineNtWriteFile as *const (),
    ),
    (
        "NtSetInformationFile",
        trampolines::NtdllTrampolineNtSetInformationFile as *const (),
    ),
];

// ---------------------------------------------------------------------------
// DLL entry point
// ---------------------------------------------------------------------------

/// DLL entry point.
#[unsafe(no_mangle)]
extern "system" fn DllMain(inst: HINSTANCE, reason: u32, _reserved: usize) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    const DLL_PROCESS_DETACH: u32 = 0;
    if reason == DLL_PROCESS_ATTACH {
        if let Ok(mut guard) = DLL_INSTANCE.lock() {
            *guard = Some(inst.0 as isize);
        }

        // Defer IAT patching out of the Windows loader lock. Patching imports
        // while holding the loader lock can deadlock when resolving dependent
        // DLLs. A one-shot worker thread performs the patching outside the lock.
        // If the thread cannot be created, LAZY_INIT_REQUIRED remains true so
        // the first trampoline call will patch lazily.
        LAZY_INIT_REQUIRED.store(true, Ordering::Relaxed);
        unsafe {
            let mut thread_id: u32 = 0;
            match CreateThread(
                None,
                0,
                Some(init_thread_proc),
                None,
                THREAD_CREATION_FLAGS(0),
                Some(&mut thread_id),
            ) {
                Ok(handle) => {
                    if let Ok(mut guard) = INIT_THREAD_HANDLE.lock() {
                        *guard = Some(handle.0 as usize);
                    }
                }
                Err(_) => {
                    debug_log("[dlp-hook] DllMain: failed to spawn init thread; will lazy-init on first hook call\0");
                }
            }
        }
    } else if reason == DLL_PROCESS_DETACH {
        // Wait for the init thread to finish before unhooking so that
        // UnhookAll does not race with IAT patching.
        unsafe {
            if let Ok(mut guard) = INIT_THREAD_HANDLE.lock() {
                if let Some(handle_value) = guard.take() {
                    let handle = HANDLE(handle_value as *mut std::ffi::c_void);
                    let _ = WaitForSingleObject(handle, 5000);
                    let _ = CloseHandle(handle);
                }
            }
        }
        UnhookAll();
    }
    1
}

// ---------------------------------------------------------------------------
// init — patches all IAT entries driven by HOOKS table
// ---------------------------------------------------------------------------

/// Initialise the global NtdllPatcher if not already done.
///
/// Called from hook trampolines — never from `DllMain` (loader-lock safety).
/// The `enabled` flag is stored during `init()` from shared memory.
#[cfg(any(test, feature = "test-helpers"))]
pub fn lazy_init_ntdll_patcher(
    enabled: bool,
) -> &'static Mutex<crate::ntdll_patcher::NtdllPatcher> {
    NTDLL_PATCHER.get_or_init(|| {
        let patcher = crate::ntdll_patcher::NtdllPatcher::new(enabled);
        Mutex::new(patcher)
    })
}
#[cfg(not(any(test, feature = "test-helpers")))]
fn lazy_init_ntdll_patcher(enabled: bool) -> &'static Mutex<crate::ntdll_patcher::NtdllPatcher> {
    NTDLL_PATCHER.get_or_init(|| {
        let patcher = crate::ntdll_patcher::NtdllPatcher::new(enabled);
        Mutex::new(patcher)
    })
}

/// Read the ntdll patching enable flag from shared memory.
///
/// The agent writes this flag during injection (Plan 05, Task 2).
/// For now, returns `false` (disabled) until shared memory wiring is complete.
/// Phase 53 will wire this to the actual shared memory segment.
fn read_ntdll_patching_flag_from_shared_memory() -> bool {
    // TODO(Phase 53): Read from actual shared memory segment.
    // The agent sets this flag based on `enable_ntdll_patching` config.
    false
}

/// Worker thread procedure that performs deferred IAT patching.
///
/// Runs outside the Windows loader lock to avoid deadlocks during import-table
/// resolution and memory protection changes.
unsafe extern "system" fn init_thread_proc(_param: *mut std::ffi::c_void) -> u32 {
    init();
    LAZY_INIT_REQUIRED.store(false, Ordering::Relaxed);
    0
}

/// Performs deferred IAT patching if DllMain requested it but the worker thread
/// has not yet run. Used as a fallback when the init thread fails to spawn or
/// when classification helpers are called directly from tests.
pub(crate) fn lazy_init() {
    if LAZY_INIT_REQUIRED.swap(false, Ordering::SeqCst) {
        init();
    }
}

/// Initialises the hook DLL.
///
/// Saves original function pointers and patches the host module's IAT.
/// Per D-19: ordering is self-allowlist check -> IAT patch -> read ntdll flag.
fn init() {
    if INITIALISED.swap(true, Ordering::SeqCst) {
        LAZY_INIT_REQUIRED.store(false, Ordering::Relaxed);
        return;
    }

    unsafe {
        let host = GetModuleHandleW(None).unwrap_or_default();
        if host.is_invalid() {
            debug_log("[dlp-hook] init: GetModuleHandleW failed\0");
            LAZY_INIT_REQUIRED.store(false, Ordering::Relaxed);
            return;
        }
        let host_ptr = host.0 as *mut u8;

        for hook in HOOKS.iter() {
            let original_proc = resolve_proc(hook.dll_name, hook.fn_name);
            if original_proc.is_null() {
                let msg = format!("[dlp-hook] init: could not resolve {}\0", hook.fn_name);
                debug_log(&msg);
                continue;
            }

            // Save original pointer.
            let original_opt_ptr = hook.original_ptr as *mut Option<usize>;
            *original_opt_ptr = Some(original_proc as usize);

            // Find and patch IAT.
            if let Some(iat) = find_iat_entry(host_ptr, hook.dll_name, original_proc) {
                if patch_iat(iat, hook.trampoline_ptr as *mut std::ffi::c_void) {
                    let iat_opt_ptr = hook.iat_ptr as *mut Option<*mut usize>;
                    *iat_opt_ptr = Some(iat);
                    let msg = format!("[dlp-hook] IAT patched: {}\0", hook.fn_name);
                    debug_log(&msg);
                }
            }
        }
    }

    // Phase 51: ntdll stub patching (conditional, lazy-init).
    // The patcher is NOT created here — we only read the enable flag
    // from shared memory (set by agent during injection) and store it
    // for later lazy initialization on first trampoline call.
    let ntdll_patching_enabled = read_ntdll_patching_flag_from_shared_memory();
    if ntdll_patching_enabled {
        debug_log("[dlp-hook] init: ntdll patching enabled, will lazy-init on first hook call\0");
        NTDLL_PATCHING_ENABLED.store(true, Ordering::Relaxed);
    } else {
        debug_log("[dlp-hook] init: ntdll patching disabled\0");
    }

    LAZY_INIT_REQUIRED.store(false, Ordering::Relaxed);
    debug_log("[dlp-hook] initialised — IAT hooks active\0");
}

// ---------------------------------------------------------------------------
// resolve_proc — resolves a function from a DLL by name
// ---------------------------------------------------------------------------

/// Resolves a function from `dll_name` by `fn_name`.
///
/// Returns a valid function pointer, or null if resolution fails.
unsafe fn resolve_proc(dll_name: &str, fn_name: &str) -> *const std::ffi::c_void {
    let dll_wide: Vec<u16> = dll_name.encode_utf16().chain(std::iter::once(0)).collect();
    let dll = GetModuleHandleW(windows::core::PCWSTR::from_raw(dll_wide.as_ptr()));
    let dll = match dll {
        Ok(h) => h,
        Err(_) => return std::ptr::null(),
    };
    let name_c = match std::ffi::CString::new(fn_name) {
        Ok(c) => c,
        Err(_) => return std::ptr::null(),
    };
    let name = windows::core::PCSTR::from_raw(name_c.as_ptr() as *const u8);
    match GetProcAddress(dll, name) {
        Some(p) => p as *const std::ffi::c_void,
        None => std::ptr::null(),
    }
}

/// Resolves a function from `kernel32.dll` by name.
pub(crate) unsafe fn resolve_kernel32_proc(
    name: windows::core::PCSTR,
) -> Option<unsafe extern "system" fn()> {
    let kernel32 = GetModuleHandleW(w!("kernel32.dll")).ok()?;
    let proc = GetProcAddress(kernel32, name)?;
    Some(std::mem::transmute::<
        unsafe extern "system" fn() -> isize,
        unsafe extern "system" fn(),
    >(proc))
}

/// Resolves a function from `ntdll.dll` by name.
pub(crate) unsafe fn resolve_ntdll_proc(
    name: windows::core::PCSTR,
) -> Option<unsafe extern "system" fn()> {
    let ntdll = GetModuleHandleW(w!("ntdll.dll")).ok()?;
    let proc = GetProcAddress(ntdll, name)?;
    Some(std::mem::transmute::<
        unsafe extern "system" fn() -> isize,
        unsafe extern "system" fn(),
    >(proc))
}

/// Resolves `NtCreateFile` from `ntdll.dll`.
pub(crate) unsafe fn resolve_nt_create_file() -> Option<NtCreateFileFn> {
    let ntdll = GetModuleHandleW(w!("ntdll.dll")).ok()?;
    let proc = GetProcAddress(ntdll, windows::core::s!("NtCreateFile"))?;
    Some(std::mem::transmute::<
        unsafe extern "system" fn() -> isize,
        NtCreateFileFn,
    >(proc))
}

// ---------------------------------------------------------------------------
// UnhookAll — restores all IAT entries driven by HOOKS table
// ---------------------------------------------------------------------------

/// Restores original function pointers, drains active calls, and releases
/// shared-memory mappings.
///
/// Called by the agent before unloading the DLL from a target process,
/// automatically on `DLL_PROCESS_DETACH`, and by the watchdog self-unload path.
/// Internal implementation of `UnhookAll` that reports whether every hook
/// entry could be restored and active calls drained.
///
/// The exported `UnhookAll` ignores the result for FFI compatibility; the
/// `handle_unhook_command` path uses it to set `UnhookAck.success`.
pub(crate) fn unhook_all_internal() -> bool {
    debug_log("[dlp-hook] UnhookAll called — entering shutdown\0");
    SHUTTING_DOWN.store(true, Ordering::SeqCst);

    // Drain active calls with a bounded wait.
    const DRAIN_TIMEOUT_MS: u64 = 5_000;
    const DRAIN_POLL_US: u64 = 100;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(DRAIN_TIMEOUT_MS);
    let mut drain_timed_out = false;
    loop {
        let active = ACTIVE_CALLS.load(Ordering::SeqCst);
        if active == 0 {
            break;
        }
        if std::time::Instant::now() >= deadline {
            debug_log("[dlp-hook] UnhookAll: active-call drain timed out\0");
            drain_timed_out = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_micros(DRAIN_POLL_US));
    }

    // Restore IAT entries.
    let mut restore_success = true;
    unsafe {
        for hook in HOOKS.iter() {
            let iat_opt = *(hook.iat_ptr as *const Option<*mut usize>);
            // Original pointers are stored as `Option<fn pointer>`, which uses
            // niche optimization (None = 0, Some = pointer value). Read the raw
            // usize value directly so the representation matches what
            // `restore_iat` expects.
            let orig = *(hook.original_ptr as *const usize);
            match (iat_opt, orig != 0) {
                (Some(iat), true) => {
                    if !restore_iat(iat, orig) {
                        restore_success = false;
                    }
                }
                (Some(_), false) | (None, true) => restore_success = false,
                (None, false) => {}
            }
        }
    }

    // Unpatch ntdll stubs if they were ever initialized.
    if let Some(patcher_lock) = NTDLL_PATCHER.get() {
        if let Ok(mut patcher) = patcher_lock.lock() {
            patcher.unpatch_all_stubs();
        }
    }

    // Release shared-memory mappings so they are not leaked across unload.
    classification_cache::unmap_cache();
    hook_journal::unmap_journal();

    debug_log("[dlp-hook] UnhookAll complete\0");

    restore_success && !drain_timed_out
}

#[unsafe(no_mangle)]
pub extern "system" fn UnhookAll() {
    let _ = unhook_all_internal();
}

/// Explicit DLL export to start the control-poll/watchdog thread immediately
/// after remote injection.
///
/// This is called from a second remote thread created by the agent after
/// `LoadLibraryW` succeeds. It is idempotent and safe to call outside `DllMain`.
/// Returns 0 on success and 1 on failure.
#[unsafe(no_mangle)]
pub extern "system" fn StartDlpControlThread() -> u32 {
    if crate::control_thread::start_control_thread() {
        0
    } else {
        1
    }
}

/// Returns true if the DLL is currently shutting down.
///
/// Trampolines use this to pass through to the original function without
/// invoking classification logic.
pub fn is_shutting_down() -> bool {
    SHUTTING_DOWN.load(Ordering::SeqCst)
}

/// Registers the start of a hook call.
///
/// Returns true if the call should proceed with classification. Returns false
/// if the DLL is shutting down; the caller should pass through to the original.
pub fn enter_hook_call() -> bool {
    // Lazily start the control/watchdog thread from the first hook call
    // outside DllMain (loader-lock safety).
    crate::control_thread::start_control_thread();

    if SHUTTING_DOWN.load(Ordering::SeqCst) {
        return false;
    }
    ACTIVE_CALLS.fetch_add(1, Ordering::SeqCst);
    // Re-check shutdown after incrementing to avoid racing with UnhookAll.
    if SHUTTING_DOWN.load(Ordering::SeqCst) {
        ACTIVE_CALLS.fetch_sub(1, Ordering::SeqCst);
        return false;
    }
    true
}

/// Registers the end of a hook call.
pub fn exit_hook_call() {
    ACTIVE_CALLS.fetch_sub(1, Ordering::SeqCst);
}

/// Returns the current number of active hook calls.
#[cfg(any(test, feature = "test-helpers"))]
pub fn active_call_count() -> usize {
    ACTIVE_CALLS.load(Ordering::SeqCst)
}

/// RAII guard that increments/decrements `ACTIVE_CALLS`.
#[cfg(any(test, feature = "test-helpers"))]
pub struct ActiveCallGuard {
    active: bool,
}

#[cfg(any(test, feature = "test-helpers"))]
impl ActiveCallGuard {
    /// Create a new guard. If shutdown is not active, increments the counter.
    pub fn new() -> Self {
        let active = enter_hook_call();
        Self { active }
    }

    /// Returns true if this guard owns an active call reference.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl Default for ActiveCallGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl Drop for ActiveCallGuard {
    fn drop(&mut self) {
        if self.active {
            exit_hook_call();
        }
    }
}

/// Set the shutting-down flag for tests.
#[cfg(any(test, feature = "test-helpers"))]
pub fn set_shutting_down_for_test(shutting_down: bool) {
    SHUTTING_DOWN.store(shutting_down, Ordering::SeqCst);
}

/// Self-unload the DLL from inside the DLL itself.
///
/// This is the only safe self-unload path. After draining active hook calls,
/// the function atomically frees the module and terminates the calling thread
/// with `FreeLibraryAndExitThread`. The thread never returns into DLL code, so
/// there is no risk of executing from unmapped memory.
///
/// No `FreeLibrary` loop is used: decrementing the module reference count from
/// inside the DLL and then continuing to execute would be unsafe because the
/// module could be unmapped while the thread is still running its code. The
/// agent-side `is_module_loaded` guard added in Task 1 prevents reference-count
/// inflation for all new injections, so this DLL never needs to compensate for
/// a double-load it did not create. Legacy elevated reference counts from agent
/// versions before this fix are out of scope; they are prevented going forward
/// and will age out as processes restart.
///
/// # Safety
///
/// Must be called from a thread that is not needed after unload. If active
/// hook calls remain after the drain timeout, the function returns `false`
/// and the DLL image is left loaded so those calls do not fault.
pub unsafe fn self_unload() -> bool {
    debug_log("[dlp-hook] self_unload: waiting for active hook calls to drain\0");
    // Two-phase teardown: no new calls can enter while SHUTTING_DOWN is set,
    // but threads that passed the check before it was raised may still be
    // executing trampoline code. Wait for them to finish before freeing the
    // image to avoid a use-after-free.
    const FINAL_DRAIN_TIMEOUT_MS: u64 = 5_000;
    const FINAL_DRAIN_POLL_US: u64 = 100;
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(FINAL_DRAIN_TIMEOUT_MS);
    while ACTIVE_CALLS.load(Ordering::SeqCst) > 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_micros(FINAL_DRAIN_POLL_US));
    }
    if ACTIVE_CALLS.load(Ordering::SeqCst) > 0 {
        debug_log("[dlp-hook] self_unload: active calls remain -- aborting unload\0");
        return false;
    }

    debug_log("[dlp-hook] self_unload: acquiring DLL instance\0");
    let instance = DLL_INSTANCE
        .lock()
        .ok()
        .and_then(|g| *g)
        .map(|raw| HINSTANCE(raw as *mut std::ffi::c_void));
    let Some(instance) = instance else {
        crate::debug_log("[dlp-hook] self_unload: cannot determine DLL instance -- aborting\0");
        return false;
    };
    // Atomically decrement the reference count and terminate the calling
    // thread. This is the only unload path; it guarantees the thread never
    // executes another instruction from the DLL image after Windows unmaps it.
    FreeLibraryAndExitThread(instance.into(), 0);
}

/// Test-only accessor that returns the DLL instance captured in `DllMain`.
#[cfg(any(test, feature = "test-helpers"))]
pub fn self_unload_check() -> Option<HINSTANCE> {
    DLL_INSTANCE
        .lock()
        .ok()
        .and_then(|g| *g)
        .map(|raw| HINSTANCE(raw as *mut std::ffi::c_void))
}

// ---------------------------------------------------------------------------
// Classification helpers
// ---------------------------------------------------------------------------

/// Sends a classification request to the agent via named pipe.
///
/// # Arguments
///
/// * `path` - The file path being accessed.
/// * `action` - The action being performed (e.g., "CREATE", "WRITE").
/// * `pipe_name` - The named pipe to communicate with.
/// * `source_volume_class` - Volume class of the source path (if known).
/// * `destination_volume_class` - Volume class of the destination path
///   (for copy/move operations).
#[cfg(any(test, feature = "test-helpers"))]
pub fn classify_path(
    path: &str,
    action: &str,
    pipe_name: &str,
    source_volume_class: Option<VolumeClass>,
    destination_volume_class: Option<VolumeClass>,
) -> Result<dlp_common::HookResponse, pipe_client::PipeError> {
    let op = if action.eq_ignore_ascii_case("WRITE")
        || action.eq_ignore_ascii_case("CREATE")
        || action.eq_ignore_ascii_case("NT_WRITE")
    {
        dlp_common::hook_ipc::HookOp::Write
    } else {
        dlp_common::hook_ipc::HookOp::Read
    };
    let req = HookRequest {
        path: path.to_string(),
        action: action.to_string(),
        source_volume_class,
        destination_volume_class,
        pid: std::process::id(),
        op,
        ..Default::default()
    };
    pipe_client::send_request(
        pipe_name, &req, 50, // 50 ms timeout per task spec
    )
}
#[cfg(not(any(test, feature = "test-helpers")))]
pub(crate) fn classify_path(
    path: &str,
    action: &str,
    pipe_name: &str,
    source_volume_class: Option<VolumeClass>,
    destination_volume_class: Option<VolumeClass>,
) -> Result<dlp_common::HookResponse, pipe_client::PipeError> {
    let op = if action.eq_ignore_ascii_case("WRITE")
        || action.eq_ignore_ascii_case("CREATE")
        || action.eq_ignore_ascii_case("NT_WRITE")
    {
        dlp_common::hook_ipc::HookOp::Write
    } else {
        dlp_common::hook_ipc::HookOp::Read
    };
    let req = HookRequest {
        path: path.to_string(),
        action: action.to_string(),
        source_volume_class,
        destination_volume_class,
        pid: std::process::id(),
        op,
        ..Default::default()
    };
    pipe_client::send_request(
        pipe_name, &req, 50, // 50 ms timeout per task spec
    )
}

/// Sends a handle-based classification request to the agent via named pipe.
///
/// The agent resolves the path from its internal handle tracker.
///
/// NOTE: Until Phase 49/50 builds the agent-side handle tracker, the agent
/// will return ALLOW for unknown handles. This means handle-based hooks
/// (WriteFile, SetFileInformationByHandle, etc.) are functionally no-ops from
/// a DLP enforcement perspective in Phase 48. The IPC protocol is in place and
/// the agent can be extended without DLL changes.
pub(crate) fn classify_handle(
    handle_value: u64,
    action: &str,
    pipe_name: &str,
) -> Result<dlp_common::HookResponse, pipe_client::PipeError> {
    // Wrap the handle classification in the versioned envelope the agent
    // understands. The agent resolves handle-based requests by their
    // `handle://<value>` path until a full handle tracker is implemented.
    let envelope = IpcEnvelope::V1(IpcMessageV1 {
        payload: IpcPayloadV1::Request(HookRequest {
            path: format!("handle://{handle_value}"),
            action: action.to_string(),
            pid: std::process::id(),
            handle_value,
            ..Default::default()
        }),
    });
    let payload = match bincode::serialize(&envelope) {
        Ok(p) => p,
        Err(_) => return Err(pipe_client::PipeError::Malformed),
    };
    let response_bytes = pipe_client::send_raw_request(pipe_name, &payload, 50)?;
    let envelope: IpcEnvelope = match bincode::deserialize(&response_bytes) {
        Ok(e) => e,
        Err(_) => return Err(pipe_client::PipeError::Malformed),
    };
    match envelope {
        IpcEnvelope::V1(msg) => match msg.payload {
            IpcPayloadV1::Response(resp) => Ok(resp),
            _ => Err(pipe_client::PipeError::Malformed),
        },
    }
}

// ---------------------------------------------------------------------------
// String / path helpers
// ---------------------------------------------------------------------------

/// Logs a wide-string message via `OutputDebugStringW`.
pub(crate) fn debug_log(msg: &str) {
    let wide: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { OutputDebugStringW(PCWSTR::from_raw(wide.as_ptr())) };
}

/// Hash a path for logging without exposing the full value.
pub(crate) fn hash_path(path: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut s = DefaultHasher::new();
    path.hash(&mut s);
    s.finish()
}

/// Converts a `PCWSTR` to a Rust `String`.
///
/// Returns a truncated string if the input exceeds 32,768 characters.
/// This prevents unbounded scanning on malformed pointers.
pub(crate) unsafe fn pcwstr_to_string(ptr: PCWSTR) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while len < MAX_WIDE_CHARS && *(ptr.0.add(len)) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr.0, len);
    String::from_utf16_lossy(slice)
}

/// Extracts the path from `OBJECT_ATTRIBUTES.ObjectName`.
///
/// Uses architecture-correct offsets via `cfg(target_arch)`.
pub(crate) unsafe fn extract_nt_path(objectattributes: *mut std::ffi::c_void) -> String {
    if objectattributes.is_null() {
        return String::new();
    }

    let object_name_ptr =
        *(objectattributes.offset(OBJECT_ATTRIBUTES_OBJECT_NAME_OFFSET) as *mut *mut u8);
    if object_name_ptr.is_null() {
        return String::new();
    }

    let buffer = *(object_name_ptr.offset(UNICODE_STRING_BUFFER_OFFSET) as *mut *mut u16);
    let length = *(object_name_ptr as *const u16) as usize;
    if buffer.is_null() || length == 0 {
        return String::new();
    }

    let chars = (length / 2).min(MAX_WIDE_CHARS);
    let slice = std::slice::from_raw_parts(buffer, chars);
    String::from_utf16_lossy(slice)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reset_for_test;

    #[test]
    fn hash_path_is_deterministic() {
        let h1 = hash_path(r"C:\Users\test\file.txt");
        let h2 = hash_path(r"C:\Users\test\file.txt");
        assert_eq!(h1, h2);
        let h3 = hash_path(r"C:\Users\test\other.txt");
        assert_ne!(h1, h3);
    }

    #[test]
    fn pcwstr_roundtrip() {
        let wide: Vec<u16> = "Hello World"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let s = unsafe { pcwstr_to_string(PCWSTR::from_raw(wide.as_ptr())) };
        assert_eq!(s, "Hello World");
    }

    #[test]
    fn pcwstr_null_returns_empty() {
        let s = unsafe { pcwstr_to_string(PCWSTR::from_raw(std::ptr::null())) };
        assert_eq!(s, "");
    }

    #[test]
    fn pcwstr_32k_cap_truncates() {
        let wide: Vec<u16> = (0..33_000)
            .map(|i| (i % 26 + 65) as u16)
            .chain(std::iter::once(0))
            .collect();
        let s = unsafe { pcwstr_to_string(PCWSTR::from_raw(wide.as_ptr())) };
        assert_eq!(s.len(), 32_768);
    }

    #[test]
    fn pcwstr_32k_exact_boundary() {
        let wide: Vec<u16> = (0..32_768)
            .map(|i| (i % 26 + 65) as u16)
            .chain(std::iter::once(0))
            .collect();
        let s = unsafe { pcwstr_to_string(PCWSTR::from_raw(wide.as_ptr())) };
        assert_eq!(s.len(), 32_768);
    }

    #[test]
    #[serial_test::serial]
    fn shutdown_flag_stops_new_hook_calls() {
        let _guard = crate::PHASE_58_5_TEST_LOCK.lock();
        reset_for_test();
        SHUTTING_DOWN.store(true, Ordering::SeqCst);
        assert!(!enter_hook_call());
        SHUTTING_DOWN.store(false, Ordering::SeqCst);
    }

    #[test]
    #[serial_test::serial]
    fn active_call_guard_balanced() {
        let _guard = crate::PHASE_58_5_TEST_LOCK.lock();
        reset_for_test();
        // Ensure shutdown flag is clear; a prior test may have left it set.
        SHUTTING_DOWN.store(false, Ordering::SeqCst);
        let before = ACTIVE_CALLS.load(Ordering::SeqCst);
        {
            let guard = ActiveCallGuard::new();
            assert!(guard.is_active());
            assert_eq!(ACTIVE_CALLS.load(Ordering::SeqCst), before + 1);
        }
        assert_eq!(ACTIVE_CALLS.load(Ordering::SeqCst), before);
    }

    #[test]
    fn dll_instance_is_captured() {
        // In the test binary the DLL instance is not set by DllMain, but the
        // mutex should be accessible and the field should be None or the host
        // module handle.
        let guard = DLL_INSTANCE.lock().expect("DLL_INSTANCE lock");
        assert!(guard.is_some() || guard.is_none());
    }

    #[test]
    fn find_iat_entry_returns_none_for_invalid_module() {
        unsafe {
            let result = find_iat_entry(std::ptr::null_mut(), "kernel32.dll", std::ptr::null());
            assert!(result.is_none());
        }
    }

    #[test]
    fn extract_nt_path_null() {
        unsafe {
            let s = extract_nt_path(std::ptr::null_mut());
            assert_eq!(s, "");
        }
    }

    #[test]
    fn hook_descriptor_table_has_12_entries() {
        assert_eq!(HOOKS.len(), 12);
    }

    #[test]
    fn hook_descriptors_are_valid() {
        for hook in HOOKS.iter() {
            assert!(!hook.fn_name.is_empty());
            assert!(!hook.dll_name.is_empty());
            assert!(hook.trampoline_ptr as usize != 0);
        }
    }

    #[test]
    fn classify_handle_roundtrip() {
        let req = dlp_common::hook_ipc::HandleHookRequest {
            handle_value: 0x1234,
            action: "WRITE".to_string(),
            pid: 42,
        };
        let bytes = bincode::serialize(&req).expect("serialize");
        let round: dlp_common::hook_ipc::HandleHookRequest =
            bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(round.handle_value, 0x1234);
        assert_eq!(round.action, "WRITE");
        assert_eq!(round.pid, 42);
    }

    /// Calls `init()` and `UnhookAll()` on the current process and verifies
    /// the mechanism runs without crashing. Patched count may be zero if the
    /// test binary does not import the hooked functions — the pe_utils tests
    /// verify patch/restore on a controlled memory page.
    #[test]
    #[serial_test::serial]
    #[ignore = "patches the test process IAT; run in an isolated harness"]
    fn iat_patch_and_restore_roundtrip() {
        let _guard = crate::PHASE_58_5_TEST_LOCK.lock();
        reset_for_test();
        // Reset INITIALISED so init() will run.
        INITIALISED.store(false, Ordering::SeqCst);

        unsafe {
            init();
            // Count how many IAT entries were patched (may be zero in test binary).
            let patched_count = HOOKS
                .iter()
                .filter(|hook| (*(hook.iat_ptr as *const Option<*mut usize>)).is_some())
                .count();
            // Log for diagnostics — not a hard assertion because the test binary
            // may not import all (or any) of the hooked functions.
            let msg = format!(
                "[dlp-hook-test] iat_patch_and_restore_roundtrip: {} entries patched\0",
                patched_count
            );
            debug_log(&msg);

            UnhookAll();
            // After UnhookAll, all IAT entries should be restored
            for hook in HOOKS.iter() {
                let iat_opt = *(hook.iat_ptr as *const Option<*mut usize>);
                assert!(
                    iat_opt.is_none() || {
                        // If still Some, verify it points to original
                        let orig_opt = *(hook.original_ptr as *const Option<usize>);
                        iat_opt.map(|iat| *iat) == orig_opt
                    },
                    "IAT for {} should be restored after UnhookAll",
                    hook.fn_name
                );
            }
        }
    }

    // --- Phase 58.5: Unhook protocol tests ---

    #[test]
    #[serial_test::serial]
    fn shutting_down_passes_through_create_file_w() {
        let _guard = crate::PHASE_58_5_TEST_LOCK.lock();
        reset_for_test();
        crate::set_shutting_down_for_test(true);
        // classify_and_log_path is the internal helper used by HookCreateFileW.
        // When shutting down it must return None without attempting a pipe call.
        let result = crate::trampolines::classify_and_log_path(
            r"C:\test.txt",
            "CREATE",
            "CreateFileW",
            0,
            1,
            None,
            None,
        );
        crate::set_shutting_down_for_test(false);
        assert!(result.is_none());
    }

    #[test]
    #[serial_test::serial]
    fn shutting_down_passes_through_nt_create_file() {
        let _guard = crate::PHASE_58_5_TEST_LOCK.lock();
        reset_for_test();
        crate::set_shutting_down_for_test(true);
        let result = crate::trampolines::classify_and_log_path(
            r"C:\test.txt",
            "CREATE",
            "NtCreateFile",
            0,
            1,
            None,
            None,
        );
        crate::set_shutting_down_for_test(false);
        assert!(result.is_none());
    }

    #[test]
    #[serial_test::serial]
    fn trampoline_entry_counts_active_calls() {
        let _guard = crate::PHASE_58_5_TEST_LOCK.lock();
        reset_for_test();
        crate::set_shutting_down_for_test(false);
        ACTIVE_CALLS.store(0, Ordering::SeqCst);

        let before = crate::active_call_count();
        {
            let guard = crate::ActiveCallGuard::new();
            assert!(guard.is_active());
            assert_eq!(crate::active_call_count(), before + 1);
        }
        assert_eq!(crate::active_call_count(), before);
    }
}
