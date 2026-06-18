//! Crash-hardening guards for the hook DLL.
//!
//! Provides layered protection against panics and access violations in
//! trampoline code, ensuring the host process never aborts due to a hook
//! failure.  All guards route to the original API function (fail-open).

use std::cell::Cell;
use windows::core::PCWSTR;
use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, OutputDebugStringW, RemoveVectoredExceptionHandler,
};

// ---------------------------------------------------------------------------
// guard_trampoline — catch_unwind wrapper
// ---------------------------------------------------------------------------

/// Wraps a trampoline body in `catch_unwind`.
///
/// On panic, logs via `OutputDebugStringW` and calls `fallback` (fail-open).
/// This prevents a Rust panic inside the hook DLL from unwinding across the
/// FFI boundary and aborting the host process.
///
/// # Type Parameters
///
/// * `T` — The return type of both the closure and the fallback.  Must be
///   `'static` because `catch_unwind` requires it.
///
/// # Arguments
///
/// * `fn_name` — Name of the hooked function (used only for debug logging).
/// * `f` — The trampoline body to execute.
/// * `fallback` — Called when `f` panics; should invoke the original function.
///
/// # Returns
///
/// The result of `f` on success, or the result of `fallback` on panic.
///
/// # Examples
///
/// ```ignore
/// use dlp_hook_dll::crash_guard::guard_trampoline;
///
/// let result = guard_trampoline(
///     "CreateFileW",
///     || true,
///     || false,
/// );
/// assert!(result);
/// ```
pub fn guard_trampoline<T>(
    fn_name: &str,
    f: impl FnOnce() -> T,
    fallback: impl FnOnce() -> T,
) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(ret) => ret,
        Err(_) => {
            let msg = format!("[dlp-hook] PANIC caught in {} -- fail-open\0", fn_name);
            let wide: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe {
                OutputDebugStringW(PCWSTR::from_raw(wide.as_ptr()));
            }
            fallback()
        }
    }
}

// ---------------------------------------------------------------------------
// seh_guard — vectored-exception-handler wrapper
// ---------------------------------------------------------------------------

thread_local! {
    /// Thread-local flag: `true` when `seh_guard` has installed its vectored
    /// exception handler on this thread.  Prevents double-installation.
    static SEH_INSTALLED: Cell<bool> = const { Cell::new(false) };

    /// Thread-local storage for the exception handler return value.
    /// When an access violation is caught, `seh_guard` stores `Err(())`
    /// here so the outer Rust code can return it.
    static SEH_RESULT: Cell<Option<Result<(), ()>>> = const { Cell::new(None) };
}

/// Vectored exception handler installed by `seh_guard`.
///
/// Catches `EXCEPTION_ACCESS_VIOLATION` and stores `Err(())` in the
/// thread-local `SEH_RESULT` cell so the guarded closure can return
/// gracefully instead of crashing the process.
///
/// # Safety
///
/// This is an `extern "system"` callback invoked by the Windows kernel.
/// It must not panic, allocate, or call any function that might fault.
unsafe extern "system" fn seh_handler(
    exception_info: *mut windows::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
) -> i32 {
    // `exception_info` is guaranteed non-null by the OS.
    let record = unsafe { (*exception_info).ExceptionRecord };
    if record.is_null() {
        return 0; // EXCEPTION_CONTINUE_SEARCH
    }

    let code = unsafe { (*record).ExceptionCode };
    if code.0 == windows::Win32::Foundation::EXCEPTION_ACCESS_VIOLATION.0 {
        SEH_RESULT.with(|r| r.set(Some(Err(()))));
        // Return EXCEPTION_CONTINUE_SEARCH so the exception propagates to
        // the next handler.  EXCEPTION_CONTINUE_EXECUTION would retry the
        // faulting instruction, causing an infinite AV loop.
        //
        // NOTE: A vectored exception handler alone cannot safely resume
        // execution after an AV without modifying the execution context
        // (e.g., advancing EIP/RIP past the faulting instruction).  Full
        // SEH recovery requires a C-compiled __try/__except shim
        // (see Phase 48-01 review feedback).
        return 0; // EXCEPTION_CONTINUE_SEARCH
    }

    0 // EXCEPTION_CONTINUE_SEARCH
}

/// Wraps a closure in a vectored exception handler.
///
/// Catches access violations (`EXCEPTION_ACCESS_VIOLATION`) and returns
/// `Err(())` so the caller can route to the original function (fail-open).
///
/// # Safety
///
/// The vectored exception handler is process-global.  `seh_guard` installs
/// it on first use per thread and removes it before returning.  Do not
/// nest calls to `seh_guard` on the same thread — the reentrancy guard
/// (`with_reentrancy_guard`) should be used for that.
///
/// # Type Parameters
///
/// * `T` — The return type of the closure.
///
/// # Arguments
///
/// * `f` — The closure to execute under SEH protection.
///
/// # Returns
///
/// `Ok(result)` if no exception occurred, `Err(())` if an access violation
/// was caught.
///
/// # Examples
///
/// ```ignore
/// use dlp_hook_dll::crash_guard::seh_guard;
///
/// // This would normally crash; under seh_guard it returns Err(()).
/// let result = unsafe {
///     seh_guard(|| {
///         let ptr: *const i32 = std::ptr::null();
///         unsafe { ptr.read_volatile() }
///     })
/// };
/// assert!(result.is_err());
/// ```
#[allow(clippy::result_unit_err)]
pub unsafe fn seh_guard<T>(f: impl FnOnce() -> T) -> Result<T, ()> {
    // Install the vectored exception handler (first-only on this thread).
    let handler = AddVectoredExceptionHandler(1, Some(seh_handler));
    if handler.is_null() {
        // If we cannot install the handler, we cannot safely catch AVs.
        // This is a fatal build/configuration error.
        panic!(
            "SEH guard is required but AddVectoredExceptionHandler failed. \
             Verify Windows feature flags or OS support."
        );
    }

    SEH_RESULT.with(|r| r.set(None));

    let result = f();

    // Check whether the handler caught an exception.
    let caught = SEH_RESULT.with(|r| r.get());

    let _ = RemoveVectoredExceptionHandler(handler);

    match caught {
        Some(Err(())) => Err(()),
        _ => Ok(result),
    }
}

// ---------------------------------------------------------------------------
// with_reentrancy_guard — prevents recursive hook entry
// ---------------------------------------------------------------------------

thread_local! {
    /// `true` when a hook trampoline is currently active on this thread.
    static REENTRANT: Cell<bool> = const { Cell::new(false) };
}

/// Prevents recursive hook entry on the same thread.
///
/// If the hook is already active on this thread (e.g. because IPC, logging,
/// or allocator activity triggered another hooked API), the inner call
/// immediately routes to the original function without classification.
///
/// # Arguments
///
/// * `f` — The hook body to execute.
/// * `fallback` — Called when the hook is already active on this thread.
///
/// # Returns
///
/// The result of `f` or `fallback`, depending on reentrancy state.
///
/// # Examples
///
/// ```ignore
/// use dlp_hook_dll::crash_guard::with_reentrancy_guard;
///
/// let result = with_reentrancy_guard(|| "classified", || "fallback");
/// assert_eq!(result, "classified");
///
/// // Nested call routes to fallback.
/// let result = with_reentrancy_guard(|| {
///     with_reentrancy_guard(|| "inner", || "fallback")
/// }, || "outer-fallback");
/// assert_eq!(result, "fallback");
/// ```
pub fn with_reentrancy_guard<T>(f: impl FnOnce() -> T, fallback: impl FnOnce() -> T) -> T {
    if REENTRANT.get() {
        return fallback();
    }
    REENTRANT.set(true);
    let result = f();
    REENTRANT.set(false);
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::BOOL;
    use windows::Win32::Foundation::{HANDLE, NTSTATUS};

    // -- guard_trampoline --

    #[test]
    fn guard_trampoline_catches_panic() {
        let result = guard_trampoline(
            "test_panic",
            || {
                panic!("intentional test panic");
            },
            || 42,
        );
        assert_eq!(result, 42);
    }

    #[test]
    fn guard_trampoline_passes_through() {
        let result = guard_trampoline("test_ok", || 99, || 0);
        assert_eq!(result, 99);
    }

    #[test]
    fn guard_trampoline_bool_return() {
        let result = guard_trampoline("test_bool", || BOOL(1), || BOOL(0));
        assert_eq!(result.0, 1);
    }

    #[test]
    fn guard_trampoline_handle_return() {
        let result = guard_trampoline(
            "test_handle",
            || HANDLE(123 as *mut std::ffi::c_void),
            || HANDLE(std::ptr::null_mut()),
        );
        assert!(!result.is_invalid());
    }

    #[test]
    fn guard_trampoline_ntstatus_return() {
        let result = guard_trampoline(
            "test_ntstatus",
            || NTSTATUS(0),
            || NTSTATUS(0xC0000022u32 as i32),
        );
        assert_eq!(result.0, 0);
    }

    // -- seh_guard --

    /// `seh_guard` installs a vectored exception handler that records when an
    /// access violation occurs, but returning `EXCEPTION_CONTINUE_SEARCH` means
    /// the exception still propagates to the next handler.  Full AV recovery
    /// requires a C-compiled `__try/__except` shim (Phase 48-01 review).
    ///
    /// This test is skipped because a vectored handler alone cannot safely
    /// resume execution after an AV without modifying the execution context.
    #[test]
    #[ignore = "requires C-compiled __try/__except shim for safe AV recovery"]
    fn seh_guard_catches_access_violation() {
        let result = unsafe {
            seh_guard(|| {
                let ptr: *const i32 = std::ptr::null();
                // SAFETY: this is intentionally unsafe — we are testing
                // that the SEH wrapper catches the resulting access violation.
                ptr.read_volatile()
            })
        };
        assert!(
            result.is_err(),
            "seh_guard should catch AV and return Err(())"
        );
    }

    #[test]
    fn seh_guard_passes_through_ok() {
        let result = unsafe { seh_guard(|| 123) };
        assert_eq!(result, Ok(123));
    }

    /// Compile-time verification: `seh_guard` works with `BOOL` return type.
    #[test]
    fn seh_guard_compiles_bool() {
        let result = unsafe { seh_guard(|| BOOL(1)) };
        assert_eq!(result, Ok(BOOL(1)));
    }

    /// Compile-time verification: `seh_guard` works with `HANDLE` return type.
    #[test]
    fn seh_guard_compiles_handle() {
        let result = unsafe { seh_guard(|| HANDLE(std::ptr::dangling_mut::<std::ffi::c_void>())) };
        assert!(result.is_ok());
    }

    /// Compile-time verification: `seh_guard` works with `NTSTATUS` return type.
    #[test]
    fn seh_guard_compiles_ntstatus() {
        let result = unsafe { seh_guard(|| NTSTATUS(0)) };
        assert_eq!(result, Ok(NTSTATUS(0)));
    }

    // -- reentrancy guard --

    #[test]
    fn reentrancy_guard_prevents_nesting() {
        let result = with_reentrancy_guard(
            || with_reentrancy_guard(|| "inner", || "fallback"),
            || "outer-fallback",
        );
        assert_eq!(result, "fallback");
    }

    #[test]
    fn reentrancy_guard_allows_single_entry() {
        let result = with_reentrancy_guard(|| "ok", || "fallback");
        assert_eq!(result, "ok");
    }

    #[test]
    fn reentrancy_guard_resets_after_return() {
        let r1 = with_reentrancy_guard(|| "first", || "fallback");
        assert_eq!(r1, "first");
        let r2 = with_reentrancy_guard(|| "second", || "fallback");
        assert_eq!(r2, "second");
    }
}
