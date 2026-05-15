//! Deterministic fail-closed return values for the hook DLL.
//!
//! When the ABAC engine denies an operation, the trampoline must inject a
//! return value that makes the caller believe the OS denied the request.
//! This module provides the [`DenyReturn`] enum and the [`fail_closed!`]
//! macro that generate the correct return value for each Windows API family.

use windows::Win32::Foundation::{
    SetLastError, ERROR_ACCESS_DENIED, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS,
};
use windows::core::BOOL;

// ---------------------------------------------------------------------------
// DenyReturn enum
// ---------------------------------------------------------------------------

/// Determines the return value injected when a hooked operation is denied.
///
/// Each variant maps to a specific Windows API return-value family so that
/// the caller receives a plausible OS-level denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReturn {
    /// Return `BOOL(0)` and set `LastError` to `ERROR_ACCESS_DENIED`.
    BoolFalse,
    /// Return `INVALID_HANDLE_VALUE` and set `LastError` to `ERROR_ACCESS_DENIED`.
    InvalidHandleValue,
    /// Return `NTSTATUS(0xC0000022)` (`STATUS_ACCESS_DENIED`).
    StatusAccessDenied,
}

// ---------------------------------------------------------------------------
// fail_closed! macro
// ---------------------------------------------------------------------------

/// Generates the correct fail-closed return value for a hooked API.
///
/// # Variants
///
/// * `fail_closed!(BoolFalse)` — returns `BOOL(0)` and sets `LastError`.
/// * `fail_closed!(InvalidHandleValue)` — returns `INVALID_HANDLE_VALUE` and
///   sets `LastError`.
/// * `fail_closed!(StatusAccessDenied)` — returns `NTSTATUS(STATUS_ACCESS_DENIED)`.
///
/// # Examples
///
/// ```
/// use dlp_hook_dll::fail_closed;
/// use windows::Win32::Foundation::BOOL;
///
/// let result: BOOL = fail_closed!(BoolFalse);
/// assert_eq!(result.0, 0);
/// ```
#[macro_export]
macro_rules! fail_closed {
    (BoolFalse) => {{
        unsafe { SetLastError(ERROR_ACCESS_DENIED) };
        BOOL(0)
    }};
    (InvalidHandleValue) => {{
        unsafe { SetLastError(ERROR_ACCESS_DENIED) };
        INVALID_HANDLE_VALUE
    }};
    (StatusAccessDenied) => {
        NTSTATUS(0xC0000022u32 as i32)
    };
}

// ---------------------------------------------------------------------------
// DenyReturnValue — type-erased return for runtime dispatch
// ---------------------------------------------------------------------------

/// Type-erased return value from a deny decision.
///
/// This is used when the [`DenyReturn`] variant is chosen at runtime (e.g.
/// from a [`HookDescriptor`] table) rather than known at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReturnValue {
    /// Boolean false return.
    Bool(BOOL),
    /// Invalid handle return.
    Handle(HANDLE),
    /// NTSTATUS access-denied return.
    NtStatus(NTSTATUS),
}

/// Applies the deny return value.
///
/// This is a convenience wrapper for trampolines that receive a
/// [`DenyReturn`] at runtime (e.g. from a `HookDescriptor` table).
/// Individual trampolines should use the [`fail_closed!`] macro directly
/// for zero overhead when the variant is known at compile time.
///
/// # Arguments
///
/// * `deny` — The deny variant to apply.
///
/// # Returns
///
/// A [`DenyReturnValue`] containing the concrete Windows API return value.
pub fn apply_deny_return(deny: DenyReturn) -> DenyReturnValue {
    match deny {
        DenyReturn::BoolFalse => DenyReturnValue::Bool(BOOL(0)),
        DenyReturn::InvalidHandleValue => DenyReturnValue::Handle(INVALID_HANDLE_VALUE),
        DenyReturn::StatusAccessDenied => {
            DenyReturnValue::NtStatus(NTSTATUS(0xC0000022u32 as i32))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::GetLastError;

    #[test]
    fn fail_closed_bool_false_returns_zero() {
        let result: BOOL = fail_closed!(BoolFalse);
        assert_eq!(result.0, 0);
    }

    #[test]
    fn fail_closed_bool_false_sets_last_error() {
        // Set a different error first to ensure we're not seeing stale state.
        unsafe { SetLastError(windows::Win32::Foundation::ERROR_FILE_NOT_FOUND) };
        let _result: BOOL = fail_closed!(BoolFalse);
        let last = unsafe { GetLastError() };
        assert_eq!(last, ERROR_ACCESS_DENIED);
    }

    #[test]
    fn fail_closed_invalid_handle_value() {
        let result: HANDLE = fail_closed!(InvalidHandleValue);
        assert!(result.is_invalid());
    }

    #[test]
    fn fail_closed_invalid_handle_sets_last_error() {
        unsafe { SetLastError(windows::Win32::Foundation::ERROR_FILE_NOT_FOUND) };
        let _result: HANDLE = fail_closed!(InvalidHandleValue);
        let last = unsafe { GetLastError() };
        assert_eq!(last, ERROR_ACCESS_DENIED);
    }

    #[test]
    fn fail_closed_status_access_denied() {
        let result: NTSTATUS = fail_closed!(StatusAccessDenied);
        assert_eq!(result.0, 0xC0000022u32 as i32);
    }

    #[test]
    fn deny_return_round_trip_clone_copy() {
        let d = DenyReturn::BoolFalse;
        let d2 = d;
        assert_eq!(d, d2);

        let d = DenyReturn::InvalidHandleValue;
        let d2 = d;
        assert_eq!(d, d2);

        let d = DenyReturn::StatusAccessDenied;
        let d2 = d;
        assert_eq!(d, d2);
    }

    #[test]
    fn deny_return_value_bool() {
        let v = DenyReturnValue::Bool(BOOL(0));
        assert_eq!(v, DenyReturnValue::Bool(BOOL(0)));
    }

    #[test]
    fn deny_return_value_handle() {
        let v = DenyReturnValue::Handle(INVALID_HANDLE_VALUE);
        assert!(matches!(v, DenyReturnValue::Handle(h) if h.is_invalid()));
    }

    #[test]
    fn deny_return_value_ntstatus() {
        let v = DenyReturnValue::NtStatus(NTSTATUS(0xC0000022u32 as i32));
        assert!(matches!(v, DenyReturnValue::NtStatus(n) if n.0 == 0xC0000022u32 as i32));
    }

    #[test]
    fn apply_deny_return_bool_false() {
        let v = apply_deny_return(DenyReturn::BoolFalse);
        assert!(matches!(v, DenyReturnValue::Bool(b) if b.0 == 0));
    }

    #[test]
    fn apply_deny_return_invalid_handle() {
        let v = apply_deny_return(DenyReturn::InvalidHandleValue);
        assert!(matches!(v, DenyReturnValue::Handle(h) if h.is_invalid()));
    }

    #[test]
    fn apply_deny_return_status_access_denied() {
        let v = apply_deny_return(DenyReturn::StatusAccessDenied);
        assert!(
            matches!(v, DenyReturnValue::NtStatus(n) if n.0 == 0xC0000022u32 as i32)
        );
    }
}
