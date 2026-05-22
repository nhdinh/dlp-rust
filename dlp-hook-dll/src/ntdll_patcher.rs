#![allow(dead_code)]
#![allow(clippy::enum_variant_names)]

//! Ntdll syscall-stub patcher with retour integration and EDR coexistence.
//!
//! This module implements the core of Phase 51: in-memory Detours-style
//! 5-byte JMP trampolines on ntdll syscall stubs to close the direct-syscall
//! bypass hole. It builds on Plan 01's EDR detection and thread safety modules.
//!
//! ## Architecture
//!
//! - [`NtdllPatcher`] holds per-stub state for the 4 ntdll functions we patch.
//! - [`StubPatchState`] tracks whether each stub is unpatched, patched, skipped
//!   due to EDR, skipped due to a race, or overwritten.
//! - EDR detection is consulted before every patch attempt (D-04).
//! - Thread suspension is used during the atomic patch (D-08).
//! - No disk-reading functions exist (D-06 compliance).

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Per-stub patch state machine.
///
/// Each of the 4 ntdll stubs has independent state per D-13 (per-stub
/// granularity). One stub can be clean while another is overwritten by EDR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StubPatchState {
    /// Stub has not been patched yet.
    Unpatched,
    /// Stub is currently patched with an active retour detour.
    Patched,
    /// Stub was skipped because EDR was detected on it.
    SkippedEdr,
    /// Stub was skipped because a thread's RIP was in the stub range.
    SkippedRaced,
    /// Our trampoline was overwritten (by EDR or another hook).
    Overwritten,
}

/// The four ntdll functions we patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StubName {
    /// `NtCreateFile` syscall stub.
    NtCreateFile,
    /// `NtOpenFile` syscall stub.
    NtOpenFile,
    /// `NtWriteFile` syscall stub.
    NtWriteFile,
    /// `NtSetInformationFile` syscall stub.
    NtSetInformationFile,
}

impl StubName {
    /// Returns the function name as a static string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            StubName::NtCreateFile => "NtCreateFile",
            StubName::NtOpenFile => "NtOpenFile",
            StubName::NtWriteFile => "NtWriteFile",
            StubName::NtSetInformationFile => "NtSetInformationFile",
        }
    }

    /// Returns the index into the `stubs` array.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            StubName::NtCreateFile => 0,
            StubName::NtOpenFile => 1,
            StubName::NtWriteFile => 2,
            StubName::NtSetInformationFile => 3,
        }
    }
}

/// Errors that can occur during stub patching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchError {
    /// The stub address could not be resolved.
    ResolveFailed,
    /// EDR was detected on the stub.
    EdrDetected,
    /// A thread's RIP was inside the stub range.
    RipInStubRange,
    /// retour failed to create or enable the detour.
    DetourFailed,
}

impl std::fmt::Display for PatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatchError::ResolveFailed => write!(f, "could not resolve stub address"),
            PatchError::EdrDetected => write!(f, "EDR detected on stub"),
            PatchError::RipInStubRange => {
                write!(f, "thread RIP is inside stub range")
            }
            PatchError::DetourFailed => write!(f, "retour detour failed"),
        }
    }
}

impl std::error::Error for PatchError {}

pub use dlp_common::hook_ipc::BypassReason;

/// Result of verifying a patched ntdll stub's integrity.
///
/// Per D-13: re-verification is per-stub, not all-or-nothing. One stub can be
/// clean while another is overwritten by EDR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StubIntegrity {
    /// First 5 bytes match our JMP pattern (0xE9 targeting our trampoline).
    Clean,
    /// Bytes do not match our JMP pattern — EDR or another hook overwrote us.
    Overwritten,
    /// Stub was never patched (Unpatched, SkippedEdr, or SkippedRaced state).
    NotPatched,
    /// Could not read stub bytes (null pointer or access denied).
    Unknown,
}

// ---------------------------------------------------------------------------
// NtdllPatcher
// ---------------------------------------------------------------------------

/// Core ntdll patcher with per-stub state, EDR detection, and thread-suspend
/// safety.
///
/// The patcher is designed to be instantiated once per process and lives for
/// the lifetime of the hook DLL. It is NOT created from `DllMain` (loader-lock
/// safety per D-08 pitfall) — instead it is lazily initialized on the first
/// hook call or from a background thread.
pub struct NtdllPatcher {
    /// Per-stub patch state for the 4 ntdll functions.
    stubs: [StubPatchState; 4],
    /// EDR detector instance.
    edr_detector: crate::edr_detector::EdrDetector,
    /// Whether ntdll patching is enabled (from agent config).
    enabled: bool,
}

impl NtdllPatcher {
    /// Creates a new ntdll patcher.
    ///
    /// # Arguments
    ///
    /// * `enabled` — Whether ntdll patching is enabled. If `false`,
    ///   `patch_all_stubs()` is a no-op.
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self {
            stubs: [
                StubPatchState::Unpatched,
                StubPatchState::Unpatched,
                StubPatchState::Unpatched,
                StubPatchState::Unpatched,
            ],
            edr_detector: crate::edr_detector::EdrDetector::new(),
            enabled,
        }
    }

    /// Returns whether patching is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the current state of a stub.
    #[must_use]
    pub fn stub_state(&self, name: StubName) -> &StubPatchState {
        &self.stubs[name.index()]
    }

    /// Patches all 4 ntdll stubs.
    ///
    /// If `!self.enabled`, returns immediately without doing anything.
    ///
    /// For each stub:
    /// 1. Resolve the stub address via `GetProcAddress(ntdll, fn_name)`.
    /// 2. If resolution fails, log and continue (per-stub granularity per D-13).
    /// 3. Check EDR detection — if EDR is present, skip and emit alert.
    /// 4. Call `patch_stub()` under thread suspension.
    pub fn patch_all_stubs(&mut self) {
        if !self.enabled {
            crate::debug_log("[dlp-hook] ntdll patching disabled\0");
            return;
        }

        crate::debug_log("[dlp-hook] patching ntdll stubs...\0");

        for name in [
            StubName::NtCreateFile,
            StubName::NtOpenFile,
            StubName::NtWriteFile,
            StubName::NtSetInformationFile,
        ] {
            let fn_name = name.as_str();

            // Resolve stub address.
            let stub_addr = unsafe {
                let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleW(
                    windows::core::w!("ntdll.dll"),
                );
                let ntdll = match ntdll {
                    Ok(h) => h,
                    Err(_) => {
                        let msg = format!(
                            "[dlp-hook] ntdll patch: could not load ntdll.dll for {}\0",
                            fn_name
                        );
                        crate::debug_log(&msg);
                        continue;
                    }
                };
                let name_pcstr = windows::core::PCSTR::from_raw(fn_name.as_ptr());
                match windows::Win32::System::LibraryLoader::GetProcAddress(ntdll, name_pcstr) {
                    Some(p) => p as *mut u8,
                    None => {
                        let msg =
                            format!("[dlp-hook] ntdll patch: could not resolve {}\0", fn_name);
                        crate::debug_log(&msg);
                        continue;
                    }
                }
            };

            // Check EDR detection before patching.
            let edr_detected = unsafe { self.edr_detector.is_edr_hooked(stub_addr) };
            if edr_detected {
                let msg = format!("[dlp-hook] EDR detected on {}, skipping\0", fn_name);
                crate::debug_log(&msg);
                self.stubs[name.index()] = StubPatchState::SkippedEdr;
                emit_bypass_alert(BypassReason::EdrDetected, fn_name);
                continue;
            }

            // Attempt to patch the stub.
            match self.patch_stub(fn_name, stub_addr) {
                Ok(()) => {
                    let msg = format!("[dlp-hook] ntdll stub patched: {}\0", fn_name);
                    crate::debug_log(&msg);
                    self.stubs[name.index()] = StubPatchState::Patched;
                }
                Err(PatchError::RipInStubRange) => {
                    let msg = format!("[dlp-hook] ntdll patch raced on {}, skipping\0", fn_name);
                    crate::debug_log(&msg);
                    self.stubs[name.index()] = StubPatchState::SkippedRaced;
                    emit_bypass_alert(BypassReason::PatchRaced, fn_name);
                }
                Err(e) => {
                    let msg = format!("[dlp-hook] ntdll patch failed on {}: {}\0", fn_name, e);
                    crate::debug_log(&msg);
                    // Leave state as Unpatched (or whatever it was).
                }
            }
        }

        crate::debug_log("[dlp-hook] ntdll stub patching complete\0");
    }

    /// Patches a single ntdll stub using retour under thread suspension.
    ///
    /// # Arguments
    ///
    /// * `fn_name` — The ntdll function name (for logging).
    /// * `stub_addr` — The address of the ntdll syscall stub.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, `Err(PatchError)` on failure.
    ///
    /// # Safety
    ///
    /// `stub_addr` must point to a valid ntdll syscall stub. The thread-suspend
    /// protocol ensures no torn instructions during the patch.
    fn patch_stub(&mut self, fn_name: &str, stub_addr: *mut u8) -> Result<(), PatchError> {
        // We need the detour function pointer. Since the ntdll-specific
        // trampolines (NtdllTrampolineNtCreateFile etc.) are defined in Plan
        // 03, we temporarily store a placeholder. In the actual implementation,
        // this will look up the detour from NTDLL_STUBS.
        let detour_fn = find_detour_for_stub(fn_name)?;

        // Alignment check: retour expects properly aligned function pointers.
        if !(stub_addr as usize).is_multiple_of(std::mem::align_of::<usize>()) {
            return Err(PatchError::DetourFailed);
        }

        // Execute the patch under thread suspension.
        let result = crate::thread_suspender::with_suspended_threads(stub_addr, || {
            let detour = unsafe { retour::RawDetour::new(stub_addr as *const (), detour_fn) }
                .map_err(|_| PatchError::DetourFailed)?;
            unsafe { detour.enable() }.map_err(|_| PatchError::DetourFailed)?;

            // Save original 5 bytes for integrity verification.
            let original_bytes = unsafe { std::slice::from_raw_parts(stub_addr, 5) };
            let mut bytes = [0u8; 5];
            bytes.copy_from_slice(original_bytes);

            // Store in the corresponding HookDescriptor.
            if let Some(hook) = find_hook_descriptor(fn_name) {
                unsafe {
                    (*hook).ntdll_stub_addr = stub_addr;
                    (*hook).original_ntdll_bytes = bytes;
                }
            }

            Ok(detour)
        });

        match result {
            Ok(Ok(detour)) => {
                // Store the detour. Since we can't store RawDetour in the
                // HookDescriptor (it's not Copy/Clone), we store it in a
                // separate static array indexed by stub name.
                store_detour(fn_name, detour);
                Ok(())
            }
            Ok(Err(e)) => Err(e),
            Err(crate::thread_suspender::PatchError::RipInStubRange) => {
                Err(PatchError::RipInStubRange)
            }
            Err(_) => Err(PatchError::DetourFailed),
        }
    }

    /// Unpatches all stubs that are currently in `Patched` state.
    ///
    /// For each patched stub, calls `detour.disable()` and transitions to
    /// `Unpatched`. Per D-06: never restores "clean" bytes from disk — retour
    /// handles restoration internally.
    pub fn unpatch_all_stubs(&mut self) {
        for name in [
            StubName::NtCreateFile,
            StubName::NtOpenFile,
            StubName::NtWriteFile,
            StubName::NtSetInformationFile,
        ] {
            if *self.stub_state(name) == StubPatchState::Patched {
                if let Some(detour) = take_detour(name.as_str()) {
                    let _ = unsafe { detour.disable() };
                    let msg = format!("[dlp-hook] ntdll stub unpatched: {}\0", name.as_str());
                    crate::debug_log(&msg);
                }
                self.stubs[name.index()] = StubPatchState::Unpatched;
            }
        }
    }

    /// Returns the original trampoline pointer for a patched stub.
    ///
    /// # Arguments
    ///
    /// * `fn_name` — The ntdll function name (e.g., "NtCreateFile").
    ///
    /// # Returns
    ///
    /// `Some(trampoline_ptr)` if the stub is patched, `None` otherwise.
    #[must_use]
    pub fn get_original_trampoline(&self, fn_name: &str) -> Option<*const ()> {
        let name = stub_name_from_str(fn_name)?;
        if *self.stub_state(name) != StubPatchState::Patched {
            return None;
        }
        get_detour_trampoline(fn_name)
    }

    /// Verifies the integrity of a single ntdll stub.
    ///
    /// Per D-12: reads the first 5 bytes of the stub and verifies they match
    /// our JMP pattern (0xE9 rel32 targeting our trampoline range). This is
    /// per-stub — one stub can be clean while another is overwritten.
    ///
    /// # Arguments
    ///
    /// * `fn_name` — The ntdll function name (e.g., "NtCreateFile").
    ///
    /// # Returns
    ///
    /// [`StubIntegrity::Clean`] if the stub bytes match our JMP pattern,
    /// [`StubIntegrity::Overwritten`] if EDR or another hook replaced our JMP,
    /// [`StubIntegrity::NotPatched`] if the stub was never patched,
    /// [`StubIntegrity::Unknown`] if the stub address could not be read.
    #[must_use]
    pub fn verify_stub_integrity(&self, fn_name: &str) -> StubIntegrity {
        let name = match stub_name_from_str(fn_name) {
            Some(n) => n,
            None => return StubIntegrity::Unknown,
        };

        // If not in Patched state, there is nothing to verify.
        if *self.stub_state(name) != StubPatchState::Patched {
            return StubIntegrity::NotPatched;
        }

        // Find the HookDescriptor to get the stub address.
        let stub_addr = match find_hook_descriptor(fn_name) {
            Some(hook) => unsafe { (*hook).ntdll_stub_addr },
            None => return StubIntegrity::Unknown,
        };

        if stub_addr.is_null() {
            return StubIntegrity::Unknown;
        }

        // SAFETY: stub_addr is a valid ntdll stub address that we patched.
        // We read 5 bytes atomically (x64: aligned 8-byte read is atomic).
        let first_byte = unsafe { std::ptr::read(stub_addr) };

        // Step 1: Verify first byte is 0xE9 (JMP rel32).
        // Original ntdll stub starts with `mov r10, rcx` = 0x4C 0x8B 0xD1.
        // If not 0xE9, someone overwrote our JMP with something else.
        if first_byte != 0xE9 {
            return StubIntegrity::Overwritten;
        }

        // Step 2: Read the rel32 offset and calculate the JMP target.
        // SAFETY: stub_addr+1 is within the stub (we read 4 bytes for rel32).
        let rel32 = unsafe { std::ptr::read_unaligned(stub_addr.add(1) as *const i32) };
        let target = unsafe { stub_addr.add(5).offset(rel32 as isize) };

        // Step 3: Verify the target falls within our trampoline function range.
        // We check if the target is within any of our NtdllTrampoline* functions.
        // Each function is at most a few KB, so we use a generous 64KB window.
        // This distinguishes our JMP (targeting our trampoline) from an EDR JMP
        // (targeting EDR code).
        if is_target_in_our_trampoline_range(target) {
            StubIntegrity::Clean
        } else {
            StubIntegrity::Overwritten
        }
    }

    /// Marks a stub as permanently overwritten and emits a bypass alert.
    ///
    /// Per D-07: on HookOverwritten detection, emit alert and mark stub as
    /// "EDR-controlled, skip permanently." Do NOT re-patch.
    ///
    /// # Arguments
    ///
    /// * `fn_name` — The ntdll function name (e.g., "NtCreateFile").
    pub fn mark_stub_overwritten(&mut self, fn_name: &str) {
        let name = match stub_name_from_str(fn_name) {
            Some(n) => n,
            None => return,
        };

        self.stubs[name.index()] = StubPatchState::Overwritten;

        let msg = format!(
            "[dlp-hook] ntdll stub marked Overwritten: {}\0",
            fn_name
        );
        crate::debug_log(&msg);

        emit_bypass_alert(BypassReason::HookOverwritten, fn_name);
    }

    /// Verifies all 4 ntdll stubs independently.
    ///
    /// Returns a vector of (fn_name, integrity) pairs. Per D-13: each stub is
    /// checked independently — one can be clean while another is overwritten.
    #[must_use]
    pub fn verify_all_stubs(&self) -> Vec<(&'static str, StubIntegrity)> {
        let mut results = Vec::with_capacity(4);
        for name in [
            StubName::NtCreateFile,
            StubName::NtOpenFile,
            StubName::NtWriteFile,
            StubName::NtSetInformationFile,
        ] {
            let fn_name = name.as_str();
            let integrity = self.verify_stub_integrity(fn_name);
            results.push((fn_name, integrity));
        }
        results
    }

    /// Returns a copy of all stub states for inspection.
    ///
    /// Used by tests and diagnostics to check the current state of each stub
    /// without exposing internal mutable access.
    #[must_use]
    pub fn stub_states(&self) -> [StubPatchState; 4] {
        self.stubs.clone()
    }
}

// ---------------------------------------------------------------------------
// Detour storage (static, since RawDetour is not Copy/Clone)
// ---------------------------------------------------------------------------

use parking_lot::Mutex;

/// Static storage for the 4 retour detours.
///
/// RawDetour is neither Copy nor Clone, so we cannot store it in the
/// `const HOOKS` table. Instead we use a static Mutex array indexed by
/// stub name. The Mutex is only held briefly during store/retrieve.
static DETOURS: Mutex<[Option<retour::RawDetour>; 4]> = Mutex::new([None, None, None, None]);

fn store_detour(fn_name: &str, detour: retour::RawDetour) {
    let idx = match stub_name_from_str(fn_name) {
        Some(n) => n.index(),
        None => return,
    };
    DETOURS.lock()[idx] = Some(detour);
}

fn take_detour(fn_name: &str) -> Option<retour::RawDetour> {
    let idx = stub_name_from_str(fn_name)?.index();
    DETOURS.lock().get_mut(idx)?.take()
}

fn get_detour_trampoline(fn_name: &str) -> Option<*const ()> {
    let idx = stub_name_from_str(fn_name)?.index();
    let guard = DETOURS.lock();
    guard[idx].as_ref().map(|d| d.trampoline() as *const ())
}

/// Returns the original trampoline pointer for a patched stub.
///
/// This free function is callable from ntdll trampolines (which do not have
/// access to a [`NtdllPatcher`] instance). It looks up the detour in the
/// static `DETOURS` array and returns retour's generated trampoline pointer.
///
/// # Arguments
///
/// * `fn_name` — The ntdll function name (e.g., "NtCreateFile").
///
/// # Returns
///
/// `Some(trampoline_ptr)` if the stub is patched and the detour exists,
/// `None` otherwise.
pub fn get_original_trampoline(fn_name: &str) -> Option<*const ()> {
    get_detour_trampoline(fn_name)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Maps a string to a [`StubName`].
fn stub_name_from_str(s: &str) -> Option<StubName> {
    match s {
        "NtCreateFile" => Some(StubName::NtCreateFile),
        "NtOpenFile" => Some(StubName::NtOpenFile),
        "NtWriteFile" => Some(StubName::NtWriteFile),
        "NtSetInformationFile" => Some(StubName::NtSetInformationFile),
        _ => None,
    }
}

/// Finds the [`HookDescriptor`] for an ntdll function by name.
///
/// Returns a mutable pointer to the descriptor in the `HOOKS` table.
fn find_hook_descriptor(fn_name: &str) -> Option<*mut crate::HookDescriptor> {
    for hook in crate::HOOKS {
        if hook.fn_name == fn_name && hook.dll_name == "ntdll.dll" {
            return Some(hook as *const _ as *mut _);
        }
    }
    None
}

/// Finds the detour function pointer for a stub.
///
/// Looks up the ntdll function name in the [`NTDLL_STUBS`] constant and
/// returns the corresponding trampoline pointer.
///
/// # Arguments
///
/// * `fn_name` — The ntdll function name (e.g., "NtCreateFile").
///
/// # Returns
///
/// `Ok(trampoline_ptr)` if found, `Err(PatchError::DetourFailed)` otherwise.
fn find_detour_for_stub(fn_name: &str) -> Result<*const (), PatchError> {
    for (name, ptr) in crate::NTDLL_STUBS {
        if *name == fn_name {
            return Ok(*ptr);
        }
    }
    Err(PatchError::DetourFailed)
}

/// Checks whether a JMP target address falls within our trampoline range.
///
/// We compare the target against the addresses of our four ntdll trampoline
/// functions. Each trampoline is at most a few KB, so we use a generous 64KB
/// window to account for code layout variations.
///
/// # Arguments
///
/// * `target` — The calculated JMP target address.
///
/// # Returns
///
/// `true` if the target is within any of our trampoline functions.
fn is_target_in_our_trampoline_range(target: *mut u8) -> bool {
    // SAFETY: We are comparing raw pointers as integers. The trampolines are
    // valid function addresses in our module's .text section.
    let target_usize = target as usize;
    let trampolines: [*const (); 4] = [
        crate::trampolines::NtdllTrampolineNtCreateFile as *const (),
        crate::trampolines::NtdllTrampolineNtOpenFile as *const (),
        crate::trampolines::NtdllTrampolineNtWriteFile as *const (),
        crate::trampolines::NtdllTrampolineNtSetInformationFile as *const (),
    ];

    let min = trampolines.iter().map(|t| *t as usize).min().unwrap_or(0);
    let max = trampolines.iter().map(|t| *t as usize).max().unwrap_or(0);
    // Add generous margin for function size + padding
    let margin = 16 * 1024; // 16KB per function
    target_usize >= min.saturating_sub(margin) && target_usize <= max.saturating_add(margin)
}

/// Emits a bypass alert via the named pipe.
///
/// This is best-effort; if the pipe fails, log via `debug_log` and continue.
fn emit_bypass_alert(reason: BypassReason, stub_name: &str) {
    let alert = dlp_common::hook_ipc::BypassAlert {
        reason,
        stub_name: stub_name.to_string(),
        pid: std::process::id(),
        timestamp_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    if let Ok(payload) = bincode::serialize(&alert) {
        let _ = crate::pipe_client::send_raw_request(
            crate::DEFAULT_PIPE_NAME,
            &payload,
            50,
        );
    }
    // Also log locally
    let msg = format!(
        "[dlp-hook] BypassAlert: reason={:?} stub={} ",
        reason, stub_name
    );
    crate::debug_log(&msg);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntdll_patcher_new_disabled() {
        let patcher = NtdllPatcher::new(false);
        assert!(!patcher.is_enabled());
        for name in [
            StubName::NtCreateFile,
            StubName::NtOpenFile,
            StubName::NtWriteFile,
            StubName::NtSetInformationFile,
        ] {
            assert_eq!(*patcher.stub_state(name), StubPatchState::Unpatched);
        }
    }

    #[test]
    fn ntdll_patcher_new_enabled() {
        let patcher = NtdllPatcher::new(true);
        assert!(patcher.is_enabled());
    }

    #[test]
    fn ntdll_patcher_disabled_does_nothing() {
        let mut patcher = NtdllPatcher::new(false);
        // patch_all_stubs should be a no-op when disabled.
        patcher.patch_all_stubs();
        for name in [
            StubName::NtCreateFile,
            StubName::NtOpenFile,
            StubName::NtWriteFile,
            StubName::NtSetInformationFile,
        ] {
            assert_eq!(*patcher.stub_state(name), StubPatchState::Unpatched);
        }
    }

    #[test]
    fn stub_patch_state_transitions() {
        let mut patcher = NtdllPatcher::new(true);

        // All start as Unpatched.
        assert_eq!(
            *patcher.stub_state(StubName::NtCreateFile),
            StubPatchState::Unpatched
        );

        // Simulate EDR skip.
        patcher.stubs[StubName::NtCreateFile.index()] = StubPatchState::SkippedEdr;
        assert_eq!(
            *patcher.stub_state(StubName::NtCreateFile),
            StubPatchState::SkippedEdr
        );

        // Simulate patch.
        patcher.stubs[StubName::NtCreateFile.index()] = StubPatchState::Patched;
        assert_eq!(
            *patcher.stub_state(StubName::NtCreateFile),
            StubPatchState::Patched
        );

        // Simulate unpatch.
        patcher.stubs[StubName::NtCreateFile.index()] = StubPatchState::Unpatched;
        assert_eq!(
            *patcher.stub_state(StubName::NtCreateFile),
            StubPatchState::Unpatched
        );
    }

    #[test]
    fn ntdll_patcher_get_original_trampoline_unpatched() {
        let patcher = NtdllPatcher::new(true);
        // Unpatched stub should return None.
        assert_eq!(patcher.get_original_trampoline("NtCreateFile"), None);
    }

    #[test]
    fn ntdll_patcher_per_stub_granularity() {
        let mut patcher = NtdllPatcher::new(true);

        // Simulate one stub being patched, another skipped due to EDR.
        patcher.stubs[StubName::NtCreateFile.index()] = StubPatchState::Patched;
        patcher.stubs[StubName::NtOpenFile.index()] = StubPatchState::SkippedEdr;
        patcher.stubs[StubName::NtWriteFile.index()] = StubPatchState::SkippedRaced;
        patcher.stubs[StubName::NtSetInformationFile.index()] = StubPatchState::Overwritten;

        assert_eq!(
            *patcher.stub_state(StubName::NtCreateFile),
            StubPatchState::Patched
        );
        assert_eq!(
            *patcher.stub_state(StubName::NtOpenFile),
            StubPatchState::SkippedEdr
        );
        assert_eq!(
            *patcher.stub_state(StubName::NtWriteFile),
            StubPatchState::SkippedRaced
        );
        assert_eq!(
            *patcher.stub_state(StubName::NtSetInformationFile),
            StubPatchState::Overwritten
        );
    }

    #[test]
    fn stub_name_as_str() {
        assert_eq!(StubName::NtCreateFile.as_str(), "NtCreateFile");
        assert_eq!(StubName::NtOpenFile.as_str(), "NtOpenFile");
        assert_eq!(StubName::NtWriteFile.as_str(), "NtWriteFile");
        assert_eq!(
            StubName::NtSetInformationFile.as_str(),
            "NtSetInformationFile"
        );
    }

    #[test]
    fn stub_name_index() {
        assert_eq!(StubName::NtCreateFile.index(), 0);
        assert_eq!(StubName::NtOpenFile.index(), 1);
        assert_eq!(StubName::NtWriteFile.index(), 2);
        assert_eq!(StubName::NtSetInformationFile.index(), 3);
    }

    #[test]
    fn stub_name_from_str_valid() {
        assert_eq!(
            stub_name_from_str("NtCreateFile"),
            Some(StubName::NtCreateFile)
        );
        assert_eq!(stub_name_from_str("NtOpenFile"), Some(StubName::NtOpenFile));
    }

    #[test]
    fn stub_name_from_str_invalid() {
        assert_eq!(stub_name_from_str("NtQuerySystemInformation"), None);
        assert_eq!(stub_name_from_str(""), None);
    }

    #[test]
    fn patch_error_display() {
        assert_eq!(
            format!("{}", PatchError::ResolveFailed),
            "could not resolve stub address"
        );
        assert_eq!(
            format!("{}", PatchError::EdrDetected),
            "EDR detected on stub"
        );
        assert_eq!(
            format!("{}", PatchError::RipInStubRange),
            "thread RIP is inside stub range"
        );
        assert_eq!(
            format!("{}", PatchError::DetourFailed),
            "retour detour failed"
        );
    }

    #[test]
    fn bypass_reason_debug() {
        // Just verify the enum variants exist and are debug-printable.
        let _ = format!("{:?}", BypassReason::HookOverwritten);
        let _ = format!("{:?}", BypassReason::PatchRaced);
        let _ = format!("{:?}", BypassReason::EdrDetected);
    }

    #[test]
    fn verify_stub_integrity_not_patched() {
        // Unpatched stub should return NotPatched.
        let patcher = NtdllPatcher::new(true);
        let result = patcher.verify_stub_integrity("NtCreateFile");
        assert_eq!(result, StubIntegrity::NotPatched);
    }

    #[test]
    fn verify_stub_integrity_unknown_name() {
        // Unknown function name should return Unknown.
        let patcher = NtdllPatcher::new(true);
        let result = patcher.verify_stub_integrity("NtQuerySystemInformation");
        assert_eq!(result, StubIntegrity::Unknown);
    }

    #[test]
    fn verify_stub_mark_overwritten() {
        // mark_stub_overwritten should set state to Overwritten.
        let mut patcher = NtdllPatcher::new(true);

        // Start as Unpatched.
        assert_eq!(
            *patcher.stub_state(StubName::NtCreateFile),
            StubPatchState::Unpatched
        );

        patcher.mark_stub_overwritten("NtCreateFile");

        assert_eq!(
            *patcher.stub_state(StubName::NtCreateFile),
            StubPatchState::Overwritten
        );
    }

    #[test]
    fn verify_all_stubs_returns_four_results() {
        let patcher = NtdllPatcher::new(true);
        let results = patcher.verify_all_stubs();
        assert_eq!(results.len(), 4);

        // All should be NotPatched since nothing was actually patched.
        for (name, integrity) in &results {
            assert_eq!(*integrity, StubIntegrity::NotPatched, "{} should be NotPatched", name);
        }
    }

    #[test]
    fn stub_integrity_equality() {
        assert_eq!(StubIntegrity::Clean, StubIntegrity::Clean);
        assert_ne!(StubIntegrity::Clean, StubIntegrity::Overwritten);
        assert_ne!(StubIntegrity::NotPatched, StubIntegrity::Unknown);
    }

    #[test]
    fn is_target_in_our_trampoline_range_detects_our_trampolines() {
        // Verify that our own trampoline addresses are recognized.
        let addr = crate::trampolines::NtdllTrampolineNtCreateFile as *mut u8;
        assert!(is_target_in_our_trampoline_range(addr));

        let addr = crate::trampolines::NtdllTrampolineNtOpenFile as *mut u8;
        assert!(is_target_in_our_trampoline_range(addr));

        let addr = crate::trampolines::NtdllTrampolineNtWriteFile as *mut u8;
        assert!(is_target_in_our_trampoline_range(addr));

        let addr = crate::trampolines::NtdllTrampolineNtSetInformationFile as *mut u8;
        assert!(is_target_in_our_trampoline_range(addr));
    }

    #[test]
    fn is_target_in_our_trampoline_range_rejects_foreign_address() {
        // A null pointer should not be in our range.
        assert!(!is_target_in_our_trampoline_range(std::ptr::null_mut()));

        // A high arbitrary address should not match.
        let far_addr = 0xFFFF_FFFF_FFFF_0000 as *mut u8;
        assert!(!is_target_in_our_trampoline_range(far_addr));
    }
}
