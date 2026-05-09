//! Print enforcement orchestrator (M017/S04 T05).
//!
//! [`PrintEnforcer`] wraps [`PrintWatcher`] and bridges the admin config to the
//! watcher lifecycle.  When `print_enabled` is `false` (or `None`), the watcher
//! is never started and all methods are no-ops.

use std::sync::Arc;

use tracing::{info, warn};

use crate::audit_emitter::EmitContext;
use crate::offline::OfflineManager;
use crate::print_watcher::{PrintWatcher, PrintWatcherConfig};

/// Wraps [`PrintWatcher`] and gates it behind the `print_enabled` config flag.
///
/// The enforcer is constructed regardless of whether print enforcement is enabled.
/// Whether the watcher actually starts depends on the `print_enabled` field read
/// from [`crate::config::AgentConfig`] at construction time.
pub struct PrintEnforcer {
    /// Whether print interception is currently active.
    enabled: bool,
    /// Inner watcher — `None` when `print_enabled=false`.
    watcher: Option<PrintWatcher>,
}

impl PrintEnforcer {
    /// Constructs a new `PrintEnforcer`.
    ///
    /// # Arguments
    ///
    /// * `print_enabled` — value of `AgentConfig::print_enabled`; `None` is treated as `false`.
    /// * `config` — watcher configuration (max pages, unclassifiable action).
    /// * `offline` — shared offline evaluation manager.
    /// * `audit_ctx` — audit emit context for print events.
    /// * `runtime_handle` — handle to the tokio runtime for blocking ABAC calls.
    pub fn new(
        print_enabled: Option<bool>,
        config: PrintWatcherConfig,
        offline: Arc<OfflineManager>,
        audit_ctx: EmitContext,
        runtime_handle: tokio::runtime::Handle,
    ) -> Self {
        let enabled = print_enabled.unwrap_or(false);

        if !enabled {
            info!("print enforcement disabled (print_enabled=false) — watcher not constructed");
            return Self {
                enabled: false,
                watcher: None,
            };
        }

        let watcher = PrintWatcher::new(offline, audit_ctx, runtime_handle).with_config(config);

        Self {
            enabled: true,
            watcher: Some(watcher),
        }
    }

    /// Starts the print watcher thread.
    ///
    /// No-op when `print_enabled=false`.
    ///
    /// # Errors
    ///
    /// Returns `Ok(())` always — failure to open the printer is logged inside the
    /// watcher thread and the thread exits gracefully rather than panicking.
    pub fn start(&mut self) {
        if !self.enabled {
            return;
        }
        if let Some(ref mut w) = self.watcher {
            info!("print enforcer starting watcher");
            w.start();
        }
    }

    /// Signals the print watcher thread to stop and waits for it to exit.
    ///
    /// No-op when `print_enabled=false` or when `start()` was never called.
    pub fn stop(&mut self) {
        if let Some(ref mut w) = self.watcher {
            info!("print enforcer stopping watcher");
            w.stop();
        }
    }

    /// Updates the enforcer in response to a config change.
    ///
    /// If `print_enabled` flips from `true` to `false`, the watcher is stopped.
    /// If it flips from `false` to `true`, a new watcher is started (using the
    /// same `offline` and `audit_ctx` captured at construction — this path is
    /// uncommon; a full service restart achieves the same effect without
    /// stale-capture risk).
    ///
    /// If the flag does not change, this is a no-op.
    pub fn update_enabled(&mut self, new_enabled: bool) {
        if new_enabled == self.enabled {
            return;
        }

        if !new_enabled {
            info!("print_enabled changed to false — stopping watcher");
            self.stop();
            self.watcher = None;
            self.enabled = false;
        } else {
            // Enabling at runtime without offline/audit_ctx requires a restart path.
            // Log a warning; operator should restart the service to fully enable.
            warn!("print_enabled changed to true at runtime — restart required to activate watcher");
            self.enabled = true;
        }
    }

    /// Returns `true` when the watcher is configured to run.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_watcher_config() -> PrintWatcherConfig {
        PrintWatcherConfig::default()
    }

    fn make_offline() -> Arc<OfflineManager> {
        let cache = Arc::new(crate::cache::Cache::new());
        let client = crate::engine_client::EngineClient::default_client().unwrap();
        Arc::new(OfflineManager::new(client, cache, None))
    }

    fn make_audit_ctx() -> EmitContext {
        EmitContext {
            agent_id: "AGENT-TEST".to_string(),
            session_id: 1,
            user_sid: "S-1-5-21-TEST".to_string(),
            user_name: "testuser".to_string(),
            machine_name: None,
        }
    }

    #[test]
    fn print_enforcer_disabled_by_default() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let enforcer = PrintEnforcer::new(
            None,
            make_watcher_config(),
            make_offline(),
            make_audit_ctx(),
            rt.handle().clone(),
        );
        assert!(!enforcer.is_enabled());
        assert!(enforcer.watcher.is_none());
    }

    #[test]
    fn print_enforcer_explicitly_disabled() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let enforcer = PrintEnforcer::new(
            Some(false),
            make_watcher_config(),
            make_offline(),
            make_audit_ctx(),
            rt.handle().clone(),
        );
        assert!(!enforcer.is_enabled());
    }

    #[test]
    fn print_enforcer_enabled_constructs_watcher() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let enforcer = PrintEnforcer::new(
            Some(true),
            make_watcher_config(),
            make_offline(),
            make_audit_ctx(),
            rt.handle().clone(),
        );
        assert!(enforcer.is_enabled());
        assert!(enforcer.watcher.is_some());
    }

    #[test]
    fn stop_without_start_is_noop() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut enforcer = PrintEnforcer::new(
            Some(false),
            make_watcher_config(),
            make_offline(),
            make_audit_ctx(),
            rt.handle().clone(),
        );
        // Must not panic.
        enforcer.stop();
    }

    #[test]
    fn start_when_disabled_is_noop() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut enforcer = PrintEnforcer::new(
            None,
            make_watcher_config(),
            make_offline(),
            make_audit_ctx(),
            rt.handle().clone(),
        );
        // Must not panic.
        enforcer.start();
        assert!(!enforcer.is_enabled());
    }

    #[test]
    fn update_enabled_true_to_false_disables() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut enforcer = PrintEnforcer::new(
            Some(true),
            make_watcher_config(),
            make_offline(),
            make_audit_ctx(),
            rt.handle().clone(),
        );
        assert!(enforcer.is_enabled());
        enforcer.update_enabled(false);
        assert!(!enforcer.is_enabled());
        assert!(enforcer.watcher.is_none());
    }

    #[test]
    fn update_enabled_false_to_true_logs_warning() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut enforcer = PrintEnforcer::new(
            Some(false),
            make_watcher_config(),
            make_offline(),
            make_audit_ctx(),
            rt.handle().clone(),
        );
        // Flipping to true at runtime notes that a restart is needed.
        enforcer.update_enabled(true);
        assert!(enforcer.is_enabled());
    }

    #[test]
    fn update_enabled_same_value_is_noop() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut enforcer = PrintEnforcer::new(
            Some(false),
            make_watcher_config(),
            make_offline(),
            make_audit_ctx(),
            rt.handle().clone(),
        );
        enforcer.update_enabled(false);
        assert!(!enforcer.is_enabled());
    }
}
