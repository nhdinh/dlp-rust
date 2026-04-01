//! Policy Store — JSON file persistence with version tracking and hot-reload.
//!
//! ## Responsibilities
//!
//! - Load and validate policies from a JSON file on disk.
//! - Persist policy changes back to the same file.
//! - Track per-policy version numbers (monotonically increasing).
//! - Provide atomic policy set replacement for the ABAC engine.
//!
//! ## Hot-Reload
//!
//! File-system notifications via `notify` detect external policy file changes.
//! On a modify event the store reloads and re-validates the file within 5 s.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dlp_common::abac::{EvaluateRequest, EvaluateResponse, Policy};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{debug, error, info, warn};

use crate::engine::AbacEngine;
use crate::error::{PolicyEngineError, Result};

/// The policy store manages the JSON file on disk and keeps the engine in sync.
#[derive(Debug)]
pub struct PolicyStore {
    /// Path to the policy JSON file on disk.
    path: PathBuf,
    /// The ABAC engine to keep synchronized.
    pub(crate) engine: Arc<AbacEngine>,
    /// Guards access to `next_version`.
    version_lock: parking_lot::Mutex<u64>,
    /// The next version number to assign (monotonically increasing).
    #[allow(dead_code)]
    next_version: u64,
    /// Set to true to stop the hot-reload watcher.
    #[allow(dead_code)]
    shutdown_flag: Arc<AtomicBool>,
}

impl PolicyStore {
    /// Opens (or creates) the policy store at the given path.
    ///
    /// If `path` does not exist, creates it with an empty policy list.
    ///
    /// # Errors
    ///
    /// Returns `PolicyEngineError::PolicyStoreError` if the file cannot be read
    /// or if the JSON is malformed.
    pub fn open(path: PathBuf, engine: Arc<AbacEngine>) -> Result<Self> {
        let (policies, max_version) = Self::load_from_disk(&path)?;

        // Sync loaded policies into the engine immediately.
        engine.reload_policies(policies.clone())?;

        let policy_count = policies.len();
        info!(path = %path.display(), policy_count, "policy store loaded");

        Ok(Self {
            path,
            engine,
            version_lock: parking_lot::Mutex::new(0),
            next_version: max_version.saturating_add(1),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Loads policies from the JSON file, returning the policy list and the
    /// highest version number found (for version sequencing).
    fn load_from_disk(path: &Path) -> Result<(Vec<Policy>, u64)> {
        if !path.exists() {
            info!(path = %path.display(), "policy file not found; creating with empty policy set");
            let empty: Vec<Policy> = Vec::new();
            let json =
                serde_json::to_string_pretty(&empty).expect("serializing empty vec cannot fail");
            fs::write(path, json).map_err(|e| {
                PolicyEngineError::PolicyStoreError(format!("failed to create policy file: {e}"))
            })?;
            return Ok((empty, 0));
        }

        let content = fs::read_to_string(path)
            .map_err(|e| PolicyEngineError::PolicyStoreError(format!("failed to read: {e}")))?;

        let policies: Vec<Policy> = serde_json::from_str(&content)
            .map_err(|e| PolicyEngineError::PolicyStoreError(format!("JSON parse error: {e}")))?;

        let max_version = policies.iter().map(|p| p.version).max().unwrap_or(0);

        // Validate each policy on load; skip invalid ones so a single bad entry
        // does not prevent the entire store from loading.
        let valid_policies: Vec<Policy> = policies
            .into_iter()
            .filter(|policy| {
                if let Err(e) = super::engine::validate_policy(policy) {
                    warn!(policy_id = %policy.id, "invalid policy skipped: {}", e);
                    false
                } else {
                    true
                }
            })
            .collect();

        Ok((valid_policies, max_version))
    }

    /// Saves the current in-memory policy set to disk.
    ///
    /// This is a full overwrite — the file is rewritten atomically using a
    /// rename-from-temporary to avoid partial-write corruption.
    pub fn save(&self) -> Result<()> {
        let policies = self.engine.get_policies();
        self.save_policies(&policies)
    }

    /// Saves the given policy set to disk.
    fn save_policies(&self, policies: &[Policy]) -> Result<()> {
        let json = serde_json::to_string_pretty(policies).map_err(PolicyEngineError::JsonError)?;

        let tmp_path = PathBuf::from(format!("{}.tmp", self.path.display()));
        fs::write(&tmp_path, json)
            .map_err(|e| PolicyEngineError::PolicyStoreError(format!("write failed: {e}")))?;

        // Atomic rename — eliminates partial-write window.
        fs::rename(&tmp_path, &self.path).map_err(|e| {
            PolicyEngineError::PolicyStoreError(format!("atomic rename failed: {e}"))
        })?;

        info!(path = %self.path.display(), count = policies.len(), "policies persisted");
        Ok(())
    }

    /// Adds a new policy to the store with the next available version number.
    ///
    /// The new policy is saved to disk and the engine is reloaded.
    pub fn add_policy(&self, mut policy: Policy) -> Result<()> {
        let version = {
            let mut guard = self.version_lock.lock();
            let v = *guard;
            *guard = v + 1;
            v
        };
        policy.version = version;
        let mut policies = self.engine.get_policies();
        policies.push(policy);
        self.engine.reload_policies(policies.clone())?;
        self.save_policies(&policies)?;
        Ok(())
    }

    /// Updates an existing policy in the store.
    ///
    /// The policy's version number is incremented. The engine is reloaded.
    ///
    /// # Errors
    ///
    /// Returns `PolicyEngineError::PolicyNotFound` if `policy_id` does not exist.
    pub fn update_policy(&self, policy_id: &str, mut updated: Policy) -> Result<()> {
        let mut policies = self.engine.get_policies();
        let idx = policies
            .iter()
            .position(|p| p.id == policy_id)
            .ok_or_else(|| PolicyEngineError::PolicyNotFound(policy_id.to_string()))?;

        let version = {
            let mut guard = self.version_lock.lock();
            let v = *guard;
            *guard = v + 1;
            v
        };
        updated.id = policy_id.to_string();
        updated.version = version;

        policies[idx] = updated;
        self.engine.reload_policies(policies.clone())?;
        self.save_policies(&policies)?;
        Ok(())
    }

    /// Removes a policy from the store by ID.
    ///
    /// # Errors
    ///
    /// Returns `PolicyEngineError::PolicyNotFound` if `policy_id` does not exist.
    pub fn delete_policy(&self, policy_id: &str) -> Result<()> {
        let mut policies = self.engine.get_policies();
        let initial_len = policies.len();
        policies.retain(|p| p.id != policy_id);
        if policies.len() == initial_len {
            return Err(PolicyEngineError::PolicyNotFound(policy_id.to_string()));
        }
        self.engine.reload_policies(policies.clone())?;
        self.save_policies(&policies)?;
        Ok(())
    }

    /// Returns a snapshot of all currently loaded policies.
    pub fn list_policies(&self) -> Vec<Policy> {
        self.engine.get_policies()
    }

    /// Starts a background thread that watches the policy file for changes.
    ///
    /// On a file-modify event the new content is loaded, validated, and
    /// atomically swapped into the engine. Concurrent modify events are
    /// coalesced — only one reload runs at a time.
    ///
    /// The watcher stops when `shutdown_flag` (stored in `PolicyStore`) is set.
    ///
    /// # Panics
    ///
    /// Panics if the underlying `notify` watcher cannot be created.
    pub fn start_hot_reload(&self) {
        let path = self.path.clone();
        let engine = self.engine.clone();
        let shutdown_flag = self.shutdown_flag.clone();

        // Debounce window: coalesce rapid file-change events.
        let debounce = Duration::from_secs(2);

        std::thread::spawn(move || {
            let (tx, rx) = std::sync::mpsc::channel();

            let mut watcher = RecommendedWatcher::new(
                move |res: std::result::Result<notify::Event, notify::Error>| {
                    if res.is_ok() {
                        let _ = tx.send(());
                    }
                },
                Config::default().with_poll_interval(Duration::from_secs(1)),
            )
            .expect("failed to create notify watcher");

            // Watch the parent directory to catch rename/replace events too.
            if let Some(parent) = path.parent() {
                let _ = watcher.watch(parent, RecursiveMode::NonRecursive);
            }

            let mut pending_reload = false;

            loop {
                // Check shutdown flag.
                if shutdown_flag.load(Ordering::Relaxed) {
                    debug!("hot-reload watcher stopping");
                    break;
                }

                // Wait for an event (with timeout so we can re-check shutdown).
                let timeout = if pending_reload {
                    // After an event, wait for debounce period then reload.
                    debounce
                } else {
                    Duration::from_secs(1)
                };

                match rx.recv_timeout(timeout) {
                    Ok(()) => {
                        // Event received — set flag to reload after debounce.
                        pending_reload = true;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if pending_reload {
                            pending_reload = false;
                            // Perform reload on this thread to avoid blocking notify.
                            let engine_clone = engine.clone();
                            let path_clone = path.clone();
                            std::thread::spawn(move || match Self::load_from_disk(&path_clone) {
                                Ok((policies, _)) => {
                                    if let Err(e) = engine_clone.reload_policies(policies) {
                                        error!(error = %e, "hot-reload failed: invalid policies");
                                    } else {
                                        debug!("hot-reload: policies reloaded");
                                    }
                                }
                                Err(e) => {
                                    error!(error = %e, "hot-reload failed: could not read file");
                                }
                            });
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        break;
                    }
                }
            }
        });

        info!(path = %self.path.display(), "hot-reload watcher started");
    }

    /// Evaluates an ABAC access request against the loaded policy set.
    ///
    /// This is the async wrapper around the engine's synchronous `evaluate()`.
    /// The engine call runs on a blocking thread to avoid stalling the async runtime.
    pub async fn evaluate(&self, request: &EvaluateRequest) -> EvaluateResponse {
        let engine = self.engine.clone();
        let request = request.clone();
        tokio::task::spawn_blocking(move || engine.evaluate(&request))
            .await
            .unwrap_or_else(|_| EvaluateResponse::default_deny())
    }
}

// `get_policies()` is defined as `pub(crate)` in `engine.rs`.

// ─────────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use dlp_common::abac::{Decision, Policy, PolicyCondition};
    use dlp_common::Classification;

    fn temp_store() -> (tempfile::TempDir, PolicyStore) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("policies.json");
        let engine = std::sync::Arc::new(AbacEngine::new());
        let store = PolicyStore::open(path, engine).unwrap();
        (tmp, store)
    }

    fn make_policy(id: &str) -> Policy {
        Policy {
            id: id.into(),
            name: format!("Policy {}", id),
            description: None,
            priority: 1,
            conditions: vec![PolicyCondition::Classification {
                op: "eq".into(),
                value: Classification::T3,
            }],
            action: Decision::DENY,
            enabled: true,
            version: 0,
        }
    }

    #[test]
    fn test_creates_empty_file_if_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("missing.json");
        let engine = std::sync::Arc::new(AbacEngine::new());
        let store = PolicyStore::open(path.clone(), engine).unwrap();
        assert!(path.exists());
        assert!(store.list_policies().is_empty());
    }

    #[test]
    fn test_add_policy() {
        let (_tmp, store) = temp_store();
        let pol = make_policy("pol-new");
        store.add_policy(pol).unwrap();
        assert_eq!(store.list_policies().len(), 1);
    }

    #[test]
    fn test_update_policy() {
        let (_tmp, store) = temp_store();
        store.add_policy(make_policy("pol-upd")).unwrap();
        let updated = Policy {
            id: "pol-upd".into(),
            name: "Updated Name".into(),
            description: None,
            priority: 5,
            conditions: vec![],
            action: Decision::ALLOW,
            enabled: true,
            version: 0,
        };
        store.update_policy("pol-upd", updated).unwrap();
        let policies = store.list_policies();
        assert_eq!(policies[0].name, "Updated Name");
        assert!(policies[0].version > 0);
    }

    #[test]
    fn test_delete_policy() {
        let (_tmp, store) = temp_store();
        store.add_policy(make_policy("pol-del")).unwrap();
        store.delete_policy("pol-del").unwrap();
        assert!(store.list_policies().is_empty());
    }

    #[test]
    fn test_delete_nonexistent_returns_error() {
        let (_tmp, store) = temp_store();
        let err = store.delete_policy("nonexistent").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }
}
