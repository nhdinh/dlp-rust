---
wave: 2
depends_on: [wave1]
order: 2
description: Wire PolicyStore into AppState, construct at startup, and add inline unit tests.
files_modified:
  - dlp-server/src/main.rs     (modify)
  - dlp-server/src/lib.rs      (modify — PolicyStore field added to AppState, impl From<PolicyEngineError>)
  - dlp-server/src/policy_store.rs  (add unit tests as #[cfg(test)] module)
---

# Wave 2: AppState Integration and Startup Wiring

## Objective

Wire `PolicyStore` into `AppState` in `lib.rs`, construct it at startup in `main.rs`, and spawn the background cache refresh task. After this wave, the server starts with a fully loaded policy cache and a background task keeping it fresh. Unit tests for `PolicyStore` are also added inline.

---

## Task 2.1 — Add `policy_store` to `AppState` in `lib.rs`

### Purpose

`AppState` must hold an `Arc<PolicyStore>` so all handlers can reach it via the axum `State` extractor.

### `<read_first>`

```
dlp-server/src/lib.rs                          (current AppState definition)
dlp-server/src/policy_store.rs                 (PolicyStore type, from Wave 1)
dlp-server/src/policy_engine_error.rs          (PolicyEngineError type, from Wave 1)
```

Read `AppState` struct definition in `lib.rs` lines 29–40 to confirm field structure.

Read `PolicyStore` struct definition and constructor signature in `policy_store.rs`.

### `<action>`

In `dlp-server/src/lib.rs`:

1. Add the import for `PolicyStore`:
   ```rust
   use crate::policy_store::PolicyStore;
   ```

2. Add the `policy_store` field to `AppState`:
   ```rust
   #[derive(Clone)]
   pub struct AppState {
       pub pool: Arc<db::Pool>,
       pub policy_store: Arc<PolicyStore>,   // ← add this field
       pub siem: siem_connector::SiemConnector,
       pub alert: alert_router::AlertRouter,
       pub ad: Option<AdClient>,
   }
   ```

3. Update the `Debug` impl for `AppState` to include the new field (add `.field("policy_store", &"PolicyStore(...)")` or similar).

4. Add the `impl From<PolicyEngineError> for AppError` conversion (if not done in Wave 1 — add it here if Wave 1 skipped that step):
   ```rust
   /// Maps `PolicyEngineError::PolicyNotFound` to `AppError::NotFound`.
   impl From<PolicyEngineError> for AppError {
       fn from(e: PolicyEngineError) -> Self {
           match e {
               PolicyEngineError::PolicyNotFound(id) => AppError::NotFound(id),
           }
       }
   }
   ```

### `<acceptance_criteria>`

- [ ] `AppState` struct has field `pub policy_store: Arc<PolicyStore>`
- [ ] `impl Debug for AppState` includes the new field (no compile errors)
- [ ] `impl From<PolicyEngineError> for AppError` present (PolicyNotFound → NotFound)
- [ ] `lib.rs` compiles: `cargo build -p dlp-server` — no warnings, no errors
- [ ] `Arc<AppState>` remains `Clone` (required by axum)

---

## Task 2.2 — Construct `PolicyStore` in `main.rs`

### Purpose

Load the policy cache synchronously at startup before `AppState` is built. The background refresh task is spawned after `AppState` is built.

### `<read_first>`

```
dlp-server/src/main.rs                    (current startup sequence)
dlp-server/src/lib.rs                     (AppState fields, from updated Task 2.1)
dlp-server/src/policy_store.rs            (PolicyStore::new signature)
```

Read the startup sequence in `main.rs` lines 133–213 (from `#[tokio::main]` to end of `main()`).

Key insertion points:
- After line 183 (after AD client init) → construct `PolicyStore::new(&pool)`
- After line 195 (after offline sweeper spawn) → spawn background refresh task

### `<action>`

In `dlp-server/src/main.rs`:

1. Add the import for `PolicyStore`:
   ```rust
   use dlp_server::policy_store::PolicyStore;
   ```

2. After the AD client block (line 183 area, after `None => None`) but before `// Build shared application state` (line 185):

   ```rust
   // Load all policies into the in-memory cache.
   // Fails the server startup if the DB is corrupt or unreachable.
   let policy_store = Arc::new(
       PolicyStore::new(Arc::clone(&pool)).map_err(|e| {
           eprintln!("Error: failed to load policies: {e}");
           anyhow::anyhow!("policy store initialization failed: {e}")
       })?,
   );
   info!(count = policy_store.list_policies().len(), "policy store loaded");
   ```

3. Update the `AppState` construction to include `policy_store`:
   ```rust
   let state = Arc::new(AppState {
       pool,
       policy_store,
       siem,
       alert,
       ad: ad_client,
   });
   ```

4. After `agent_registry::spawn_offline_sweeper(Arc::clone(&state));` (line 195), add the background refresh task:

   ```rust
   // Background task: reload the policy cache every POLICY_REFRESH_INTERVAL_SECS.
   // Refresh failures are logged but do not crash the server — stale cache is used
   // until the next interval.
   let refresh_store = Arc::clone(&state.policy_store);
   let refresh_interval_secs = crate::policy_store::POLICY_REFRESH_INTERVAL_SECS;
   tokio::spawn(async move {
       let mut interval = tokio::time::interval(std::time::Duration::from_secs(refresh_interval_secs));
       loop {
           interval.tick().await;
           refresh_store.refresh();
       }
   });
   ```

   Note: `POLICY_REFRESH_INTERVAL_SECS` is a `const` exported from `policy_store.rs`.

### `<acceptance_criteria>`

- [ ] `PolicyStore::new(pool)` is called with `Arc::clone(&pool)` after the AD client init
- [ ] Startup failure (map_err) if policy store load fails — server does NOT start with an empty cache silently
- [ ] `state.policy_store` is set in `AppState` construction
- [ ] Background refresh task spawns with `tokio::spawn`, loops on `tokio::time::interval`
- [ ] `tokio::time::Duration::from_secs(refresh_interval_secs)` is used (not `std::time::Duration`)
- [ ] `cargo build -p dlp-server` — no warnings, no errors
- [ ] `cargo build -p dlp-server --release` — no warnings, no errors

---

## Task 2.3 — Unit tests for `PolicyStore` (inline in `policy_store.rs`)

### Purpose

Validate condition matching, default-deny logic, and cache invalidation without needing a running server. Tests are placed in Wave 2 (not hidden) so they are visible and trackable immediately.

### `<read_first>`

```
dlp-server/src/policy_store.rs              (the implementation to test)
dlp-common/src/abac.rs                      (EvaluateRequest builder helpers, Decision enum)
dlp-common/src/classification.rs           (Classification::T1..T4)
```

Read `Policy` and `EvaluateRequest` structs in `abac.rs` to understand how to construct test fixtures.

### `<action>`

Add the following tests as a `#[cfg(test)]` module at the bottom of `dlp-server/src/policy_store.rs`:

```rust
#[cfg(test)]
mod tests {
    use dlp_common::abac::{
        AccessContext, Classification, Decision, DeviceTrust, Environment,
        EvaluateRequest, EvaluateResponse, NetworkLocation, Policy,
        PolicyCondition, Resource, Subject,
    };
    use dlp_common::Classification;

    use super::*;

    /// Helper: build a minimal EvaluateRequest for testing.
    fn make_request(
        classification: Classification,
        groups: Vec<String>,
        device_trust: DeviceTrust,
        network_location: NetworkLocation,
        access_context: AccessContext,
    ) -> EvaluateRequest {
        EvaluateRequest {
            subject: Subject {
                user_sid: "S-1-5-21-1".to_string(),
                username: "testuser".to_string(),
                display_name: "Test User".to_string(),
                email: None,
                groups,
                device_trust,
                network_location,
            },
            resource: Resource {
                path: r"C:\test\file.txt".to_string(),
                classification,
                file_fingerprint: None,
            },
            environment: Environment { access_context },
            action: dlp_common::abac::Action::READ,
            agent: None,
        }
    }

    /// Helper: build a Policy with a single Classification condition.
    fn classify_policy(id: &str, priority: u32, value: Classification, action: Decision) -> Policy {
        Policy {
            id: id.to_string(),
            name: id.to_string(),
            description: None,
            priority,
            conditions: vec![PolicyCondition::Classification {
                op: "eq".to_string(),
                value,
            }],
            action,
            enabled: true,
            version: 1,
        }
    }

    // ---- Tiered default-deny tests ----

    #[test]
    fn test_default_deny_t3() {
        let pool = Arc::new(crate::db::new_pool(":memory:").unwrap());
        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
        let request = make_request(
            Classification::T3,
            vec![],
            DeviceTrust::Unknown,
            NetworkLocation::Unknown,
            AccessContext::Local,
        );
        let resp = store.evaluate(&request);
        assert_eq!(resp.decision, Decision::DENY, "T3 with no policy must DENY");
        assert!(resp.matched_policy_id.is_none());
    }

    #[test]
    fn test_default_deny_t4() {
        let pool = Arc::new(crate::db::new_pool(":memory:").unwrap());
        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
        let request = make_request(
            Classification::T4,
            vec![],
            DeviceTrust::Unknown,
            NetworkLocation::Unknown,
            AccessContext::Local,
        );
        let resp = store.evaluate(&request);
        assert_eq!(resp.decision, Decision::DENY, "T4 with no policy must DENY");
    }

    #[test]
    fn test_default_allow_t1() {
        let pool = Arc::new(crate::db::new_pool(":memory:").unwrap());
        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
        let request = make_request(
            Classification::T1,
            vec![],
            DeviceTrust::Unknown,
            NetworkLocation::Unknown,
            AccessContext::Local,
        );
        let resp = store.evaluate(&request);
        assert_eq!(resp.decision, Decision::ALLOW, "T1 with no policy must ALLOW");
    }

    #[test]
    fn test_default_allow_t2() {
        let pool = Arc::new(crate::db::new_pool(":memory:").unwrap());
        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
        let request = make_request(
            Classification::T2,
            vec![],
            DeviceTrust::Unknown,
            NetworkLocation::Unknown,
            AccessContext::Local,
        );
        let resp = store.evaluate(&request);
        assert_eq!(resp.decision, Decision::ALLOW, "T2 with no policy must ALLOW");
    }

    // ---- Classification condition matching tests ----

    #[test]
    fn test_classification_eq_match() {
        let pool = Arc::new(crate::db::new_pool(":memory:").unwrap());
        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
        store.cache.write().push(classify_policy("p1", 1, Classification::T3, Decision::DENY));
        let request = make_request(
            Classification::T3,
            vec![],
            DeviceTrust::Unknown,
            NetworkLocation::Unknown,
            AccessContext::Local,
        );
        let resp = store.evaluate(&request);
        assert_eq!(resp.decision, Decision::DENY);
        assert_eq!(resp.matched_policy_id.as_deref(), Some("p1"));
    }

    #[test]
    fn test_classification_eq_no_match() {
        let pool = Arc::new(crate::db::new_pool(":memory:").unwrap());
        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
        store.cache.write().push(classify_policy("p1", 1, Classification::T3, Decision::DENY));
        let request = make_request(
            Classification::T1,
            vec![],
            DeviceTrust::Unknown,
            NetworkLocation::Unknown,
            AccessContext::Local,
        );
        let resp = store.evaluate(&request);
        // T1 with no other policy → ALLOW (default-allow)
        assert_eq!(resp.decision, Decision::ALLOW);
        assert!(resp.matched_policy_id.is_none());
    }

    #[test]
    fn test_classification_neq_match() {
        let pool = Arc::new(crate::db::new_pool(":memory:").unwrap());
        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
        store.cache.write().push(Policy {
            id: "p1".to_string(),
            name: "p1".to_string(),
            description: None,
            priority: 1,
            conditions: vec![PolicyCondition::Classification {
                op: "neq".to_string(),
                value: Classification::T4,
            }],
            action: Decision::ALLOW,
            enabled: true,
            version: 1,
        });
        let request = make_request(
            Classification::T1,
            vec![],
            DeviceTrust::Unknown,
            NetworkLocation::Unknown,
            AccessContext::Local,
        );
        let resp = store.evaluate(&request);
        assert_eq!(resp.decision, Decision::ALLOW);
        assert_eq!(resp.matched_policy_id.as_deref(), Some("p1"));
    }

    // ---- MemberOf condition matching tests ----

    #[test]
    fn test_memberof_in_match() {
        let pool = Arc::new(crate::db::new_pool(":memory:").unwrap());
        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
        store.cache.write().push(Policy {
            id: "p1".to_string(),
            name: "p1".to_string(),
            description: None,
            priority: 1,
            conditions: vec![PolicyCondition::MemberOf {
                op: "in".to_string(),
                group_sid: "S-1-5-21-512".to_string(),
            }],
            action: Decision::DENY,
            enabled: true,
            version: 1,
        });
        let request = make_request(
            Classification::T3,
            vec!["S-1-5-21-512".to_string(), "S-1-5-21-513".to_string()],
            DeviceTrust::Unknown,
            NetworkLocation::Unknown,
            AccessContext::Local,
        );
        let resp = store.evaluate(&request);
        assert_eq!(resp.decision, Decision::DENY);
        assert_eq!(resp.matched_policy_id.as_deref(), Some("p1"));
    }

    #[test]
    fn test_memberof_in_no_match() {
        let pool = Arc::new(crate::db::new_pool(":memory:").unwrap());
        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
        store.cache.write().push(Policy {
            id: "p1".to_string(),
            name: "p1".to_string(),
            description: None,
            priority: 1,
            conditions: vec![PolicyCondition::MemberOf {
                op: "in".to_string(),
                group_sid: "S-1-5-21-999".to_string(),
            }],
            action: Decision::DENY,
            enabled: true,
            version: 1,
        });
        let request = make_request(
            Classification::T3,
            vec!["S-1-5-21-512".to_string()],
            DeviceTrust::Unknown,
            NetworkLocation::Unknown,
            AccessContext::Local,
        );
        let resp = store.evaluate(&request);
        // T3 with no matching policy → default-deny
        assert_eq!(resp.decision, Decision::DENY);
        assert!(resp.matched_policy_id.is_none());
    }

    #[test]
    fn test_memberof_not_in_match() {
        let pool = Arc::new(crate::db::new_pool(":memory:").unwrap());
        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
        store.cache.write().push(Policy {
            id: "p1".to_string(),
            name: "p1".to_string(),
            description: None,
            priority: 1,
            conditions: vec![PolicyCondition::MemberOf {
                op: "not_in".to_string(),
                group_sid: "S-1-5-21-512".to_string(),
            }],
            action: Decision::ALLOW,
            enabled: true,
            version: 1,
        });
        // Subject NOT in the restricted group
        let request = make_request(
            Classification::T2,
            vec!["S-1-5-21-888".to_string()],
            DeviceTrust::Unknown,
            NetworkLocation::Unknown,
            AccessContext::Local,
        );
        let resp = store.evaluate(&request);
        assert_eq!(resp.decision, Decision::ALLOW);
    }

    // ---- First-match tests ----

    #[test]
    fn test_first_match_wins() {
        let pool = Arc::new(crate::db::new_pool(":memory:").unwrap());
        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
        // Insert in reverse priority order to verify they are NOT reordered.
        // The cache returned by PolicyStore::new is sorted by the SQL query
        // (ORDER BY priority ASC), so we push in order for clarity.
        store.cache.write().push(Policy {
            id: "p-high".to_string(),
            name: "high-priority".to_string(),
            description: None,
            priority: 1,
            conditions: vec![PolicyCondition::Classification {
                op: "eq".to_string(),
                value: Classification::T3,
            }],
            action: Decision::DENY,
            enabled: true,
            version: 1,
        });
        store.cache.write().push(Policy {
            id: "p-low".to_string(),
            name: "low-priority".to_string(),
            description: None,
            priority: 2,
            conditions: vec![PolicyCondition::Classification {
                op: "eq".to_string(),
                value: Classification::T3,
            }],
            action: Decision::AllowWithLog,
            enabled: true,
            version: 1,
        });
        let request = make_request(
            Classification::T3,
            vec![],
            DeviceTrust::Unknown,
            NetworkLocation::Unknown,
            AccessContext::Local,
        );
        let resp = store.evaluate(&request);
        // Priority 1 (lowest number) wins
        assert_eq!(resp.matched_policy_id.as_deref(), Some("p-high"));
        assert_eq!(resp.decision, Decision::DENY);
    }

    #[test]
    fn test_disabled_policy_skipped() {
        let pool = Arc::new(crate::db::new_pool(":memory:").unwrap());
        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
        store.cache.write().push(Policy {
            id: "p-disabled".to_string(),
            name: "disabled".to_string(),
            description: None,
            priority: 1,
            conditions: vec![PolicyCondition::Classification {
                op: "eq".to_string(),
                value: Classification::T3,
            }],
            action: Decision::ALLOW, // Would ALLOW if matched
            enabled: false,         // But it's disabled
            version: 1,
        });
        let request = make_request(
            Classification::T3,
            vec![],
            DeviceTrust::Unknown,
            NetworkLocation::Unknown,
            AccessContext::Local,
        );
        let resp = store.evaluate(&request);
        // T3 with no matching policy → default-deny
        assert_eq!(resp.decision, Decision::DENY);
        assert!(resp.matched_policy_id.is_none());
    }

    // ---- DeviceTrust / NetworkLocation / AccessContext condition tests ----

    #[test]
    fn test_device_trust_match() {
        let pool = Arc::new(crate::db::new_pool(":memory:").unwrap());
        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
        store.cache.write().push(Policy {
            id: "p1".to_string(),
            name: "p1".to_string(),
            description: None,
            priority: 1,
            conditions: vec![PolicyCondition::DeviceTrust {
                op: "eq".to_string(),
                value: DeviceTrust::Managed,
            }],
            action: Decision::ALLOW,
            enabled: true,
            version: 1,
        });
        let request = make_request(
            Classification::T2,
            vec![],
            DeviceTrust::Managed,
            NetworkLocation::Unknown,
            AccessContext::Local,
        );
        let resp = store.evaluate(&request);
        assert_eq!(resp.decision, Decision::ALLOW);
        assert_eq!(resp.matched_policy_id.as_deref(), Some("p1"));
    }

    #[test]
    fn test_network_location_match() {
        let pool = Arc::new(crate::db::new_pool(":memory:").unwrap());
        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
        store.cache.write().push(Policy {
            id: "p1".to_string(),
            name: "p1".to_string(),
            description: None,
            priority: 1,
            conditions: vec![PolicyCondition::NetworkLocation {
                op: "eq".to_string(),
                value: NetworkLocation::Corporate,
            }],
            action: Decision::DENY,
            enabled: true,
            version: 1,
        });
        let request = make_request(
            Classification::T3,
            vec![],
            DeviceTrust::Unknown,
            NetworkLocation::Corporate,
            AccessContext::Local,
        );
        let resp = store.evaluate(&request);
        assert_eq!(resp.decision, Decision::DENY);
    }

    #[test]
    fn test_access_context_match() {
        let pool = Arc::new(crate::db::new_pool(":memory:").unwrap());
        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
        store.cache.write().push(Policy {
            id: "p1".to_string(),
            name: "p1".to_string(),
            description: None,
            priority: 1,
            conditions: vec![PolicyCondition::AccessContext {
                op: "eq".to_string(),
                value: AccessContext::Smb,
            }],
            action: Decision::DENY,
            enabled: true,
            version: 1,
        });
        let request = make_request(
            Classification::T3,
            vec![],
            DeviceTrust::Unknown,
            NetworkLocation::Unknown,
            AccessContext::Smb,
        );
        let resp = store.evaluate(&request);
        assert_eq!(resp.decision, Decision::DENY);
    }

    // ---- in/not_in on scalar conditions returns false (defensive) ----

    #[test]
    fn test_in_op_on_classification_is_false() {
        let pool = Arc::new(crate::db::new_pool(":memory:").unwrap());
        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
        store.cache.write().push(Policy {
            id: "p1".to_string(),
            name: "p1".to_string(),
            description: None,
            priority: 1,
            conditions: vec![PolicyCondition::Classification {
                op: "in".to_string(),
                value: Classification::T3,
            }],
            action: Decision::DENY,
            enabled: true,
            version: 1,
        });
        let request = make_request(
            Classification::T3,
            vec![],
            DeviceTrust::Unknown,
            NetworkLocation::Unknown,
            AccessContext::Local,
        );
        let resp = store.evaluate(&request);
        // "in" on Classification returns false → policy doesn't match → default-deny (T3)
        assert_eq!(resp.decision, Decision::DENY);
        assert!(resp.matched_policy_id.is_none());
    }

    // ---- refresh / invalidate tests ----

    #[test]
    fn test_invalidate_reloads_cache() {
        let pool = Arc::new(crate::db::new_pool(":memory:").unwrap());

        // Insert a policy directly into the DB before creating the store.
        {
            let conn = pool.get().unwrap();
            conn.execute(
                "INSERT INTO policies (id, name, priority, conditions, action, enabled, version, updated_at) \
                 VALUES ('initial', 'initial', 1, '[]', 'Allow', 1, 1, '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }

        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();
        assert_eq!(store.list_policies().len(), 1);

        // Insert another policy directly in the DB.
        {
            let conn = pool.get().unwrap();
            conn.execute(
                "INSERT INTO policies (id, name, priority, conditions, action, enabled, version, updated_at) \
                 VALUES ('second', 'second', 2, '[]', 'Deny', 1, 1, '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }

        store.invalidate();
        assert_eq!(store.list_policies().len(), 2);
    }

    #[test]
    fn test_refresh_reloads_cache() {
        let pool = Arc::new(crate::db::new_pool(":memory:").unwrap());

        {
            let conn = pool.get().unwrap();
            conn.execute(
                "INSERT INTO policies (id, name, priority, conditions, action, enabled, version, updated_at) \
                 VALUES ('initial', 'initial', 1, '[]', 'Allow', 1, 1, '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }

        let store = PolicyStore::new(Arc::clone(&pool)).unwrap();

        {
            let conn = pool.get().unwrap();
            conn.execute(
                "INSERT INTO policies (id, name, priority, conditions, action, enabled, version, updated_at) \
                 VALUES ('second', 'second', 2, '[]', 'Deny', 1, 1, '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }

        store.refresh();
        assert_eq!(store.list_policies().len(), 2);
    }
}
```

### `<acceptance_criteria>`

- [ ] `#[cfg(test)]` module present at bottom of `policy_store.rs`
- [ ] `cargo test -p dlp-server policy_store::tests` — all tests pass
- [ ] `cargo test -p dlp-server` — no test regressions
- [ ] `cargo clippy -p dlp-server -- -D warnings` — no warnings
