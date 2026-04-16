---
wave: 3
depends_on: [wave2]
order: 3
description: Wire POST /evaluate into admin_router, add cache invalidation to CRUD handlers, and delete the orphaned policy_api.rs.
files_modified:
  - dlp-server/src/admin_api.rs      (modify)
  - dlp-server/src/policy_api.rs    (delete)
---

# Wave 3: Evaluation Endpoint and Admin API Integration

## Objective

Wire `POST /evaluate` into the `admin_router`, add cache invalidation calls to all three policy CRUD handlers, and delete the orphaned `policy_api.rs`.

---

## Task 3.1 — Add `POST /evaluate` route to `admin_router`

### Purpose

`POST /evaluate` is the ABAC evaluation endpoint called by agents. It requires no JWT auth (agents identify themselves via `AgentInfo` in the request body). It is added to the **public routes** section of `admin_router`.

### `<read_first>`

```
dlp-server/src/admin_api.rs                              (admin_router function, lines 350–421)
dlp-server/src/policy_api.rs                            (evaluate_handler function to copy, lines 57–91)
dlp-server/src/policy_store.rs                          (PolicyStore::evaluate signature — synchronous)
```

Read the `admin_router` function in `admin_api.rs` lines 350–421 — note the `public_routes` and `protected_routes` sections and the `.merge()` pattern.

Read the `evaluate_handler` in `policy_api.rs` lines 68–91 — copy this function (adapted) into `admin_api.rs`.

Read `PolicyStore::evaluate` in `policy_store.rs` to confirm it is **synchronous** (`&self`, not `&self` + `async`).

### `<action>`

In `dlp-server/src/admin_api.rs`:

1. Add the import for `EvaluateRequest` and `EvaluateResponse` from `dlp_common::abac` at the top of the file (near the existing `use` statements):

   ```rust
   use dlp_common::abac::{EvaluateRequest, EvaluateResponse};
   ```

2. Add the `evaluate_handler` function as a private helper in `admin_api.rs`. Place it in the Policy CRUD section (near line 453) or near the top of the file after imports. The handler must:
   - Accept `State<Arc<AppState>>` and `Json<EvaluateRequest>`
   - Call `state.policy_store.evaluate(&request)` — **synchronous, no `.await`**
   - Return `Result<Json<EvaluateResponse>, AppError>`
   - Be annotated `async` for axum compatibility

   ```rust
   /// Evaluates an ABAC access request against the loaded policy set.
   ///
   /// `POST /evaluate` — intentionally unauthenticated.
   /// Agent identity is established by `AgentInfo` in the request body.
   /// See 11-CONTEXT.md § Q1 for the auth decision.
   async fn evaluate_handler(
       State(state): State<Arc<AppState>>,
       Json(request): Json<EvaluateRequest>,
   ) -> Result<Json<EvaluateResponse>, AppError> {
       let agent_id = request
           .agent
           .as_ref()
           .map(|a| {
               format!(
                   "{}\\{}",
                   a.machine_name.as_deref().unwrap_or("unknown"),
                   a.current_user.as_deref().unwrap_or("unknown"),
               )
           })
           .unwrap_or_else(|| "unknown".to_string());

       info!(
           agent_id = %agent_id,
           resource_classification = ?request.resource.classification,
           "policy evaluation request"
       );

       // NOTE: evaluate() is synchronous — no .await here.
       let response = state.policy_store.evaluate(&request);
       Ok(Json(response))
   }
   ```

3. Add `POST /evaluate` to the `public_routes` `Router::new()` in `admin_router()`. The replacement must preserve all existing routes — only add the new line:

   ```rust
   let public_routes = Router::new()
       .route("/health", get(health))
       .route("/ready", get(ready))
       .route("/evaluate", post(evaluate_handler))  // ← add this line
       .route("/auth/login", post(admin_auth::login).route_layer(rate_limiter::strict_config()))
       .route("/agents/register", post(agent_registry::register_agent))
       .route(
           "/agents/{id}/heartbeat",
           post(agent_registry::heartbeat).route_layer(rate_limiter::moderate_config()),
       )
       .route(
           "/audit/events",
           post(audit_store::ingest_events).route_layer(rate_limiter::per_agent_config()),
       )
       .route("/agent-credentials/auth-hash", get(get_agent_auth_hash))
       .route("/agent-config/{id}", get(get_agent_config_for_agent));  // ← must be preserved
   ```

   All existing public routes must remain — verify `get_agent_config_for_agent` is present.

### `<acceptance_criteria>`

- [ ] `POST /evaluate` route added to `public_routes` in `admin_router`
- [ ] `evaluate_handler` is defined in `admin_api.rs` (not imported from `policy_api.rs`)
- [ ] `evaluate_handler` calls `state.policy_store.evaluate(&request)` — **no `.await`**
- [ ] `evaluate_handler` returns `Result<Json<EvaluateResponse>, AppError>`
- [ ] All existing public routes are preserved (verify `get_agent_config_for_agent` is present)
- [ ] `cargo build -p dlp-server` — no warnings, no errors

---

## Task 3.2 — Add cache invalidation to policy CRUD handlers

### Purpose

After every admin write to the `policies` table, the `PolicyStore` cache must be invalidated so the next evaluation request sees the updated policy set.

### `<read_first>`

```
dlp-server/src/admin_api.rs                    (create_policy, update_policy, delete_policy)
```

Read the end of `create_policy`, `update_policy`, and `delete_policy` to find where `uow.commit()` is called. Search for `uow.commit()` — add `state.policy_store.invalidate()` immediately after it (before any `.await` or audit event spawn).

### `<action>`

In `admin_api.rs`, find each handler and add `state.policy_store.invalidate()` **after the `uow.commit()` line** and **before the audit event spawn**.

Do NOT use specific line numbers — use structural search: look for `uow.commit()`. The pattern in each function is:

```
uow.commit().map_err(AppError::Database)?;
<-- insert invalidate() call here
let audit_event = spawn_blocking(...).await?;
```

**`create_policy`:** After `uow.commit().map_err(AppError::Database)?` succeeds, before the audit event spawn:
```rust
// After uow.commit().map_err(AppError::Database)?;
state.policy_store.invalidate();
```

**`update_policy`:** After `uow.commit().map_err(AppError::Database)?` succeeds, before the audit event spawn:
```rust
// After uow.commit().map_err(AppError::Database)?;
state.policy_store.invalidate();
```

**`delete_policy`:** After `uow.commit().map_err(AppError::Database)?` succeeds, before the audit event spawn:
```rust
// After uow.commit().map_err(AppError::Database)?;
state.policy_store.invalidate();
```

The call is synchronous — no `spawn_blocking` needed. The write lock is held only for the duration of the Vec swap.

### `<acceptance_criteria>`

- [ ] `create_policy` calls `state.policy_store.invalidate()` after DB commit succeeds
- [ ] `update_policy` calls `state.policy_store.invalidate()` after DB commit succeeds
- [ ] `delete_policy` calls `state.policy_store.invalidate()` after DB commit succeeds
- [ ] Invalidation is NOT inside `spawn_blocking` (it's an in-memory operation)
- [ ] Invalidation is placed AFTER `uow.commit()` and BEFORE the audit event spawn
- [ ] `cargo build -p dlp-server` — no warnings, no errors

---

## Task 3.3 — Delete `policy_api.rs`

### Purpose

The `policy_api.rs` file is orphaned (not declared in `lib.rs`, not compiled) and all its useful content has been moved into `admin_api.rs`. Delete it to avoid confusion and stale code.

Note: `policy_api.rs` contains CRUD handlers (`list_policies`, `create_policy`, `update_policy`, `delete_policy`, `get_policy`, `get_policy_versions`) that are **duplicates of the handlers already in `admin_api.rs`**. These duplicates reference `store.add_policy()`, `store.update_policy()`, etc. which do NOT exist on `PolicyStore` (PolicyStore only reads from DB; admin_api.rs handles all actual CRUD writes via `PolicyRepository`). These CRUD handlers were dead code that never compiled. Only `evaluate_handler` was salvageable — it has been moved to `admin_api.rs` in Task 3.1.

### `<read_first>`

```
dlp-server/src/policy_api.rs                          (file to be deleted — confirm CRUD handlers are duplicates)
dlp-server/src/admin_api.rs                            (confirm evaluate_handler was copied, Task 3.1)
dlp-server/src/lib.rs                                 (confirm policy_api is NOT declared here)
```

Confirm that `policy_api` does NOT appear in `lib.rs` (grep for `pub mod policy_api`).

### `<action>`

Delete `dlp-server/src/policy_api.rs`:

```bash
rm dlp-server/src/policy_api.rs
```

Or, if the executor cannot run shell commands, note in the plan that the file must be manually deleted.

After deletion, verify `cargo build -p dlp-server` still compiles without errors. The `router()` function and all its handlers from `policy_api.rs` are no longer needed.

### `<acceptance_criteria>`

- [ ] File `dlp-server/src/policy_api.rs` does not exist
- [ ] `lib.rs` does not contain `pub mod policy_api` or `mod policy_api`
- [ ] `cargo build -p dlp-server` — no warnings, no errors
- [ ] `cargo test -p dlp-server` — all tests pass
