//! Password + JWT authentication for admin users (P5-T03).
//!
//! Provides login (bcrypt verify + JWT issuance) and admin user
//! provisioning at startup.  There is no HTTP endpoint for creating
//! admin users — the admin account is set up interactively when
//! dlp-server first starts, or non-interactively via `--init-admin`.
//!
//! TOTP/MFA support is deferred to a future iteration.

use std::sync::Arc;

use axum::extract::State;
use axum::http::header;
use axum::middleware::Next;
use axum::response::Response;
use axum::Json;
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::audit_store;
use crate::db::repositories::{AdminUserRepository, CredentialsRepository};
use crate::db::UnitOfWork;
use crate::AppError;
use crate::AppState;
use dlp_common;

/// Axum extractor that yields the verified admin username.
///
/// The username is placed in request extensions by `require_auth` middleware
/// after JWT verification succeeds. This extractor reads it back out.
///
/// # Errors
///
/// Returns `AppError::Unauthorized` if the request extensions are absent
/// (i.e. the request did not pass through `require_auth`).
#[derive(Clone)]
pub struct AdminUsername(pub String);

impl AdminUsername {
    /// Extracts the verified admin username from the request headers.
    ///
    /// Called inline in handlers that consumed the request body as `Json`. Uses the
    /// same JWT verification logic as `require_auth` middleware.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Unauthorized` if the token is missing, malformed, or invalid.
    pub fn extract_from_headers(headers: &axum::http::HeaderMap) -> Result<String, AppError> {
        let auth_header = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("invalid Authorization format".to_string()))?;
        let claims = verify_jwt(token)?;
        Ok(claims.sub)
    }
}

/// Insecure fallback secret used only when `--dev` is active.
const DEV_JWT_SECRET: &str = "dlp-server-dev-secret-change-me";

/// Resolves the JWT signing secret from the encrypted DB row, falling
/// back to a one-shot env-var migration and (in dev mode) the insecure
/// dev secret.
///
/// Control flow (Phase 47 Task 47-06 — Wave 4 canonical entry point):
///
/// 1. Try `jwt_secret::get(conn)`. If the encrypted row exists, decrypt
///    and return — the env var is no longer needed once the DB row is
///    seeded.
/// 2. Else: if `JWT_SECRET` env var is set and non-empty, encrypt +
///    insert into `secrets_jwt`, emit a one-shot `tracing::warn!`
///    deprecation notice, and return the plaintext as `SecretString`.
///    NOTE: in steady-state production, the Task 47-06 startup
///    [`crate::secrets_migration::migrate_secrets_to_encrypted`] flow
///    has already seeded the row before this function runs, so the
///    env-var branch only fires on a server that was started for the
///    first time WITHOUT the migration step (e.g., a test that builds
///    AppState directly).
/// 3. Else: if `dev_mode == true`, return the `DEV_JWT_SECRET` fallback
///    without writing anything to the DB (dev mode keeps the database
///    pristine for ephemeral test runs).
/// 4. Else: production with neither DB row nor env var — return the
///    typed error message.
///
/// # Arguments
///
/// * `pool` — connection pool used both for the SELECT and the
///   first-run INSERT (steps 1 and 2).
/// * `crypto` — active KEK handle. Decryption (step 1) and encryption
///   (step 2) both run under this version.
/// * `dev_mode` — set to true for `--dev`. When true, step 3 fires
///   instead of the production error.
///
/// # Errors
///
/// Returns a human-readable error string suitable for surfacing as a
/// startup failure message. Database / DPAPI errors are wrapped with a
/// short context line so the operator can grep for them.
pub fn resolve_jwt_secret(
    pool: &crate::db::Pool,
    crypto: &crate::crypto::SecretCrypto,
    dev_mode: bool,
) -> Result<secrecy::SecretString, String> {
    use crate::crypto::{aad_for, Envelope};
    use crate::db::repositories::jwt_secret;

    let conn = pool
        .get()
        .map_err(|e| format!("acquire connection for JWT secret read: {e}"))?;

    // Step 1: encrypted DB row already exists -> decrypt and return.
    if let Some((envelope, _kek_version)) =
        jwt_secret::get(&conn).map_err(|e| format!("read secrets_jwt: {e}"))?
    {
        let aad = aad_for("secrets_jwt", "secret");
        let plaintext = crypto
            .decrypt(&envelope, &aad)
            .map_err(|_| "decrypt failed for secrets_jwt.secret (KEK mismatch?)".to_string())?;
        return Ok(plaintext);
    }
    // Explicit drop so the immutable borrow ends before any later write.
    drop(conn);

    // Step 2: env var present -> migrate into encrypted DB row.
    if let Ok(env_value) = std::env::var("JWT_SECRET") {
        if !env_value.is_empty() {
            let aad = aad_for("secrets_jwt", "secret");
            let envelope: Envelope = crypto
                .encrypt(env_value.as_bytes(), &aad)
                .map_err(|_| "encrypt failed for secrets_jwt.secret".to_string())?;
            let conn = pool
                .get()
                .map_err(|e| format!("acquire connection for JWT secret write: {e}"))?;
            jwt_secret::upsert_encrypted(&conn, &envelope, crypto.version(), chrono::Utc::now())
                .map_err(|e| format!("upsert secrets_jwt: {e}"))?;
            tracing::warn!(
                "JWT_SECRET env-var migrated into encrypted DB row; the env var is no \
                 longer required and will be ignored on future startups"
            );
            return Ok(secrecy::SecretString::new(env_value));
        }
    }

    // Step 3: dev-mode fallback — never writes to the DB.
    if dev_mode {
        tracing::warn!(
            "JWT_SECRET not set and no encrypted DB row — using insecure dev secret \
             (--dev mode). Do NOT use --dev in production!"
        );
        return Ok(secrecy::SecretString::new(DEV_JWT_SECRET.to_string()));
    }

    // Step 4: production failure.
    Err("JWT secret not configured.\n\
         Set JWT_SECRET environment variable on first startup, or use --dev for development:\n\n\
         \x20 export JWT_SECRET=\"your-secure-random-secret\"\n\
         \x20 dlp-server.exe\n\n\
         Or for development only:\n\n\
         \x20 dlp-server.exe --dev"
        .to_string())
}

/// Process-wide JWT secret, set once at startup via [`resolve_jwt_secret`].
///
/// All JWT operations read from this static instead of re-reading the
/// env var on every request.
static JWT_SECRET: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Stores the resolved JWT secret for the process lifetime.
///
/// Must be called once at startup before serving requests.
pub fn set_jwt_secret(secret: String) {
    if JWT_SECRET.set(secret).is_err() {
        tracing::warn!("JWT secret already set — ignoring duplicate call");
    }
}

/// Returns the JWT secret. Panics if [`set_jwt_secret`] was not called.
fn jwt_secret() -> &'static str {
    JWT_SECRET
        .get()
        .expect("JWT secret not initialized — call set_jwt_secret() at startup")
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Login credentials submitted by an admin user.
#[derive(Debug, Clone, Deserialize)]
pub struct LoginRequest {
    /// Admin username.
    pub username: String,
    /// Plaintext password (transmitted over TLS).
    pub password: String,
}

/// Successful login response containing a JWT bearer token.
#[derive(Debug, Clone, Serialize)]
pub struct TokenResponse {
    /// JWT bearer token.
    pub token: String,
    /// Token expiry as ISO 8601 timestamp.
    pub expires_at: String,
}

/// JWT claims embedded in every issued token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — the admin username.
    pub sub: String,
    /// Expiration time (Unix epoch seconds).
    pub exp: usize,
    /// Issuer.
    pub iss: String,
    /** User SID (from AD lookup). Optional for local admin accounts. */
    pub sid: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /auth/login` — authenticate an admin user and issue a JWT.
///
/// # Errors
///
/// Returns `AppError::Unauthorized` if credentials are invalid.
/// Returns `AppError::Database` on SQLite failures.
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(creds): Json<LoginRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let username = creds.username.clone();

    // Fetch the stored password hash from SQLite.
    let hash: String = {
        let pool = Arc::clone(&state.pool);
        let uname = username.clone();
        tokio::task::spawn_blocking(move || -> Result<String, AppError> {
            let hash =
                AdminUserRepository::get_password_hash(&pool, &uname).map_err(AppError::from)?;
            Ok(hash)
        })
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))?
        .map_err(|_| AppError::Unauthorized("invalid credentials".to_string()))?
    };

    // Verify the password against the bcrypt hash (CPU-bound).
    let password = creds.password.clone();
    let valid =
        tokio::task::spawn_blocking(move || bcrypt::verify(password, &hash).unwrap_or(false))
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))?;

    if !valid {
        return Err(AppError::Unauthorized("invalid credentials".to_string()));
    }

    // Issue a JWT with 24-hour expiry.
    let expires_at = Utc::now() + chrono::Duration::hours(24);
    let claims = Claims {
        sub: username,
        exp: expires_at.timestamp() as usize,
        iss: "dlp-server".to_string(),
        sid: None,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret().as_bytes()),
    )
    .map_err(|e| AppError::Internal(anyhow::anyhow!("jwt encode error: {e}")))?;

    tracing::info!(user = %claims.sub, "admin login successful");

    Ok(Json(TokenResponse {
        token,
        expires_at: expires_at.to_rfc3339(),
    }))
}

// ---------------------------------------------------------------------------
// Change password handler (JWT-protected)
// ---------------------------------------------------------------------------

/// Payload for changing the admin password.
#[derive(Debug, Clone, Deserialize)]
pub struct ChangePasswordRequest {
    /// Current password (for re-verification).
    pub current_password: String,
    /// New password.
    pub new_password: String,
}

/// `PUT /auth/password` — change the current admin's password (JWT required).
///
/// Re-verifies the current password before accepting the change.
pub async fn change_password(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Extract the username from the JWT token.
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("invalid Authorization format".to_string()))?;
    let claims = verify_jwt(token)?;
    let username = claims.sub;

    // Parse the body.
    let body = axum::body::to_bytes(req.into_body(), 1024 * 64)
        .await
        .map_err(|e| AppError::BadRequest(format!("failed to read body: {e}")))?;
    let payload: ChangePasswordRequest = serde_json::from_slice(&body)?;

    if payload.new_password.is_empty() {
        return Err(AppError::BadRequest(
            "new password cannot be empty".to_string(),
        ));
    }

    // Verify the current password.
    let pool2 = Arc::clone(&state.pool);
    let uname = username.clone();
    let current_hash: String = tokio::task::spawn_blocking(move || -> Result<String, AppError> {
        let hash =
            AdminUserRepository::get_password_hash(&pool2, &uname).map_err(AppError::from)?;
        Ok(hash)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))?
    .map_err(|_| AppError::Unauthorized("user not found".to_string()))?;

    let current_pw = payload.current_password.clone();
    let valid = tokio::task::spawn_blocking(move || {
        bcrypt::verify(current_pw, &current_hash).unwrap_or(false)
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))?;

    if !valid {
        return Err(AppError::Unauthorized(
            "current password is incorrect".to_string(),
        ));
    }

    // Hash the new password and update.
    let new_pw = payload.new_password.clone();
    let new_hash = tokio::task::spawn_blocking(move || bcrypt::hash(new_pw, 12))
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))?
        .map_err(|e| AppError::Internal(anyhow::anyhow!("bcrypt error: {e}")))?;

    let uname = username.clone();
    let pool = Arc::clone(&state.pool);
    let ts = Utc::now().to_rfc3339();
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = UnitOfWork::new(&mut conn).map_err(AppError::from)?;
        AdminUserRepository::update_password_hash(&uow, &uname, &new_hash)
            .map_err(AppError::from)?;
        CredentialsRepository::upsert(&uow, "DLPAuthHash", &new_hash, &ts)
            .map_err(AppError::from)?;
        uow.commit().map_err(AppError::from)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    // Emit admin audit event after successful password update.
    let audit_event = dlp_common::AuditEvent::new(
        dlp_common::EventType::AdminAction,
        String::new(),
        username.clone(),
        format!("password_change:{}", username),
        dlp_common::Classification::T3,
        dlp_common::Action::PasswordChange,
        dlp_common::Decision::ALLOW,
        "server".to_string(),
        0,
    );
    let pool = Arc::clone(&state.pool);
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut conn = pool.get().map_err(AppError::from)?;
        let uow = crate::db::UnitOfWork::new(&mut conn).map_err(AppError::from)?;
        audit_store::store_events_sync(&uow, &[audit_event])?;
        uow.commit().map_err(AppError::from)?;
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))??;

    tracing::info!(user = %username, "admin password changed");
    Ok(Json(serde_json::json!({ "status": "password changed" })))
}

// ---------------------------------------------------------------------------
// Admin user provisioning (startup-only, no HTTP endpoint)
// ---------------------------------------------------------------------------

/// Returns `true` if at least one admin user exists in the database.
///
/// Called during server startup to decide whether to prompt for initial
/// admin credentials.
pub fn has_admin_users(pool: &crate::db::Pool) -> anyhow::Result<bool> {
    AdminUserRepository::has_any(pool)
        .map_err(|e| anyhow::anyhow!("failed to query admin_users: {e}"))
}

/// Creates a new admin user with the given username and plaintext password.
///
/// The password is bcrypt-hashed (cost 12) before storage. This function
/// is called during server startup — it is NOT exposed as an HTTP endpoint.
///
/// # Errors
///
/// Returns an error if bcrypt hashing or the database insert fails.
pub fn create_admin_user(
    pool: &crate::db::Pool,
    username: &str,
    password: &str,
) -> anyhow::Result<()> {
    let hash =
        bcrypt::hash(password, 12).map_err(|e| anyhow::anyhow!("bcrypt hash failed: {e}"))?;
    let now = Utc::now().to_rfc3339();

    let mut conn = pool.get()?;
    let uow = crate::db::UnitOfWork::new(&mut conn)
        .map_err(|e| anyhow::anyhow!("transaction failed: {e}"))?;
    AdminUserRepository::insert(&uow, username, &hash, &now)
        .map_err(|e| anyhow::anyhow!("failed to insert admin user: {e}"))?;
    CredentialsRepository::upsert(&uow, "DLPAuthHash", &hash, &now)
        .map_err(|e| anyhow::anyhow!("failed to upsert agent auth hash: {e}"))?;
    uow.commit()
        .map_err(|e| anyhow::anyhow!("commit failed: {e}"))?;

    tracing::info!(user = %username, "admin user created");
    Ok(())
}

/// Verifies a JWT token string and returns the decoded claims.
///
/// # Arguments
///
/// * `token` - The raw JWT string (without "Bearer " prefix).
///
/// # Errors
///
/// Returns `AppError::Unauthorized` if the token is invalid or expired.
pub fn verify_jwt(token: &str) -> Result<Claims, AppError> {
    let mut validation = Validation::default();
    validation.set_issuer(&["dlp-server"]);

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret().as_bytes()),
        &validation,
    )
    .map_err(|e| AppError::Unauthorized(format!("invalid token: {e}")))?;

    Ok(token_data.claims)
}

/// Axum middleware that requires a valid JWT Bearer token on every request.
///
/// Extracts the `Authorization: Bearer <token>` header, verifies it,
/// and rejects the request with 401 if invalid.
pub async fn require_auth(
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, AppError> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("invalid Authorization header format".to_string()))?;

    let claims = verify_jwt(token)?;

    let mut req = req;
    req.extensions_mut().insert(claims.sub.clone());
    req.extensions_mut().insert(claims.sid);

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ensures the JWT secret is initialized for tests.
    /// Safe to call from multiple tests — `OnceLock::set` is a no-op
    /// after the first successful call.
    fn ensure_test_secret() {
        let _ = JWT_SECRET.set(DEV_JWT_SECRET.to_string());
    }

    #[test]
    fn test_jwt_round_trip() {
        ensure_test_secret();
        let claims = Claims {
            sub: "admin".to_string(),
            exp: (Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            iss: "dlp-server".to_string(),
            sid: None,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(jwt_secret().as_bytes()),
        )
        .expect("encode JWT");

        let decoded = verify_jwt(&token).expect("verify JWT");
        assert_eq!(decoded.sub, "admin");
        assert_eq!(decoded.iss, "dlp-server");
    }

    #[test]
    fn test_expired_token_rejected() {
        ensure_test_secret();
        let claims = Claims {
            sub: "admin".to_string(),
            // Expired 1 hour ago.
            exp: (Utc::now() - chrono::Duration::hours(1)).timestamp() as usize,
            iss: "dlp-server".to_string(),
            sid: None,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(jwt_secret().as_bytes()),
        )
        .expect("encode JWT");

        let result = verify_jwt(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_token_rejected() {
        ensure_test_secret();
        let result = verify_jwt("not.a.valid.token");
        assert!(result.is_err());
    }

    #[test]
    fn test_login_request_serde() {
        let json = r#"{"username":"admin","password":"secret"}"#;
        let req: LoginRequest = serde_json::from_str(json).expect("deserialize");
        assert_eq!(req.username, "admin");
    }

    // -----------------------------------------------------------------------
    // Phase 47 Task 47-05 / 47-06: resolve_jwt_secret tests
    // -----------------------------------------------------------------------
    //
    // These tests mutate the process environment (`JWT_SECRET`). `std::env::set_var`
    // is documented as unsafe-with-respect-to-multithreading; we serialize the
    // four tests below behind a process-wide mutex so the threaded cargo test
    // runner doesn't race them.

    use crate::crypto::{SecretCrypto, ENVELOPE_VERSION_V1};
    use crate::db::new_pool;
    use secrecy::ExposeSecret;

    const RESOLVE_TEST_KEK: [u8; 32] = [
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55,
    ];

    fn resolve_test_crypto() -> SecretCrypto {
        SecretCrypto::from_kek(RESOLVE_TEST_KEK, ENVELOPE_VERSION_V1)
    }

    /// Process-wide serialization for the JWT-env-var tests. Two
    /// concurrently-running tests would race on `set_var("JWT_SECRET", ...)`.
    static JWT_ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn resolve_jwt_with_crypto_migrates_env_var_into_db() {
        let _guard = JWT_ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // SAFETY: env-var mutation is gated by JWT_ENV_TEST_LOCK above and
        // the test binary is the only consumer; no concurrent reads.
        unsafe { std::env::set_var("JWT_SECRET", "env-var-XYZ") };

        let pool = new_pool(":memory:").expect("create pool");
        let crypto = resolve_test_crypto();

        // First call: no DB row, env var present -> migrate.
        let secret = resolve_jwt_secret(&pool, &crypto, false).expect("first resolve");
        assert_eq!(secret.expose_secret(), "env-var-XYZ");

        // DB row must now exist.
        let conn = pool.get().expect("acquire connection");
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM secrets_jwt", [], |r| r.get(0))
            .expect("count");
        assert_eq!(n, 1, "first resolve must seed the encrypted DB row");
        drop(conn);

        // Second call with env-var cleared: read from DB.
        unsafe { std::env::remove_var("JWT_SECRET") };
        let secret2 = resolve_jwt_secret(&pool, &crypto, false).expect("second resolve");
        assert_eq!(
            secret2.expose_secret(),
            "env-var-XYZ",
            "second resolve must read from DB, env var no longer needed"
        );
    }

    #[test]
    fn resolve_jwt_with_crypto_dev_mode_fallback_does_not_write_db() {
        let _guard = JWT_ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("JWT_SECRET") };

        let pool = new_pool(":memory:").expect("create pool");
        let crypto = resolve_test_crypto();

        let secret = resolve_jwt_secret(&pool, &crypto, true).expect("dev resolve");
        assert_eq!(secret.expose_secret(), DEV_JWT_SECRET);

        let conn = pool.get().expect("acquire connection");
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM secrets_jwt", [], |r| r.get(0))
            .expect("count");
        assert_eq!(n, 0, "dev-mode fallback must NOT write secrets_jwt");
    }

    #[test]
    fn resolve_jwt_with_crypto_production_without_env_returns_error() {
        let _guard = JWT_ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("JWT_SECRET") };

        let pool = new_pool(":memory:").expect("create pool");
        let crypto = resolve_test_crypto();

        let err = resolve_jwt_secret(&pool, &crypto, false)
            .expect_err("production w/o env w/o DB row must fail");
        assert!(
            err.contains("JWT secret not configured"),
            "expected typed error; got: {err}"
        );
    }

    #[test]
    fn resolve_jwt_with_crypto_prefers_db_over_env_var() {
        // Once the DB row exists, the env var is silently ignored — this
        // is the post-migration steady state per the deprecation warn.
        let _guard = JWT_ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let pool = new_pool(":memory:").expect("create pool");
        let crypto = resolve_test_crypto();

        // Seed the DB row with one value.
        unsafe { std::env::set_var("JWT_SECRET", "first-value") };
        let _ = resolve_jwt_secret(&pool, &crypto, false).expect("seed");

        // Now change the env var; resolve must return the DB value, not env.
        unsafe { std::env::set_var("JWT_SECRET", "different-value") };
        let secret = resolve_jwt_secret(&pool, &crypto, false).expect("second resolve");
        assert_eq!(
            secret.expose_secret(),
            "first-value",
            "DB row must win over env var"
        );

        unsafe { std::env::remove_var("JWT_SECRET") };
    }
}

#[allow(clippy::items_after_test_module)]
// Temporary extension trait for SID extraction
pub trait AdminSidExt {
    fn extract_sid_from_headers(
        headers: &axum::http::HeaderMap,
    ) -> Result<Option<String>, AppError>;
}

impl AdminSidExt for AdminUsername {
    fn extract_sid_from_headers(
        headers: &axum::http::HeaderMap,
    ) -> Result<Option<String>, AppError> {
        let auth_header = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("invalid Authorization format".to_string()))?;
        let claims = verify_jwt(token)?;
        Ok(claims.sid)
    }
}
