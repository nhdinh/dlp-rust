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
use jsonwebtoken::{
    decode, encode, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};

use crate::db::Database;
use crate::AppError;

/// Insecure fallback secret used only when `--dev` is active.
const DEV_JWT_SECRET: &str = "dlp-server-dev-secret-change-me";

/// Resolves the JWT signing secret.
///
/// - If `JWT_SECRET` env var is set, uses it.
/// - If `dev_mode` is true and env var is absent, uses an insecure fallback.
/// - Otherwise returns an error (server should refuse to start).
///
/// # Errors
///
/// Returns an error message if `JWT_SECRET` is not set and `dev_mode` is false.
pub fn resolve_jwt_secret(dev_mode: bool) -> Result<String, String> {
    match std::env::var("JWT_SECRET") {
        Ok(s) if !s.is_empty() => Ok(s),
        _ if dev_mode => {
            tracing::warn!(
                "JWT_SECRET not set — using insecure dev secret (--dev mode). \
                 Do NOT use --dev in production!"
            );
            Ok(DEV_JWT_SECRET.to_string())
        }
        _ => Err(
            "JWT_SECRET environment variable is required.\n\
             Set it before starting the server, or use --dev for development:\n\n\
             \x20 export JWT_SECRET=\"your-secure-random-secret\"\n\
             \x20 dlp-server.exe\n\n\
             Or for development only:\n\n\
             \x20 dlp-server.exe --dev"
                .to_string(),
        ),
    }
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
    State(db): State<Arc<Database>>,
    Json(creds): Json<LoginRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let username = creds.username.clone();

    // Fetch the stored password hash from SQLite.
    let hash: String = {
        let db = Arc::clone(&db);
        let uname = username.clone();
        tokio::task::spawn_blocking(move || {
            let conn = db.conn().lock();
            conn.query_row(
                "SELECT password_hash FROM admin_users \
                 WHERE username = ?1",
                rusqlite::params![uname],
                |row| row.get::<_, String>(0),
            )
        })
        .await
        .map_err(|e| {
            AppError::Internal(anyhow::anyhow!("join error: {e}"))
        })?
        .map_err(|_| {
            AppError::Unauthorized("invalid credentials".to_string())
        })?
    };

    // Verify the password against the bcrypt hash (CPU-bound).
    let password = creds.password.clone();
    let valid = tokio::task::spawn_blocking(move || {
        bcrypt::verify(password, &hash).unwrap_or(false)
    })
    .await
    .map_err(|e| {
        AppError::Internal(anyhow::anyhow!("join error: {e}"))
    })?;

    if !valid {
        return Err(AppError::Unauthorized(
            "invalid credentials".to_string(),
        ));
    }

    // Issue a JWT with 24-hour expiry.
    let expires_at = Utc::now() + chrono::Duration::hours(24);
    let claims = Claims {
        sub: username,
        exp: expires_at.timestamp() as usize,
        iss: "dlp-server".to_string(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret().as_bytes()),
    )
    .map_err(|e| {
        AppError::Internal(anyhow::anyhow!("jwt encode error: {e}"))
    })?;

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
    State(db): State<Arc<Database>>,
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
        return Err(AppError::BadRequest("new password cannot be empty".to_string()));
    }

    // Verify the current password.
    let db2 = Arc::clone(&db);
    let uname = username.clone();
    let current_hash: String = tokio::task::spawn_blocking(move || {
        let conn = db2.conn().lock();
        conn.query_row(
            "SELECT password_hash FROM admin_users WHERE username = ?1",
            rusqlite::params![uname],
            |row| row.get::<_, String>(0),
        )
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
        return Err(AppError::Unauthorized("current password is incorrect".to_string()));
    }

    // Hash the new password and update.
    let new_pw = payload.new_password.clone();
    let new_hash = tokio::task::spawn_blocking(move || bcrypt::hash(new_pw, 12))
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("join error: {e}")))?
        .map_err(|e| AppError::Internal(anyhow::anyhow!("bcrypt error: {e}")))?;

    let uname = username.clone();
    tokio::task::spawn_blocking(move || {
        let conn = db.conn().lock();
        conn.execute(
            "UPDATE admin_users SET password_hash = ?1 WHERE username = ?2",
            rusqlite::params![new_hash, uname],
        )
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
pub fn has_admin_users(db: &Database) -> anyhow::Result<bool> {
    let conn = db.conn().lock();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM admin_users", [], |row| row.get(0))
        .map_err(|e| anyhow::anyhow!("failed to query admin_users: {e}"))?;
    Ok(count > 0)
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
    db: &Database,
    username: &str,
    password: &str,
) -> anyhow::Result<()> {
    let hash = bcrypt::hash(password, 12)
        .map_err(|e| anyhow::anyhow!("bcrypt hash failed: {e}"))?;
    let now = Utc::now().to_rfc3339();

    let conn = db.conn().lock();
    conn.execute(
        "INSERT INTO admin_users (username, password_hash, created_at) \
         VALUES (?1, ?2, ?3)",
        rusqlite::params![username, hash, now],
    )
    .map_err(|e| anyhow::anyhow!("failed to insert admin user: {e}"))?;

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
    .map_err(|e| {
        AppError::Unauthorized(format!("invalid token: {e}"))
    })?;

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
        .ok_or_else(|| {
            AppError::Unauthorized(
                "missing Authorization header".to_string(),
            )
        })?;

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        AppError::Unauthorized(
            "invalid Authorization header format".to_string(),
        )
    })?;

    verify_jwt(token)?;

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
            exp: (Utc::now() + chrono::Duration::hours(1))
                .timestamp() as usize,
            iss: "dlp-server".to_string(),
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
            exp: (Utc::now() - chrono::Duration::hours(1))
                .timestamp() as usize,
            iss: "dlp-server".to_string(),
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
        let req: LoginRequest =
            serde_json::from_str(json).expect("deserialize");
        assert_eq!(req.username, "admin");
    }
}
