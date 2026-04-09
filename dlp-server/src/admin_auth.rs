//! Password + JWT authentication for admin users (P5-T03).
//!
//! Provides login (bcrypt verify + JWT issuance) and admin user creation.
//! TOTP/MFA support is deferred to a future iteration.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
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

/// Secret used for HS256 JWT signing.
///
/// In production this MUST be loaded from an environment variable.
/// Falls back to a compile-time default **only** for development.
fn jwt_secret() -> String {
    std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "dlp-server-dev-secret-change-me".to_string())
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

/// Payload for creating a new admin user.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateAdminRequest {
    /// Desired username.
    pub username: String,
    /// Plaintext password (will be bcrypt-hashed before storage).
    pub password: String,
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

/// `POST /auth/admin` — create a new admin user (first-run setup).
///
/// The password is bcrypt-hashed before storage.
///
/// # Errors
///
/// Returns `AppError::BadRequest` if username/password are empty.
/// Returns `AppError::Database` on SQLite failures.
pub async fn create_admin(
    State(db): State<Arc<Database>>,
    Json(payload): Json<CreateAdminRequest>,
) -> Result<StatusCode, AppError> {
    if payload.username.is_empty() || payload.password.is_empty() {
        return Err(AppError::BadRequest(
            "username and password are required".to_string(),
        ));
    }

    // Hash the password (CPU-bound).
    let password = payload.password.clone();
    let hash = tokio::task::spawn_blocking(move || {
        bcrypt::hash(password, bcrypt::DEFAULT_COST)
    })
    .await
    .map_err(|e| {
        AppError::Internal(anyhow::anyhow!("join error: {e}"))
    })?
    .map_err(|e| {
        AppError::Internal(anyhow::anyhow!("bcrypt error: {e}"))
    })?;

    let username = payload.username.clone();
    let now = Utc::now().to_rfc3339();

    tokio::task::spawn_blocking(move || {
        let conn = db.conn().lock();
        conn.execute(
            "INSERT INTO admin_users (username, password_hash, created_at) \
             VALUES (?1, ?2, ?3)",
            rusqlite::params![username, hash, now],
        )
    })
    .await
    .map_err(|e| {
        AppError::Internal(anyhow::anyhow!("join error: {e}"))
    })??;

    tracing::info!(user = %payload.username, "admin user created");
    Ok(StatusCode::CREATED)
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

    #[test]
    fn test_jwt_round_trip() {
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
