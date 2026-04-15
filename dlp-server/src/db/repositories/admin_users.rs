//! Repository for the `admin_users` table.
//!
//! Encapsulates all SQL for admin user management, including authentication
//! lookups, user creation, and startup presence checks.

use rusqlite::params;

use crate::db::{Pool, UnitOfWork};

/// Plain data row for an admin user read.
#[derive(Debug, Clone)]
pub struct AdminUserRow {
    /// Login username (e.g., `"dlp-admin"`).
    pub username: String,
    /// bcrypt-hashed password.
    pub password_hash: String,
    /// Optional Windows SID associated with this admin account.
    pub user_sid: Option<String>,
    /// ISO-8601 timestamp of account creation.
    pub created_at: String,
}

/// Stateless repository for the `admin_users` table.
pub struct AdminUserRepository;

impl AdminUserRepository {
    /// Returns the bcrypt password hash for the given username.
    ///
    /// Returns `rusqlite::Error::QueryReturnedNoRows` if the username does
    /// not exist — callers should map this to an `Unauthorized` error.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    /// * `username` - Username to look up.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn get_password_hash(pool: &Pool, username: &str) -> rusqlite::Result<String> {
        let conn = pool.get().map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(e))
        })?;
        conn.query_row(
            "SELECT password_hash FROM admin_users WHERE username = ?1",
            params![username],
            |row| row.get(0),
        )
    }

    /// Returns `true` if at least one admin user exists in the database.
    ///
    /// Used at server startup to determine whether first-run setup is needed.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn has_any(pool: &Pool) -> rusqlite::Result<bool> {
        let count = Self::count(pool)?;
        Ok(count > 0)
    }

    /// Returns the total number of admin users in the database.
    ///
    /// # Arguments
    ///
    /// * `pool` - Connection pool to acquire a read connection from.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if pool acquisition or query execution fails.
    pub fn count(pool: &Pool) -> rusqlite::Result<i64> {
        let conn = pool.get().map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(e))
        })?;
        conn.query_row("SELECT COUNT(*) FROM admin_users", [], |r| r.get(0))
    }

    /// Inserts a new admin user record.
    ///
    /// # Arguments
    ///
    /// * `uow` - Active unit of work to execute the write within.
    /// * `username` - Login username.
    /// * `password_hash` - bcrypt hash of the user's password.
    /// * `created_at` - ISO-8601 creation timestamp.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` if the insert fails (e.g., duplicate username).
    pub fn insert(
        uow: &UnitOfWork<'_>,
        username: &str,
        password_hash: &str,
        created_at: &str,
    ) -> rusqlite::Result<()> {
        uow.tx.execute(
            "INSERT INTO admin_users (username, password_hash, created_at) \
             VALUES (?1, ?2, ?3)",
            params![username, password_hash, created_at],
        )?;
        Ok(())
    }
}
