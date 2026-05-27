//! Phase 47 Task 47-11 — Log + audit-event cleartext-leak scan
//! (success criterion #5).
//!
//! Strategy:
//!
//! 1. Install a tracing subscriber that writes to an in-memory buffer.
//! 2. Build an `admin_router` with a fresh DB.
//! 3. POST a fixture secret containing a 64-char hex "magic" string as
//!    `smtp_password`.
//! 4. Trigger representative flows: GET, PUT (config save), simulated
//!    server-restart cycle (drop pool + re-bootstrap crypto + read).
//! 5. Assert: the magic string appears in NO tracing log line AND in
//!    NO TEXT column of `audit_events`.
//!
//! The scan is dynamic (`PRAGMA table_info('audit_events')`) so future
//! schema additions are covered automatically without test churn.
//!
//! Windows-only because the underlying repositories were authored
//! against the Windows DPAPI path; the deterministic test KEK still
//! avoids actually calling DPAPI.

#![cfg(windows)]

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use dlp_server::admin_api::{admin_router, AlertRouterConfigPayload};
use dlp_server::admin_auth::{set_jwt_secret, Claims};
use dlp_server::crypto::{SecretCrypto, ENVELOPE_VERSION_V1};
use dlp_server::{alert_router, db, policy_store, secrets_migration, siem_connector, AppState};
use jsonwebtoken::{encode, EncodingKey, Header};
use tempfile::NamedTempFile;
use tower::ServiceExt;
use tracing_subscriber::fmt::MakeWriter;

const TEST_JWT_SECRET: &str = "dlp-server-dev-secret-change-me";

/// `MakeWriter` that appends every line into a shared `Vec<u8>`.
///
/// Using a shared `Arc<Mutex<Vec<u8>>>` lets the test code read the
/// captured bytes after the spans flush, while the tracing layer can
/// write concurrently from any task.
#[derive(Clone)]
struct BufferWriter(Arc<Mutex<Vec<u8>>>);

impl<'a> MakeWriter<'a> for BufferWriter {
    type Writer = BufferGuard;
    fn make_writer(&'a self) -> Self::Writer {
        BufferGuard(self.0.clone())
    }
}

/// One-shot writer handle that locks the shared buffer for the duration
/// of a single tracing event.
struct BufferGuard(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BufferGuard {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut guard = self.0.lock().expect("buffer poisoned");
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Returns a 64-char hex string drawn from `OsRng`. The high entropy
/// guarantees no accidental collisions with literals in logs or audit
/// rows -- if the magic string appears anywhere, it must be from the
/// secret we POSTed.
fn random_magic_secret() -> String {
    // Use the aes-gcm crate's re-exported OsRng to avoid pulling rand
    // into dev-dependencies just for this helper. The trait is the
    // standard `rand_core::RngCore` re-exported through aead.
    use aes_gcm::aead::rand_core::RngCore;
    use aes_gcm::aead::OsRng;
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write as _;
        write!(&mut s, "{b:02x}").expect("hex");
    }
    s
}

fn seed_admin_user(pool: &db::Pool, username: &str, password_plain: &str) {
    let hash = bcrypt::hash(password_plain, 4).expect("bcrypt");
    let now = Utc::now().to_rfc3339();
    let conn = pool.get().expect("acquire");
    conn.execute(
        "INSERT INTO admin_users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![username, hash, now],
    )
    .expect("seed admin");
}

fn mint_jwt(username: &str) -> String {
    let claims = Claims {
        sub: username.to_string(),
        exp: (Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
        iss: "dlp-server".to_string(),
        sid: None,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .expect("jwt")
}

fn build_state(pool: &Arc<db::Pool>, crypto: &Arc<SecretCrypto>) -> Arc<AppState> {
    let siem = siem_connector::SiemConnector::new(Arc::clone(pool), Arc::clone(crypto));
    let alert = alert_router::AlertRouter::new(Arc::clone(pool), Arc::clone(crypto));
    let policy_store =
        Arc::new(policy_store::PolicyStore::new(Arc::clone(pool)).expect("policy store"));
    let label_service = Arc::new(dlp_server::label_service::LabelService::new(Arc::clone(
        pool,
    )));
    let approval_token_crypto = SecretCrypto::from_kek([0x77; 32], 1);
    let approval_token_conn = pool.get().expect("pool");
    let approval_token_service = Arc::new(
        dlp_server::approval_token::ApprovalTokenService::new(
            &approval_token_crypto,
            &approval_token_conn,
        )
        .expect("approval token service"),
    );
    let syslog =
        dlp_server::syslog_connector::SyslogConnector::new(Arc::clone(pool), Arc::clone(crypto));
    Arc::new(AppState {
        pool: Arc::clone(pool),
        crypto: Arc::clone(crypto),
        policy_store,
        siem,
        alert,
        ad: None,
        label_service,
        approval_token_service,
        syslog,
        label_aware_enabled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        protected_paths: std::sync::Arc::new(dlp_server::db::repositories::protected_paths::ProtectedPathsRepository),
    })
}

#[tokio::test]
async fn test_no_cleartext_secret_appears_in_tracing_or_audit_log() {
    // ---- Step 1: install a per-test tracing subscriber. -------------
    let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let writer = BufferWriter(buf.clone());
    // Use `set_default` -> the returned guard uninstalls the
    // subscriber on drop so concurrent tests do not fight over the
    // global subscriber registry.
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt::Subscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(writer)
            .with_ansi(false)
            .finish(),
    );

    // ---- Step 2: spin up the admin router. --------------------------
    set_jwt_secret(TEST_JWT_SECRET.to_string());
    let tmp = NamedTempFile::new().expect("create temp DB");
    let pool = Arc::new(db::new_pool(tmp.path().to_str().expect("UTF-8 path")).expect("init pool"));
    let crypto = Arc::new(SecretCrypto::from_kek([0xD7; 32], ENVELOPE_VERSION_V1));
    secrets_migration::migrate_secrets_to_encrypted(&pool, &crypto, None)
        .expect("Phase 47 migration");
    let state = build_state(&pool, &crypto);
    let app = admin_router(Arc::clone(&state));

    seed_admin_user(&pool, "logscan-admin", "pw");
    let jwt = mint_jwt("logscan-admin");

    // ---- Step 3: POST a fixture config containing the magic secret. -
    let magic = random_magic_secret();
    let payload = AlertRouterConfigPayload {
        smtp_host: "smtp.example.com".to_string(),
        smtp_port: 587,
        smtp_username: "alert@example.com".to_string(),
        smtp_password: magic.clone(),
        smtp_from: "alert@example.com".to_string(),
        smtp_to: "ops@example.com".to_string(),
        smtp_enabled: true,
        webhook_url: String::new(),
        webhook_secret: String::new(),
        webhook_enabled: false,
    };
    let body = serde_json::to_vec(&payload).expect("serialise");
    let req = Request::builder()
        .method("PUT")
        .uri("/admin/alert-config")
        .header("Authorization", format!("Bearer {jwt}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .expect("build req");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK, "PUT must succeed");

    // ---- Step 4: trigger representative flows. ----------------------
    // (a) GET alert-config -> mask path; no plaintext should hit logs.
    let req = Request::builder()
        .method("GET")
        .uri("/admin/alert-config")
        .header("Authorization", format!("Bearer {jwt}"))
        .body(Body::empty())
        .expect("build");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    // (b) GET it twice more to trigger any cached log hits.
    for _ in 0..2 {
        let req = Request::builder()
            .method("GET")
            .uri("/admin/alert-config")
            .header("Authorization", format!("Bearer {jwt}"))
            .body(Body::empty())
            .expect("build");
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // (c) Server-restart cycle: drop the in-flight state, re-bootstrap
    // crypto + AppState from the same DB file (the rows must still
    // decrypt). This exercises the cold-start log path.
    drop(app);
    drop(state);
    let crypto2 = Arc::new(SecretCrypto::from_kek([0xD7; 32], ENVELOPE_VERSION_V1));
    let state2 = build_state(&pool, &crypto2);
    let app2 = admin_router(state2);
    let req = Request::builder()
        .method("GET")
        .uri("/admin/alert-config")
        .header("Authorization", format!("Bearer {jwt}"))
        .body(Body::empty())
        .expect("build");
    let resp = app2.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    // ---- Step 5a: log buffer scan. ----------------------------------
    // Drop any subscriber-side temporaries by reading the buffer
    // directly. Anything still pending is in `buf` at this point
    // because the subscriber writes synchronously inside the event
    // emit path.
    let log_text = {
        let guard = buf.lock().expect("buf");
        String::from_utf8_lossy(&guard).to_string()
    };
    assert!(
        !log_text.contains(&magic),
        "CRITICAL: cleartext secret leaked into tracing buffer. \
         A regression in logging hygiene (Task 47-09) broke success \
         criterion #5. Log buffer excerpt: {} bytes; magic={magic}",
        log_text.len()
    );

    // ---- Step 5b: audit_events scan. --------------------------------
    // Dynamically enumerate every TEXT column of audit_events so the
    // scan is robust against future schema additions. Then for every
    // row + every TEXT column assert the magic does not appear.
    let conn = pool.get().expect("acquire");
    let mut text_cols = Vec::new();
    {
        let mut stmt = conn
            .prepare("PRAGMA table_info('audit_events')")
            .expect("prepare");
        let mut rows = stmt.query([]).expect("query");
        while let Some(r) = rows.next().expect("row") {
            let name: String = r.get(1).expect("name");
            let ctype: String = r.get(2).expect("type");
            if ctype.to_ascii_uppercase().contains("TEXT") {
                text_cols.push(name);
            }
        }
    }
    assert!(
        !text_cols.is_empty(),
        "audit_events must have at least one TEXT column to scan"
    );

    // Iterate every row, every TEXT column.
    let select_sql = format!("SELECT {} FROM audit_events", text_cols.join(", "));
    let mut stmt = conn.prepare(&select_sql).expect("prepare select");
    let mut rows = stmt.query([]).expect("query");
    let mut leak: Option<(String, String)> = None;
    while let Some(r) = rows.next().expect("row iter") {
        for (idx, col) in text_cols.iter().enumerate() {
            let val: Option<String> = r.get(idx).ok();
            if let Some(s) = val {
                if s.contains(&magic) {
                    leak = Some((col.clone(), s));
                    break;
                }
            }
        }
        if leak.is_some() {
            break;
        }
    }
    assert!(
        leak.is_none(),
        "CRITICAL: cleartext secret leaked into audit_events.{:?}: '{:?}'",
        leak.as_ref().map(|(c, _)| c),
        leak.as_ref().map(|(_, v)| v)
    );
}
