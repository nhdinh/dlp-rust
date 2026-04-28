//! End-to-end integration test harness for the Enterprise DLP System.
//!
//! Provides shared helpers for spinning up in-process server routers,
//! mock evaluation engines, and headless TUI testing. All downstream
//! Phase 30 integration tests import from this crate.

// Re-export common types so tests only need one `use dlp_e2e::helpers::*;`
pub use dlp_common::EvaluateResponse;

/// Grouped re-exports so test files can write `use dlp_e2e::helpers::{server, tui}`.
///
/// All three sub-modules are re-exported here as well as at the crate root
/// (`dlp_e2e::server`, `dlp_e2e::tui`, `dlp_e2e::mock_engine`) to support
/// both import styles used across the test suite.
pub mod helpers {
    pub use crate::mock_engine;
    pub use crate::server;
    pub use crate::tui;
}

// ---------------------------------------------------------------------------
// Public helper modules
// ---------------------------------------------------------------------------

/// Helpers for spinning up in-process `dlp-server` routers and minting JWTs.
pub mod server {
    use std::sync::Arc;

    use axum::Router;
    use chrono::Utc;
    use dlp_server::admin_api::admin_router;
    use dlp_server::admin_auth::{set_jwt_secret, Claims};
    use dlp_server::{alert_router, db, policy_store, siem_connector, AppState};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use tempfile::NamedTempFile;

    /// Shared JWT secret used across all test binaries.
    ///
    /// Must match `admin_auth::DEV_JWT_SECRET` so that multiple test files
    /// running in the same process do not conflict on the first-set-wins
    /// `OnceLock` inside `set_jwt_secret`.
    pub const TEST_JWT_SECRET: &str = "dlp-server-dev-secret-change-me";

    /// Builds a fresh test router backed by a temporary SQLite database.
    ///
    /// Returns the axum `Router` and the underlying connection pool so callers
    /// can verify the database directly when needed.
    ///
    /// # Panics
    ///
    /// Panics if the temporary database file cannot be created or the pool
    /// cannot be built.
    ///
    /// # OnceLock constraint
    ///
    /// `set_jwt_secret` uses a `OnceLock` internally: the first call wins and
    /// all subsequent calls are silently ignored. `cargo test` runs tests in
    /// parallel, so call order is non-deterministic. This is safe because every
    /// test that uses this helper shares the same `TEST_JWT_SECRET` constant.
    pub fn build_test_app() -> (Router, Arc<db::Pool>) {
        set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let siem = siem_connector::SiemConnector::new(Arc::clone(&pool));
        let alert = alert_router::AlertRouter::new(Arc::clone(&pool));
        let ps = Arc::new(policy_store::PolicyStore::new(Arc::clone(&pool)).expect("policy store"));
        let state = Arc::new(AppState {
            pool: Arc::clone(&pool),
            policy_store: ps,
            siem,
            alert,
            ad: None,
        });
        (admin_router(state), pool)
    }

    /// Mints a valid admin JWT for the test secret.
    ///
    /// The token expires in 1 hour and is signed with [`TEST_JWT_SECRET`].
    ///
    /// # Panics
    ///
    /// Panics if JWT encoding fails (should never happen with a valid secret).
    pub fn mint_jwt() -> String {
        let claims = Claims {
            sub: "test-admin".to_string(),
            exp: (Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            iss: "dlp-server".to_string(),
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
        )
        .expect("mint JWT")
    }
}

/// Helpers for spawning mock axum evaluation engines.
pub mod mock_engine {
    use std::net::SocketAddr;

    use axum::{extract::Json, routing::post, Router};
    use dlp_common::{EvaluateRequest, EvaluateResponse};
    use tokio::net::TcpListener;

    /// Starts a mock axum server that returns a fixed `EvaluateResponse` for
    /// every `POST /evaluate` request.
    ///
    /// Binds to `127.0.0.1:0` (OS-assigned ephemeral port) and spawns a
    /// background Tokio task to serve requests.
    ///
    /// # Returns
    ///
    /// Returns `(SocketAddr, JoinHandle<()>)` — the bound address and the
    /// server task handle. Callers should abort the handle when done.
    pub async fn start_mock_server_with_response(
        response: EvaluateResponse,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let app = Router::new().route(
            "/evaluate",
            post(move |Json(_): Json<EvaluateRequest>| async move { Json(response.clone()) }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock server");
        let addr = listener.local_addr().expect("get local addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock server serve");
        });

        (addr, handle)
    }

    /// Starts a mock axum server that returns a fixed HTTP status code with
    /// an empty body for every `POST /evaluate` request.
    ///
    /// Useful for testing error-handling paths (e.g. 500, 503) in the agent
    /// or admin CLI.
    ///
    /// # Returns
    ///
    /// Returns `(SocketAddr, JoinHandle<()>)` — the bound address and the
    /// server task handle. Callers should abort the handle when done.
    pub async fn start_mock_server_with_status(
        status_code: u16,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let app = Router::new().route(
            "/evaluate",
            post(move || async move {
                (
                    axum::http::StatusCode::from_u16(status_code)
                        .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
                    "",
                )
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock server");
        let addr = listener.local_addr().expect("get local addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock server serve");
        });

        (addr, handle)
    }
}

/// Helpers for headless TUI testing.
pub mod tui {
    use dlp_admin_cli::app::App;
    use dlp_admin_cli::client::EngineClient;
    use dlp_admin_cli::event::AppEvent;
    use dlp_admin_cli::screens::handle_event;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use crate::server::mint_jwt;

    /// Builds a test `App` instance wired to a mock server.
    ///
    /// Creates an `EngineClient` pointing at `base_url`, sets a JWT token
    /// minted with [`mint_jwt`], and wraps it in a fresh tokio runtime and
    /// `App` instance.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The mock server base URL (e.g. `http://127.0.0.1:12345`).
    ///
    /// # Panics
    ///
    /// Panics if the tokio runtime cannot be created.
    pub fn build_test_app_with_mock_client(base_url: String) -> App {
        let mut client = EngineClient::for_test_with_url(base_url);
        client.set_token(mint_jwt());
        let rt = tokio::runtime::Runtime::new().expect("create tokio runtime");
        App::new(client, rt)
    }

    /// Injects a sequence of key events into the TUI app state machine.
    ///
    /// Iterates over `keys` and calls [`handle_event`] with
    /// `AppEvent::Key(key)` for each event.
    ///
    /// # Arguments
    ///
    /// * `app` - Mutable reference to the TUI app state.
    /// * `keys` - Vector of crossterm key events to inject.
    pub fn inject_key_sequence(app: &mut App, keys: Vec<crossterm::event::KeyEvent>) {
        for key in keys {
            handle_event(app, AppEvent::Key(key));
        }
    }

    /// Renders the current TUI app state into a `TestBackend` buffer.
    ///
    /// Creates a `Terminal` with a `TestBackend` of the given dimensions,
    /// calls [`dlp_admin_cli::screens::draw`], and returns the backend for
    /// buffer inspection.
    ///
    /// # Arguments
    ///
    /// * `app` - Reference to the TUI app state.
    /// * `width` - Terminal width in cells.
    /// * `height` - Terminal height in cells.
    ///
    /// # Returns
    ///
    /// The `TestBackend` containing the rendered buffer.
    pub fn render_to_buffer(app: &App, width: u16, height: u16) -> TestBackend {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("create terminal");
        terminal
            .draw(|f| {
                dlp_admin_cli::screens::draw(app, f);
            })
            .expect("draw frame");
        terminal.backend().clone()
    }
}
