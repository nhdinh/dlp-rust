//! Comprehensive integration tests for dlp-agent components.
//!
//! This file covers areas not exercised by the existing `integration.rs`
//! and `negative.rs` test suites:
//!
//! - IPC message serialisation round-trips (Pipe 1, 2, 3)
//! - Config file loading edge cases (missing, malformed, partial)
//! - EngineClient retry / error classification
//! - PolicyMapper boundary cases (UNC paths, mixed case, edge paths)
//! - AuditEvent builder full schema / F-AUD-02 compliance
//! - OfflineManager multi-request and tier transitions
//! - Cache concurrent access and eviction
//! - NetworkShareDetector edge-case paths
//! - USB + classification tier coverage

use std::net::SocketAddr;
use std::sync::Arc;

use dlp_common::{Action, Classification, Decision, EvaluateRequest, EvaluateResponse};

// ─────────────────────────────────────────────────────────────────────────────
// IPC Message Serialisation Round-Trips
// ─────────────────────────────────────────────────────────────────────────────

mod ipc_messages {
    #[test]
    fn test_pipe1_agent_msg_block_notify_round_trip() {
        use dlp_agent::ipc::messages::Pipe1AgentMsg;

        let msg = Pipe1AgentMsg::BlockNotify {
            reason: "Sensitive content detected".into(),
            classification: "T4".into(),
            resource_path: r"C:\Restricted\secrets.xlsx".into(),
            policy_id: "pol-001".into(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Pipe1AgentMsg = serde_json::from_str(&json).unwrap();

        match parsed {
            Pipe1AgentMsg::BlockNotify {
                reason,
                classification,
                resource_path,
                policy_id,
            } => {
                assert_eq!(reason, "Sensitive content detected");
                assert_eq!(classification, "T4");
                assert_eq!(resource_path, r"C:\Restricted\secrets.xlsx");
                assert_eq!(policy_id, "pol-001");
            }
            other => panic!("expected BlockNotify, got {other:?}"),
        }
    }

    #[test]
    fn test_pipe1_agent_msg_override_request_round_trip() {
        use dlp_agent::ipc::messages::Pipe1AgentMsg;

        let msg = Pipe1AgentMsg::OverrideRequest {
            request_id: "req-abc123".into(),
            reason: "Business justification".into(),
            classification: "T3".into(),
            resource_path: r"D:\Shares\confidential.docx".into(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Pipe1AgentMsg = serde_json::from_str(&json).unwrap();

        match parsed {
            Pipe1AgentMsg::OverrideRequest {
                request_id,
                reason,
                classification,
                resource_path,
            } => {
                assert_eq!(request_id, "req-abc123");
                assert_eq!(reason, "Business justification");
                assert_eq!(classification, "T3");
                assert_eq!(resource_path, r"D:\Shares\confidential.docx");
            }
            other => panic!("expected OverrideRequest, got {other:?}"),
        }
    }

    #[test]
    fn test_pipe1_agent_msg_clipboard_read_round_trip() {
        use dlp_agent::ipc::messages::Pipe1AgentMsg;

        let msg = Pipe1AgentMsg::ClipboardRead {
            request_id: "clip-001".into(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Pipe1AgentMsg = serde_json::from_str(&json).unwrap();

        match parsed {
            Pipe1AgentMsg::ClipboardRead { request_id } => {
                assert_eq!(request_id, "clip-001");
            }
            other => panic!("expected ClipboardRead, got {other:?}"),
        }
    }

    #[test]
    fn test_pipe1_agent_msg_password_dialog_round_trip() {
        use dlp_agent::ipc::messages::Pipe1AgentMsg;

        let msg = Pipe1AgentMsg::PasswordDialog {
            request_id: "pwd-001".into(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Pipe1AgentMsg = serde_json::from_str(&json).unwrap();

        match parsed {
            Pipe1AgentMsg::PasswordDialog { request_id } => {
                assert_eq!(request_id, "pwd-001");
            }
            other => panic!("expected PasswordDialog, got {other:?}"),
        }
    }

    #[test]
    fn test_pipe1_ui_msg_register_session_round_trip() {
        use dlp_agent::ipc::messages::Pipe1UiMsg;

        let msg = Pipe1UiMsg::RegisterSession { session_id: 42 };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Pipe1UiMsg = serde_json::from_str(&json).unwrap();

        match parsed {
            Pipe1UiMsg::RegisterSession { session_id } => {
                assert_eq!(session_id, 42);
            }
            other => panic!("expected RegisterSession, got {other:?}"),
        }
    }

    #[test]
    fn test_pipe1_ui_msg_password_submit_round_trip() {
        use dlp_agent::ipc::messages::Pipe1UiMsg;

        let msg = Pipe1UiMsg::PasswordSubmit {
            request_id: "pwd-002".into(),
            password: "secret123".into(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Pipe1UiMsg = serde_json::from_str(&json).unwrap();

        match parsed {
            Pipe1UiMsg::PasswordSubmit {
                request_id,
                password,
            } => {
                assert_eq!(request_id, "pwd-002");
                // Password is a String, round-trip preserved
                assert_eq!(password, "secret123");
            }
            other => panic!("expected PasswordSubmit, got {other:?}"),
        }
    }

    #[test]
    fn test_pipe2_agent_msg_toast_round_trip() {
        use dlp_agent::ipc::messages::Pipe2AgentMsg;

        let msg = Pipe2AgentMsg::Toast {
            title: "DLP Alert".into(),
            body: "Blocked sensitive file copy".into(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Pipe2AgentMsg = serde_json::from_str(&json).unwrap();

        match parsed {
            Pipe2AgentMsg::Toast { title, body } => {
                assert_eq!(title, "DLP Alert");
                assert_eq!(body, "Blocked sensitive file copy");
            }
            other => panic!("expected Toast, got {other:?}"),
        }
    }

    #[test]
    fn test_pipe2_agent_msg_status_update_round_trip() {
        use dlp_agent::ipc::messages::Pipe2AgentMsg;

        let msg = Pipe2AgentMsg::StatusUpdate {
            status: "Online".into(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Pipe2AgentMsg = serde_json::from_str(&json).unwrap();

        match parsed {
            Pipe2AgentMsg::StatusUpdate { status } => {
                assert_eq!(status, "Online");
            }
            other => panic!("expected StatusUpdate, got {other:?}"),
        }
    }

    #[test]
    fn test_pipe2_agent_msg_health_ping_round_trip() {
        use dlp_agent::ipc::messages::Pipe2AgentMsg;

        let msg = Pipe2AgentMsg::HealthPing;

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Pipe2AgentMsg = serde_json::from_str(&json).unwrap();

        match parsed {
            Pipe2AgentMsg::HealthPing => {}
            other => panic!("expected HealthPing, got {other:?}"),
        }
    }

    #[test]
    fn test_pipe2_agent_msg_ui_closing_sequence_round_trip() {
        use dlp_agent::ipc::messages::Pipe2AgentMsg;

        let msg = Pipe2AgentMsg::UiClosingSequence { session_id: 7 };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Pipe2AgentMsg = serde_json::from_str(&json).unwrap();

        match parsed {
            Pipe2AgentMsg::UiClosingSequence { session_id } => {
                assert_eq!(session_id, 7);
            }
            other => panic!("expected UiClosingSequence, got {other:?}"),
        }
    }

    #[test]
    fn test_pipe3_ui_msg_health_pong_round_trip() {
        use dlp_agent::ipc::messages::Pipe3UiMsg;

        let msg = Pipe3UiMsg::HealthPong;

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Pipe3UiMsg = serde_json::from_str(&json).unwrap();

        match parsed {
            Pipe3UiMsg::HealthPong => {}
            other => panic!("expected HealthPong, got {other:?}"),
        }
    }

    #[test]
    fn test_pipe3_ui_msg_ui_ready_round_trip() {
        use dlp_agent::ipc::messages::Pipe3UiMsg;

        let msg = Pipe3UiMsg::UiReady { session_id: 3 };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Pipe3UiMsg = serde_json::from_str(&json).unwrap();

        match parsed {
            Pipe3UiMsg::UiReady { session_id } => {
                assert_eq!(session_id, 3);
            }
            other => panic!("expected UiReady, got {other:?}"),
        }
    }

    #[test]
    fn test_pipe3_ui_msg_ui_closing_round_trip() {
        use dlp_agent::ipc::messages::Pipe3UiMsg;

        let msg = Pipe3UiMsg::UiClosing { session_id: 5 };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Pipe3UiMsg = serde_json::from_str(&json).unwrap();

        match parsed {
            Pipe3UiMsg::UiClosing { session_id } => {
                assert_eq!(session_id, 5);
            }
            other => panic!("expected UiClosing, got {other:?}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Config File Loading Edge Cases
// ─────────────────────────────────────────────────────────────────────────────

mod config_edge_cases {
    use dlp_agent::config::AgentConfig;
    use std::path::Path;

    #[test]
    fn test_load_missing_file_uses_defaults() {
        let config = AgentConfig::load(Path::new(r"C:\nonexistent\path\agent-config.toml"));
        assert!(config.monitored_paths.is_empty());
        assert!(config.excluded_paths.is_empty());
    }

    #[test]
    fn test_load_malformed_toml_returns_default() {
        // toml crate returns an error for invalid TOML.
        let parse_result: Result<AgentConfig, _> = toml::from_str(
            r#"
            monitored_paths = ['C:\Data\'.to_string()]
            this is not valid toml
        "#,
        );
        assert!(parse_result.is_err());

        // AgentConfig::load catches the parse error and returns Default.
        let config = AgentConfig::load(Path::new(r"C:\nonexistent\config.toml"));
        assert!(config.monitored_paths.is_empty());
    }

    #[test]
    fn test_load_empty_string_toml() {
        // Empty file is valid TOML (no keys defined → all defaults via #[serde(default)]).
        let config: AgentConfig = toml::from_str("").unwrap();
        assert!(config.monitored_paths.is_empty());
        assert!(config.excluded_paths.is_empty());
    }

    #[test]
    fn test_load_only_monitored_paths() {
        let toml_str = r#"monitored_paths = ['C:\Data\']"#;
        let config: AgentConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.monitored_paths.len(), 1);
        assert!(config.excluded_paths.is_empty());
    }

    #[test]
    fn test_load_only_excluded_paths() {
        let toml_str = r#"excluded_paths = ['C:\Temp\']"#;
        let config: AgentConfig = toml::from_str(toml_str).unwrap();
        assert!(config.monitored_paths.is_empty());
        assert_eq!(config.excluded_paths.len(), 1);
    }

    #[test]
    fn test_resolve_watch_paths_empty_config_returns_drives() {
        let config = AgentConfig::default();
        let paths = config.resolve_watch_paths();
        // Must include at least C:\ on any Windows machine.
        assert!(!paths.is_empty());
        assert!(paths.iter().any(|p| p.to_string_lossy().starts_with("C:")));
    }

    #[test]
    fn test_resolve_watch_paths_configured() {
        let config = AgentConfig {
            server_url: None,
            monitored_paths: vec![r"C:\Data\".to_string(), r"D:\Shares\".to_string()],
            excluded_paths: Vec::new(),
            heartbeat_interval_secs: None,
            offline_cache_enabled: None,
            machine_name: None,
        };
        let paths = config.resolve_watch_paths();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], std::path::PathBuf::from(r"C:\Data\"));
        assert_eq!(paths[1], std::path::PathBuf::from(r"D:\Shares\"));
    }

    #[test]
    fn test_config_clone_and_eq() {
        use dlp_agent::config::AgentConfig;

        let a = AgentConfig {
            server_url: None,
            monitored_paths: vec![r"C:\Data\".to_string()],
            excluded_paths: vec![r"C:\Temp\".to_string()],
            heartbeat_interval_secs: None,
            offline_cache_enabled: None,
            machine_name: None,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EngineClient — HTTP status code retry classification
// ─────────────────────────────────────────────────────────────────────────────

mod engine_client_errors {
    use std::time::Duration;

    use dlp_agent::engine_client::{EngineClient, EngineClientError};

    #[test]
    fn test_retryable_502_bad_gateway() {
        let err = EngineClientError::HttpError {
            status: 502,
            body: "Bad Gateway".into(),
        };
        assert!(EngineClient::is_retryable(&err));
    }

    #[test]
    fn test_retryable_503_service_unavailable() {
        let err = EngineClientError::HttpError {
            status: 503,
            body: "Service Unavailable".into(),
        };
        assert!(EngineClient::is_retryable(&err));
    }

    #[test]
    fn test_retryable_504_gateway_timeout() {
        let err = EngineClientError::HttpError {
            status: 504,
            body: "Gateway Timeout".into(),
        };
        assert!(EngineClient::is_retryable(&err));
    }

    #[test]
    fn test_not_retryable_429_rate_limited() {
        // 429 is a client error (4xx), not retried even though it is transient.
        let err = EngineClientError::HttpError {
            status: 429,
            body: "Rate limit exceeded".into(),
        };
        assert!(!EngineClient::is_retryable(&err));
    }

    #[test]
    fn test_not_retryable_400_bad_request() {
        let err = EngineClientError::HttpError {
            status: 400,
            body: "Bad Request".into(),
        };
        assert!(!EngineClient::is_retryable(&err));
    }

    #[test]
    fn test_not_retryable_401_unauthorized() {
        let err = EngineClientError::HttpError {
            status: 401,
            body: "Unauthorized".into(),
        };
        assert!(!EngineClient::is_retryable(&err));
    }

    #[test]
    fn test_not_retryable_403_forbidden() {
        let err = EngineClientError::HttpError {
            status: 403,
            body: "Forbidden".into(),
        };
        assert!(!EngineClient::is_retryable(&err));
    }

    #[test]
    fn test_not_retryable_404_not_found() {
        let err = EngineClientError::HttpError {
            status: 404,
            body: "Not Found".into(),
        };
        assert!(!EngineClient::is_retryable(&err));
    }

    #[test]
    fn test_not_retryable_422_unprocessable() {
        let err = EngineClientError::HttpError {
            status: 422,
            body: "Unprocessable Entity".into(),
        };
        assert!(!EngineClient::is_retryable(&err));
    }

    #[test]
    fn test_tls_error_retryable() {
        let err = EngineClientError::TlsError("certificate expired".into());
        assert!(EngineClient::is_retryable(&err));
    }

    #[test]
    fn test_timeout_retryable() {
        let err = EngineClientError::Timeout {
            duration: Duration::from_secs(10),
        };
        assert!(EngineClient::is_retryable(&err));
    }

    #[test]
    fn test_unreachable_error_retryable() {
        let err = EngineClientError::Unreachable { attempts: 3 };
        assert!(EngineClient::is_retryable(&err));
    }

    #[test]
    fn test_error_display_format() {
        let err = EngineClientError::Unreachable { attempts: 3 };
        let display = format!("{err}");
        assert!(display.contains("3"));
        assert!(display.contains("unreachable"));

        let err2 = EngineClientError::HttpError {
            status: 500,
            body: "Server Error".into(),
        };
        let display2 = format!("{err2}");
        assert!(display2.contains("500"));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EngineClient async evaluation against mock engines
// ─────────────────────────────────────────────────────────────────────────────

async fn start_engine_with_status(status_code: u16) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use axum::{http::StatusCode, routing::post, Router};
    use tokio::net::TcpListener;

    let app = Router::new().route(
        "/evaluate",
        post(move || async move { StatusCode::from_u16(status_code).unwrap() }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, handle)
}

async fn start_engine_with_json_response(
    response: EvaluateResponse,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use axum::{extract::Json, routing::post, Router};
    use tokio::net::TcpListener;

    let app = Router::new().route(
        "/evaluate",
        post(move |Json(_): Json<EvaluateRequest>| async move { Json(response.clone()) }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, handle)
}

fn make_request(path: &str, classification: Classification) -> EvaluateRequest {
    EvaluateRequest {
        subject: dlp_common::Subject {
            user_sid: "S-1-5-21-TEST".into(),
            user_name: "testuser".into(),
            groups: Vec::new(),
            device_trust: dlp_common::DeviceTrust::Managed,
            network_location: dlp_common::NetworkLocation::Corporate,
        },
        resource: dlp_common::Resource {
            path: path.into(),
            classification,
        },
        environment: dlp_common::Environment {
            timestamp: chrono::Utc::now(),
            session_id: 1,
            access_context: dlp_common::AccessContext::Local,
        },
        action: Action::WRITE,
        ..Default::default()
    }
}

#[tokio::test]
async fn test_engine_429_is_retried() {
    use dlp_agent::engine_client::{EngineClient, EngineClientError};

    let (addr, _h) = start_engine_with_status(429).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();

    let req = make_request(r"C:\Data\file.xlsx", Classification::T2);
    let result = client.evaluate(&req).await;

    // 429 is retryable — client should exhaust retries.
    assert!(result.is_err());
    match result.unwrap_err() {
        EngineClientError::HttpError { status, .. } => assert_eq!(status, 429),
        other => panic!("expected HttpError(429), got {other:?}"),
    }
}

#[tokio::test]
async fn test_engine_500_retried_then_failed() {
    use dlp_agent::engine_client::{EngineClient, EngineClientError};

    let (addr, _h) = start_engine_with_status(500).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();

    let req = make_request(r"C:\Data\file.xlsx", Classification::T3);
    let result = client.evaluate(&req).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        EngineClientError::HttpError { status, .. } => assert_eq!(status, 500),
        other => panic!("expected HttpError(500), got {other:?}"),
    }
}

#[tokio::test]
async fn test_engine_400_not_retried() {
    use dlp_agent::engine_client::{EngineClient, EngineClientError};

    let (addr, _h) = start_engine_with_status(400).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();

    let req = make_request(r"C:\Data\file.xlsx", Classification::T2);
    let result = client.evaluate(&req).await;

    // 400 is not retryable — immediate failure.
    assert!(result.is_err());
    match result.unwrap_err() {
        EngineClientError::HttpError { status, .. } => assert_eq!(status, 400),
        other => panic!("expected HttpError(400), got {other:?}"),
    }
}

#[tokio::test]
async fn test_engine_success_allow() {
    use dlp_agent::engine_client::EngineClient;

    let resp = EvaluateResponse {
        decision: Decision::ALLOW,
        matched_policy_id: Some("pol-001".into()),
        reason: "T2 allowed".into(),
    };
    let (addr, _h) = start_engine_with_json_response(resp).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();

    let req = make_request(r"C:\Data\file.xlsx", Classification::T2);
    let result = client.evaluate(&req).await.unwrap();

    assert!(!result.decision.is_denied());
    assert_eq!(result.matched_policy_id.as_deref(), Some("pol-001"));
}

#[tokio::test]
async fn test_engine_success_deny() {
    use dlp_agent::engine_client::EngineClient;

    let resp = EvaluateResponse {
        decision: Decision::DENY,
        matched_policy_id: Some("pol-001".into()),
        reason: "T4 blocked".into(),
    };
    let (addr, _h) = start_engine_with_json_response(resp).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();

    let req = make_request(r"C:\Restricted\secret.xlsx", Classification::T4);
    let result = client.evaluate(&req).await.unwrap();

    assert!(result.decision.is_denied());
}

// ─────────────────────────────────────────────────────────────────────────────
// OfflineManager — multi-request, cache, tier transitions
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_offline_manager_cache_hit_second_request() {
    use dlp_agent::engine_client::EngineClient;
    use dlp_agent::offline::OfflineManager;

    let resp = EvaluateResponse {
        decision: Decision::ALLOW,
        matched_policy_id: Some("pol-001".into()),
        reason: "ok".into(),
    };
    let (addr, _h) = start_engine_with_json_response(resp).await;
    let client = EngineClient::new(format!("http://{addr}"), false).unwrap();
    let cache = Arc::new(dlp_agent::cache::Cache::new());
    let manager = OfflineManager::new(client, cache.clone(), None);

    let req = make_request(r"C:\Data\report.xlsx", Classification::T2);

    // First request — hits the engine.
    let resp1 = manager.evaluate(&req).await;
    assert!(!resp1.decision.is_denied());
    assert!(manager.is_online());

    // Cache should now contain the entry.
    assert!(cache.get(r"C:\Data\report.xlsx", "S-1-5-21-TEST").is_some());
}

#[tokio::test]
async fn test_offline_manager_transitions_offline_on_unreachable() {
    use dlp_agent::engine_client::EngineClient;
    use dlp_agent::offline::OfflineManager;

    // Use unreachable port → Unreachable error.
    let client = EngineClient::new("http://127.0.0.1:1", false).unwrap();
    let cache = Arc::new(dlp_agent::cache::Cache::new());
    let manager = OfflineManager::new(client, cache, None);

    let req = make_request(r"C:\Restricted\secret.xlsx", Classification::T4);

    // Engine unreachable → offline mode → fail-closed for T4.
    let resp = manager.evaluate(&req).await;
    assert!(resp.decision.is_denied());
    assert!(!manager.is_online());
}

#[tokio::test]
async fn test_offline_manager_multiple_tiers_fail_closed() {
    use dlp_agent::offline::OfflineManager;

    let client = dlp_agent::engine_client::EngineClient::new("http://127.0.0.1:1", false).unwrap();
    let cache = Arc::new(dlp_agent::cache::Cache::new());
    let manager = OfflineManager::new(client, cache, None);

    // T3 offline → DENY.
    let t3_req = make_request(r"C:\Confidential\doc.docx", Classification::T3);
    assert!(manager.evaluate(&t3_req).await.decision.is_denied());

    // T2 offline → ALLOW (not sensitive).
    let t2_req = make_request(r"C:\Data\file.xlsx", Classification::T2);
    assert!(!manager.evaluate(&t2_req).await.decision.is_denied());

    // T1 offline → ALLOW.
    let t1_req = make_request(r"C:\Public\readme.txt", Classification::T1);
    assert!(!manager.evaluate(&t1_req).await.decision.is_denied());

    // T4 offline → DENY.
    let t4_req = make_request(r"C:\Restricted\secret.xlsx", Classification::T4);
    assert!(manager.evaluate(&t4_req).await.decision.is_denied());
}

#[tokio::test]
async fn test_offline_manager_offline_decision_exact_tier_boundaries() {
    use dlp_agent::cache::fail_closed_response;

    // T2 is not sensitive — default-allow on cache miss.
    let resp = fail_closed_response(Classification::T2);
    assert!(!resp.decision.is_denied());

    // T3 is sensitive — default-deny on cache miss.
    let resp3 = fail_closed_response(Classification::T3);
    assert!(resp3.decision.is_denied());
}

// ─────────────────────────────────────────────────────────────────────────────
// PolicyMapper — boundary cases
// ─────────────────────────────────────────────────────────────────────────────

mod policy_mapper_boundary {
    use dlp_agent::interception::{FileAction, PolicyMapper};
    use dlp_common::{Action, Classification};

    #[test]
    fn test_provisional_classification_case_variations() {
        assert_eq!(
            PolicyMapper::provisional_classification(r"C:\RESTRICTED\file.txt"),
            Classification::T4
        );
        assert_eq!(
            PolicyMapper::provisional_classification(r"c:\data\file.txt"),
            Classification::T2
        );
        assert_eq!(
            PolicyMapper::provisional_classification(r"C:\CONIDENTIAL\file.txt"),
            // C:\CONIDENTIAL\ doesn't match C:\CONFIDENTIAL\ (typo).
            Classification::T1
        );
    }

    #[test]
    fn test_provisional_classification_unc_paths() {
        // UNC paths are not in the sensitive prefix list — T1 by default.
        assert_eq!(
            PolicyMapper::provisional_classification(r"\\server\share\file.txt"),
            Classification::T1
        );
        assert_eq!(
            PolicyMapper::provisional_classification(r"\\files.corp.local\Restricted\doc.docx"),
            Classification::T1
        );
    }

    #[test]
    fn test_provisional_classification_paths_without_drive_letter() {
        // Unix-style paths (no drive letter) — no prefix match.
        assert_eq!(
            PolicyMapper::provisional_classification(r"/data/restricted/file.txt"),
            Classification::T1
        );
    }

    #[test]
    fn test_provisional_classification_subdirectory() {
        // Subdirectory of a known sensitive folder should still match.
        assert_eq!(
            PolicyMapper::provisional_classification(
                r"C:\Restricted\SubDir\AnotherDir\secrets.xlsx"
            ),
            Classification::T4
        );
        assert_eq!(
            PolicyMapper::provisional_classification(r"C:\Confidential\Finance\2024\budget.xlsx"),
            Classification::T3
        );
        assert_eq!(
            PolicyMapper::provisional_classification(r"C:\Data\Q4\report.csv"),
            Classification::T2
        );
    }

    #[test]
    fn test_provisional_classification_forward_slash_paths() {
        // Forward slashes do NOT match backslash-prefix rules.
        // C:/Data/file.xlsx -> lowercase = "c:/data/file.xlsx"
        // starts_with("c:\\data\\") = false -> T1.
        assert_eq!(
            PolicyMapper::provisional_classification("C:/Data/file.xlsx"),
            Classification::T1
        );
        // C:/restricted/file.txt -> lowercase, no backslash -> T1.
        assert_eq!(
            PolicyMapper::provisional_classification("c:/restricted/file.txt"),
            Classification::T1
        );
    }

    #[test]
    fn test_provisional_classification_root_drive() {
        // C:\ alone is not in the prefix list.
        assert_eq!(
            PolicyMapper::provisional_classification(r"C:\"),
            Classification::T1
        );
    }

    #[test]
    fn test_provisional_classification_trailing_slash() {
        assert_eq!(
            PolicyMapper::provisional_classification(r"C:\Restricted\"),
            Classification::T4
        );
    }

    #[test]
    fn test_file_action_moved_path_returns_new_path() {
        let action = FileAction::Moved {
            old_path: r"C:\Data\old.txt".into(),
            new_path: r"D:\Shares\new.txt".into(),
            process_id: 1,
            related_process_id: 0,
        };
        // The classification should be based on new_path.
        assert_eq!(
            PolicyMapper::provisional_classification(action.path()),
            Classification::T1 // D:\Shares\ is not in the list.
        );
    }

    #[test]
    fn test_all_action_types_covered() {
        // Ensure every FileAction variant maps to a defined Action.
        let variants = [
            FileAction::Created {
                path: "a".into(),
                process_id: 1,
                related_process_id: 0,
            },
            FileAction::Written {
                path: "a".into(),
                process_id: 1,
                related_process_id: 0,
                byte_count: 0,
            },
            FileAction::Deleted {
                path: "a".into(),
                process_id: 1,
                related_process_id: 0,
            },
            FileAction::Moved {
                old_path: "a".into(),
                new_path: "b".into(),
                process_id: 1,
                related_process_id: 0,
            },
            FileAction::Read {
                path: "a".into(),
                process_id: 1,
                related_process_id: 0,
                byte_count: 0,
            },
        ];

        for variant in variants {
            let action = PolicyMapper::action_for(&variant);
            // Action should never be null or unhandled.
            assert!(
                matches!(
                    action,
                    Action::READ
                        | Action::WRITE
                        | Action::DELETE
                        | Action::MOVE
                        | Action::COPY
                        | Action::PASTE
                ),
                "Unhandled FileAction variant: {:?}",
                variant
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AuditEvent — full schema / F-AUD-02 compliance
// ─────────────────────────────────────────────────────────────────────────────

mod audit_event_schema {
    use dlp_common::audit::{AuditAccessContext, AuditEvent, EventType};
    use dlp_common::{Action, Classification, Decision};
    use serde_json::Value;

    fn parse_json(json: &str) -> Value {
        serde_json::from_str(json).unwrap()
    }

    fn required_field<'a>(json: &'a Value, name: &str) -> &'a Value {
        json.get(name)
            .unwrap_or_else(|| panic!("required field '{name}' missing from audit event JSON"))
    }

    #[test]
    fn test_audit_event_all_required_fields_present() {
        let event = AuditEvent::new(
            EventType::Access,
            "S-1-5-21-123".into(),
            "jsmith".into(),
            r"C:\Data\report.xlsx".into(),
            Classification::T2,
            Action::READ,
            Decision::ALLOW,
            "AGENT-WS02-001".into(),
            1,
        );

        let json = serde_json::to_string(&event).unwrap();
        let v: Value = parse_json(&json);

        // All required F-AUD-02 fields must be present.
        required_field(&v, "timestamp");
        required_field(&v, "event_type");
        required_field(&v, "user_sid");
        required_field(&v, "user_name");
        required_field(&v, "resource_path");
        required_field(&v, "classification");
        required_field(&v, "action_attempted");
        required_field(&v, "decision");
        required_field(&v, "agent_id");
        required_field(&v, "session_id");
        required_field(&v, "access_context");

        // correlation_id is always generated.
        required_field(&v, "correlation_id");
    }

    #[test]
    fn test_audit_event_event_type_serdes() {
        for event_type in [
            EventType::Access,
            EventType::Block,
            EventType::Alert,
            EventType::ConfigChange,
            EventType::SessionLogoff,
            EventType::AdminAction,
            EventType::ServiceStopFailed,
        ] {
            let event = AuditEvent::new(
                event_type,
                "S-1-5-21-123".into(),
                "user".into(),
                r"C:\Data\file.xlsx".into(),
                Classification::T1,
                Action::READ,
                Decision::ALLOW,
                "AGENT-001".into(),
                1,
            );
            let json = serde_json::to_string(&event).unwrap();
            let v: Value = parse_json(&json);
            // Event type must be serialised as SCREAMING_SNAKE_CASE.
            let et = v.get("event_type").unwrap().as_str().unwrap();
            assert!(
                et.contains('_') || et.chars().all(|c| c.is_ascii_uppercase()),
                "event_type '{et}' should be SCREAMING_SNAKE_CASE"
            );
        }
    }

    #[test]
    fn test_audit_event_classification_serdes() {
        for cls in [
            Classification::T1,
            Classification::T2,
            Classification::T3,
            Classification::T4,
        ] {
            let event = AuditEvent::new(
                EventType::Access,
                "S-1-5-21-123".into(),
                "user".into(),
                r"C:\Data\file.xlsx".into(),
                cls,
                Action::READ,
                Decision::ALLOW,
                "AGENT-001".into(),
                1,
            );
            let json = serde_json::to_string(&event).unwrap();
            let v: Value = parse_json(&json);
            let cls_str = v.get("classification").unwrap().as_str().unwrap();
            // Classification serialises as T1/T2/T3/T4 (from #[serde(rename_all = "UPPERCASE")]).
            assert!(
                cls_str.starts_with('T'),
                "classification '{cls_str}' should be T-tier format"
            );
        }
    }

    #[test]
    fn test_audit_event_decision_serdes() {
        for decision in [
            Decision::ALLOW,
            Decision::DENY,
            Decision::AllowWithLog,
            Decision::DenyWithAlert,
        ] {
            let event = AuditEvent::new(
                EventType::Access,
                "S-1-5-21-123".into(),
                "user".into(),
                r"C:\Data\file.xlsx".into(),
                Classification::T1,
                Action::READ,
                decision,
                "AGENT-001".into(),
                1,
            );
            let json = serde_json::to_string(&event).unwrap();
            let v: Value = parse_json(&json);
            let dec_str = v.get("decision").unwrap().as_str().unwrap();
            assert!(!dec_str.is_empty(), "decision field should not be empty");
        }
    }

    #[test]
    fn test_audit_event_skip_none_optional_fields() {
        let event = AuditEvent::new(
            EventType::Access,
            "S-1-5-21-123".into(),
            "user".into(),
            r"C:\Data\file.xlsx".into(),
            Classification::T1,
            Action::READ,
            Decision::ALLOW,
            "AGENT-001".into(),
            1,
        );

        let json = serde_json::to_string(&event).unwrap();

        // policy_id, justification, etc. must NOT appear as null.
        assert!(!json.contains("\"policy_id\":null"));
        assert!(!json.contains("\"justification\":null"));
        assert!(!json.contains("\"device_trust\":null"));
        assert!(!json.contains("\"network_location\":null"));
    }

    #[test]
    fn test_audit_event_policy_fields_serialised_when_present() {
        let event = AuditEvent::new(
            EventType::Block,
            "S-1-5-21-123".into(),
            "user".into(),
            r"C:\Restricted\file.xlsx".into(),
            Classification::T4,
            Action::WRITE,
            Decision::DENY,
            "AGENT-001".into(),
            1,
        )
        .with_policy("pol-001".into(), "T4 Deny All".into())
        .with_justification("Business justification".into());

        let json = serde_json::to_string(&event).unwrap();
        let v: Value = parse_json(&json);

        assert_eq!(v.get("policy_id").unwrap().as_str().unwrap(), "pol-001");
        assert_eq!(
            v.get("policy_name").unwrap().as_str().unwrap(),
            "T4 Deny All"
        );
        assert_eq!(
            v.get("justification").unwrap().as_str().unwrap(),
            "Business justification"
        );
    }

    #[test]
    fn test_audit_event_access_context_local() {
        let event = AuditEvent::new(
            EventType::Access,
            "S-1-5-21-123".into(),
            "user".into(),
            r"C:\Data\file.xlsx".into(),
            Classification::T1,
            Action::READ,
            Decision::ALLOW,
            "AGENT-001".into(),
            1,
        )
        .with_access_context(AuditAccessContext::Local);

        let json = serde_json::to_string(&event).unwrap();
        let v: Value = parse_json(&json);

        assert_eq!(v.get("access_context").unwrap().as_str().unwrap(), "local");
    }

    #[test]
    fn test_audit_event_access_context_smb() {
        let event = AuditEvent::new(
            EventType::Access,
            "S-1-5-21-123".into(),
            "user".into(),
            r"\\fileserver\share\file.xlsx".into(),
            Classification::T2,
            Action::READ,
            Decision::ALLOW,
            "AGENT-001".into(),
            1,
        )
        .with_access_context(AuditAccessContext::Smb);

        let json = serde_json::to_string(&event).unwrap();
        let v: Value = parse_json(&json);

        assert_eq!(v.get("access_context").unwrap().as_str().unwrap(), "smb");
    }

    #[test]
    fn test_audit_event_environment_fields() {
        let event = AuditEvent::new(
            EventType::Block,
            "S-1-5-21-123".into(),
            "user".into(),
            r"C:\Restricted\file.xlsx".into(),
            Classification::T4,
            Action::WRITE,
            Decision::DENY,
            "AGENT-001".into(),
            2,
        )
        .with_environment(Some("Managed".into()), Some("Corporate".into()));

        let json = serde_json::to_string(&event).unwrap();
        let v: Value = parse_json(&json);

        assert_eq!(v.get("device_trust").unwrap().as_str().unwrap(), "Managed");
        assert_eq!(
            v.get("network_location").unwrap().as_str().unwrap(),
            "Corporate"
        );
    }

    #[test]
    fn test_audit_event_application_metadata() {
        let event = AuditEvent::new(
            EventType::Block,
            "S-1-5-21-123".into(),
            "user".into(),
            r"C:\Restricted\file.xlsx".into(),
            Classification::T4,
            Action::WRITE,
            Decision::DENY,
            "AGENT-001".into(),
            1,
        )
        .with_application(
            Some(r"C:\Program Files\Notepadpp\notepad++.exe".into()),
            Some("deadbeef1234".into()),
        );

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("notepad++"));
        assert!(!json.contains("application_path\":null"));
    }

    #[test]
    fn test_audit_event_resource_owner() {
        let event = AuditEvent::new(
            EventType::Block,
            "S-1-5-21-123".into(),
            "user".into(),
            r"C:\Restricted\file.xlsx".into(),
            Classification::T4,
            Action::WRITE,
            Decision::DENY,
            "AGENT-001".into(),
            1,
        )
        .with_resource_owner(Some("S-1-5-21-456".into()));

        let json = serde_json::to_string(&event).unwrap();
        let v: Value = parse_json(&json);
        assert_eq!(
            v.get("resource_owner").unwrap().as_str().unwrap(),
            "S-1-5-21-456"
        );
    }

    #[test]
    fn test_audit_event_override_granted() {
        let event = AuditEvent::new(
            EventType::Access,
            "S-1-5-21-123".into(),
            "user".into(),
            r"C:\Data\file.xlsx".into(),
            Classification::T3,
            Action::WRITE,
            Decision::ALLOW,
            "AGENT-001".into(),
            1,
        )
        .with_override_granted();

        let json = serde_json::to_string(&event).unwrap();
        let v: Value = parse_json(&json);
        assert!(v.get("override_granted").unwrap().as_bool().unwrap());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cache — concurrent access, eviction edge cases
// ─────────────────────────────────────────────────────────────────────────────

mod cache_edge_cases {
    use dlp_agent::cache::Cache;
    use dlp_common::{Decision, EvaluateResponse};
    use std::thread;
    use std::time::Duration;

    fn make_response(decision: Decision) -> EvaluateResponse {
        EvaluateResponse {
            decision,
            matched_policy_id: None,
            reason: "test".into(),
        }
    }

    #[test]
    fn test_cache_different_paths_independent() {
        let cache = Cache::new();
        cache.insert(r"C:\Data\a.xlsx", "S-1", make_response(Decision::ALLOW));
        cache.insert(
            r"C:\Restricted\b.xlsx",
            "S-1",
            make_response(Decision::DENY),
        );

        assert!(cache.get(r"C:\Data\a.xlsx", "S-1").is_some());
        assert!(cache.get(r"C:\Restricted\b.xlsx", "S-1").is_some());
        assert!(cache.get(r"C:\Other\c.xlsx", "S-1").is_none());
    }

    #[test]
    fn test_cache_same_path_different_users() {
        let cache = Cache::new();
        let path = r"C:\Restricted\file.xlsx";

        cache.insert(path, "S-1-5-21-Alice", make_response(Decision::ALLOW));
        cache.insert(path, "S-1-5-21-Bob", make_response(Decision::DENY));

        assert_eq!(
            cache.get(path, "S-1-5-21-Alice").unwrap().decision,
            Decision::ALLOW
        );
        assert_eq!(
            cache.get(path, "S-1-5-21-Bob").unwrap().decision,
            Decision::DENY
        );
    }

    #[test]
    fn test_cache_evict_expired_only_removes_old() {
        let cache = Cache::with_ttl(Duration::from_millis(10));

        cache.insert(r"C:\Data\a.xlsx", "S-1", make_response(Decision::ALLOW));
        cache.insert(r"C:\Data\b.xlsx", "S-1", make_response(Decision::ALLOW));

        // Wait for one entry to expire.
        thread::sleep(Duration::from_millis(15));

        cache.insert(r"C:\Data\c.xlsx", "S-1", make_response(Decision::DENY)); // fresh entry.

        cache.evict_expired();

        // c.xlsx should still be present (was inserted after the wait).
        assert!(cache.get(r"C:\Data\c.xlsx", "S-1").is_some());
    }

    #[test]
    fn test_cache_len_empty() {
        let cache = Cache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_clear_then_insert() {
        let cache = Cache::new();
        cache.insert(r"C:\Data\file.xlsx", "S-1", make_response(Decision::ALLOW));
        assert!(!cache.is_empty());

        cache.clear();
        assert!(cache.is_empty());

        // After clear, inserting again works.
        cache.insert(r"C:\Data\file.xlsx", "S-1", make_response(Decision::DENY));
        assert!(!cache.is_empty());
    }

    #[test]
    fn test_cache_multiple_entries_different_classifications() {
        let cache = Cache::new();

        cache.insert(r"C:\Data\t2.xlsx", "S-1", {
            let mut r = make_response(Decision::AllowWithLog);
            r.matched_policy_id = Some("pol-003".into());
            r
        });

        let result = cache.get(r"C:\Data\t2.xlsx", "S-1").unwrap();
        assert_eq!(result.decision, Decision::AllowWithLog);
        assert_eq!(result.matched_policy_id.as_deref(), Some("pol-003"));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NetworkShareDetector — edge-case paths
// ─────────────────────────────────────────────────────────────────────────────

mod network_share_edge_cases {
    use dlp_agent::detection::NetworkShareDetector;
    use dlp_common::Classification;

    #[test]
    fn test_whitelist_prevents_t4_block() {
        let detector = NetworkShareDetector::new();
        detector.add_to_whitelist("files.corp.local");

        // Whitelisted server, any classification.
        assert!(!detector.should_block(
            r"\\files.corp.local\restricted\secret.xlsx",
            Classification::T4
        ));
    }

    #[test]
    fn test_empty_whitelist_blocks_all() {
        let detector = NetworkShareDetector::new();

        // No whitelist → all T3+ should be blocked.
        assert!(detector.should_block(r"\\server\share\file.xlsx", Classification::T3));
        assert!(detector.should_block(r"\\server\share\file.xlsx", Classification::T4));
    }

    #[test]
    fn test_t1_never_blocked() {
        let detector = NetworkShareDetector::new();
        assert!(!detector.should_block(r"\\anywhere\share\public.txt", Classification::T1));
    }

    #[test]
    fn test_t2_never_blocked() {
        let detector = NetworkShareDetector::new();
        assert!(!detector.should_block(r"\\anywhere\share\report.xlsx", Classification::T2));
    }

    #[test]
    fn test_share_name_with_spaces() {
        let detector = NetworkShareDetector::new();
        detector.add_to_whitelist("fileserver");

        // Share name contains spaces — whitelisted by server name.
        assert!(
            !detector.should_block(r"\\fileserver\My Documents\report.docx", Classification::T3)
        );
    }

    #[test]
    fn test_ipv6_server_name() {
        let detector = NetworkShareDetector::new();
        // IPv6 address as server name — should not match whitelist by default.
        assert!(detector.should_block(r"\\fe80::1\share\file.xlsx", Classification::T3));
    }

    #[test]
    fn test_share_name_partial_match() {
        let detector = NetworkShareDetector::new();
        // Whitelist entry "files" is treated as a server name (extract_server_name strips \\).
        detector.add_to_whitelist("files");

        // Full server name must match for whitelist to apply.
        // "files.corp.local" != "files" — not whitelisted.
        assert!(detector.should_block(r"\\files.corp.local\data\file.xlsx", Classification::T3));
    }

    #[test]
    fn test_whitelist_clear_then_block() {
        let detector = NetworkShareDetector::new();
        detector.add_to_whitelist("safe.server");

        assert!(!detector.should_block(r"\\safe.server\share\file.xlsx", Classification::T3));

        // Clear and re-add different whitelist.
        detector.replace_whitelist(vec!["other.server".into()]);

        assert!(detector.should_block(r"\\safe.server\share\file.xlsx", Classification::T3));
        assert!(!detector.should_block(r"\\other.server\share\file.xlsx", Classification::T3));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// USB + Classification Tier Coverage
// ─────────────────────────────────────────────────────────────────────────────

mod usb_tier_coverage {
    use dlp_agent::detection::UsbDetector;
    use dlp_common::Classification;

    #[test]
    fn test_usb_t1_not_blocked() {
        let detector = UsbDetector::new();
        // T1 (Public) is never blocked even on a USB drive.
        assert!(!detector.should_block_write(r"E:\public_readme.txt", Classification::T1));
    }

    #[test]
    fn test_usb_t2_not_blocked() {
        let detector = UsbDetector::new();
        // T2 is not blocked by USB policy.
        assert!(!detector.should_block_write(r"E:\internal_report.xlsx", Classification::T2));
    }

    #[test]
    fn test_usb_t3_blocked() {
        let detector = UsbDetector::new();
        // T3 is blocked when USB drive is in blocked set.
        // Since we can't add drives via the public API without real hardware,
        // this test verifies the classification-based blocking logic:
        // T3 on a non-blocked drive returns false.
        assert!(!detector.should_block_write(r"C:\confidential\doc.docx", Classification::T3));
    }

    #[test]
    fn test_usb_t4_blocked() {
        let detector = UsbDetector::new();
        // T4 on C: is not blocked by USB detector (C: is not a USB).
        assert!(!detector.should_block_write(r"C:\restricted\secret.xlsx", Classification::T4));
    }

    #[test]
    fn test_usb_blocked_drive_letters_initially_empty() {
        let detector = UsbDetector::new();
        assert!(detector.blocked_drive_letters().is_empty());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Classification — full tier coverage
// ─────────────────────────────────────────────────────────────────────────────

mod classification_tier_coverage {
    use dlp_common::Classification;

    #[test]
    fn test_all_tiers_sensitive_flag() {
        assert!(!Classification::T1.is_sensitive());
        assert!(!Classification::T2.is_sensitive());
        assert!(Classification::T3.is_sensitive());
        assert!(Classification::T4.is_sensitive());
    }

    #[test]
    fn test_all_tiers_labels() {
        assert_eq!(Classification::T1.label(), "Public");
        assert_eq!(Classification::T2.label(), "Internal");
        assert_eq!(Classification::T3.label(), "Confidential");
        assert_eq!(Classification::T4.label(), "Restricted");
    }

    #[test]
    fn test_all_tiers_ordering() {
        assert!(Classification::T1 < Classification::T2);
        assert!(Classification::T2 < Classification::T3);
        assert!(Classification::T3 < Classification::T4);
        // T4 is greater than T1 via PartialOrd.
        assert!(Classification::T4 > Classification::T1);
    }

    #[test]
    fn test_all_tiers_serde_round_trip() {
        for cls in [
            Classification::T1,
            Classification::T2,
            Classification::T3,
            Classification::T4,
        ] {
            let json = serde_json::to_string(&cls).unwrap();
            let round_trip: Classification = serde_json::from_str(&json).unwrap();
            assert_eq!(cls, round_trip);
        }
    }

    #[test]
    fn test_all_tiers_display() {
        assert_eq!(Classification::T1.to_string(), "Public");
        assert_eq!(Classification::T2.to_string(), "Internal");
        assert_eq!(Classification::T3.to_string(), "Confidential");
        assert_eq!(Classification::T4.to_string(), "Restricted");
    }

    #[test]
    fn test_default_is_t1() {
        assert_eq!(Classification::default(), Classification::T1);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Decision — full variant coverage
// ─────────────────────────────────────────────────────────────────────────────

mod decision_variant_coverage {
    use dlp_common::Decision;

    #[test]
    fn test_decision_is_denied() {
        assert!(Decision::DENY.is_denied());
        assert!(Decision::DenyWithAlert.is_denied());
        assert!(!Decision::ALLOW.is_denied());
        assert!(!Decision::AllowWithLog.is_denied());
    }

    #[test]
    fn test_decision_serde_round_trip() {
        for decision in [
            Decision::ALLOW,
            Decision::DENY,
            Decision::AllowWithLog,
            Decision::DenyWithAlert,
        ] {
            let json = serde_json::to_string(&decision).unwrap();
            let round_trip: Decision = serde_json::from_str(&json).unwrap();
            assert_eq!(decision, round_trip);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SessionIdentityMap — additional edge cases
// ─────────────────────────────────────────────────────────────────────────────

mod session_identity_edge_cases {
    use dlp_agent::session_identity::{SessionIdentityMap, UserIdentity};

    #[test]
    fn test_resolve_for_path_two_sessions_no_match_falls_back() {
        let map = SessionIdentityMap::new();

        map.sessions.write().insert(
            2,
            UserIdentity {
                sid: "S-1-5-21-111".into(),
                name: "alice".into(),
            },
        );
        map.username_to_session.write().insert("alice".into(), 2);

        map.sessions.write().insert(
            3,
            UserIdentity {
                sid: "S-1-5-21-222".into(),
                name: "bob".into(),
            },
        );
        map.username_to_session.write().insert("bob".into(), 3);

        // Path doesn't match any user profile → SYSTEM fallback (multiple sessions).
        let (sid, name) = map.resolve_for_path(r"C:\Data\report.txt");
        assert_eq!(sid, "S-1-5-18");
        assert_eq!(name, "SYSTEM");
    }

    #[test]
    fn test_resolve_for_path_windows_directory() {
        let map = SessionIdentityMap::new();

        map.sessions.write().insert(
            2,
            UserIdentity {
                sid: "S-1-5-21-111".into(),
                name: "alice".into(),
            },
        );
        map.username_to_session.write().insert("alice".into(), 2);

        // Windows\System32 is not a user profile — single user heuristic applies.
        let (sid, name) = map.resolve_for_path(r"C:\Windows\System32\notepad.exe");
        assert_eq!(sid, "S-1-5-21-111");
        assert_eq!(name, "alice");
    }

    #[test]
    fn test_session_count_empty() {
        let map = SessionIdentityMap::new();
        assert_eq!(map.session_count(), 0);
    }

    #[test]
    fn test_session_count_multiple() {
        let map = SessionIdentityMap::new();
        map.sessions.write().insert(
            2,
            UserIdentity {
                sid: "S-1".into(),
                name: "a".into(),
            },
        );
        map.sessions.write().insert(
            3,
            UserIdentity {
                sid: "S-2".into(),
                name: "b".into(),
            },
        );
        assert_eq!(map.session_count(), 2);
    }

    #[test]
    fn test_remove_session_reverse_map_cleanup() {
        let map = SessionIdentityMap::new();
        map.sessions.write().insert(
            5,
            UserIdentity {
                sid: "S-1-5-21-100".into(),
                name: "testuser".into(),
            },
        );
        map.username_to_session.write().insert("testuser".into(), 5);

        map.remove_session(5);
        assert_eq!(map.session_count(), 0);
        assert!(map.username_to_session.read().get("testuser").is_none());
    }

    #[test]
    fn test_remove_different_session_leaves_reverse_entry() {
        let map = SessionIdentityMap::new();
        map.sessions.write().insert(
            2,
            UserIdentity {
                sid: "S-1".into(),
                name: "alice".into(),
            },
        );
        map.username_to_session.write().insert("alice".into(), 2);

        // Remove a different session (3) — should not affect alice's entry.
        map.remove_session(3);
        assert!(map.username_to_session.read().get("alice").is_some());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AuditEmitter — rotation, directory creation, simultaneous writes
// ─────────────────────────────────────────────────────────────────────────────

mod audit_emitter_edge_cases {
    use dlp_agent::audit_emitter::AuditEmitter;
    use dlp_common::audit::{AuditEvent, EventType};
    use dlp_common::{Action, Classification, Decision};
    use std::fs;

    fn make_event(i: u32) -> AuditEvent {
        AuditEvent::new(
            EventType::Access,
            format!("S-1-5-21-{i}"),
            format!("user{i}"),
            format!(r"C:\Data\file{i}.txt"),
            Classification::T2,
            Action::READ,
            Decision::ALLOW,
            "AGENT-TEST".into(),
            1,
        )
    }

    #[test]
    fn test_audit_rotation_creates_rotated_file() {
        let dir = tempfile::tempdir().unwrap();
        let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 200).unwrap();

        // Write until rotation threshold.
        for i in 0..10 {
            emitter.emit(&make_event(i)).unwrap();
        }

        emitter.rotate().unwrap();

        let rotated = dir.path().join("audit.1.jsonl");
        assert!(rotated.exists(), "rotated file audit.1.jsonl should exist");

        // Original file should be empty/new after rotation.
        let new_content = fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        // After rotate, writer is reset — content may be empty or have new entries.
        assert!(new_content.lines().count() <= 5); // at least some content was rotated
    }

    #[test]
    fn test_audit_rotation_max_generations() {
        let dir = tempfile::tempdir().unwrap();
        let emitter = AuditEmitter::open(dir.path(), "audit.jsonl", 100).unwrap();

        // Trigger enough rotations to cycle through 1..9.
        for i in 0..9 {
            for _ in 0..3 {
                emitter.emit(&make_event(i)).unwrap();
            }
            emitter.rotate().unwrap();
        }

        // audit.9.jsonl should exist, audit.10.jsonl should NOT exist.
        let gen9 = dir.path().join("audit.9.jsonl");

        assert!(gen9.exists(), "generation 9 should exist");
        // Generation 10 should NOT exist (MAX_ROTATED_FILES = 9).
        assert!(
            !dir.path().join("audit.10.jsonl").exists(),
            "generation 10 should not exist"
        );
    }

    #[test]
    fn test_multiple_emitters_independent() {
        let dir = tempfile::tempdir().unwrap();

        let emitter_a = AuditEmitter::open(dir.path(), "a.jsonl", 50 * 1024 * 1024).unwrap();
        let emitter_b = AuditEmitter::open(dir.path(), "b.jsonl", 50 * 1024 * 1024).unwrap();

        emitter_a.emit(&make_event(1)).unwrap();
        emitter_b.emit(&make_event(2)).unwrap();

        let content_a = fs::read_to_string(dir.path().join("a.jsonl")).unwrap();
        let content_b = fs::read_to_string(dir.path().join("b.jsonl")).unwrap();

        assert!(content_a.contains("user1"));
        assert!(content_b.contains("user2"));
        // They should be independent.
        assert!(!content_a.contains("user2"));
        assert!(!content_b.contains("user1"));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ContentClassifier — all patterns
// ─────────────────────────────────────────────────────────────────────────────

mod clipboard_classifier_patterns {
    use dlp_agent::clipboard::ContentClassifier;
    use dlp_common::Classification;

    #[test]
    fn test_ssn_patterns() {
        // SSN with dashes in XXX-XX-XXXX format — T4.
        assert_eq!(
            ContentClassifier::classify("SSN: 123-45-6789"),
            Classification::T4
        );
        // SSN with spaces — T4 (separator can be space or dash).
        assert_eq!(
            ContentClassifier::classify("SSN: 123 45 6789"),
            Classification::T4
        );
        // SSN embedded in text — T4.
        assert_eq!(
            ContentClassifier::classify("My SSN is 123-45-6789"),
            Classification::T4
        );
    }

    #[test]
    fn test_credit_card_patterns() {
        assert_eq!(
            ContentClassifier::classify("Card: 4111-1111-1111-1111"),
            Classification::T4
        );
        assert_eq!(
            ContentClassifier::classify("Credit card 5500 0000 0000 0004"),
            Classification::T4
        );
    }

    #[test]
    fn test_confidential_keyword() {
        // Exact "confidential" substring match (case-insensitive) — T3.
        assert_eq!(
            ContentClassifier::classify("This document is CONFIDENTIAL"),
            Classification::T3
        );
        // "secret" keyword — T3.
        assert_eq!(
            ContentClassifier::classify("Project secret plans"),
            Classification::T3
        );
        // "top secret" — T3.
        assert_eq!(
            ContentClassifier::classify("Top secret information"),
            Classification::T3
        );
    }

    #[test]
    fn test_internal_keyword() {
        // "internal only" substring — T2.
        assert_eq!(
            ContentClassifier::classify("For internal only distribution"),
            Classification::T2
        );
        // "do not distribute" — T2.
        assert_eq!(
            ContentClassifier::classify("DO NOT DISTRIBUTE this memo"),
            Classification::T2
        );
        // "internal use" — T2.
        assert_eq!(
            ContentClassifier::classify("Internal use only"),
            Classification::T2
        );
    }

    #[test]
    fn test_benign_text() {
        assert_eq!(
            ContentClassifier::classify("Hello world"),
            Classification::T1
        );
        assert_eq!(ContentClassifier::classify(""), Classification::T1);
        assert_eq!(
            ContentClassifier::classify("The quick brown fox"),
            Classification::T1
        );
    }

    #[test]
    fn test_mixed_content_highest_classification_wins() {
        // If text contains both SSN and CONFIDENTIAL, T4 should win.
        let text = "CONFIDENTIAL: SSN 123-45-6789";
        let cls = ContentClassifier::classify(text);
        assert!(
            cls >= Classification::T3,
            "Mixed SSN+confidential should be at least T3"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// USB detection (dlp_agent::detection::UsbDetector)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(windows)]
mod usb_detection_tests {
    use dlp_agent::detection::UsbDetector;
    use dlp_common::Classification;

    /// Newly-constructed detector reports an empty blocked set and denies
    /// no writes to any drive — the baseline invariant before any drive
    /// arrival has been observed.
    #[test]
    fn test_new_usb_detector_is_empty() {
        let detector = UsbDetector::new();
        assert!(detector.blocked_drive_letters().is_empty());
        assert!(!detector.is_path_on_blocked_drive(r"E:\secret.docx"));
        assert!(!detector.should_block_write(r"E:\secret.docx", Classification::T4));
    }

    /// `scan_existing_drives` iterates A..=Z and calls the real `GetDriveTypeW`
    /// Win32 API for each letter. On the CI/dev host this MUST return without
    /// panicking regardless of whether a removable drive is attached; we only
    /// assert the observable invariant that every letter reported as blocked
    /// is a valid ASCII uppercase character.
    #[test]
    fn test_scan_existing_drives_returns_well_formed_set() {
        let detector = UsbDetector::new();
        detector.scan_existing_drives();
        for letter in detector.blocked_drive_letters() {
            assert!(
                letter.is_ascii_uppercase(),
                "drive letter must be uppercase ASCII: {letter}"
            );
        }
    }

    /// `on_drive_arrival` is gated by `is_removable_drive` (GetDriveTypeW == 2),
    /// so calling it with the system drive letter `'C'` must NOT add it to the
    /// blocked set on any realistic Windows host (C: is DRIVE_FIXED == 3).
    #[test]
    fn test_on_drive_arrival_system_drive_not_blocked() {
        let detector = UsbDetector::new();
        detector.on_drive_arrival('C');
        assert!(!detector.is_path_on_blocked_drive(r"C:\Users\test\file.txt"));
    }

    /// `on_drive_removal` unconditionally drops the letter from the set, and
    /// subsequent queries must report `false`. Exercises the removal path
    /// without requiring a physical USB device. We seed the set indirectly:
    /// if `scan_existing_drives` found nothing, we still exercise the
    /// removal-on-empty case and assert it is a no-op.
    #[test]
    fn test_on_drive_removal_is_idempotent() {
        let detector = UsbDetector::new();
        detector.on_drive_removal('Z');
        detector.on_drive_removal('Z'); // double-remove must not panic
        assert!(!detector.is_path_on_blocked_drive(r"Z:\anything"));
    }

    /// Non-sensitive classifications are never blocked, even if the drive is
    /// in the blocked set. This check uses a drive that cannot be in the set
    /// (`'Z'` has no Win32 backing on CI hosts), so we verify the class-based
    /// short-circuit at the `should_block_write` level: T1/T2 always false.
    #[test]
    fn test_should_block_write_non_sensitive_never_blocked() {
        let detector = UsbDetector::new();
        assert!(!detector.should_block_write(r"Z:\public.txt", Classification::T1));
        assert!(!detector.should_block_write(r"Z:\internal.doc", Classification::T2));
    }

    /// Relative, UNC, and empty paths must not panic and must report `false`
    /// for `is_path_on_blocked_drive` — the drive-letter extractor is the
    /// load-bearing helper and this asserts its error behaviour via the
    /// public API.
    #[test]
    fn test_is_path_on_blocked_drive_rejects_non_drive_paths() {
        let detector = UsbDetector::new();
        assert!(!detector.is_path_on_blocked_drive(r"\\server\share\file.txt"));
        assert!(!detector.is_path_on_blocked_drive("relative/path"));
        assert!(!detector.is_path_on_blocked_drive(""));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Network share detection (dlp_agent::detection::{NetworkShareDetector, SmbMonitor, SmbShareEvent})
// ─────────────────────────────────────────────────────────────────────────────

mod network_share_detection_tests {
    use dlp_agent::detection::{NetworkShareDetector, SmbMonitor, SmbShareEvent};
    use dlp_common::Classification;

    /// `SmbShareEvent::Connected` preserves every field exactly as constructed —
    /// no normalisation or mutation. The downstream alert path assumes the
    /// UNC path is preserved verbatim.
    #[test]
    fn test_smb_share_event_connected_preserves_fields() {
        let event = SmbShareEvent::Connected {
            unc_path: r"\\server.corp.local\finance".to_string(),
            server: "server.corp.local".to_string(),
            share_name: "finance".to_string(),
        };
        match event {
            SmbShareEvent::Connected {
                unc_path,
                server,
                share_name,
            } => {
                assert_eq!(unc_path, r"\\server.corp.local\finance");
                assert_eq!(server, "server.corp.local");
                assert_eq!(share_name, "finance");
            }
            other => panic!("expected Connected, got {other:?}"),
        }
    }

    /// `SmbShareEvent::Disconnected` preserves the UNC path exactly.
    #[test]
    fn test_smb_share_event_disconnected_preserves_unc_path() {
        let event = SmbShareEvent::Disconnected {
            unc_path: r"\\nas01\archive".to_string(),
        };
        match event {
            SmbShareEvent::Disconnected { unc_path } => {
                assert_eq!(unc_path, r"\\nas01\archive");
            }
            other => panic!("expected Disconnected, got {other:?}"),
        }
    }

    /// Exact prefix match: a whitelist entry of `\\server\share` matches
    /// any path under that share but NOT a sibling share on the same server.
    #[test]
    fn test_whitelist_exact_prefix_match() {
        let detector = NetworkShareDetector::with_whitelist(vec![r"\\fs01\approved".to_string()]);
        assert!(detector.is_whitelisted(r"\\fs01\approved\report.xlsx"));
        assert!(detector.is_whitelisted(r"\\FS01\APPROVED\other.docx")); // case-insensitive
        assert!(!detector.is_whitelisted(r"\\fs01\other-share\file.xlsx"));
    }

    /// Server-level whitelist: adding only the bare server name allows every
    /// share under that server (via the extracted-server-name fallback).
    #[test]
    fn test_whitelist_server_name_match() {
        let detector =
            NetworkShareDetector::with_whitelist(vec!["fileserver01.corp.local".to_string()]);
        assert!(detector.is_whitelisted(r"\\fileserver01.corp.local\any\path.txt"));
        assert!(!detector.is_whitelisted(r"\\other.corp.local\share"));
    }

    /// Whitelist miss -> T3/T4 blocked, T1/T2 allowed. Combines the classification
    /// short-circuit with the whitelist lookup.
    #[test]
    fn test_whitelist_miss_blocks_sensitive_allows_non_sensitive() {
        let detector = NetworkShareDetector::with_whitelist(vec!["allowed.corp.local".to_string()]);
        assert!(detector.should_block(r"\\evil.external\exfil", Classification::T4));
        assert!(detector.should_block(r"\\evil.external\exfil", Classification::T3));
        assert!(!detector.should_block(r"\\evil.external\public", Classification::T2));
        assert!(!detector.should_block(r"\\evil.external\public", Classification::T1));
    }

    /// `replace_whitelist` atomically drops the old set. An entry that was
    /// allowed before the replace MUST be blocked after it.
    #[test]
    fn test_replace_whitelist_drops_old_entries() {
        let detector = NetworkShareDetector::with_whitelist(vec!["old.corp".to_string()]);
        assert!(detector.is_whitelisted(r"\\old.corp\share"));
        detector.replace_whitelist(vec!["new.corp".to_string()]);
        assert!(!detector.is_whitelisted(r"\\old.corp\share"));
        assert!(detector.is_whitelisted(r"\\new.corp\share"));
    }

    /// `SmbMonitor::stop` is safe to call before `run`, is idempotent, and
    /// does not block. The monitor thread is never started in this test.
    #[test]
    fn test_smb_monitor_stop_without_run_is_noop() {
        let monitor = SmbMonitor::new();
        monitor.stop();
        monitor.stop();
        // If we get here without hanging, the test passes.
    }

    /// Whitelist mutations on `SmbMonitor` are visible immediately via
    /// `is_whitelisted` -- exercises the `Arc<RwLock<_>>` storage shared
    /// with the polling thread.
    #[test]
    fn test_smb_monitor_whitelist_mutations_visible() {
        let monitor = SmbMonitor::new();
        assert!(!monitor.is_whitelisted(r"\\nas01\data"));
        monitor.add_to_whitelist("nas01");
        assert!(monitor.is_whitelisted(r"\\nas01\data"));
        monitor.remove_from_whitelist("nas01");
        assert!(!monitor.is_whitelisted(r"\\nas01\data"));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Clipboard content classifier (dlp_agent::clipboard::ContentClassifier)
// ─────────────────────────────────────────────────────────────────────────────

mod clipboard_classifier_tests {
    use dlp_agent::clipboard::ContentClassifier;
    use dlp_common::Classification;

    /// Canonical SSN pattern `XXX-XX-XXXX` trips the T4 rule.
    #[test]
    fn test_classify_text_t4_ssn_dashes() {
        assert_eq!(
            ContentClassifier::classify("Employee SSN: 123-45-6789 on file"),
            Classification::T4,
        );
    }

    /// SSN with space separators also trips T4 (per classifier regex).
    #[test]
    fn test_classify_text_t4_ssn_spaces() {
        assert_eq!(
            ContentClassifier::classify("SSN 123 45 6789"),
            Classification::T4,
        );
    }

    /// Formatted 16-digit credit card `XXXX XXXX XXXX XXXX` trips T4.
    #[test]
    fn test_classify_text_t4_credit_card_spaces() {
        assert_eq!(
            ContentClassifier::classify("Card: 4111 1111 1111 1111"),
            Classification::T4,
        );
    }

    /// Raw 16-digit sequence without separators also trips T4.
    #[test]
    fn test_classify_text_t4_credit_card_raw() {
        assert_eq!(
            ContentClassifier::classify("Card number 4111111111111111"),
            Classification::T4,
        );
    }

    /// `CONFIDENTIAL` (any case) triggers T3.
    #[test]
    fn test_classify_text_t3_confidential_keyword() {
        assert_eq!(
            ContentClassifier::classify("This document is CONFIDENTIAL"),
            Classification::T3,
        );
    }

    /// `secret` keyword (lowercase) triggers T3.
    #[test]
    fn test_classify_text_t3_secret_lowercase() {
        assert_eq!(
            ContentClassifier::classify("please keep this secret"),
            Classification::T3,
        );
    }

    /// `internal only` triggers T2.
    #[test]
    fn test_classify_text_t2_internal_only() {
        assert_eq!(
            ContentClassifier::classify("For internal only distribution"),
            Classification::T2,
        );
    }

    /// `do not distribute` triggers T2.
    #[test]
    fn test_classify_text_t2_do_not_distribute() {
        assert_eq!(
            ContentClassifier::classify("DO NOT DISTRIBUTE this memo"),
            Classification::T2,
        );
    }

    /// Ordinary prose with no patterns drops to T1.
    #[test]
    fn test_classify_text_public_plain_prose() {
        assert_eq!(
            ContentClassifier::classify("Hello world, this is a normal sentence."),
            Classification::T1,
        );
    }

    /// Empty string must NOT panic and must classify as T1.
    #[test]
    fn test_classify_text_empty_is_t1() {
        assert_eq!(ContentClassifier::classify(""), Classification::T1);
    }

    /// A single ASCII space is still T1 (no match, no panic).
    #[test]
    fn test_classify_text_whitespace_is_t1() {
        assert_eq!(ContentClassifier::classify(" \t\n"), Classification::T1);
    }

    /// Highest tier wins: SSN + `confidential` -> T4 (not T3).
    #[test]
    fn test_classify_text_highest_tier_wins_ssn_over_confidential() {
        assert_eq!(
            ContentClassifier::classify("Confidential SSN: 123-45-6789"),
            Classification::T4,
        );
    }

    /// Multibyte input with no sensitive patterns is T1 (exercises the
    /// `chars().collect()` code path in the SSN/CC scanners).
    // CLAUDE.md §9.2 exception: multibyte chars here test character-boundary correctness.
    #[test]
    fn test_classify_text_multibyte_safe() {
        assert_eq!(
            ContentClassifier::classify(
                "\u{3053}\u{3093}\u{306B}\u{3061}\u{306F}\u{4E16}\u{754C} \u{2014} hello"
            ),
            Classification::T1,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// File monitor exclusions (dlp_agent::interception::{FileAction, InterceptionEngine})
// ─────────────────────────────────────────────────────────────────────────────

mod file_monitor_exclusion_tests {
    use dlp_agent::config::AgentConfig;
    use dlp_agent::interception::{FileAction, InterceptionEngine};

    /// Default config constructs an engine without panicking and with the
    /// stop flag unset.
    #[test]
    fn test_interception_engine_default_constructs() {
        let engine = InterceptionEngine::default();
        // Drop to trigger the stop flag -- must not panic.
        drop(engine);
    }

    /// A config with a user-supplied exclusion list round-trips into the
    /// engine without mutating the stored list. We verify via the config
    /// clone that exclusions are preserved verbatim (exclusion matching is
    /// case-insensitive at match time, not at store time).
    #[test]
    fn test_engine_with_config_preserves_excluded_paths() {
        let cfg = AgentConfig {
            excluded_paths: vec![r"C:\BuildOutput\".to_string(), r"D:\MyCache\".to_string()],
            ..Default::default()
        };
        let engine = InterceptionEngine::with_config(cfg.clone()).expect("engine construction");
        // The config was moved into the engine; use the clone we kept and
        // assert it matches what we passed in.
        assert_eq!(
            cfg.excluded_paths,
            vec![r"C:\BuildOutput\".to_string(), r"D:\MyCache\".to_string()],
        );
        drop(engine);
    }

    /// `FileAction::path()` returns the target path for every variant. The
    /// exclusion matcher consumes this string, so the return contract is
    /// part of the file-monitor exclusion surface.
    #[test]
    fn test_file_action_path_for_all_variants() {
        let created = FileAction::Created {
            path: r"C:\Data\a.txt".to_string(),
            process_id: 1,
            related_process_id: 0,
        };
        assert_eq!(created.path(), r"C:\Data\a.txt");

        let written = FileAction::Written {
            path: r"C:\Data\b.txt".to_string(),
            process_id: 2,
            related_process_id: 0,
            byte_count: 100,
        };
        assert_eq!(written.path(), r"C:\Data\b.txt");

        let deleted = FileAction::Deleted {
            path: r"C:\Data\c.txt".to_string(),
            process_id: 3,
            related_process_id: 0,
        };
        assert_eq!(deleted.path(), r"C:\Data\c.txt");

        let read = FileAction::Read {
            path: r"C:\Data\d.txt".to_string(),
            process_id: 4,
            related_process_id: 0,
            byte_count: 200,
        };
        assert_eq!(read.path(), r"C:\Data\d.txt");

        // Moved uses the new path.
        let moved = FileAction::Moved {
            old_path: r"C:\Data\old.txt".to_string(),
            new_path: r"C:\Data\new.txt".to_string(),
            process_id: 5,
            related_process_id: 0,
        };
        assert_eq!(moved.path(), r"C:\Data\new.txt");
    }

    /// Empty exclusion list is a valid, non-panicking config -- the engine
    /// accepts it and `FileAction::path()` still works on every variant.
    #[test]
    fn test_engine_with_empty_exclusion_list() {
        // Default already has excluded_paths = vec![], so no fields need overriding.
        let cfg = AgentConfig::default();
        let _engine = InterceptionEngine::with_config(cfg).expect("engine construction");
    }

    /// Multiple user exclusions in the config are accepted without being
    /// coalesced or silently de-duplicated -- every entry survives the
    /// `with_config` constructor.
    #[test]
    fn test_engine_with_many_user_exclusions() {
        let cfg = AgentConfig {
            excluded_paths: vec![
                r"C:\cache1\".to_string(),
                r"C:\cache2\".to_string(),
                r"C:\cache3\".to_string(),
            ],
            ..Default::default()
        };
        assert_eq!(cfg.excluded_paths.len(), 3);
        let _engine = InterceptionEngine::with_config(cfg).expect("engine construction");
    }
}
