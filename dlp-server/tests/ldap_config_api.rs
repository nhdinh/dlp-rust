//! Integration tests for the LDAP config admin API.
//!
//! Tests GET /admin/ldap-config and PUT /admin/ldap-config endpoints.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::Utc;
use dlp_server::admin_api::{admin_router, LdapConfigPayload};
use dlp_server::admin_auth::{set_jwt_secret, Claims};
use dlp_server::{alert_router, db, siem_connector, AppState};
use jsonwebtoken::{encode, EncodingKey, Header};
use tempfile::NamedTempFile;
use tower::ServiceExt;

/// Shared test JWT secret — must match what `set_jwt_secret` initialises.
const TEST_JWT_SECRET: &str = "dlp-server-dev-secret-change-me";

/// Builds a test router backed by a fresh in-memory database.
fn test_app() -> axum::Router {
    set_jwt_secret(TEST_JWT_SECRET.to_string());
    let tmp = NamedTempFile::new().expect("create temp db");
    let pool = Arc::new(db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
    let siem = siem_connector::SiemConnector::new(Arc::clone(&pool));
    let alert = alert_router::AlertRouter::new(Arc::clone(&pool));
    let state = Arc::new(AppState {
        pool: Arc::clone(&pool),
        siem,
        alert,
        ad: None,
    });
    admin_router(state)
}

/// Mints a valid admin JWT for the test secret.
fn mint_admin_jwt() -> String {
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

#[tokio::test]
async fn get_ldap_config_returns_defaults() {
    let app = test_app();
    let token = mint_admin_jwt();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/admin/ldap-config")
                .method("GET")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    let config: LdapConfigPayload = serde_json::from_slice(&body).unwrap();

    assert_eq!(config.ldap_url, "ldaps://dc.corp.internal:636");
    assert_eq!(config.base_dn, "");
    assert!(config.require_tls);
    assert_eq!(config.cache_ttl_secs, 300);
    assert_eq!(config.vpn_subnets, "");
}

#[tokio::test]
async fn put_ldap_config_updates_and_returns_new_config() {
    let app = test_app();
    let token = mint_admin_jwt();

    let payload = LdapConfigPayload {
        ldap_url: "ldaps://new-dc.corp.internal:636".to_string(),
        base_dn: "DC=newdomain,DC=corp".to_string(),
        require_tls: false,
        cache_ttl_secs: 600,
        vpn_subnets: "10.10.0.0/16".to_string(),
    };

    let body = serde_json::to_string(&payload).unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/admin/ldap-config")
                .method("PUT")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    let returned: LdapConfigPayload = serde_json::from_slice(&body).unwrap();

    assert_eq!(returned.ldap_url, "ldaps://new-dc.corp.internal:636");
    assert_eq!(returned.cache_ttl_secs, 600);
    assert!(!returned.require_tls);
}

#[tokio::test]
async fn put_ldap_config_rejects_cache_ttl_too_low() {
    let app = test_app();
    let token = mint_admin_jwt();

    let payload = LdapConfigPayload {
        ldap_url: "ldaps://dc.corp.internal:636".to_string(),
        base_dn: "DC=corp,DC=internal".to_string(),
        require_tls: true,
        cache_ttl_secs: 30, // below minimum of 60
        vpn_subnets: "".to_string(),
    };

    let body = serde_json::to_string(&payload).unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/admin/ldap-config")
                .method("PUT")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_ldap_config_requires_auth() {
    let app = test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/admin/ldap-config")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}