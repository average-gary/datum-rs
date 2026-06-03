//! Operator-facing HTTP API.
//!
//! Phase 4 status: 14-endpoint URL contract from
//! [drop-in-surface-inventory] § HTTP API endpoints is wired up. JSON
//! shapes return placeholder data sourced from a `MetricsSource` trait;
//! the live runtime plugs the real source. Embedded HTML/CSS/SVG and
//! HTTP Digest auth are deferred — the JSON contract (which Umbrel
//! widgets and operator polling scripts actually use) is what ships
//! first.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub mod digest;

pub trait MetricsSource: Send + Sync {
    fn snapshot(&self) -> Value;
}

#[derive(Clone)]
pub struct ApiState {
    pub metrics: Arc<dyn MetricsSource>,
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/clients", get(clients))
        .route("/threads", get(threads))
        .route("/coinbaser", get(coinbaser))
        .route("/config", get(config_get))
        .route("/cmd", post(cmd_post))
        .route("/NOTIFY", post(notify_post))
        .route("/testnet_fastforward", post(testnet_fastforward))
        .route("/umbrel-api", get(umbrel_api))
        .with_state(state)
}

async fn root(State(s): State<ApiState>) -> impl IntoResponse {
    Json(json!({ "service": "datum_gateway", "metrics": s.metrics.snapshot() }))
}

async fn clients(State(s): State<ApiState>) -> impl IntoResponse {
    Json(s.metrics.snapshot())
}

async fn threads(State(_s): State<ApiState>) -> impl IntoResponse {
    Json(json!({ "threads": [] }))
}

async fn coinbaser(State(_s): State<ApiState>) -> impl IntoResponse {
    Json(json!({ "outputs": [] }))
}

async fn config_get(State(_s): State<ApiState>) -> impl IntoResponse {
    Json(json!({}))
}

async fn cmd_post() -> impl IntoResponse {
    (StatusCode::ACCEPTED, "ok")
}

async fn notify_post() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn testnet_fastforward() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn umbrel_api(State(s): State<ApiState>) -> impl IntoResponse {
    Json(s.metrics.snapshot())
}

/// CSRF token format from [drop-in-surface-inventory] § four hard surfaces:
/// `SHA256("DATUM Anti-CSRF Token" + port + admin_password)`. Returned as
/// 64 hex chars.
pub fn csrf_token(port: u16, admin_password: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"DATUM Anti-CSRF Token");
    h.update(port.to_string().as_bytes());
    h.update(admin_password.as_bytes());
    hex_lower(&h.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(hex_nib(b >> 4));
        s.push(hex_nib(b & 0x0F));
    }
    s
}

fn hex_nib(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + n - 10) as char,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    struct DummyMetrics;
    impl MetricsSource for DummyMetrics {
        fn snapshot(&self) -> Value {
            json!({ "miner_count": 0, "share_rate_5m": 0.0 })
        }
    }

    fn app() -> Router {
        router(ApiState {
            metrics: Arc::new(DummyMetrics),
        })
    }

    #[tokio::test]
    async fn root_returns_metrics() {
        let resp = app()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["service"], "datum_gateway");
    }

    #[tokio::test]
    async fn umbrel_api_returns_json() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .uri("/umbrel-api")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn notify_post_returns_ok() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/NOTIFY")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn csrf_token_is_deterministic_64_hex() {
        let t1 = csrf_token(7152, "secret");
        let t2 = csrf_token(7152, "secret");
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 64);
        assert!(t1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn csrf_token_changes_with_port() {
        assert_ne!(csrf_token(7152, "x"), csrf_token(7153, "x"));
    }

    #[test]
    fn csrf_token_changes_with_password() {
        assert_ne!(csrf_token(7152, "a"), csrf_token(7152, "b"));
    }
}
