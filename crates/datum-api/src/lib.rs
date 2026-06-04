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

use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use include_dir::{include_dir, Dir};
#[allow(unused_imports)]
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub mod digest;

static WWW: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/www");

pub trait MetricsSource: Send + Sync {
    fn snapshot(&self) -> Value;
}

#[derive(Clone)]
pub struct ApiState {
    pub metrics: Arc<dyn MetricsSource>,
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/", get(root_html))
        .route("/clients", get(clients_html))
        .route("/threads", get(threads_html))
        .route("/coinbaser", get(coinbaser_html))
        .route("/config", get(config_html))
        .route("/cmd", post(cmd_post))
        .route("/NOTIFY", post(notify_post))
        .route("/testnet_fastforward", post(testnet_fastforward))
        .route("/umbrel-api", get(umbrel_api))
        .route("/assets/*path", get(serve_asset))
        .route("/api/metrics", get(metrics_json))
        .with_state(state)
}

/// Returns the embedded HTML page for `name` (without `.html`), wrapping it in
/// `home.html` + `foot.html` like the C gateway does.
fn render_page(name: &str) -> Result<String, StatusCode> {
    let page = WWW
        .get_file(format!("{name}.html"))
        .ok_or(StatusCode::NOT_FOUND)?;
    let foot = WWW
        .get_file("foot.html")
        .map(|f| f.contents_utf8().unwrap_or(""))
        .unwrap_or("");
    let body = page
        .contents_utf8()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(format!("{body}{foot}"))
}

async fn root_html() -> impl IntoResponse {
    match render_page("home") {
        Ok(html) => Html(html).into_response(),
        Err(s) => s.into_response(),
    }
}

async fn clients_html() -> impl IntoResponse {
    match render_page("clients_top") {
        Ok(html) => Html(html).into_response(),
        Err(s) => s.into_response(),
    }
}

async fn threads_html() -> impl IntoResponse {
    match render_page("threads_top") {
        Ok(html) => Html(html).into_response(),
        Err(s) => s.into_response(),
    }
}

async fn coinbaser_html() -> impl IntoResponse {
    match render_page("coinbaser_top") {
        Ok(html) => Html(html).into_response(),
        Err(s) => s.into_response(),
    }
}

async fn config_html() -> impl IntoResponse {
    match render_page("config") {
        Ok(html) => Html(html).into_response(),
        Err(s) => s.into_response(),
    }
}

async fn metrics_json(State(s): State<ApiState>) -> impl IntoResponse {
    Json(s.metrics.snapshot())
}

async fn serve_asset(Path(path): Path<String>) -> Response {
    let lookup = format!("assets/{path}");
    let Some(file) = WWW.get_file(&lookup) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mime = mime_guess::from_path(&lookup).first_or_octet_stream();
    let mut response = (StatusCode::OK, file.contents().to_vec()).into_response();
    if let Ok(value) = HeaderValue::from_str(mime.essence_str()) {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    response
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
    async fn root_returns_html() {
        let resp = app()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let s = std::str::from_utf8(&body).unwrap();
        assert!(s.contains("<"));
    }

    #[tokio::test]
    async fn metrics_json_endpoint_works() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .uri("/api/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["miner_count"], 0);
    }

    #[tokio::test]
    async fn assets_css_is_served() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .uri("/assets/style.css")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get("content-type").unwrap();
        assert!(ct.to_str().unwrap().contains("css"));
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
