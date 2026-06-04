use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use tokio::sync::RwLock;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub enum Auth {
    /// `~/.bitcoin/.cookie` — re-read on 401.
    Cookie(PathBuf),
    /// Static user/pass.
    UserPass { user: String, pass: String },
}

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("read cookie {path}: {source}")]
    CookieRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cookie file is empty: {path}")]
    CookieEmpty { path: PathBuf },
    #[error("rpc error code={code}: {message}")]
    Remote { code: i64, message: String },
    #[error("malformed rpc response (no `result` and no `error`): {body}")]
    Malformed { body: String },
    #[error("deserialize result: {0}")]
    Deserialize(#[from] serde_json::Error),
    #[error("auth failed and cookie reload did not help (HTTP 401)")]
    AuthFailed,
}

pub struct Client {
    http: reqwest::Client,
    url: String,
    auth: RwLock<Auth>,
    cached_userpass: RwLock<Option<String>>,
    next_id: AtomicU64,
}

impl Client {
    pub fn new(url: impl Into<String>, auth: Auth) -> Result<Self, RpcError> {
        let http = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .connect_timeout(DEFAULT_TIMEOUT)
            .tcp_nodelay(true)
            .build()?;
        Ok(Self {
            http,
            url: url.into(),
            auth: RwLock::new(auth),
            cached_userpass: RwLock::new(None),
            next_id: AtomicU64::new(1),
        })
    }

    pub fn with_timeout(
        url: impl Into<String>,
        auth: Auth,
        timeout: Duration,
    ) -> Result<Self, RpcError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .tcp_nodelay(true)
            .build()?;
        Ok(Self {
            http,
            url: url.into(),
            auth: RwLock::new(auth),
            cached_userpass: RwLock::new(None),
            next_id: AtomicU64::new(1),
        })
    }

    /// Generic JSON-RPC call with cookie-reload-on-401 retry semantics
    /// (matches datum_jsonrpc.c's `bitcoind_json_rpc_call`). Uses the
    /// client's default timeout (5s).
    pub async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<T, RpcError> {
        let resp_value = self.call_value(method, params, None).await?;
        Ok(serde_json::from_value(resp_value)?)
    }

    /// Like [`call`], but overrides the per-request timeout — necessary for
    /// long-poll calls (`getblocktemplate` with `longpollid` set) which
    /// bitcoind holds open up to ~60s waiting for tip changes.
    pub async fn call_with_timeout<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<T, RpcError> {
        let resp_value = self.call_value(method, params, Some(timeout)).await?;
        Ok(serde_json::from_value(resp_value)?)
    }

    async fn call_value(
        &self,
        method: &str,
        params: Value,
        per_call_timeout: Option<Duration>,
    ) -> Result<Value, RpcError> {
        let userpass = self.userpass().await?;
        let body = self.request_body(method, &params);

        let resp = self.http_call(&userpass, &body, per_call_timeout).await?;
        if let Some(value) = resp {
            return parse_rpc_response(value);
        }

        if matches!(*self.auth.read().await, Auth::Cookie(_)) {
            let _ = self.cached_userpass.write().await.take();
            let userpass = self.userpass().await?;
            let resp = self.http_call(&userpass, &body, per_call_timeout).await?;
            if let Some(value) = resp {
                return parse_rpc_response(value);
            }
        }

        Err(RpcError::AuthFailed)
    }

    async fn http_call(
        &self,
        userpass: &str,
        body: &str,
        per_call_timeout: Option<Duration>,
    ) -> Result<Option<Value>, RpcError> {
        let (user, pass) = split_userpass(userpass);
        let mut req = self
            .http
            .post(&self.url)
            .basic_auth(user, Some(pass))
            .header("Content-Type", "application/json")
            .body(body.to_owned());
        if let Some(t) = per_call_timeout {
            req = req.timeout(t);
        }
        let response = req.send().await?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Ok(None);
        }

        let value: Value = response.error_for_status()?.json().await?;
        Ok(Some(value))
    }

    fn request_body(&self, method: &str, params: &Value) -> String {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        json!({
            "jsonrpc": "1.0",
            "id": id.to_string(),
            "method": method,
            "params": params,
        })
        .to_string()
    }

    async fn userpass(&self) -> Result<String, RpcError> {
        if let Some(cached) = self.cached_userpass.read().await.clone() {
            return Ok(cached);
        }
        let auth = self.auth.read().await.clone();
        let userpass = resolve_auth(&auth)?;
        *self.cached_userpass.write().await = Some(userpass.clone());
        Ok(userpass)
    }
}

impl Client {
    pub async fn getbestblockhash(&self) -> Result<String, RpcError> {
        self.call("getbestblockhash", json!([])).await
    }

    pub async fn getblocktemplate(&self, rules: &[&str]) -> Result<Value, RpcError> {
        self.call("getblocktemplate", json!([{ "rules": rules }]))
            .await
    }

    /// Submit a fully-serialized block (header || varint(tx_count) || serialized
    /// transactions) as hex. Bitcoin Core returns null on success or an error
    /// string. We map a non-null result to RpcError::Remote so callers don't
    /// have to inspect strings.
    pub async fn submitblock(&self, hex_block: &str) -> Result<(), RpcError> {
        let result: Value = self.call("submitblock", json!([hex_block])).await?;
        match result {
            Value::Null => Ok(()),
            Value::String(s) if s.is_empty() => Ok(()),
            Value::String(s) => Err(RpcError::Remote {
                code: -1,
                message: s,
            }),
            other => Err(RpcError::Remote {
                code: -1,
                message: other.to_string(),
            }),
        }
    }

    pub async fn preciousblock(&self, blockhash_hex: &str) -> Result<(), RpcError> {
        let _: Value = self.call("preciousblock", json!([blockhash_hex])).await?;
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct RpcRemoteError {
    code: i64,
    #[serde(default)]
    message: String,
}

fn parse_rpc_response(value: Value) -> Result<Value, RpcError> {
    let body_text = value.to_string();
    let Value::Object(mut map) = value else {
        return Err(RpcError::Malformed { body: body_text });
    };
    if let Some(err_value) = map.remove("error") {
        if !err_value.is_null() {
            let err: RpcRemoteError =
                serde_json::from_value(err_value).map_err(RpcError::Deserialize)?;
            return Err(RpcError::Remote {
                code: err.code,
                message: err.message,
            });
        }
    }
    match map.remove("result") {
        Some(v) => Ok(v),
        None => Err(RpcError::Malformed { body: body_text }),
    }
}

fn resolve_auth(auth: &Auth) -> Result<String, RpcError> {
    match auth {
        Auth::Cookie(path) => {
            let raw = std::fs::read_to_string(path).map_err(|source| RpcError::CookieRead {
                path: path.clone(),
                source,
            })?;
            let line = raw.lines().next().unwrap_or("").trim();
            if line.is_empty() {
                return Err(RpcError::CookieEmpty { path: path.clone() });
            }
            Ok(line.to_string())
        }
        Auth::UserPass { user, pass } => Ok(format!("{user}:{pass}")),
    }
}

fn split_userpass(s: &str) -> (&str, &str) {
    match s.find(':') {
        Some(idx) => (&s[..idx], &s[idx + 1..]),
        None => (s, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn cookie_parse_strips_newline() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "__cookie__:abc123def").unwrap();
        let userpass = resolve_auth(&Auth::Cookie(tmp.path().to_path_buf())).unwrap();
        assert_eq!(userpass, "__cookie__:abc123def");
    }

    #[test]
    fn cookie_empty_file_errors() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let err = resolve_auth(&Auth::Cookie(tmp.path().to_path_buf())).unwrap_err();
        assert!(matches!(err, RpcError::CookieEmpty { .. }));
    }

    #[test]
    fn cookie_missing_file_errors() {
        let path = PathBuf::from("/nonexistent/path/to/cookie");
        let err = resolve_auth(&Auth::Cookie(path.clone())).unwrap_err();
        assert!(matches!(err, RpcError::CookieRead { .. }));
    }

    #[test]
    fn userpass_resolves_directly() {
        let auth = Auth::UserPass {
            user: "rpc".into(),
            pass: "secret".into(),
        };
        assert_eq!(resolve_auth(&auth).unwrap(), "rpc:secret");
    }

    #[test]
    fn split_userpass_basic() {
        assert_eq!(split_userpass("rpc:secret"), ("rpc", "secret"));
        assert_eq!(split_userpass("__cookie__:abc"), ("__cookie__", "abc"));
        assert_eq!(split_userpass("nopass"), ("nopass", ""));
        assert_eq!(split_userpass(":only-pass"), ("", "only-pass"));
    }

    #[test]
    fn parse_response_success() {
        let v = json!({ "result": "deadbeef", "error": null, "id": "1" });
        let r = parse_rpc_response(v).unwrap();
        assert_eq!(r, json!("deadbeef"));
    }

    #[test]
    fn parse_response_error() {
        let v = json!({
            "result": null,
            "error": {"code": -8, "message": "bad-txns"},
            "id": "1"
        });
        let err = parse_rpc_response(v).unwrap_err();
        match err {
            RpcError::Remote { code, message } => {
                assert_eq!(code, -8);
                assert_eq!(message, "bad-txns");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_response_malformed() {
        let v = json!({ "id": "1" });
        let err = parse_rpc_response(v).unwrap_err();
        assert!(matches!(err, RpcError::Malformed { .. }));
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use http_body_util::{BodyExt, Full};
    use hyper::body::{Bytes, Incoming};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::net::TcpListener;

    /// Spawn a one-shot mock JSON-RPC server. Each accepted connection is
    /// served by `handler`. Returns the URL and a request counter.
    async fn spawn_mock<H, Fut>(handler: H) -> (String, Arc<AtomicUsize>)
    where
        H: Fn(Request<Incoming>, Arc<AtomicUsize>) -> Fut + Send + Sync + Clone + 'static,
        Fut: Future<Output = Response<Full<Bytes>>> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        let server_counter = counter.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let io = TokioIo::new(stream);
                let h = handler.clone();
                let c = server_counter.clone();
                tokio::spawn(async move {
                    let _ = http1::Builder::new()
                        .serve_connection(
                            io,
                            service_fn(|req| {
                                let h = h.clone();
                                let c = c.clone();
                                async move { Ok::<_, Infallible>(h(req, c).await) }
                            }),
                        )
                        .await;
                });
            }
        });
        (format!("http://{addr}"), counter)
    }

    fn body(s: &str) -> Full<Bytes> {
        Full::new(Bytes::copy_from_slice(s.as_bytes()))
    }

    fn user_pass() -> Auth {
        Auth::UserPass {
            user: "u".into(),
            pass: "p".into(),
        }
    }

    #[tokio::test]
    async fn getbestblockhash_round_trip() {
        let (url, _) = spawn_mock(|_req, counter| async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Response::new(body(
                r#"{"result":"000000000000000000aabbcc","error":null,"id":"1"}"#,
            ))
        })
        .await;
        let client = Client::new(url, user_pass()).unwrap();
        let hash = client.getbestblockhash().await.unwrap();
        assert_eq!(hash, "000000000000000000aabbcc");
    }

    #[tokio::test]
    async fn submitblock_null_result_means_accepted() {
        let (url, _) = spawn_mock(|req, _| async move {
            let bytes = req.into_body().collect().await.unwrap().to_bytes();
            let req_json: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(req_json["method"], "submitblock");
            assert_eq!(req_json["params"][0], "deadbeefhex");
            Response::new(body(r#"{"result":null,"error":null,"id":"1"}"#))
        })
        .await;
        let client = Client::new(url, user_pass()).unwrap();
        client.submitblock("deadbeefhex").await.unwrap();
    }

    #[tokio::test]
    async fn cookie_reload_on_401_then_success() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "__cookie__:wrong").unwrap();
        let cookie_path = tmp.path().to_path_buf();

        let (url, counter) = spawn_mock(|_req, c| async move {
            let n = c.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                let mut resp = Response::new(body(""));
                *resp.status_mut() = StatusCode::UNAUTHORIZED;
                resp
            } else {
                Response::new(body(r#"{"result":"00112233","error":null,"id":"2"}"#))
            }
        })
        .await;

        std::fs::write(&cookie_path, "__cookie__:freshhex\n").unwrap();
        let client = Client::new(url, Auth::Cookie(cookie_path)).unwrap();
        let hash = client.getbestblockhash().await.unwrap();
        assert_eq!(hash, "00112233");
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn rpc_error_propagates() {
        let (url, _) = spawn_mock(|_req, _| async move {
            Response::new(body(
                r#"{"result":null,"error":{"code":-8,"message":"bad-txns"},"id":"1"}"#,
            ))
        })
        .await;
        let client = Client::new(url, user_pass()).unwrap();
        let err = client.getbestblockhash().await.unwrap_err();
        match err {
            RpcError::Remote { code, message } => {
                assert_eq!(code, -8);
                assert_eq!(message, "bad-txns");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
