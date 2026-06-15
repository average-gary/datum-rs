//! SV1 server task: TCP listener + per-connection state machine.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use crate::{extranonce1, StratumRequest, StratumResponse};

/// Inbound notify payload from the runtime: a fully-pre-built `mining.notify`
/// params array. Phase 3 punts coinbase + merkle synthesis up the call stack;
/// the SV1 server just relays whatever the runtime publishes.
pub type NotifyParams = Value;

/// Forwarded share-submit, populated when a miner sends `mining.submit`.
/// The runtime decides what to do with it — typically encode as a DATUM
/// `0x27` share submission and forward upstream.
#[derive(Debug, Clone)]
pub struct SubmittedShare {
    pub username: String,
    pub job_id: String,
    pub extranonce2_hex: String,
    pub ntime_hex: String,
    pub nonce_hex: String,
    /// Per-connection extranonce1 (4 bytes). The DATUM `0x27` opcode expects
    /// the full 12-byte extranonce field as `xn1 || xn2`; we forward `xn1` so
    /// the relay can prepend it.
    pub extranonce1: [u8; 4],
}

#[derive(Clone)]
pub struct ServerState {
    pub thread_id: u16,
    pub client_id: Arc<AtomicU32>,
    pub notify_rx: watch::Receiver<Option<NotifyParams>>,
    pub submit_tx: Option<tokio::sync::mpsc::Sender<SubmittedShare>>,
}

impl ServerState {
    pub fn new(notify_rx: watch::Receiver<Option<NotifyParams>>) -> Self {
        Self {
            thread_id: 0,
            client_id: Arc::new(AtomicU32::new(0)),
            notify_rx,
            submit_tx: None,
        }
    }

    pub fn with_submit_tx(mut self, tx: tokio::sync::mpsc::Sender<SubmittedShare>) -> Self {
        self.submit_tx = Some(tx);
        self
    }
}

/// Bind + accept loop. Spawns one task per accepted connection. Returns when
/// `shutdown` resolves; in-flight connections are dropped.
pub async fn run(
    listener: TcpListener,
    state: ServerState,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("sv1 server: shutdown received");
                    return;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((sock, peer)) => {
                        let st = state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(sock, st).await {
                                tracing::debug!(%peer, error = %e, "sv1 connection ended");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "sv1 accept failed");
                    }
                }
            }
        }
    }
}

async fn handle_connection(sock: TcpStream, state: ServerState) -> std::io::Result<()> {
    let client_id = state.client_id.fetch_add(1, Ordering::Relaxed);
    let xn1 = extranonce1(state.thread_id, client_id);
    let xn1_hex = format!("{xn1:08x}");
    // C reference: extranonce1 is 4 bytes, extranonce2 is 8 bytes — total 12.
    // OCEAN's DATUM `0x27` opcode is hard-coded to a 12-byte extranonce field
    // (`pow.extranonce[12]` + `msg[i]=12` length byte), and the server only
    // accepts that split. Advertising 4 here would force the miner to send
    // 4-byte extranonce2s, which would never reconstruct to 12 bytes upstream.
    let extranonce2_size: u32 = 8;
    let mut subscribed = false;
    let mut authorized = false;
    let mut authorized_username: String = String::new();

    let (rd, mut wr) = sock.into_split();
    let mut lines = BufReader::new(rd).lines();
    let mut notify_rx = state.notify_rx.clone();

    loop {
        tokio::select! {
            biased;
            line = lines.next_line() => {
                let line = match line? {
                    Some(l) => l,
                    None => return Ok(()), // peer closed
                };
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let req: StratumRequest = match serde_json::from_str(trimmed) {
                    Ok(r) => r,
                    Err(_) => {
                        let resp = StratumResponse::err(Value::Null, -32700, "Parse error");
                        write_response(&mut wr, &resp).await?;
                        continue;
                    }
                };
                match req.method.as_str() {
                    "mining.subscribe" => {
                        let session_id = format!("{client_id:08x}");
                        let result = json!([
                            [
                                ["mining.set_difficulty", "1"],
                                ["mining.notify", session_id]
                            ],
                            xn1_hex,
                            extranonce2_size,
                        ]);
                        write_response(&mut wr, &StratumResponse::ok(req.id, result)).await?;
                        subscribed = true;
                    }
                    "mining.authorize" => {
                        if let Some(name) = req.params.get(0).and_then(|v| v.as_str()) {
                            authorized_username = name.to_string();
                        }
                        write_response(
                            &mut wr,
                            &StratumResponse::ok(req.id, Value::Bool(true)),
                        )
                        .await?;
                        authorized = true;
                        let pending = notify_rx.borrow().clone();
                        if let Some(params) = pending {
                            send_notify(&mut wr, &params).await?;
                        }
                    }
                    "mining.submit" => {
                        if !subscribed {
                            write_response(
                                &mut wr,
                                &StratumResponse::err(req.id, 25, "Not subscribed"),
                            )
                            .await?;
                            continue;
                        }
                        if !authorized {
                            write_response(
                                &mut wr,
                                &StratumResponse::err(req.id, 24, "Unauthorized worker"),
                            )
                            .await?;
                            continue;
                        }
                        // Parse SV1 submit params: [username, job_id,
                        // extranonce2_hex, ntime_hex, nonce_hex]
                        let parsed = parse_submit_params(&req.params);
                        match parsed {
                            Some(s) => {
                                let share = SubmittedShare {
                                    username: if s.username.is_empty() {
                                        authorized_username.clone()
                                    } else {
                                        s.username
                                    },
                                    job_id: s.job_id,
                                    extranonce2_hex: s.extranonce2_hex,
                                    ntime_hex: s.ntime_hex,
                                    nonce_hex: s.nonce_hex,
                                    // The wire-side extranonce1 bytes are the
                                    // natural left-to-right interpretation of
                                    // the 8-char hex emitted in mining.subscribe
                                    // (`{xn1:08x}`) — i.e. big-endian byte order.
                                    // C reference: `pk_u32le(extranonce_bin, 0,
                                    // m->sid_inv)` writes those exact bytes.
                                    extranonce1: xn1.to_be_bytes(),
                                };
                                if let Some(tx) = &state.submit_tx {
                                    if tx.send(share).await.is_err() {
                                        tracing::warn!("submit_tx receiver dropped");
                                    }
                                } else {
                                    tracing::debug!(
                                        "mining.submit received but no submit_tx wired"
                                    );
                                }
                                // Optimistically ack — the upstream pool
                                // sends a separate ShareResponse asynchronously
                                // which the runtime can route back via
                                // future plumbing.
                                write_response(
                                    &mut wr,
                                    &StratumResponse::ok(req.id, Value::Bool(true)),
                                )
                                .await?;
                            }
                            None => {
                                write_response(
                                    &mut wr,
                                    &StratumResponse::err(
                                        req.id,
                                        20,
                                        "Malformed mining.submit params",
                                    ),
                                )
                                .await?;
                            }
                        }
                    }
                    "mining.suggest_difficulty" => {
                        write_response(&mut wr, &StratumResponse::ok(req.id, Value::Bool(true))).await?;
                    }
                    other => {
                        write_response(
                            &mut wr,
                            &StratumResponse::err(req.id, 20, &format!("Unknown method: {other}")),
                        )
                        .await?;
                    }
                }
            }
            changed = notify_rx.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
                if subscribed && authorized {
                    let pending = notify_rx.borrow_and_update().clone();
                    if let Some(params) = pending {
                        send_notify(&mut wr, &params).await?;
                    }
                }
            }
        }
    }
}

/// SV1 `mining.submit` params: `[username, job_id, extranonce2, ntime, nonce]`,
/// all strings. Returns `None` if the array is missing, has fewer than 5
/// entries, or any entry is not a string.
fn parse_submit_params(params: &Value) -> Option<SubmittedShare> {
    let arr = params.as_array()?;
    if arr.len() < 5 {
        return None;
    }
    let username = arr[0].as_str()?.to_string();
    let job_id = arr[1].as_str()?.to_string();
    let extranonce2_hex = arr[2].as_str()?.to_string();
    let ntime_hex = arr[3].as_str()?.to_string();
    let nonce_hex = arr[4].as_str()?.to_string();
    Some(SubmittedShare {
        username,
        job_id,
        extranonce2_hex,
        ntime_hex,
        nonce_hex,
        // The connection-bound extranonce1 is filled in at the call site;
        // parse_submit_params only knows the wire-supplied fields.
        extranonce1: [0u8; 4],
    })
}

async fn write_response<W: AsyncWriteExt + Unpin>(
    wr: &mut W,
    resp: &StratumResponse,
) -> std::io::Result<()> {
    let mut s = serde_json::to_string(resp).unwrap();
    s.push('\n');
    wr.write_all(s.as_bytes()).await
}

async fn send_notify<W: AsyncWriteExt + Unpin>(
    wr: &mut W,
    params: &NotifyParams,
) -> std::io::Result<()> {
    let frame = json!({
        "id": Value::Null,
        "method": "mining.notify",
        "params": params,
    });
    let mut s = serde_json::to_string(&frame).unwrap();
    s.push('\n');
    wr.write_all(s.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::sync::watch;

    async fn spawn_server() -> (
        std::net::SocketAddr,
        watch::Sender<Option<NotifyParams>>,
        watch::Sender<bool>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (notify_tx, notify_rx) = watch::channel(None);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let state = ServerState::new(notify_rx);
        tokio::spawn(run(listener, state, shutdown_rx));
        (addr, notify_tx, shutdown_tx)
    }

    async fn read_line<R: AsyncBufReadExt + Unpin>(r: &mut R) -> String {
        let mut buf = String::new();
        r.read_line(&mut buf).await.unwrap();
        buf.trim().to_string()
    }

    #[tokio::test]
    async fn subscribe_authorize_notify_submit_round_trip() {
        let (addr, notify_tx, _shutdown_tx) = spawn_server().await;
        let stream = TcpStream::connect(addr).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);

        // mining.subscribe
        wr.write_all(b"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"test/0.1\"]}\n")
            .await
            .unwrap();
        let resp = read_line(&mut rd).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["id"], 1);
        // result is [subscriptions, extranonce1_hex, extranonce2_size]
        let xn1_hex = v["result"][1].as_str().unwrap();
        assert_eq!(xn1_hex.len(), 8);
        assert_eq!(v["result"][2], 8);

        // mining.authorize
        wr.write_all(b"{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"bc1q\",\"x\"]}\n")
            .await
            .unwrap();
        let resp = read_line(&mut rd).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"], true);

        // server publishes a notify; client should receive it
        let params = json!(["job-1", "00".repeat(32), "01", "02", []]);
        notify_tx.send(Some(params.clone())).unwrap();
        let line = read_line(&mut rd).await;
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["method"], "mining.notify");
        assert_eq!(v["params"], params);

        // mining.submit
        wr.write_all(
            b"{\"id\":3,\"method\":\"mining.submit\",\"params\":[\"bc1q\",\"job-1\",\"00000000\",\"6712f000\",\"deadbeef\"]}\n",
        )
        .await
        .unwrap();
        let resp = read_line(&mut rd).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["id"], 3);
        assert_eq!(v["result"], true);
    }

    #[tokio::test]
    async fn submit_without_subscribe_is_rejected() {
        let (addr, _notify_tx, _shutdown_tx) = spawn_server().await;
        let stream = TcpStream::connect(addr).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);

        wr.write_all(
            b"{\"id\":1,\"method\":\"mining.submit\",\"params\":[\"bc1q\",\"j\",\"0\",\"0\",\"0\"]}\n",
        )
        .await
        .unwrap();
        let resp = read_line(&mut rd).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        let err = &v["error"];
        assert_eq!(err[0], 25);
    }

    #[tokio::test]
    async fn unknown_method_returns_structured_error() {
        let (addr, _notify_tx, _shutdown_tx) = spawn_server().await;
        let stream = TcpStream::connect(addr).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);

        wr.write_all(b"{\"id\":1,\"method\":\"mining.fancy\",\"params\":[]}\n")
            .await
            .unwrap();
        let resp = read_line(&mut rd).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["error"][0], 20);
    }

    #[tokio::test]
    async fn malformed_json_gets_parse_error_response() {
        let (addr, _notify_tx, _shutdown_tx) = spawn_server().await;
        let stream = TcpStream::connect(addr).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);

        wr.write_all(b"this is not json\n").await.unwrap();
        let resp = read_line(&mut rd).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["error"][0], -32700);
    }
}
