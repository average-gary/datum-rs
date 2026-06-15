//! SV1 server task: TCP listener + per-connection state machine.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use crate::{extranonce1, StratumRequest, StratumResponse};

/// Pool-allowed BIP-310 version-rolling mask. Mirrors C reference
/// `datum_stratum.c:1399` — the bits of nVersion the pool will accept the miner
/// rolling. Any miner-requested mask is ANDed with this before being acked.
const POOL_VERSION_MASK: u32 = 0x1fffe000;

/// Inbound notify job from the runtime: the pre-built `mining.notify` params
/// JSON array plus the byte offset within `coinb1` where the PoT placeholder
/// lives. The server patches the placeholder byte to `floor_pot(current_diff)`
/// per-miner before sending — the C reference does the same in
/// `datum_stratum.c:1597-1598`. A `target_pot_index` of 0 disables patching
/// (used by tests with synthetic params).
#[derive(Debug, Clone)]
pub struct NotifyJob {
    pub params: Value,
    pub target_pot_index: u16,
}

impl NotifyJob {
    pub fn new(params: Value, target_pot_index: u16) -> Self {
        Self {
            params,
            target_pot_index,
        }
    }
}

/// Compatibility alias for callers that already speak the JSON-array shape.
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
    /// BIP-310 version-rolling: bits the miner rolled, already masked against
    /// the negotiated mask. Zero when the miner never sent mining.configure or
    /// when no rolled bits were set in the share.
    pub version_rolling: u32,
    /// Per-miner difficulty at the moment this share was submitted. Stamped
    /// by the SV1 server's vardiff loop (the server task is the sole owner of
    /// the per-connection diff state). Used by the share-relay to set the
    /// DATUM `0x27` `target_byte = floor_pot(current_diff)`.
    pub current_diff: u64,
}

/// Per-connection vardiff knobs. Defaults match `vardiff_min=1`,
/// `target_shares_min=8`, a 30s recheck cadence, and a generous max ceiling.
/// Datum-bin overrides these from `cfg.stratum.*` at startup.
#[derive(Debug, Clone, Copy)]
pub struct VardiffParams {
    pub min: u64,
    pub target_shares_min: u32,
    pub recheck_secs: u64,
    pub max: u64,
}

impl Default for VardiffParams {
    fn default() -> Self {
        Self {
            min: 1,
            target_shares_min: 8,
            recheck_secs: 30,
            max: 1u64 << 40,
        }
    }
}

#[derive(Clone)]
pub struct ServerState {
    pub thread_id: u16,
    pub client_id: Arc<AtomicU32>,
    pub notify_rx: watch::Receiver<Option<NotifyJob>>,
    pub submit_tx: Option<tokio::sync::mpsc::Sender<SubmittedShare>>,
    pub vardiff: VardiffParams,
}

impl ServerState {
    pub fn new(notify_rx: watch::Receiver<Option<NotifyJob>>) -> Self {
        Self {
            thread_id: 0,
            client_id: Arc::new(AtomicU32::new(0)),
            notify_rx,
            submit_tx: None,
            vardiff: VardiffParams::default(),
        }
    }

    pub fn with_submit_tx(mut self, tx: tokio::sync::mpsc::Sender<SubmittedShare>) -> Self {
        self.submit_tx = Some(tx);
        self
    }

    pub fn with_vardiff(mut self, vardiff: VardiffParams) -> Self {
        self.vardiff = vardiff;
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

    // BIP-310 per-connection state. Antminers send mining.configure BEFORE
    // mining.subscribe; none of the dispatcher arms gate on subscribed/authorized
    // so this is safe.
    let mut version_rolling_enabled: bool = false;
    let mut version_rolling_mask: u32 = 0;
    let mut min_diff_acked: bool = false;
    let mut subscribe_extranonce_acked: bool = false;

    // Vardiff per-connection state. The server task is the sole owner of this
    // miner's diff — no shared map / lock needed (Option A in the design).
    let mut current_diff: u64 = state.vardiff.min;
    let mut shares_since_snap: u32 = 0;
    let mut last_snap = tokio::time::Instant::now();
    let mut diff_timer =
        tokio::time::interval(std::time::Duration::from_secs(state.vardiff.recheck_secs));
    diff_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // First tick fires immediately; burn it so the timer aligns to recheck_secs
    // from connection-establishment time, not 0.
    diff_timer.tick().await;

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
                    "mining.configure" => {
                        // BIP-310: params = [ [extension names...], { options } ].
                        // Be permissive: a missing options object defaults each
                        // extension to its conservative default. Some Antminer
                        // firmware variants send params[1] as null.
                        let arr = req.params.as_array();
                        let names = arr
                            .and_then(|a| a.first())
                            .and_then(|v| v.as_array());
                        let opts = arr
                            .and_then(|a| a.get(1))
                            .and_then(|v| v.as_object());
                        let Some(names) = names else {
                            write_response(
                                &mut wr,
                                &StratumResponse::err(
                                    req.id,
                                    20,
                                    "Malformed mining.configure params",
                                ),
                            )
                            .await?;
                            continue;
                        };
                        let mut result_obj = serde_json::Map::new();
                        let mut negotiated_mask: Option<u32> = None;
                        for ext in names {
                            let Some(name) = ext.as_str() else { continue };
                            match name {
                                "version-rolling" => {
                                    let requested_mask = opts
                                        .and_then(|o| o.get("version-rolling.mask"))
                                        .and_then(|v| v.as_str())
                                        .and_then(|s| {
                                            u32::from_str_radix(
                                                s.trim_start_matches("0x"),
                                                16,
                                            )
                                            .ok()
                                        })
                                        .unwrap_or(POOL_VERSION_MASK);
                                    let mask = requested_mask & POOL_VERSION_MASK;
                                    version_rolling_enabled = true;
                                    version_rolling_mask = mask;
                                    negotiated_mask = Some(mask);
                                    result_obj.insert(
                                        "version-rolling".to_string(),
                                        Value::Bool(true),
                                    );
                                    result_obj.insert(
                                        "version-rolling.mask".to_string(),
                                        Value::String(format!("{mask:08x}")),
                                    );
                                    tracing::info!(
                                        client_id,
                                        mask = format!("{mask:08x}"),
                                        "mining.configure: version-rolling negotiated"
                                    );
                                }
                                "minimum-difficulty" => {
                                    let val = opts
                                        .and_then(|o| o.get("minimum-difficulty.value"))
                                        .and_then(|v| v.as_u64());
                                    min_diff_acked = true;
                                    // We ack true because vardiff_min from config governs the
                                    // floor; diverges from C (which returns false) on purpose.
                                    result_obj.insert(
                                        "minimum-difficulty".to_string(),
                                        Value::Bool(true),
                                    );
                                    if let Some(v) = val {
                                        tracing::debug!(
                                            client_id,
                                            requested = v,
                                            "mining.configure: minimum-difficulty requested"
                                        );
                                    }
                                }
                                "subscribe-extranonce" => {
                                    subscribe_extranonce_acked = true;
                                    // No actual mining.set_extranonce push wiring yet — see
                                    // server.rs RISK note: if we ever rotate xn1 mid-connection
                                    // for any reason, this ack must be downgraded to false.
                                    result_obj.insert(
                                        "subscribe-extranonce".to_string(),
                                        Value::Bool(true),
                                    );
                                }
                                _ => {
                                    // BIP-310: silently ignore unknown extensions.
                                }
                            }
                        }
                        write_response(
                            &mut wr,
                            &StratumResponse::ok(req.id, Value::Object(result_obj)),
                        )
                        .await?;
                        if let Some(mask) = negotiated_mask {
                            send_set_version_mask(&mut wr, mask).await?;
                        }
                        let _ = min_diff_acked;
                        let _ = subscribe_extranonce_acked;
                    }
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
                        // Push the initial mining.set_difficulty so the miner has a target
                        // BEFORE the first notify. C reference: datum_stratum.c:1772 sends
                        // set_difficulty, then notify, on subscribe. We mirror that ordering
                        // (the first notify is deferred to authorize in the Rust handler).
                        send_set_difficulty(&mut wr, current_diff).await?;
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
                        if let Some(job) = pending {
                            send_notify(&mut wr, &job, current_diff).await?;
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
                        // extranonce2_hex, ntime_hex, nonce_hex, optional nversion_hex]
                        let parsed = parse_submit_params(&req.params);
                        match parsed {
                            Some(s) => {
                                // BIP-310: if version-rolling was negotiated, the 6th
                                // param is REQUIRED and must only set bits within the
                                // negotiated mask. C reference: datum_stratum.c:1061.
                                let version_rolling = if version_rolling_enabled {
                                    match s.version_rolling_raw {
                                        Some(nv) if (nv & !version_rolling_mask) == 0 => {
                                            nv & version_rolling_mask
                                        }
                                        _ => {
                                            write_response(
                                                &mut wr,
                                                &StratumResponse::err(req.id, 23, "Bad version"),
                                            )
                                            .await?;
                                            continue;
                                        }
                                    }
                                } else {
                                    // Version-rolling not negotiated: ignore any 6th param.
                                    0
                                };
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
                                    version_rolling,
                                    current_diff,
                                };
                                shares_since_snap = shares_since_snap.saturating_add(1);
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
                    if let Some(job) = pending {
                        send_notify(&mut wr, &job, current_diff).await?;
                    }
                }
            }
            _ = diff_timer.tick() => {
                // Vardiff: snapshot-based rate measurement. Compares observed
                // submits in the window against the expected count at the
                // configured target_shares_min. Halve when way under, double
                // when way over (with a 16-share guard for upward bumps to
                // avoid flapping on bursty miners — mirrors C's share_count_since_snap
                // < 16 check).
                let elapsed = last_snap.elapsed();
                let target = state.vardiff.target_shares_min as u64;
                let window_secs = elapsed.as_secs().max(1);
                let expected = (target * window_secs).div_ceil(60).max(1);
                let observed = shares_since_snap as u64;
                let mut new_diff = current_diff;
                if observed >= 16 && observed > expected.saturating_mul(2) {
                    new_diff = current_diff.saturating_mul(2).min(state.vardiff.max);
                } else if observed.saturating_mul(2) < expected
                    && elapsed.as_secs() >= state.vardiff.recheck_secs
                {
                    new_diff = (current_diff / 2).max(state.vardiff.min);
                }
                if new_diff != current_diff && subscribed {
                    current_diff = new_diff;
                    send_set_difficulty(&mut wr, current_diff).await?;
                    tracing::info!(
                        client_id,
                        diff = current_diff,
                        "vardiff: diff changed"
                    );
                    // C reference rebuilds coinb1 per-miner with the new PoT
                    // byte and re-emits the current notify (datum_stratum.c
                    // calls send_mining_notify on diff change). Mirror that —
                    // otherwise the miner keeps hashing the OLD PoT byte until
                    // the next template lands.
                    if authorized {
                        let pending = notify_rx.borrow().clone();
                        if let Some(job) = pending {
                            send_notify(&mut wr, &job, current_diff).await?;
                        }
                    }
                }
                shares_since_snap = 0;
                last_snap = tokio::time::Instant::now();
            }
        }
    }
}

/// Parsed SV1 `mining.submit` params. Distinct from `SubmittedShare` because
/// the per-connection state (xn1, current_diff, version-rolling validation
/// outcome) is layered on at the call site.
struct ParsedSubmit {
    username: String,
    job_id: String,
    extranonce2_hex: String,
    ntime_hex: String,
    nonce_hex: String,
    /// Big-endian u32 hex from the optional 6th param (BIP-310 nversion).
    /// `None` when absent or unparseable. Validation against the negotiated
    /// mask happens at the call site.
    version_rolling_raw: Option<u32>,
}

/// SV1 `mining.submit` params: `[username, job_id, extranonce2, ntime, nonce,
/// nversion?]`, all strings. Returns `None` if the array is missing, has fewer
/// than 5 entries, or any of the first 5 is not a string. The optional 6th is
/// parsed best-effort.
fn parse_submit_params(params: &Value) -> Option<ParsedSubmit> {
    let arr = params.as_array()?;
    if arr.len() < 5 {
        return None;
    }
    let username = arr[0].as_str()?.to_string();
    let job_id = arr[1].as_str()?.to_string();
    let extranonce2_hex = arr[2].as_str()?.to_string();
    let ntime_hex = arr[3].as_str()?.to_string();
    let nonce_hex = arr[4].as_str()?.to_string();
    let version_rolling_raw = arr
        .get(5)
        .and_then(|v| v.as_str())
        .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok());
    Some(ParsedSubmit {
        username,
        job_id,
        extranonce2_hex,
        ntime_hex,
        nonce_hex,
        version_rolling_raw,
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
    job: &NotifyJob,
    current_diff: u64,
) -> std::io::Result<()> {
    let params = patch_coinb1_pot_byte(&job.params, job.target_pot_index, current_diff);
    let frame = json!({
        "id": Value::Null,
        "method": "mining.notify",
        "params": params,
    });
    let mut s = serde_json::to_string(&frame).unwrap();
    s.push('\n');
    wr.write_all(s.as_bytes()).await
}

/// Patch the PoT placeholder byte inside `coinb1` (params index 2) at
/// `target_pot_index` to `floor_pot(current_diff)`. The miner hashes the
/// scriptsig; OCEAN re-hashes the same scriptsig server-side and compares the
/// PoT byte against the per-miner diff. Mirrors `datum_stratum.c:1597-1598`.
///
/// `target_pot_index == 0` is treated as "no patch needed" (tests construct
/// synthetic params; the real assembler always emits a non-zero index because
/// coinb1 starts with the version+prev_hash header).
fn patch_coinb1_pot_byte(params: &Value, target_pot_index: u16, current_diff: u64) -> Value {
    if target_pot_index == 0 {
        return params.clone();
    }
    let mut params = params.clone();
    let Some(arr) = params.as_array_mut() else {
        return params;
    };
    let Some(coinb1_v) = arr.get_mut(2) else {
        return params;
    };
    let Some(coinb1_hex) = coinb1_v.as_str() else {
        return params;
    };
    let hex_offset = (target_pot_index as usize) * 2;
    if hex_offset + 2 > coinb1_hex.len() {
        return params;
    }
    let pot = floor_pot(current_diff);
    let patched = format!(
        "{}{:02x}{}",
        &coinb1_hex[..hex_offset],
        pot,
        &coinb1_hex[hex_offset + 2..]
    );
    *coinb1_v = Value::String(patched);
    params
}

/// `floorPoT(x)`: position of the highest set bit; 0 for x=0. Mirrors
/// `datum_utils.c::floorPoT`.
fn floor_pot(x: u64) -> u8 {
    if x == 0 {
        0
    } else {
        (63 - x.leading_zeros()) as u8
    }
}

async fn send_set_difficulty<W: AsyncWriteExt + Unpin>(
    wr: &mut W,
    diff: u64,
) -> std::io::Result<()> {
    // C reference datum_stratum.c:1650 — params is a JSON number (uint64),
    // not a string. Trailing newline matches every other server-pushed frame.
    let frame = json!({
        "id": Value::Null,
        "method": "mining.set_difficulty",
        "params": [diff],
    });
    let mut s = serde_json::to_string(&frame).unwrap();
    s.push('\n');
    wr.write_all(s.as_bytes()).await
}

async fn send_set_version_mask<W: AsyncWriteExt + Unpin>(
    wr: &mut W,
    mask: u32,
) -> std::io::Result<()> {
    // BIP-310: unsolicited mining.set_version_mask must follow a successful
    // mining.configure that negotiated version-rolling. C reference:
    // datum_stratum.c:1409.
    let frame = json!({
        "id": Value::Null,
        "method": "mining.set_version_mask",
        "params": [format!("{mask:08x}")],
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
        watch::Sender<Option<NotifyJob>>,
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

    async fn spawn_server_with_submit() -> (
        std::net::SocketAddr,
        watch::Sender<Option<NotifyJob>>,
        watch::Sender<bool>,
        tokio::sync::mpsc::Receiver<SubmittedShare>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (notify_tx, notify_rx) = watch::channel(None);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (submit_tx, submit_rx) = tokio::sync::mpsc::channel(8);
        let state = ServerState::new(notify_rx).with_submit_tx(submit_tx);
        tokio::spawn(run(listener, state, shutdown_rx));
        (addr, notify_tx, shutdown_tx, submit_rx)
    }

    async fn spawn_server_with_vardiff(
        vardiff: VardiffParams,
    ) -> (
        std::net::SocketAddr,
        watch::Sender<Option<NotifyJob>>,
        watch::Sender<bool>,
        tokio::sync::mpsc::Receiver<SubmittedShare>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (notify_tx, notify_rx) = watch::channel(None);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (submit_tx, submit_rx) = tokio::sync::mpsc::channel(64);
        let state = ServerState::new(notify_rx)
            .with_submit_tx(submit_tx)
            .with_vardiff(vardiff);
        tokio::spawn(run(listener, state, shutdown_rx));
        (addr, notify_tx, shutdown_tx, submit_rx)
    }

    #[test]
    fn patch_coinb1_writes_floor_pot_at_target_index() {
        // coinb1 hex: 9 bytes — `00 11 22 33 44 ff 55 66 77`. The byte at
        // index 5 is the 0xff placeholder. floor_pot(1024)=10 → 0x0a.
        let params = json!(["job-1", "00".repeat(32), "001122334455667788", "ee", []]);
        let patched = patch_coinb1_pot_byte(&params, 5, 1024);
        let coinb1 = patched[2].as_str().unwrap();
        assert_eq!(coinb1, "00112233440a667788");
    }

    #[test]
    fn patch_coinb1_no_op_when_index_zero() {
        let params = json!(["j", "00".repeat(32), "deadbeef", "ee", []]);
        let same = patch_coinb1_pot_byte(&params, 0, 1024);
        assert_eq!(same, params);
    }

    #[test]
    fn floor_pot_matches_c_reference() {
        assert_eq!(floor_pot(0), 0);
        assert_eq!(floor_pot(1), 0);
        assert_eq!(floor_pot(2), 1);
        assert_eq!(floor_pot(1024), 10);
        assert_eq!(floor_pot(0xFFFF_FFFF), 31);
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

        // Server pushes mining.set_difficulty immediately after subscribe.
        let line = read_line(&mut rd).await;
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["id"], Value::Null);
        assert_eq!(v["method"], "mining.set_difficulty");
        assert_eq!(v["params"], json!([1]));

        // mining.authorize
        wr.write_all(b"{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"bc1q\",\"x\"]}\n")
            .await
            .unwrap();
        let resp = read_line(&mut rd).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"], true);

        // server publishes a notify; client should receive it
        let params = json!(["job-1", "00".repeat(32), "01", "02", []]);
        notify_tx
            .send(Some(NotifyJob::new(params.clone(), 0)))
            .unwrap();
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

    #[tokio::test]
    async fn mining_configure_negotiates_version_rolling() {
        let (addr, _notify_tx, _shutdown_tx) = spawn_server().await;
        let stream = TcpStream::connect(addr).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);

        wr.write_all(
            br#"{"id":1,"method":"mining.configure","params":[["version-rolling","minimum-difficulty","subscribe-extranonce"],{"version-rolling.mask":"1fffe000","version-rolling.min-bit-count":2,"minimum-difficulty.value":2048}]}"#,
        )
        .await
        .unwrap();
        wr.write_all(b"\n").await.unwrap();

        let resp = read_line(&mut rd).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["id"], 1);
        assert_eq!(v["result"]["version-rolling"], true);
        assert_eq!(v["result"]["version-rolling.mask"], "1fffe000");
        assert_eq!(v["result"]["minimum-difficulty"], true);
        assert_eq!(v["result"]["subscribe-extranonce"], true);

        let line = read_line(&mut rd).await;
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["method"], "mining.set_version_mask");
        assert_eq!(v["params"], json!(["1fffe000"]));
    }

    #[tokio::test]
    async fn mining_configure_intersects_mask() {
        let (addr, _notify_tx, _shutdown_tx) = spawn_server().await;
        let stream = TcpStream::connect(addr).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);

        wr.write_all(
            br#"{"id":1,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"ffffffff"}]}"#,
        )
        .await
        .unwrap();
        wr.write_all(b"\n").await.unwrap();

        let resp = read_line(&mut rd).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["version-rolling.mask"], "1fffe000");
        let _ = read_line(&mut rd).await; // burn the set_version_mask push
    }

    #[tokio::test]
    async fn mining_configure_only_version_rolling_omits_other_keys() {
        let (addr, _notify_tx, _shutdown_tx) = spawn_server().await;
        let stream = TcpStream::connect(addr).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);

        wr.write_all(
            br#"{"id":1,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"1fffe000"}]}"#,
        )
        .await
        .unwrap();
        wr.write_all(b"\n").await.unwrap();

        let resp = read_line(&mut rd).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["version-rolling"], true);
        assert!(v["result"].get("minimum-difficulty").is_none());
        assert!(v["result"].get("subscribe-extranonce").is_none());
        let _ = read_line(&mut rd).await;
    }

    #[tokio::test]
    async fn submit_with_version_rolling_propagates_nversion() {
        let (addr, notify_tx, _shutdown_tx, mut submit_rx) = spawn_server_with_submit().await;
        let stream = TcpStream::connect(addr).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);

        wr.write_all(
            br#"{"id":1,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"1fffe000"}]}"#,
        )
        .await
        .unwrap();
        wr.write_all(b"\n").await.unwrap();
        let _ = read_line(&mut rd).await; // configure response
        let _ = read_line(&mut rd).await; // mining.set_version_mask push

        wr.write_all(b"{\"id\":2,\"method\":\"mining.subscribe\",\"params\":[\"v\"]}\n")
            .await
            .unwrap();
        let _ = read_line(&mut rd).await; // subscribe response
        let _ = read_line(&mut rd).await; // initial set_difficulty

        wr.write_all(b"{\"id\":3,\"method\":\"mining.authorize\",\"params\":[\"bc1q\",\"x\"]}\n")
            .await
            .unwrap();
        let _ = read_line(&mut rd).await;

        let params = json!(["job-1", "00".repeat(32), "01", "02", []]);
        notify_tx
            .send(Some(NotifyJob::new(params.clone(), 0)))
            .unwrap();
        let _ = read_line(&mut rd).await; // notify

        wr.write_all(
            br#"{"id":4,"method":"mining.submit","params":["bc1q","job-1","00000000","6712f000","deadbeef","00400000"]}"#,
        )
        .await
        .unwrap();
        wr.write_all(b"\n").await.unwrap();
        let resp = read_line(&mut rd).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"], true);

        let share = submit_rx.recv().await.unwrap();
        assert_eq!(share.version_rolling, 0x00400000);
    }

    #[tokio::test]
    async fn submit_rolls_disallowed_bits_is_rejected() {
        let (addr, notify_tx, _shutdown_tx, _submit_rx) = spawn_server_with_submit().await;
        let stream = TcpStream::connect(addr).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);

        wr.write_all(
            br#"{"id":1,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"1fffe000"}]}"#,
        )
        .await
        .unwrap();
        wr.write_all(b"\n").await.unwrap();
        let _ = read_line(&mut rd).await;
        let _ = read_line(&mut rd).await;

        wr.write_all(b"{\"id\":2,\"method\":\"mining.subscribe\",\"params\":[\"v\"]}\n")
            .await
            .unwrap();
        let _ = read_line(&mut rd).await;
        let _ = read_line(&mut rd).await;
        wr.write_all(b"{\"id\":3,\"method\":\"mining.authorize\",\"params\":[\"bc1q\",\"x\"]}\n")
            .await
            .unwrap();
        let _ = read_line(&mut rd).await;

        let params = json!(["job-1", "00".repeat(32), "01", "02", []]);
        notify_tx
            .send(Some(NotifyJob::new(params.clone(), 0)))
            .unwrap();
        let _ = read_line(&mut rd).await;

        wr.write_all(
            br#"{"id":4,"method":"mining.submit","params":["bc1q","job-1","00000000","6712f000","deadbeef","80000000"]}"#,
        )
        .await
        .unwrap();
        wr.write_all(b"\n").await.unwrap();
        let resp = read_line(&mut rd).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["error"][0], 23);
    }

    #[tokio::test]
    async fn submit_without_configure_ignores_6th_param() {
        let (addr, notify_tx, _shutdown_tx, mut submit_rx) = spawn_server_with_submit().await;
        let stream = TcpStream::connect(addr).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);

        wr.write_all(b"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"v\"]}\n")
            .await
            .unwrap();
        let _ = read_line(&mut rd).await;
        let _ = read_line(&mut rd).await; // set_difficulty
        wr.write_all(b"{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"bc1q\",\"x\"]}\n")
            .await
            .unwrap();
        let _ = read_line(&mut rd).await;

        let params = json!(["job-1", "00".repeat(32), "01", "02", []]);
        notify_tx
            .send(Some(NotifyJob::new(params.clone(), 0)))
            .unwrap();
        let _ = read_line(&mut rd).await;

        wr.write_all(
            br#"{"id":3,"method":"mining.submit","params":["bc1q","job-1","00000000","6712f000","deadbeef","00400000"]}"#,
        )
        .await
        .unwrap();
        wr.write_all(b"\n").await.unwrap();
        let resp = read_line(&mut rd).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"], true);

        let share = submit_rx.recv().await.unwrap();
        assert_eq!(share.version_rolling, 0);
    }

    #[tokio::test]
    async fn malformed_configure_returns_error_and_keeps_connection() {
        let (addr, _notify_tx, _shutdown_tx) = spawn_server().await;
        let stream = TcpStream::connect(addr).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);

        // params not an array — error code 20, connection stays alive.
        wr.write_all(b"{\"id\":1,\"method\":\"mining.configure\",\"params\":{}}\n")
            .await
            .unwrap();
        let resp = read_line(&mut rd).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["error"][0], 20);

        wr.write_all(b"{\"id\":2,\"method\":\"mining.subscribe\",\"params\":[\"v\"]}\n")
            .await
            .unwrap();
        let resp = read_line(&mut rd).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["id"], 2);
        assert_eq!(v["result"][2], 8);
    }

    #[tokio::test]
    async fn vardiff_doubles_under_flood() {
        // recheck_secs=1, target=8/min so expected per 1s window = ceil(8/60)=1.
        // Sending >=16 submits triggers the >2*expected upward bump.
        let vardiff = VardiffParams {
            min: 1,
            target_shares_min: 8,
            recheck_secs: 1,
            max: 1u64 << 10,
        };
        let (addr, notify_tx, _shutdown_tx, mut submit_rx) =
            spawn_server_with_vardiff(vardiff).await;
        let stream = TcpStream::connect(addr).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);

        wr.write_all(b"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"v\"]}\n")
            .await
            .unwrap();
        let _ = read_line(&mut rd).await; // subscribe response
        let line = read_line(&mut rd).await; // initial set_difficulty
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["params"], json!([1]));
        wr.write_all(b"{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"bc1q\",\"x\"]}\n")
            .await
            .unwrap();
        let _ = read_line(&mut rd).await;

        let params = json!(["job-1", "00".repeat(32), "01", "02", []]);
        notify_tx
            .send(Some(NotifyJob::new(params.clone(), 0)))
            .unwrap();
        let _ = read_line(&mut rd).await; // notify

        for _ in 0..32u32 {
            wr.write_all(
                br#"{"id":99,"method":"mining.submit","params":["bc1q","job-1","00000000","6712f000","deadbeef"]}"#,
            )
            .await
            .unwrap();
            wr.write_all(b"\n").await.unwrap();
        }
        // Drain shares so the server task isn't blocked on backpressure.
        for _ in 0..32u32 {
            let _ = submit_rx.recv().await.unwrap();
            let _ = read_line(&mut rd).await; // submit ack
        }

        // Wait for the next set_difficulty push from the timer.
        let line = tokio::time::timeout(std::time::Duration::from_secs(5), read_line(&mut rd))
            .await
            .expect("set_difficulty did not arrive within 5s");
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["method"], "mining.set_difficulty");
        let new_diff = v["params"][0].as_u64().unwrap();
        assert!(new_diff >= 2, "expected diff >=2, got {new_diff}");
    }

    #[tokio::test]
    async fn share_carries_current_diff() {
        let (addr, notify_tx, _shutdown_tx, mut submit_rx) = spawn_server_with_submit().await;
        let stream = TcpStream::connect(addr).await.unwrap();
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);

        wr.write_all(b"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"v\"]}\n")
            .await
            .unwrap();
        let _ = read_line(&mut rd).await;
        let _ = read_line(&mut rd).await;
        wr.write_all(b"{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"bc1q\",\"x\"]}\n")
            .await
            .unwrap();
        let _ = read_line(&mut rd).await;

        let params = json!(["job-1", "00".repeat(32), "01", "02", []]);
        notify_tx
            .send(Some(NotifyJob::new(params.clone(), 0)))
            .unwrap();
        let _ = read_line(&mut rd).await;

        wr.write_all(
            b"{\"id\":3,\"method\":\"mining.submit\",\"params\":[\"bc1q\",\"job-1\",\"00000000\",\"6712f000\",\"deadbeef\"]}\n",
        )
        .await
        .unwrap();
        let _ = read_line(&mut rd).await;
        let share = submit_rx.recv().await.unwrap();
        // Default vardiff.min == 1.
        assert_eq!(share.current_diff, 1);
    }
}
