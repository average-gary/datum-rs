//! Phase 1 end-to-end composition test.
//!
//! Proves the four foundation crates compose against a mock JSON-RPC server
//! that talks the bitcoind contract:
//!
//!   datum-rpc -> datum-blocktemplates
//!   datum-coinbaser <- (test-side V2 blob)
//!   ↓ via tokio::sync::watch
//!   downstream consumer reads both, asserts coinbase outputs cap at
//!   template.coinbase_value
//!
//! This is the integration the wiki plan's Phase 1 calls for. With this
//! green, datum-config / datum-rpc / datum-blocktemplates / datum-coinbaser
//! are wired correctly at the type and channel level.

use std::convert::Infallible;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use datum_blocktemplates::TemplatePuller;
use datum_coinbaser::{
    encode_v2_blob, parse_v2_blob, CoinbaseOutput, CoinbaserBlob, CoinbaserPublisher,
};
use datum_rpc::{Auth, Client};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::net::TcpListener;

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

fn body_str(s: &str) -> Full<Bytes> {
    Full::new(Bytes::copy_from_slice(s.as_bytes()))
}

fn user_pass() -> Auth {
    Auth::UserPass {
        user: "u".into(),
        pass: "p".into(),
    }
}

const COINBASE_VALUE: u64 = 5_000_000_000;
const TEMPLATE_HEIGHT: u32 = 800_000;

fn fake_template_response(call_n: usize) -> String {
    let lpid = format!("lpid-{call_n}");
    let template = json!({
        "version": 0x20000000u32,
        "previousblockhash": "00".repeat(32),
        "bits": "1d00ffff",
        "height": TEMPLATE_HEIGHT,
        "coinbasevalue": COINBASE_VALUE,
        "curtime": 1_700_000_000u64,
        "mintime": 1_699_999_000u64,
        "sizelimit": 4_000_000u64,
        "weightlimit": 4_000_000u64,
        "sigoplimit": 80_000,
        "transactions": [],
        "longpollid": lpid,
    });
    json!({ "result": template, "error": null, "id": "1" }).to_string()
}

#[tokio::test]
async fn foundations_compose_end_to_end() {
    let (url, counter) = spawn_mock(|_req, c| async move {
        let n = c.fetch_add(1, Ordering::SeqCst);
        Response::new(body_str(&fake_template_response(n)))
    })
    .await;

    let rpc = Arc::new(Client::new(url, user_pass()).unwrap());
    let (puller, _template_sub) = TemplatePuller::new(rpc.clone(), ["segwit".to_string()]);

    let template = puller.fetch_once(None).await.expect("fetch GBT");
    assert_eq!(template.height, TEMPLATE_HEIGHT);
    assert_eq!(template.coinbase_value, COINBASE_VALUE);
    assert_eq!(template.long_poll_id.as_deref(), Some("lpid-0"));
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    let (coinbaser_pub, mut coinbaser_sub) = CoinbaserPublisher::new();
    let blob = CoinbaserBlob {
        datum_id: 7,
        outputs: vec![
            CoinbaseOutput {
                value_sats: 4_000_000_000,
                script_pubkey: vec![0x76, 0xa9, 0x14, 0xaa, 0xbb],
            },
            CoinbaseOutput {
                value_sats: 800_000_000,
                script_pubkey: vec![0x00, 0x14, 0xcc, 0xdd, 0xee],
            },
        ],
    };
    coinbaser_pub.publish(blob.clone()).expect("publish blob");

    let received = coinbaser_sub.changed().await.expect("recv blob");
    assert_eq!(*received, blob);

    let bytes = encode_v2_blob(&blob).expect("encode");
    let parsed = parse_v2_blob(&bytes, template.coinbase_value).expect("parse");
    assert_eq!(parsed.outputs.len(), 2);
    let total: u64 = parsed.outputs.iter().map(|o| o.value_sats).sum();
    assert!(total <= template.coinbase_value);

    let bigger_blob = CoinbaserBlob {
        datum_id: 8,
        outputs: vec![
            CoinbaseOutput {
                value_sats: 4_500_000_000,
                script_pubkey: vec![0x76, 0xa9, 0x14, 0x11, 0x22],
            },
            CoinbaseOutput {
                value_sats: 600_000_000,
                script_pubkey: vec![0x76, 0xa9, 0x14, 0x33, 0x44],
            },
        ],
    };
    let bigger_bytes = encode_v2_blob(&bigger_blob).unwrap();
    let bigger_parsed = parse_v2_blob(&bigger_bytes, template.coinbase_value).unwrap();
    assert_eq!(
        bigger_parsed.outputs.len(),
        1,
        "second output should be dropped (4.5B + 0.6B > 5B coinbase_value)"
    );
}

#[tokio::test]
async fn longpoll_id_round_trips_through_request() {
    let (url, _) = spawn_mock(|req, c| async move {
        let n = c.fetch_add(1, Ordering::SeqCst);
        let bytes = req.into_body().collect().await.unwrap().to_bytes();
        let req_json: Value = serde_json::from_slice(&bytes).unwrap();
        let params = &req_json["params"][0];
        if n == 0 {
            assert!(
                params.get("longpollid").is_none(),
                "first call has no longpollid"
            );
        } else {
            assert_eq!(params["longpollid"], format!("lpid-{}", n - 1));
        }
        Response::new(body_str(&fake_template_response(n)))
    })
    .await;

    let rpc = Arc::new(Client::new(url, user_pass()).unwrap());
    let (puller, _ch) = TemplatePuller::new(rpc, ["segwit".to_string()]);

    let t1 = puller.fetch_once(None).await.unwrap();
    assert_eq!(t1.long_poll_id.as_deref(), Some("lpid-0"));
    let t2 = puller.fetch_once(t1.long_poll_id.as_deref()).await.unwrap();
    assert_eq!(t2.long_poll_id.as_deref(), Some("lpid-1"));
}
