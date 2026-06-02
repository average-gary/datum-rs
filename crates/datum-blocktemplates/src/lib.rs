use std::sync::Arc;
use std::time::Duration;

use datum_rpc::{Client, RpcError};
use serde::Deserialize;
use serde_json::{json, Value};
use thiserror::Error;
use tokio::sync::watch;

pub const DEFAULT_BACKOFF: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Deserialize)]
pub struct Template {
    pub version: u32,
    #[serde(rename = "previousblockhash")]
    pub previous_block_hash: String,
    pub bits: String,
    pub height: u32,
    #[serde(rename = "coinbasevalue")]
    pub coinbase_value: u64,
    pub curtime: u64,
    pub mintime: u64,
    pub sizelimit: u64,
    pub weightlimit: u64,
    #[serde(rename = "sigoplimit")]
    pub sigop_limit: u32,
    #[serde(default)]
    pub default_witness_commitment: Option<String>,
    #[serde(default)]
    pub transactions: Vec<TemplateTransaction>,
    #[serde(default, rename = "longpollid")]
    pub long_poll_id: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TemplateTransaction {
    pub data: String,
    pub txid: String,
    pub hash: String,
    #[serde(default)]
    pub fee: i64,
    #[serde(default, rename = "sigops")]
    pub sigops: u32,
    #[serde(default)]
    pub weight: u32,
    #[serde(default, rename = "depends")]
    pub depends: Vec<u32>,
}

impl Template {
    pub fn fetch_request(rules: &[&str], long_poll_id: Option<&str>) -> Value {
        match long_poll_id {
            Some(id) => json!([{ "rules": rules, "longpollid": id }]),
            None => json!([{ "rules": rules }]),
        }
    }
}

#[derive(Debug, Error)]
pub enum BlockTemplateError {
    #[error("rpc: {0}")]
    Rpc(#[from] RpcError),
    #[error("deserialize template: {0}")]
    Deserialize(#[from] serde_json::Error),
}

/// Broadcast handle for block templates. Cloneable; consumers `.subscribe()` for `Receiver<Arc<Template>>`.
#[derive(Clone)]
pub struct TemplateChannel {
    rx: watch::Receiver<Option<Arc<Template>>>,
}

impl TemplateChannel {
    pub fn current(&self) -> Option<Arc<Template>> {
        self.rx.borrow().clone()
    }

    pub async fn changed(&mut self) -> Result<Arc<Template>, watch::error::RecvError> {
        loop {
            self.rx.changed().await?;
            if let Some(t) = self.rx.borrow_and_update().clone() {
                return Ok(t);
            }
        }
    }
}

pub struct TemplatePuller {
    client: Arc<Client>,
    rules: Vec<String>,
    backoff: Duration,
    tx: watch::Sender<Option<Arc<Template>>>,
}

impl TemplatePuller {
    pub fn new(
        client: Arc<Client>,
        rules: impl IntoIterator<Item = String>,
    ) -> (Self, TemplateChannel) {
        let (tx, rx) = watch::channel(None);
        let puller = Self {
            client,
            rules: rules.into_iter().collect(),
            backoff: DEFAULT_BACKOFF,
            tx,
        };
        (puller, TemplateChannel { rx })
    }

    pub fn with_backoff(mut self, t: Duration) -> Self {
        self.backoff = t;
        self
    }

    pub async fn fetch_once(
        &self,
        long_poll_id: Option<&str>,
    ) -> Result<Template, BlockTemplateError> {
        let rules: Vec<&str> = self.rules.iter().map(|s| s.as_str()).collect();
        let value = self
            .client
            .call::<Value>(
                "getblocktemplate",
                Template::fetch_request(&rules, long_poll_id),
            )
            .await?;
        Ok(serde_json::from_value(value)?)
    }

    /// Drives the long-poll loop forever:
    /// - first call uses no longpollid (short timeout)
    /// - subsequent calls echo the longpollid back; bitcoind returns when the
    ///   tip changes, mempool drifts significantly, or the deadline elapses
    /// - on error, drop the longpollid (bitcoind restart invalidates it) and
    ///   back off `self.backoff` before retrying
    ///
    /// Returns when the watch channel has no remaining receivers.
    pub async fn run(self) {
        let mut long_poll_id: Option<String> = None;
        loop {
            let t = match self.fetch_once(long_poll_id.as_deref()).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(error = %e, "getblocktemplate failed; backing off");
                    long_poll_id = None;
                    tokio::time::sleep(self.backoff).await;
                    continue;
                }
            };
            long_poll_id = t.long_poll_id.clone();
            let arc = Arc::new(t);
            if self.tx.send(Some(arc)).is_err() {
                tracing::debug!("template watch channel closed; puller exiting");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_request_no_longpoll() {
        let v = Template::fetch_request(&["segwit", "taproot"], None);
        assert_eq!(v[0]["rules"], json!(["segwit", "taproot"]));
        assert!(v[0].get("longpollid").is_none());
    }

    #[test]
    fn fetch_request_with_longpoll() {
        let v = Template::fetch_request(&["segwit"], Some("abc123"));
        assert_eq!(v[0]["longpollid"], "abc123");
    }

    #[test]
    fn template_deserializes_minimal_gbt() {
        let json = json!({
            "version": 0x20000000u32,
            "previousblockhash": "00".repeat(32),
            "bits": "1d00ffff",
            "height": 800000,
            "coinbasevalue": 312500000u64,
            "curtime": 1700000000u64,
            "mintime": 1699999000u64,
            "sizelimit": 4_000_000u64,
            "weightlimit": 4_000_000u64,
            "sigoplimit": 80000,
            "transactions": [],
            "longpollid": "lpid-42"
        });
        let t: Template = serde_json::from_value(json).unwrap();
        assert_eq!(t.height, 800000);
        assert_eq!(t.long_poll_id.as_deref(), Some("lpid-42"));
        assert_eq!(t.coinbase_value, 312500000);
    }

    #[test]
    fn template_deserializes_with_transactions() {
        let json = json!({
            "version": 0x20000000u32,
            "previousblockhash": "00".repeat(32),
            "bits": "1d00ffff",
            "height": 800000,
            "coinbasevalue": 312500000u64,
            "curtime": 1700000000u64,
            "mintime": 1699999000u64,
            "sizelimit": 4_000_000u64,
            "weightlimit": 4_000_000u64,
            "sigoplimit": 80000,
            "transactions": [
                {
                    "data": "deadbeef",
                    "txid": "11".repeat(32),
                    "hash": "22".repeat(32),
                    "fee": 1000,
                    "sigops": 4,
                    "weight": 200,
                    "depends": []
                }
            ]
        });
        let t: Template = serde_json::from_value(json).unwrap();
        assert_eq!(t.transactions.len(), 1);
        assert_eq!(t.transactions[0].fee, 1000);
        assert_eq!(t.transactions[0].weight, 200);
    }
}
