use std::sync::Arc;

use datum_rpc::{Client, RpcError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SubmitError {
    #[error("primary submit: {0}")]
    Primary(#[source] RpcError),
}

/// Block-found escape hatch. Submits to the primary bitcoind, optionally
/// fan-outs to extra block-submission targets, then calls `preciousblock` on
/// the primary to ensure our block wins ties.
///
/// Per [gateway-internals-c-architecture.md], path 1 (this submission) MUST
/// NOT be gated on path 2 (DATUM upstream notification). The two are spawned
/// as independent tokio tasks at the call site; this crate is just path 1.
pub struct BlockSubmitter {
    primary: Arc<Client>,
    extras: Vec<Arc<Client>>,
}

impl BlockSubmitter {
    pub fn new(primary: Arc<Client>) -> Self {
        Self {
            primary,
            extras: Vec::new(),
        }
    }

    pub fn with_extras(mut self, extras: Vec<Arc<Client>>) -> Self {
        self.extras = extras;
        self
    }

    /// Submit a block. Returns the block hash if Bitcoin Core accepts it; the
    /// hash must be precomputed by the caller (typically via SHA-256d on the
    /// 80-byte header). The hash is used for `preciousblock` follow-up.
    ///
    /// Order of operations:
    ///   1. submit to primary; if it rejects, the entire call errors out.
    ///   2. fan-out to extras concurrently — failures are logged but ignored.
    ///   3. call `preciousblock` on the primary — failures are logged but
    ///      ignored (the block is already in the chain at this point).
    pub async fn submit(&self, block_hex: &str, block_hash_hex: &str) -> Result<(), SubmitError> {
        self.primary
            .submitblock(block_hex)
            .await
            .map_err(SubmitError::Primary)?;

        if !self.extras.is_empty() {
            let block_hex = block_hex.to_string();
            let extras = self.extras.clone();
            let mut fanout = tokio::task::JoinSet::new();
            for (i, c) in extras.into_iter().enumerate() {
                let hex = block_hex.clone();
                fanout.spawn(async move {
                    if let Err(e) = c.submitblock(&hex).await {
                        tracing::warn!(extra_idx = i, error = %e, "extra submitblock failed");
                    }
                });
            }
            while fanout.join_next().await.is_some() {}
        }

        if let Err(e) = self.primary.preciousblock(block_hash_hex).await {
            tracing::warn!(error = %e, "preciousblock follow-up failed (block already in chain)");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_submitter() {
        let _ = BlockSubmitter::new(make_dummy_client()).with_extras(vec![]);
    }

    fn make_dummy_client() -> Arc<Client> {
        Arc::new(
            Client::new(
                "http://127.0.0.1:1",
                datum_rpc::Auth::UserPass {
                    user: "u".into(),
                    pass: "p".into(),
                },
            )
            .unwrap(),
        )
    }
}
