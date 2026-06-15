# datum-rs

A Rust drop-in replacement for [`OCEAN-xyz/datum_gateway`](https://github.com/OCEAN-xyz/datum_gateway): a miner-side template-construction client that bridges local `bitcoind` (`getblocktemplate`) ↔ Stratum mining hardware ↔ OCEAN's pool over the encrypted DATUM Protocol.

**Status**: alpha. Live OCEAN beta connection works end-to-end against mainnet bitcoind. A real Bitaxe pointed at `localhost:23334` completed `mining.subscribe` → `mining.configure` (BIP-310 version-rolling) → `mining.authorize` → `mining.set_difficulty` → `mining.notify` → `mining.submit`, with shares forwarded as DATUM `0x27` frames, and per-miner vardiff converged through 1 → 16 → 32 → 64 → 128. Pool-side share acceptance has not yet been verified against an OCEAN dashboard credit.

## What works today

- DATUM handshake against live OCEAN (`datum-beta1.mine.ocean.xyz:28915`).
- `getblocktemplate` long-poll against local `bitcoind` (cookie or user/pass auth).
- Coinbaser-blob fetch + parse; outputs assembled into the SV1 `mining.notify` `coinb1`/`coinb2` split, byte-equivalent to the C reference for matched (template, coinbaser) inputs.
- Full Stratum V1 server: `mining.configure` (BIP-310 version-rolling, minimum-difficulty, subscribe-extranonce), `mining.subscribe`, `mining.authorize`, `mining.set_difficulty` push (initial + on every vardiff change), `mining.notify`, `mining.submit` with optional 6th nversion param.
- Per-miner vardiff (snapshot-based; `cfg.stratum.vardiff_min` floor; ×2 / ÷2 around `target_shares_min`).
- Full `0x27` share-submission body to OCEAN: 30-byte prefix + null-terminated username (formatted per `pool_pass_full_users` / `pool_pass_workers`) + 4 reserved bytes + first-share-of-job 0x01 block (prevhash, target_pot_index, nbits, datum_coinbaser_id, height, coinbase_value, four tx counts, merkle-branch table) + first-share-of-coinbase 0x02 block (full coinb1 / coinb2 binaries) + 0xFE cap + random padding.
- `ShareResponse` accept/reject counters surfaced in the `/metrics` JSON.
- HTTP API skeleton on `cfg.api.listen_port` with Digest auth.
- SIGUSR1 blocknotify handler (Unix).

## What does not work yet

- **SV2 server-side**: scaffolded but the SRI integration is gated on an MSRV bump upstream (we're 1.89; SRI master is 1.75).
- **Block-found escape hatch**: `flags |= 1` not yet wired — the share-relay can't tell whether a candidate also meets network target.
- **`subscribe-extranonce` push**: acked structurally but xn1 changes are never pushed to live miners.
- **Embedded HTML/CSS/SVG dashboard**: the JSON contract is green; the C reference's `www/` static assets aren't vendored yet.
- **StartOS / .deb / Docker push / static-musl**: tracked separately.

## Quick start

```sh
# Build
cargo build --release

# Run against live OCEAN beta
cargo run --release -p datum-bin -- -c ~/datum-rs-bench.json
```

A reference config (`~/datum-rs-bench.json`) — cookie auth against local mainnet bitcoind, OCEAN beta endpoint, pool address `bc1q…`:

```json
{
  "bitcoind": {
    "rpcurl": "http://127.0.0.1:8332/",
    "rpccookiefile": "/path/to/.bitcoin/.cookie",
    "work_update_seconds": 40,
    "notify_fallback": true
  },
  "stratum": {
    "listen_addr": "0.0.0.0",
    "listen_port": 23334,
    "vardiff_min": 8,
    "vardiff_target_shares_min": 8,
    "share_stale_seconds": 120,
    "fingerprint_miners": true
  },
  "mining": {
    "pool_address": "bc1q…your_payout_address…",
    "coinbase_tag_primary": "datum-rs bench",
    "coinbase_tag_secondary": "T",
    "coinbase_unique_id": 4242
  },
  "api": {
    "listen_addr": "127.0.0.1",
    "listen_port": 7152,
    "admin_password": "",
    "allow_insecure_auth": false,
    "modify_conf": false
  },
  "datum": {
    "pool_host": "datum-beta1.mine.ocean.xyz",
    "pool_port": 28915,
    "pool_pubkey": "f21f2f0ef0aa1970468f22bad9bb7f4535146f8e4a8f646bebc93da3d89b1406f40d032f09a417d94dc068055df654937922d2c89522e3e8f6f0e649de473003",
    "pool_pass_workers": true,
    "pool_pass_full_users": true,
    "always_pay_self": true,
    "pooled_mining_only": false,
    "protocol_global_timeout": 60
  }
}
```

Point your miner at `stratum+tcp://<host>:23334`. Username = a Bitcoin payout address you control (or `.workername` to ride `mining.pool_address` with a worker tag).

Bump the log filter for upstream-frame inspection:

```sh
DATUM_LOG=info,datum_protocol=debug cargo run --release -p datum-bin -- -c ~/datum-rs-bench.json
```

Expected log line sequence on a clean run:

```
INFO sv1 stratum listener bound          sv1_addr=0.0.0.0:23334
INFO datum-rpc client constructed
INFO DATUM upstream: connecting          endpoint=datum-beta1.mine.ocean.xyz:28915
INFO datum_gateway: HTTP API binding     api_addr=127.0.0.1:7152
INFO mining.configure: version-rolling negotiated   client_id=0 mask=1fffe000
INFO DATUM handshake complete            motd="…"
INFO client_config received from pool    prime_id=… vardiff_min=…
INFO coinbaser request enqueued
INFO coinbaser response received         value=… blob_len=…
INFO share forwarded to DATUM upstream   user=…
INFO vardiff: diff changed               client_id=0 diff=16
```

## Install

```sh
cargo install --path crates/datum-bin --root /usr/local
```

Produces `/usr/local/bin/datum_gateway` — same path as the C build.

## Bench validation

See [`BENCH_VALIDATION.md`](BENCH_VALIDATION.md) for the operator runbook against OCEAN beta with a real ASIC.

## Workspace

11 crates:

- `datum-config` — JSON config parsing (`datum_conf.c` replacement)
- `datum-rpc` — bitcoind JSON-RPC client (hand-rolled `reqwest + corepc-types`); cookie auth with reload-on-401 retry; per-call long-poll timeouts.
- `datum-blocktemplates` — GBT puller with native long-poll
- `datum-coinbaser` — V2 coinbaser blob parser; single source-of-truth `Vec<TxOut>` for both protocols
- `datum-submitblock` — block-found escape hatch
- `datum-protocol` — encrypted DATUM upstream (`dryoc 0.8`, XSalsa20Poly1305, Ed25519 detached signatures, MurmurHash3 header XOR chain); long-lived `DatumClient::run` with reconnect; `0x27` share-submission codec.
- `datum-stratum-sv1` — SV1 server: subscribe / configure / authorize / set_difficulty / notify / submit + per-miner vardiff. Assembler produces `mining.notify` params byte-equivalent to the C reference (BIP34 height, tag block, uid push with PoT placeholder, 14-byte enprefix push slot, legacy non-segwit coinbase serialization, sibling-path merkle branches).
- `datum-stratum-sv2` — SV2 server side (deferred; SRI MSRV gate)
- `datum-dupes` — bounded share-dedup cache
- `datum-api` — `axum` HTTP dashboard (14 endpoints; RFC 7616 SHA-256 + RFC 2617 MD5 Digest auth)
- `datum-bin` — main binary; produces `target/release/datum_gateway`. JobTracker (256-slot, insertion-order eviction) maps SV1 job-id hex strings to per-job metadata so the share-relay can encode the full `0x27` body.

## Tests

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

176+ tests across all crates. CI green on master.

## License

MIT. See [LICENSE](LICENSE).

## Relationship to upstream

Greenfield port. Not a fork of `OCEAN-xyz/datum_gateway`. Cross-references upstream issue [`OCEAN-xyz/datum_gateway#146`](https://github.com/OCEAN-xyz/datum_gateway/issues/146) (canonical SV2-DATUM bridge proposal).
