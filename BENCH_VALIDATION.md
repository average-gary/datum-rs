# Bench Validation

Operator runbook for the v0.1.0 alpha gate: a real miner submits an accepted
share to OCEAN beta through `datum-rs`. This is the bench test that turns
"compiles and tests pass" into "this thing actually mines."

## Prerequisites

- A miner that speaks Stratum V1 (CGMiner, BFGMiner, cpuminer, BraiinsOS+ in
  SV1 mode, or stock Antminer firmware). Any hashrate is fine; smaller is
  slower-to-prove but works.
- Local `bitcoind` running. **Yes, this is required** — the DATUM model is
  miner-side template construction, so `datum-rs` calls `getblocktemplate`
  against your local node and ships the result to your miner. There is no
  way to skip the local node. **Signet is the easy path** for first run:
  ~5 GB disk, ~1 hour sync, OCEAN beta accepts signet shares.
- Network egress to `datum-beta1.mine.ocean.xyz:28915`. The handshake
  probe (`./target/release/handshake_probe`) is the cheap pre-flight.
- A Bitcoin payout address you control, on the same network (signet /
  mainnet) as your local `bitcoind`. OCEAN credits shares to the address
  you use as the miner's stratum username.

## Honest scope

What this bench proves:
- The full pipeline works end-to-end at the runtime level: bitcoind →
  template puller → assembler → SV1 server → miner → submit → DATUM
  upstream → OCEAN credits.
- The handshake, encryption, message codecs, and obfuscation chain match
  what OCEAN expects (already confirmed by the live `handshake_probe`).

What this bench **does not** prove:
- Byte-for-byte coinbase parity with the C gateway. The assembler in
  `datum-stratum-sv1::assembler` produces structurally valid SV1
  `mining.notify` params, but Phase C's byte-fixture diff against a
  running C gateway is still pending. **Real-money mainnet operation is
  hard-gated on Phase C closing**: get coinbase wrong and the operator
  pays themselves, not OCEAN. Bench on signet first; do not point this at
  mainnet until the cross-protocol golden-vector test pins the assembler
  output against a known-good C output.

## Pre-flight

Run the handshake probe; it should print `OK: handshake completed against
datum-beta1.mine.ocean.xyz:28915 ...` and exit 0:

```sh
./target/release/handshake_probe --timeout-secs 15
```

If the probe fails, **stop**. The runtime will fail in the same way; fix
the network/firewall/DNS issue before proceeding.

## Setup

### 1. Bitcoind on signet

```toml
# ~/.bitcoin/bitcoin.conf
signet=1
server=1

[signet]
rpcuser=miner
rpcpassword=changeme
rpcport=38332
```

Start it:

```sh
bitcoind -daemon
# or the non-daemon equivalent for your launchd/systemd/whatever
```

Wait for sync (~1 hour). Verify:

```sh
bitcoin-cli getblockchaininfo | jq .blocks
```

### 2. datum-rs config

Save to `~/datum-rs-bench.json`:

```json
{
  "bitcoind": {
    "rpcurl": "http://127.0.0.1:38332/",
    "rpcuser": "miner",
    "rpcpassword": "changeme",
    "work_update_seconds": 40
  },
  "stratum": {
    "listen_port": 23334
  },
  "mining": {
    "pool_address": "<your-signet-bitcoin-address>",
    "coinbase_tag_primary": "datum-rs bench"
  },
  "api": {
    "listen_port": 7152
  },
  "datum": {
    "pool_host": "datum-beta1.mine.ocean.xyz",
    "pool_port": 28915,
    "pool_pubkey": "f21f2f0ef0aa1970468f22bad9bb7f4535146f8e4a8f646bebc93da3d89b1406f40d032f09a417d94dc068055df654937922d2c89522e3e8f6f0e649de473003",
    "pooled_mining_only": false
  }
}
```

Replace `<your-signet-bitcoin-address>` with an address you control. This
is what OCEAN credits.

Validate the config:

```sh
./target/release/datum_gateway --validate-config ~/datum-rs-bench.json
```

Expected: `OK: ~/datum-rs-bench.json is valid`.

### 3. Start the gateway

```sh
./target/release/datum_gateway --config ~/datum-rs-bench.json
```

Expected log lines, in order:

```
INFO: sv1 stratum listener bound  sv1_addr=0.0.0.0:23334
INFO: datum-rpc client constructed  rpcurl=http://127.0.0.1:38332/
INFO: datum_gateway: HTTP API binding  api_addr=0.0.0.0:7152
INFO: DATUM upstream: connecting  endpoint=datum-beta1.mine.ocean.xyz:28915
INFO: DATUM handshake complete  motd="DATUM Prime - v0.3.2 - ..."
INFO: coinbaser response received  value=...  blob_len=...
```

If you don't see `DATUM handshake complete` within 30 seconds, check the
firewall + the handshake_probe pre-flight.

If you don't see `coinbaser response received` within ~30 seconds of the
handshake, the pool may need a different `pool_address` shape; signet
addresses prefixed `tb1q...` should work, mainnet `bc1q...` will not be
accepted on a signet bench.

### 4. Point your miner at the gateway

Configure your miner with:

- URL: `stratum+tcp://<gateway-host>:23334`
- Username: the same Bitcoin address you put in `mining.pool_address`
- Password: anything (commonly `x`)

Example for cpuminer (small-hash CPU smoke):

```sh
./minerd -a sha256d -o stratum+tcp://127.0.0.1:23334 \
         -u tb1qyour-signet-address -p x
```

## Pass condition

Within 60 minutes of starting the miner, you should see **at least one
share credited to your address on OCEAN's beta dashboard**. Vardiff
adjusts; expect first shares within a few minutes at any non-trivial
hashrate.

In the gateway logs, you should see:

```
DEBUG: share response  ShareResponse { status: Accepted, ... }
```

In the miner logs, you should see `mining.submit` returning `result: true`.

## Fail mappings

If something goes wrong, map the symptom to the F1-F8 catalog (see
`TESTING.md`). Most common bench failures and their meaning:

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| Gateway boots but never logs `DATUM handshake complete` | Network/firewall/DNS to OCEAN beta blocked | Run `handshake_probe` standalone; debug from there |
| Handshake completes but no `coinbaser response received` | Pool didn't accept the pool_address (wrong network or invalid format) | Verify address with `bitcoin-cli validateaddress`; ensure it matches the network bitcoind is on |
| Miner subscribes + authorizes but never sees `mining.notify` | Either bitcoind isn't responding to GBT, or the assembler waits for both template + coinbaser. Check `getblocktemplate failed` lines in the log | Verify bitcoind RPC reachable: `bitcoin-cli getblocktemplate '{"rules":["segwit"]}'` |
| Miner gets `mining.notify` but every submit returns `result: false` | Likely: assembler produces structurally invalid coinbase (Phase C byte fixture pending). Could also mean stale work | **Do not run on mainnet.** File a bug with full miner + gateway logs; this is the catastrophic-if-real path |
| Gateway disconnects all stratum clients suddenly | DATUM upstream connection dropped. Currently does NOT auto-cascade close to stratum (see TESTING.md F-list); reconnects upstream after backoff | Inspect upstream-disconnect log line; if frequent, file a bug |

## Rollback

`datum-rs` shares its on-disk binary name and config path with the C
gateway, so rollback is a binary swap:

```sh
# stop the Rust gateway (Ctrl-C or systemctl)
mv $(which datum_gateway) /tmp/datum_gateway.rust-bench
cp /path/to/c/datum_gateway $(dirname $(which datum_gateway))/datum_gateway
# restart
```

The C gateway has zero state on disk, so this is a clean revert.

## After the bench passes

Open a github issue noting:
- Block height observed during the bench
- Approximate hashrate
- Number of shares accepted in the first hour
- Any anomalies in the logs (anything other than the expected lines)

This forms the empirical record for whether v0.1.0 is safe to advance to
the C-byte-fixture diff (Phase C) and eventually mainnet.

## Out of scope for this bench

- Mainnet operation. Hard-gated on Phase C and 24+ hours of clean signet
  bench operation per `TESTING.md` Tier 3.
- SV2 path validation. Phase E task; runs through the same coinbaser
  channel so once SV1 is bench-clean, SV2 inherits most of the validation.
- StartOS / .deb / Docker push. Operator polish, deferrable.
