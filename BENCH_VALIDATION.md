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
  way to skip the local node.
  - **Mainnet bitcoind**: the documented happy path. Real BTC at stake. ~700
    GB disk, ~1-2 weeks initial sync (or already synced).
  - **Signet bitcoind**: optional dry-run alternative (~5 GB, ~1 hour sync,
    OCEAN beta accepts signet shares). Only useful if you want to validate
    the operator-side workflow without committing real hashrate against
    mainnet difficulty for testing.
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
  what OCEAN expects (confirmed by the live `handshake_probe`).
- Byte-for-byte coinbase parity (`coinb1` + `coinb2`) with the C gateway,
  pinned via captured fixture in
  `crates/datum-stratum-sv1/tests/fixtures/c-mining-notify.txt`. Closes the
  catastrophic-if-violated risk that an operator pays themselves instead
  of OCEAN.
- Proper Stratum V1 merkle branch computation (sibling-path of the
  phantom coinbase position). Verified for 0/1/3/4-tx templates; mainnet
  templates with hundreds of transactions exercise the same algorithm.

What this bench **does not** prove:
- Performance under sustained load (vardiff cadence, many concurrent
  miners, prolonged uptime). The 1.2 TH/s single-miner case is well
  inside the runtime's structural envelope; multi-miner behavior is
  untested.
- Block submission against bitcoind on a real block-found event. Code is
  there (`datum-submitblock`) but no real block has been submitted by
  this binary yet.

## Pre-flight

Run the handshake probe; it should print `OK: handshake completed against
datum-beta1.mine.ocean.xyz:28915 ...` and exit 0:

```sh
./target/release/handshake_probe --timeout-secs 15
```

If the probe fails, **stop**. The runtime will fail in the same way; fix
the network/firewall/DNS issue before proceeding.

## Setup

### 1. Bitcoind on mainnet

If you don't already have a synced mainnet node, this step takes ~1-2
weeks of wall-clock plus ~700 GB disk. Once synced:

```toml
# ~/.bitcoin/bitcoin.conf
server=1
rpcuser=miner
rpcpassword=changeme
rpcport=8332
```

Start it:

```sh
bitcoind -daemon
```

Verify:

```sh
bitcoin-cli getblockchaininfo | jq .blocks
```

(Optional: signet alternative — change `bitcoin.conf` to `signet=1` and
`rpcport=38332`. Adjust the `datum-rs` config's `rpcurl` accordingly.)

### 2. datum-rs config

Save to `~/datum-rs-bench.json`:

```json
{
  "bitcoind": {
    "rpcurl": "http://127.0.0.1:8332/",
    "rpcuser": "miner",
    "rpcpassword": "changeme",
    "work_update_seconds": 40
  },
  "stratum": {
    "listen_port": 23334
  },
  "mining": {
    "pool_address": "<your-mainnet-bitcoin-address>",
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

Replace `<your-mainnet-bitcoin-address>` with an address you control. This
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
INFO: datum-rpc client constructed  rpcurl=http://127.0.0.1:8332/
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
- StartOS / .deb / Docker push. Operator polish, deferrable.

## SV2 runbook (Phase 6)

The SV2 listener is opt-in (default off). When `cfg.stratum_v2.enabled =
true` AND both `authority_pubkey_path` + `authority_secret_path` point at
files containing a base58check-encoded SV2 authority keypair, the gateway
binds a second listener on `cfg.stratum_v2.listen_port` (default `23335`).

### Generate an authority keypair

The SV2 spec requires a Schnorr / `secp256k1` keypair with the public-key
half published in base58check form (version bytes `[0x01, 0x00]` per
SV2 §Protocol-Security ch.4). Any 32-byte `secp256k1` keypair generator
works; the test fixtures in
`crates/datum-stratum-sv2/tests/setup_connection_loopback.rs` show the exact
serialization datum-rs accepts: pubkey bytes ↦
`bs58check([0x01, 0x00] ‖ pubkey[32])`, secret bytes ↦
`bs58check(secret_key.secret_bytes())`.

Save each to its own file. Operators sometimes keep the secret on a
hardware token and reference its path here; that is supported because we
only read the file at boot.

### Add the SV2 block to the config

```jsonc
{
  // ... existing bitcoind / stratum / mining / api / datum sections ...
  "stratum_v2": {
    "enabled": true,
    "listen_addr": "0.0.0.0",
    "listen_port": 23335,
    "authority_pubkey_path": "/path/to/sv2-authority-pubkey.b58",
    "authority_secret_path": "/path/to/sv2-authority-secret.b58",
    "cert_validity_sec": 3600,
    "min_hashrate_threshold": 1.0e12,
    "expected_share_per_minute": 6.0
  }
}
```

`cert_validity_sec` is hard-capped at 1 year (`31_536_000`) by validation
to dodge SRI #2103 (the Noise responder's `now + cert_validity_sec` is a
saturating-u32 add — anything above the cap risks wrap on post-2106
deployments).

`min_hashrate_threshold` (default `1.0e12` = 1 TH/s) is the minimum
hashrate a downstream is allowed to advertise. `OpenChannel` and
`UpdateChannel` requests with `nominal_hash_rate < min_hashrate_threshold`
are rejected with `invalid-nominal-hashrate`. The same value drives the
`SetTarget` clamp ceiling: every emitted target — `Open*MiningChannelSuccess.target`,
`SetTarget` from `UpdateChannel`, `SetTarget` from the vardiff loop — is
clamped from above by `hash_rate_to_target(min_hashrate_threshold,
expected_share_per_minute)`. Smaller targets (i.e. higher difficulty)
pass through unchanged. This is the live-OCEAN bug-B fix
(2026-06-16): a misconfigured `mining_device` advertising
`--nominal-hashrate-multiplier 0.001` previously caused the listener to
echo back `target = 0xff..ff = 2^256-1`, accepting every nonce and
producing a share storm of millions of "valid" shares per second. The
1 TH/s floor is a conservative production default — bitcoin ASICs in
2026 ship at 100+ TH/s; CPU/GPU miners are not viable downstream
clients at modern difficulty regardless.

`expected_share_per_minute` (default `6.0`, mirroring DMND production)
controls how often a per-channel miner is expected to submit. Combined
with `min_hashrate_threshold` it pins the SetTarget clamp ceiling to
roughly `2^228` in big-endian display order (i.e. `00000000001c25c2…`
at the defaults — well below `00000000ffff0000…` aka the diff=1 ceiling
the bitcoin protocol allows).

### Expected log line sequence

When the gateway boots with the above config, the additional log lines you
should see (interleaved with the SV1 lines from §3) are:

```
INFO  sv2: authority pubkey (publish to miners for pinning)  sv2_authority_pubkey_b58=<the-base58check-pubkey>
INFO  sv2 stratum listener bound  sv2_addr=0.0.0.0:23335 cert_validity_sec=3600 authority_pubkey_b58=<...>
```

Pin the `sv2_authority_pubkey_b58` value into your miner's SV2 client
config — that's what the device's Noise initiator uses to verify the
gateway's signed cert.

### Pointing `translator_sv2` at port 23335

The SRI `translator_sv2` (TProxy) is the canonical SV1↔SV2 translator and
is what the loopback test in `crates/datum-stratum-sv2/tests/sv2_loopback.rs`
mirrors in-process. To point a real `translator_sv2` at the gateway:

1. Build SRI's `translator_sv2` from
   `https://github.com/stratum-mining/stratum`. Translation: it accepts
   SV1 from your miner and speaks SV2 upstream.
2. In its `tproxy-config.toml`, set:
   - `upstream.address = "<gateway-host>"`
   - `upstream.port = 23335`
   - `upstream.pub_key = "<sv2_authority_pubkey_b58 from the gateway log>"`
   - Leave the SV1-facing listener at whatever your miner expects.
3. Start `translator_sv2`. Within ~5 seconds you should see in the gateway
   logs:

```
DEBUG sv2: connection accepted
DEBUG noise: first handshake message received
DEBUG noise: second handshake message sent
INFO  sv2: SetupConnection reply sent; further channel handling pending Phase 4
```

After Phase 4+ wiring is online (`OpenExtendedMiningChannel` →
`NewExtendedMiningJob` → first share submitted), you should also observe:

```
INFO  share forwarded to DATUM upstream  user=<...>
```

— same line SV1 already produces, because both protocols share the
`datum-share-relay` and DATUM upstream task.

### `/metrics` rows

Once SV2 is up the JSON at `http://<gateway>:<api.listen_port>/api/metrics`
exposes four extra rows:

```jsonc
{
  // ... existing rows ...
  "sv2_active_channels": 0,           // count of open SV2 channels right now
  "sv2_shares_accepted": 0,           // SV2 shares the relay has accepted (lifetime)
  "sv2_shares_rejected": 0,           // SV2 shares rejected by validate_share (lifetime)
  "sv2_authority_pubkey_b58": "..."   // the same pubkey announced in the boot log
}
```

`sv2_active_channels` reads through `ChannelRegistry::active_count()`, an
atomic load — it's safe to poll at any rate.

### What automated CI covers, and what it doesn't

In-tree automated tests for SV2 (run by `cargo test --workspace --locked`):

- **Wire byte-order goldens**:
  `crates/datum-stratum-sv2/tests/sv2_wire_goldens.rs` pins the six
  LE-U256 sites + a `NewExtendedMiningJob` full-frame snapshot. Catches
  any encoder regression that would silently send BE-byte-order targets
  / prevhashes / merkle paths to a downstream device.
- **In-process loopback**:
  `crates/datum-stratum-sv2/tests/sv2_loopback.rs` boots a Listener-shaped
  task on a random port + a mock DATUM upstream, drives a hand-rolled SV2
  client through Setup → OpenExtended → SubmitSharesExtended, and asserts
  the share lands as a non-empty DATUM 0x27 body on the upstream channel.
- **Setup-connection loopback**:
  `crates/datum-stratum-sv2/tests/setup_connection_loopback.rs` exercises
  the Noise NX handshake + SetupConnection success/error paths against a
  real `noise_sv2::Initiator`.

What CI **does not** cover and is operator-driven:

- **Real device leg**: ESP-Miner v2.14.0+ on a Bitaxe (Standard channel)
  or SRI `translator_sv2` on a real LAN bridging an Antminer / Whatsminer
  to the gateway (Extended channel). These require physical hardware on
  the operator's network, real `bitcoind` + real OCEAN credentials, and
  in some cases NTP sync (the cert's `valid_from` / `not_valid_after`
  reject if device clock is off by more than the cert window). Run this
  once before every tag.
- **Real block-found**: the `flags |= 1` path is unit-tested but no real
  block has been mined through the gateway yet. The same caveat as the
  SV1 path — the code is there, no production data point exists.
