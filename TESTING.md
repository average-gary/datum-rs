# Testing datum-rs

Operator-facing guide for taking `datum-rs` from "compiled" to "mining real
Bitcoin to OCEAN's mainnet pool." This is a real-money pipeline: a bug in
coinbase construction means the operator pays themselves instead of OCEAN, and
no test against live mainnet is recoverable. The pipeline is intentionally
slow.

## Status (today)

**Alpha. The v0.0.1 binary cannot mine against any pool.** Issue
[#2 v0.1.0 release blockers](https://github.com/average-gary/datum-rs/issues/2)
tracks every outstanding piece. What runs end-to-end today:

| Subcommand | Status |
|---|---|
| `datum_gateway --version` | works |
| `datum_gateway --help` | works |
| `datum_gateway --validate-config <path>` | works (validates the C gateway's own example config clean) |
| `datum_gateway --example-conf` | works |
| `datum_gateway --config <path>` | binds the HTTP API only; SV1/SV2 servers and DATUM upstream are scaffolded but not wired into the run loop |

Until the v0.1.0 blockers close, **do not point this binary at OCEAN mainnet,
testnet/beta, or any miner you care about**. Mine with the C gateway.

## The three testing tiers

```
   ┌──────────────────────────────────────────────────────────────┐
   │  Tier 1: regtest bitcoind + mock pool (hermetic, in-tree)    │
   │  Cost: zero. Risk: zero. Today: most of this works.          │
   └──────────────────────────────────┬───────────────────────────┘
                                      │ (after Phase 2 protocol crate
                                      │  closes the handshake_probe gate)
                                      ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  Tier 2: OCEAN testnet/beta (datum-beta1.mine.ocean.xyz)      │
   │  Cost: tBTC. Risk: low (testnet). Phase 2 release gate.      │
   └──────────────────────────────────┬───────────────────────────┘
                                      │ (after cross-protocol golden vector
                                      │  test passes + Phase 3 SV1/SV2 wired)
                                      ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  Tier 3: OCEAN mainnet (real BTC, real TIDES attribution)     │
   │  Cost: real Bitcoin. Risk: catastrophic-if-missed.            │
   └──────────────────────────────────────────────────────────────┘
```

Each tier gates the next. **Do not skip a tier.**

---

## Tier 1: regtest bitcoind

This is the only tier that fully works against today's `master`. Use it to
verify each crate's behavior without touching anything you care about.

### 1.1 Requirements

- `bitcoind` (Core or Knots) 25.0+, configured for regtest.
- Rust 1.89+ (auto-installed by `rust-toolchain.toml`).

### 1.2 Bring up regtest

Start a regtest `bitcoind` with a data directory you control, RPC credentials
of your choice, and an RPC port that doesn't collide with anything else
running. Daemonize it. Note the data directory, RPC port, and credentials —
you'll feed all three into the config in step 1.4.

### 1.3 Validate a known-good config

If you have the C `OCEAN-xyz/datum_gateway` source checked out locally, point
`--validate-config` at its `doc/example_datum_gateway_config.json`:

```sh
cargo run -p datum-bin -- --validate-config <path-to-datum_gateway>/doc/example_datum_gateway_config.json
```

Expected: `OK: …/example_datum_gateway_config.json is valid`. This cross-checks
the schema against C upstream's own published example.

### 1.4 Build a regtest config

Generate the default config and pipe it to a file you control:

```sh
cargo run -p datum-bin -- --example-conf > <your-regtest-config>.json
```

Open that file in an editor and set:

- `bitcoind.rpcurl` → the local RPC URL you bound in step 1.2 (e.g.
  `http://127.0.0.1:<your-rpc-port>/`).
- `bitcoind.rpcuser` / `bitcoind.rpcpassword` → the credentials you set in
  step 1.2.
- `mining.pool_address` → any regtest bech32 address (`bcrt1q…`).
- `datum.pool_host` → empty string (no upstream — pool-side connection won't
  be attempted because the runtime crates aren't wired anyway).
- `datum.pooled_mining_only` → `false` (otherwise validation fails).
- `api.listen_port` → any unused port.

### 1.5 Smoke-run

Run `datum_gateway --config <your-regtest-config>.json`. Expected:

- Validates the config and prints `config OK`.
- Binds the HTTP API on whatever `api.listen_port` you set.
- HTTP API responds: `GET /` returns the stub metrics JSON, and `GET
  /umbrel-api` works. Use `curl` (or any HTTP client) against the address
  you bound to confirm.
- Stratum ports are NOT bound (expected for v0.0.1).
- Ctrl-C performs a graceful shutdown.

### 1.6 What you've actually tested

Tier 1 verifies the config loader, validation pipeline, and HTTP API skeleton.
**It does not exercise the mining datapath at all.** Don't read more into it.

---

## Tier 2: OCEAN testnet/beta

**Gate**: Phase 2 (`datum-protocol` complete and `handshake_probe` succeeds
against `datum-beta1.mine.ocean.xyz:28915`). Until issue #2's "Phase 2 (DATUM
upstream)" checklist is fully checked, this tier is **not yet runnable**.

### 2.1 Pre-flight (when this tier opens)

- [ ] `cargo run -p datum-protocol --bin handshake_probe` exits 0 against
      `datum-beta1.mine.ocean.xyz:28915` with version `"v0.4.1-beta"`. If
      rejected, fall back to `v0.3.3` then `v0.2.6` and document the accepted
      string in `MIGRATING.md`.
- [ ] Header bitfield byte-ordering test fixture committed and green
      (inventory candidate: `datum-header-bitfield-byte-ordering`).
- [ ] Cross-protocol golden-vector test passes: SV1 `coinb1/coinb2` synthesis
      and SV2 `NewExtendedMiningJob.coinbase_tx_outputs` produce
      byte-identical sum-of-coinbase-outputs given the same template + OCEAN
      blob.
- [ ] Local bitcoind synced on signet OR testnet4 (whichever the OCEAN beta
      endpoint expects — confirm via the handshake response).

### 2.2 Test plan (when this tier opens)

1. Bring up bitcoind on the testnet variant OCEAN beta expects.
2. Configure `datum.pool_host = datum-beta1.mine.ocean.xyz`,
   `datum.pool_port = 28915`, `datum.pool_pubkey` = the 128-hex default.
3. `mining.pool_address` = a **testnet** Bitcoin address you control. Use an
   address you can recognize on OCEAN's beta dashboard.
4. Bring `datum-rs` up. Confirm DATUM handshake completes (log line).
5. Point one ASIC (or `cpuminer`/`bfgminer` for cycle-checking) at
   `datum-rs:23334` with the `mining.pool_address` you set as username.
6. **Watch the OCEAN beta dashboard for 2-4 hours**: shares accepted, share
   rate matches local rate ±10%, attribution shows your testnet address.
7. (If SV2 enabled) repeat with port 23335 and a BraiinsOS+ ASIC.
8. **Failover test**: kill DATUM upstream (`iptables -A OUTPUT -d <ocean
   ip> -j DROP`). Verify both SV1 and SV2 stratum connections cleanly close.

### 2.3 Tier 2 success = green for Tier 3

Before moving to mainnet:
- 24h of stable beta operation
- Zero attribution-window mismatches (every share you submitted shows up)
- Cross-protocol golden-vector test still green (re-run before each push)
- Log-format fixture diff vs C gateway clean

If any of these slip, **stop**. Mainnet is one-way for any block submission.

---

## Tier 3: OCEAN mainnet

**Gate**: Tier 2 has been clean for 24 hours AND the v0.1.0 release notes
list every blocker as `[x]`.

This section is intentionally short because the procedure is the C gateway's
existing operator playbook with `datum_gateway` swapped for `datum-rs`'s built
binary. Before flipping, you should already know:

- The 5-phase switch-day procedure (decide → pre-switch backup → swap → verify
  → rollback). It exists for the C gateway too; we inherit it because the
  on-disk binary name and signal handlers are identical.
- The drop-in compatibility surface that must match the C gateway exactly:
  binary name `datum_gateway` (underscore), default ports 23334 / 7152 /
  28915, the SIGUSR1 blocknotify handler, the 14-endpoint HTTP API URL paths
  and JSON shapes, and the C log line shape if any operator alerts grep on
  it.

### 3.1 Pre-flight checklist

- [ ] Tier 2 completed: 24+h clean against beta, attribution verified, log
      diff clean.
- [ ] Back up the currently-installed C `datum_gateway` binary under a
      sidecar name (e.g. `datum_gateway.c-prev`) on the same path so you
      can swap it back in one move if Tier 3 verification fails.
- [ ] Stage the Rust-built `datum_gateway` binary on the same host under a
      distinct name (e.g. `datum_gateway.rust`).
- [ ] Back up the existing `datum_gateway_config.json`.
- [ ] Snapshot current OCEAN dashboard state: miner count, share rate,
      pending payout.
- [ ] Identify monitoring touchpoints: log file locations, Grafana
      dashboards, cron-based alerts. Have at least one engineer on watch.
- [ ] Pick a low-traffic time window for the swap.

### 3.2 The swap (low-hashrate test first)

Before swapping the production fleet, run the Rust binary alongside the C
binary as a canary for 1-2h. Prefer a miner you can disconnect without
operationally caring.

1. Start the Rust binary against a separate config file. Bind its stratum
   listener on a non-default port that doesn't collide with the running C
   gateway. Use a separate `mining.pool_address` from the production fleet
   so OCEAN attribution stays isolated.
2. Configure one small miner (e.g. 1-10 TH/s) to point at the canary's
   stratum port.
3. Watch shares accepted on OCEAN's dashboard for the canary's address;
   confirm rate matches the miner's local rate within ±10% for 60 minutes.
4. If anything looks wrong, disconnect the canary miner and revert. Do not
   roll the fleet.

### 3.3 Fleet swap

Only after the canary is green: stop the running gateway, move the C binary
out of the way under its `.c-prev` backup name, install the Rust binary in
its place under the original name, and restart. The exact commands depend on
your install path and service manager.

### 3.4 Verify (5 checks; any failure → rollback)

Run all five checks within the first 10 minutes after the swap:

1. `datum_gateway --version` prints the Rust version + commit hash you
   intended.
2. Dashboard pool state: `http://gateway:7152/` shows OCEAN connection
   authenticated.
3. First share accepted within 1-2 minutes of start.
4. Share-rate floor matches pre-swap rate within ±10%.
5. Existing log-grep alerts still fire for known events (no false silence).

### 3.5 Rollback

If any check fails, roll back immediately. Do not troubleshoot in production.
Stop the gateway, rename the failing Rust binary to a `.rust-failed` sidecar,
move the `.c-prev` backup back into place under the original name, and
restart.

Re-run the 5 checks against the C binary; verify recovery. File a bug report
on this repo with the relevant log excerpt and the symptom.

### 3.6 Post-swap (24h watch)

- TIDES attribution: confirm shares attributed to the same payout address
  window for 24h. Any discontinuity → rollback.
- Log-format diff: spot-check operator alerts didn't silently misfire.
- Block-found events (if any during the window): confirm bitcoind got the
  block, OCEAN dashboard credits it, `extra_block_submissions.urls`
  fan-out worked.

---

## Failure-mode catalog (what "looks wrong" looks like)

Mirrors the C gateway's eight known failure modes:

| ID | Symptom | Most likely cause |
|----|---------|-------------------|
| F1 | Binary exits at start with `validation issue(s)` | Config schema additions; run `--validate-config` first |
| F2 | Silent re-handshake every restart | Expected — keypair is ephemeral by design (matches C) |
| F3 | ASICs reconnect-loop on `mining.subscribe` | SV1 server bug — disconnect ASIC immediately, rollback to C |
| F4 | Reconnects + log line "Bad configuration version from server" | DATUM Prime version drift — try a fall-back version string |
| F5 | Local healthy, OCEAN dashboard shows attribution to a different identity | **Coinbase divergence — rollback IMMEDIATELY**, file a P0 bug, do NOT try to debug |
| F6 | Shares lag ~30s after a block | SIGUSR1 handler missing — probably a Linux/macOS path issue |
| F7 | Operator grep alert silent for known events | Log format drift — diff against C reference |
| F8 | Umbrel widget broken or polling scripts return 404 | datum-api endpoint regression |

F5 is non-negotiable. An attribution discontinuity means the operator might be
paying themselves instead of OCEAN. Roll back without investigation. The whole
point of the tiered procedure is to catch this in tiers 1 and 2 before any
real BTC is at stake.

---

## Reporting bugs

Open an issue on https://github.com/average-gary/datum-rs/issues with:

- Tier (1/2/3)
- Output of `datum_gateway --version`
- Relevant config (with secrets redacted — `rpcpassword`, `admin_password`)
- 100 lines of log around the symptom
- Whether you rolled back to C and what its behavior was
