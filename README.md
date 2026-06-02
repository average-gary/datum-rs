# datum-rs

A Rust drop-in replacement for [`OCEAN-xyz/datum_gateway`](https://github.com/OCEAN-xyz/datum_gateway): a miner-side template-construction client that bridges local `bitcoind` (`getblocktemplate`) ↔ Stratum mining hardware ↔ OCEAN's pool over the encrypted DATUM Protocol.

**Status**: alpha — Phase 0 bootstrap. The binary builds and prints `--version`. None of the protocol crates are implemented yet.

## Goal

Phase 1 ships a single-binary drop-in that:

- Preserves SV1-to-ASIC compatibility for OCEAN's existing miner base (port `23334`).
- Adds SV2-to-ASIC as an opt-in protocol on a new port (`23335`).
- Reuses the same encrypted DATUM upstream to OCEAN (port `28915`).
- Drops in for the C `datum_gateway` binary on disk: same name (`datum_gateway`), same default config path, same default ports, same SIGUSR1 blocknotify handler.

## Workspace

11 crates:

- `datum-config` — JSON config parsing (`datum_conf.c` replacement)
- `datum-rpc` — bitcoind JSON-RPC client (hand-rolled `reqwest + corepc-types`)
- `datum-blocktemplates` — GBT puller with native long-poll
- `datum-coinbaser` — V2 coinbaser blob parser; single source-of-truth `Vec<TxOut>` for both protocols
- `datum-submitblock` — block-found escape hatch
- `datum-protocol` — encrypted DATUM upstream (`dryoc 0.8`, XSalsa20Poly1305)
- `datum-stratum-sv1` — SV1 server side
- `datum-stratum-sv2` — SV2 server side (SRI `channels_sv2` + `handlers_sv2`)
- `datum-dupes` — bounded share-dedup cache
- `datum-api` — `axum` HTTP dashboard (14 endpoints)
- `datum-bin` — main binary; produces `target/release/datum_gateway`

## Build

```sh
cargo build --release
```

## Install

```sh
cargo install --path crates/datum-bin --root /usr/local
```

This produces `/usr/local/bin/datum_gateway` — same path as the C build.

## License

MIT. See [LICENSE](LICENSE).

## Relationship to upstream

Greenfield port. Not a fork of `OCEAN-xyz/datum_gateway`. Cross-references upstream issue [`OCEAN-xyz/datum_gateway#146`](https://github.com/OCEAN-xyz/datum_gateway/issues/146) (canonical SV2-DATUM bridge proposal).
