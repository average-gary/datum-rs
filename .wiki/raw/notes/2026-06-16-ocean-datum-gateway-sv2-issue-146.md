---
title: "OCEAN datum_gateway #146: Add Stratum V2 (SV2) Support to DATUM — Concept ACK request"
source: "https://github.com/OCEAN-xyz/datum_gateway/issues/146"
type: notes
ingested: 2026-06-16
tags: [sv2, datum, ocean, gateway, prior-art, scope-decision]
summary: "Pre-Concept-ACK proposal by `electricalgrade` (Oct 2025) for adding SV2 to OCEAN's C `datum_gateway`. MVP scopes to Mining Protocol only; explicitly excludes JD/TDP. Identical architectural problem to datum-rs."
---

# OCEAN datum_gateway #146 — SV2 Support proposal

Status: **OPEN**, only 2 comments. No PR series merged. Pre-Concept-ACK.

## Architecture

- New `src/sv2/` library inside the C `datum_gateway`:
  - `sv2_wire.{h,c}` — codec
  - `sv2_common.{h,c}` — shared types
  - `sv2_mining.{h,c}` — Mining sub-protocol handlers
  - `sv2_adapter.{h,c}` — bridge into existing DATUM share path
  - Thin `datum_sv2.h` shim
- Listener on **port 3334** behind `stratum_v2_enable=true` config flag plus build flag `ENABLE_SV2=1`.
- Outer demo I/O wraps frames with a `u32 length (LE)` prefix; spec-internal header is `u16 ext | u8 msg | u24 len | payload`.

## MVP message scope (identical to what datum-rs needs)

In scope:
- `SetupConnection` / `.Success`
- `OpenExtendedMiningChannel` / `.Success`
- `SetNewPrevHash`
- `NewExtendedMiningJob`
- `SubmitSharesExtended`

**Out of scope** (reasoning: "unnecessary in DATUM"):
- Template Distribution sub-protocol
- Job Declaration sub-protocol
- `SetTarget` (deferred — see "Limitations" below)
- `Reconnect`, JD capabilities

## Noise

Author confirms: **Noise handshake working** ("SV2 needs noise protocol based handshake. So i got that working recently."). No commentary on which variant / cert chain.

## Share validation reuse

Author proposes `on_submit_ext` callback that **reuses the existing SV1 validation pipeline** — reconstruct the header, hash check, dupe check, submitblock. The DATUM share-relay logic stays unchanged; SV2 just becomes another front-end.

## Broadcast helpers

- `datum_sv2_broadcast_prevhash(prev_hash, target_pot, nbits, height, ntime)` — fed when DATUM/GBT delivers a new prev hash.
- `datum_sv2_broadcast_new_job_ext(job_id, version, version_rolling_allowed, merkle_path, coinb1, coinb2)` — fed from existing `mining.notify`-equivalent state.

## Testing

Author wrote a **Python SV1↔SV2 bridge** to test against — `cpuminer` → SV1 server → bridge → SV2 server (datum_gateway). Got it working end-to-end.

## luke-jr's only feedback

- Prefer reusing DATUM's existing socket/threading framework over a fresh event loop.
- Suggest pkg-config'd shared library if SV2 stays separate.

## Limitation (deferred items)

- `SetTarget` deferred → no per-channel vardiff at the SV2 boundary. Fine for ASIC-only LANs; **broken for Bitaxe-class devices** that need adaptive vardiff (see `esp-miner-issue-1758-sv2-byte-order-debugging`).

## Implications for datum-rs

- **Same scope decisions are valid**: Mining sub-protocol only; reuse existing share validator and DATUM 0x27 relay.
- **SetTarget cannot be deferred** if datum-rs wants to serve Bitaxe-class miners — see byte-order debugging note.
- The C author punted on SetTarget but their entire test surface is `cpuminer`, which doesn't need vardiff. A datum-rs that targets real downstream miners must include `SetTarget` from day one.
- Architecturally separate listener (port 23335 in the datum-rs scaffold matches the C plan's port 3334 split — different number, same pattern).
