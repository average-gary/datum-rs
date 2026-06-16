---
title: "SV2 Noise Handshake"
category: concept
sources:
  - raw/papers/2026-06-16-sv2-spec-04-noise-handshake.md
  - raw/notes/2026-06-16-delvingbitcoin-sjors-sv2-noise-bip324-413.md
  - raw/notes/2026-06-16-sri-issue-2103-noise-responder-overflow.md
  - raw/repos/2026-06-16-sri-stratum-mining-stratum.md
created: 2026-06-16
updated: 2026-06-16
tags: [sv2, noise, cryptography, handshake, security]
aliases: ["Noise NX", "SV2 cryptographic handshake"]
confidence: high
volatility: warm
verified: 2026-06-16
summary: "SV2's transport-layer encryption: Noise_NX with secp256k1+ElligatorSwift, ChaCha20-Poly1305, SHA-256, BIP340 Schnorr signatures over a server cert."
---

# SV2 Noise Handshake

> SV2 wraps every byte after the connection establishes in an authenticated, encrypted Noise channel. The chosen pattern is `Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256` — bespoke to SV2, not BIP324.

## Pattern

```
Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256
```

Three acts:

```
-> e
<- e, ee, s, es, SIGNATURE_NOISE_MESSAGE
```

The client validates a **server certificate** (carried in act 2) before any application data flows. There is no client-side static key — only the server is authenticated.

## Primitives

| Layer | Choice |
|-------|--------|
| Hash | SHA-256 |
| AEAD | ChaCha20-Poly1305 (IETF) |
| DH | secp256k1 with **ElligatorSwift x-only** (BIP324-style) |
| Signatures | **BIP340 Schnorr** |

## Wire sizes

| Element | Size |
|---------|------|
| Ephemeral / static pubkey on the wire | 64 B (ElligatorSwift) |
| Cert pubkeys (post-handshake / config) | 32 B (x-only) |
| Private keys | 32 B |
| Schnorr signatures | 64 B |
| AEAD MAC | 16 B |
| Act-2 frame total | 170 B |

## SIGNATURE_NOISE_MESSAGE (74 B plaintext)

```
version          U16
valid_from       U32   (Unix epoch)
not_valid_after  U32   (Unix epoch)
signature        [64]
```

The pool's **authority key** signs:

```
m = SHA256(version || valid_from || not_valid_after || server_public_key)
```

The pool's authority pubkey is distributed in the connection URL:

```
stratum2+tcp://host:port/<base58check>
```

where `<base58check>` encodes `[0x01, 0x00] || x_only_pubkey[32]`. Miners pin this per-pool.

## Transport (post-handshake)

- Each direction encrypts the 6-byte frame header into 22 B (header + MAC).
- Payload is encrypted in ≤65535 B ciphertext blocks (≤65519 B plaintext per chunk).
- AEAD nonce = 4 zero bytes + 8-byte LE counter.
- Associated data = empty.
- Counter increments after every Encrypt / Decrypt success.

## Threat model and known issues

### Spec ambiguity (Sjors)

Per [[sjors-sv2-noise-critique|Sjors' Delving Bitcoin post]] ([critique](../../raw/notes/2026-06-16-delvingbitcoin-sjors-sv2-noise-bip324-413.md)):

- "Implementations were not actually following the spec when it came to ECDH" — the SV2 Noise spec drifted from implementations.
- BIP324's wire framing is incompatible with SV2's; the cipher suite is identical but the framing isn't, so they can't share a codec.
- Proxy routing on **unencrypted** `channel_id` headers has an underspecified threat model.

### SRI Noise responder overflow (issue #2103)

Per [[sri-issue-2103-noise-responder-overflow|SRI #2103]] ([details](../../raw/notes/2026-06-16-sri-issue-2103-noise-responder-overflow.md)):

```rust
let not_valid_after = now + self.cert_validity;  // both u32
```

A pool misconfigured with `cert_validity_sec = u32::MAX` deterministically panics on first connection (debug) or wraps to a past timestamp (release). All clients reject the cert.

### NTP is mandatory

Cert validity bounds are absolute Unix timestamps. Clock skew on the miner triggers `InvalidCertificate`. NTP-synced clocks are a hard prerequisite — SRI's translator README calls this out explicitly.

## Operational guidance for datum-rs

1. Persist a long-lived **authority keypair** in config (Schnorr / x-only, 32 B pubkey).
2. The pool's **server static key** is signed by the authority. Generate the cert at startup with sane bounds (now − 60s, now + 1 day) and rotate periodically.
3. Publish the authority pubkey base58-check encoded as `[0x01,0x00] || pubkey[32]` so miners can pin it.
4. Use SRI's `noise-sv2` crate (current version `1.0.0`) — pin a known-good rev. Do **not** roll our own (the spec is too ambiguous to reimplement safely).
5. Validate `cert_validity_sec` config: cap at 1 year (31_536_000) to avoid the overflow class.
6. Document NTP as a hard prerequisite in the operator runbook.

## See Also

- [[sv2-mining-protocol|SV2 Mining Protocol]] ([SV2 Mining Protocol](sv2-mining-protocol.md)) — what flows post-handshake.
- [[sv2-downstream-architecture|SV2 Downstream Architecture]] ([SV2 Downstream Architecture](../topics/sv2-downstream-architecture.md)) — datum-rs implementation choices.
- [[sri-crate-map|SRI Crate Map]] ([SRI Crate Map](../references/sri-crate-map.md)) — `noise-sv2` lives in `sv2/noise-sv2`.

## Sources

- [SV2 Spec Ch.4: Noise](../../raw/papers/2026-06-16-sv2-spec-04-noise-handshake.md) — primary.
- [Sjors / Delving Bitcoin](../../raw/notes/2026-06-16-delvingbitcoin-sjors-sv2-noise-bip324-413.md) — spec ambiguity.
- [SRI #2103 Noise responder overflow](../../raw/notes/2026-06-16-sri-issue-2103-noise-responder-overflow.md) — config DoS.
- [SRI stratum repo](../../raw/repos/2026-06-16-sri-stratum-mining-stratum.md) — `noise_sv2 1.0.0` crate.
