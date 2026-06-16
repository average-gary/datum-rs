---
title: "Stratum V2 Specification — Chapter 4: Protocol Security (Noise handshake)"
source: "https://github.com/stratum-mining/sv2-spec/blob/main/04-Protocol-Security.md"
type: papers
ingested: 2026-06-16
tags: [sv2, spec, noise, cryptography, handshake, security]
summary: "Canonical SV2 Noise handshake spec. Pattern Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256. Pool authority signs the static key; cert lives in the connection URL."
---

# SV2 Spec Ch.4 — Protocol Security

## Pattern

```
Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256
```

Three-act handshake:

```
-> e
<- e, ee, s, es, SIGNATURE_NOISE_MESSAGE
```

Client validates the server certificate carried in the second act.

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
| Ephemeral / static pubkey on the wire (handshake) | 64 B (ElligatorSwift) |
| Cert pubkeys (post-handshake / config) | 32 B (x-only) |
| Private keys | 32 B |
| Schnorr signatures | 64 B |
| AEAD MAC | 16 B |
| Act-2 frame total | 170 B (64 e + 64 enc-s + 16 MAC + 74 enc-sig + 16 MAC) |

## SIGNATURE_NOISE_MESSAGE (74 B plaintext)

```
version          U16
valid_from       U32  (Unix epoch)
not_valid_after  U32  (Unix epoch)
signature        [64]
```

Authority signs:

```
m = SHA256(version || valid_from || not_valid_after || server_public_key)
```

## Cert distribution

Pool's authority pubkey is distributed in the connection URL:

```
stratum2+tcp://host:port/<base58check>
```

where `<base58check>` encodes:

```
[0x01, 0x00] || x_only_pubkey[32]
```

## Transport (post-handshake)

- Each direction encrypts the **6-byte frame header** into 22 B (header + MAC).
- Payload is encrypted in ≤65535 B ciphertext blocks (≤65519 B plaintext per chunk).
- AEAD nonce = 4 zero bytes + 8-byte LE counter.
- Associated data = empty.
- Counter increments after every Encrypt / Decrypt success.

## datum-rs implications

- The Rust crypto stack needed is: `chacha20poly1305`, `secp256k1` w/ ElligatorSwift, BIP340 Schnorr (already in `secp256k1`/`bitcoin` crates). SRI's `noise-sv2` crate already wires this up — preferred over rolling our own.
- Pool authority key pair must be persisted in config; the cert (`version, valid_from, not_valid_after, signature`) is regenerated periodically and pushed to clients via Act 2.
- **Time sync matters**: cert validity bounds are absolute Unix timestamps; clock skew on the miner causes `InvalidCertificate`. NTP is a hard prerequisite (see `sri-translator-proxy-readme` mention; same lesson here).
- **One known DoS class**: `not_valid_after = u32::MAX` overflows in `Responder::step_1_with_now_rng`. See [SRI #2103](https://github.com/stratum-mining/stratum/issues/2103).
