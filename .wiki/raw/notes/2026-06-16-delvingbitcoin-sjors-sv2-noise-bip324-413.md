---
title: "Delving Bitcoin: SV2 Noise vs BIP324 nuggets (Sjors Provoost)"
source: "https://delvingbitcoin.org/t/stratum-v2-noise-protocol-bip324-nuggets/413"
type: notes
ingested: 2026-06-16
tags: [sv2, noise, bip324, security, spec-ambiguity, sjors]
summary: "Bitcoin Core contributor's public technical critique of SV2's Noise variant. Identifies spec ambiguity, ECDH drift between spec and impls, and proxy-routing threat-model gap."
---

# Delving Bitcoin — SV2 Noise / BIP324 (Sjors)

Posted 2024-01-15 by sjors (Bitcoin Core contributor).

## Key claims

1. SV2's Noise does **server authentication via cert chain** over the static pubkey; BIP324 does not. Tradeoff: SV2 has TOFU/cert-trust friction BIP324 sidesteps.
2. **Spec ambiguity directly called out**: "implementations were not actually following the spec when it came to ECDH" and "it might be worth changing the spec to remove the ambiguity." Concrete evidence the SV2 Noise spec drifted from implementations.
3. **Frame layout incompatibility with BIP324**: BIP324 encrypts a 3-byte length prefix as a single blob; SV2 uses a different framing. Cipher suite (ChaCha20-Poly1305 + SHA256) is identical, but the wire codecs are not interchangeable.
4. **Proxy routing threat-model gap**: routing on **unencrypted** `channel_id` headers "is not very clear to me." The proxy threat model is underspecified in the spec.
5. Tagged-hash and EllSwift adoption are flagged as future work — current Noise variant is bespoke and not aligned with Bitcoin's ecosystem cryptographic primitives.

## datum-rs implication

- The cryptographic stack itself (ChaCha20-Poly1305, BIP340 Schnorr, secp256k1+EllSwift) is solid. The **wire framing** and **cert-chain conventions** are where ambiguity lives.
- Trust SRI's `noise-sv2` crate over rolling our own; the spec is too ambiguous to reimplement safely.
- A pool can pin **only its own authority key** in published configs (effectively reducing to Noise XK semantics from the operator's perspective). This sidesteps the TOFU friction without violating the spec.
- For datum-rs, if we ship anything, ship `noise-sv2` straight from SRI. Do not reimplement — the spec is ambiguous, and the only hardened reference is SRI's.
