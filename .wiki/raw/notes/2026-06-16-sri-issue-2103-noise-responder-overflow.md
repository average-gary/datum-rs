---
title: "SRI #2103: arithmetic overflow in noise_sv2::Responder::step_1_with_now_rng"
source: "https://github.com/stratum-mining/stratum/issues/2103"
type: notes
ingested: 2026-06-16
tags: [sri, noise-sv2, dos, overflow, fuzzing, security]
summary: "Trivial DoS in SRI's Noise responder: `now + cert_validity` (both u32) panics in debug, wraps in release. A pool misconfigured with `cert_validity_sec = u32::MAX` deterministically panics on first connection."
---

# SRI #2103 — Noise responder overflow

Found by `lucasbalieiro` (SRI maintainer) via fuzzing, March 2026.

## Bug

`responder.rs:360`:

```rust
let not_valid_after = now + self.cert_validity;  // both u32
```

- Debug builds: panic.
- Release builds: silent wrap. The signed `not_valid_after` may end up *before* `valid_from`, or far in the past, leading to all clients rejecting the cert.
- Trivially reachable: `Responder::new()` accepts arbitrary `u32 cert_validity`. **A single bad config (`cert_validity_sec = u32::MAX`) kills the pool's listener for all incoming SV2 sessions.**

## Fix

`checked_add` / `saturating_add`. Trivial. The fact that it shipped means cryptographic-handshake code in the reference impl was not fuzzed before deployment.

## Related: companion fuzz issues

`lucasbalieiro` opened #2105 to add fuzz coverage to `noise_sv2`. Confirms this layer was previously untested. Companion open issues across the binary codec layer (#2069 codec-sv2 property tests, #2064 codec-sv2 fuzz, #2071 binary-sv2 property tests) suggest the broader codec is structurally fragile.

## datum-rs implication

- **Validate `cert_validity_sec` config input**. Cap at, e.g., 1 year (31_536_000) — beyond that the `u32` math is dangerous and the operational meaning is dubious.
- Pin a known-good `noise_sv2` rev rather than tracking `main`. The fuzz pass is ongoing; bug class likely to keep landing.
- This bug is one piece of evidence for "SV2 is hard to get right" — supports a conservative scope decision (Mining only, no JD/TDP).
- If we ship our own thin wrapper over SRI's Noise, add a defensive `checked_add` on the `cert_validity_sec` bound regardless.
