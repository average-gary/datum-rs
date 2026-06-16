---
title: "datum-rs research wiki"
description: "Research notes scoped to the datum-rs project"
created: 2026-06-16
freshness_threshold: 70
---

# Wiki Configuration

## Scope

Research that informs implementation decisions for `datum-rs`:

- Stratum v2 protocol (BIP-310, the SV2 spec, Noise handshake, message framing).
- The reference implementation (Stratum Reference Implementation, SRI / `stratum-mining/stratum`) — its crate layout, traits, MSRV, channels/jobs primitives.
- DATUM protocol bridging (OCEAN's encrypted upstream).
- Downstream-miner support: how an SV2 *server* speaks to SV2 *clients* (mining devices / proxies).
- Adoption / firmware (Bitaxe, Braiins, Demand pool, Antminer SV2 firmware variants).
- Limitations, failure modes, security caveats, deployment lessons learned.

## Conventions

Beyond the llm-wiki defaults:

- Source slugs prefixed with `sv2-` when they're SV2-specific.
- Concept articles favor protocol-mechanics over politics/ecosystem-debate.
- Cite the SV2 spec section when citing the spec.
