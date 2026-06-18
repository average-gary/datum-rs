---
title: "Lessons Learned: SV2 listener implementation + live OCEAN validation"
type: lessons-learned
source: session
date: 2026-06-18
tags: [lessons-learned, sv2, datum-rs, ocean, validation, agentic-workflow]
lesson_count: 7
category: notes
confidence: high
summary: "7 lessons from the 3-day arc of building the SV2 listener and validating against live OCEAN beta — failure modes hermetic tests cannot catch, vardiff-safety-floor patterns, agent-prompting craft, and SRI integration footguns."
---

# Lessons Learned: SV2 listener implementation + live OCEAN validation

> Extracted from sessions 2026-06-16 → 2026-06-18. The arc was: research → plan → 6-phase agentic implementation → 3 gap closes → 1 e2e test (translator, deleted) → 1 e2e test (mining_device, kept) → 2 live OCEAN runs surfacing 4 distinct bugs. 7 lessons cover the bugs that only surfaced under live load, the SRI integration patterns that matter, and the agent-prompting craft that landed clean code.

## Lesson 1: SV2 share-relay must use `send().await` backpressure, not `try_send` + drop

**Category**: gotcha
**Context**: Live OCEAN run #1, mining_device flooded the listener; 3.5M `share forward dropped` warnings in 6 minutes; zero shares forwarded. SV1 path on the same connection had zero drops.
**Symptom**: `WARN: sv2: share forward dropped (commands_tx full or closed)` repeated millions of times. `sv2_shares_accepted=0`. SV1 worked fine on the same `commands_tx`.
**Root cause**: SV2 listener used `commands_tx.try_send(...)` (non-blocking, drops on Full); SV1 used `send().await` (blocking, applies backpressure). When upstream-DATUM was momentarily slow or producer was fast, SV2 silently lost shares while SV1 transparently throttled.
**Fix**: Convert all SV2 `try_send` sites to `send().await`. Differentiate `Closed` (catastrophic, log `error!` and exit the per-connection loop with a clean Reconnect frame) from `Full` (no longer a thing once awaiting). Log block-found-share forward failures at `error!` (not `warn!`) — that's data loss of the most catastrophic kind.
**Rule**: Two protocols sharing one outbound channel must use the same send semantics. If the existing protocol uses awaiting `send`, the new protocol must too — or you've introduced an asymmetry that silently drops only the new path. Audit every `try_send` for "is this the only producer on this channel, or are there others?"

## Lesson 2: Never echo client-supplied targets to clients without an upper-bound clamp

**Category**: rule
**Context**: Live OCEAN run #1, `mining_device --nominal-hashrate-multiplier 0.001` advertised ~5 KH/s, which our `handle_open_extended_mining_channel` and `handle_update_channel` echoed back as the channel's max_target. The "honor requested_max_target" comment said it explicitly: we accepted whatever the client asked for.
**Symptom**: Listener emitted `SetTarget = 0xff…ff` (= 2^256-1). Every nonce was a "valid share." mining_device produced a 30 GB log of "Found share" lines in 6 minutes.
**Root cause**: Two-layer policy gap: (a) no minimum `nominal_hash_rate` floor at OpenChannel/UpdateChannel — clients could self-report any hashrate; (b) no upper-bound clamp on emitted targets — even if math went sideways, we'd never have caught it.
**Fix**: Two-layer defense (Bug B fix at commit `3b297bb`):
  1. Reject `OpenChannel`/`UpdateChannel` with `nominal_hash_rate < cfg.stratum_v2.min_hashrate_threshold` (default 1 TH/s) → SRI error `invalid-nominal-hashrate`.
  2. Compute `min_target_le = hash_rate_to_target(min_hashrate_threshold, expected_share_per_minute)` once at startup. Clamp every emitted SetTarget to `min(client_request, min_target_le)`. Production default: 1 TH/s + 6 SPM yields `min_target_le ≈ 2^218` BE.
**Rule**: Every server-side limit policy needs both a *gate* (reject malformed input at the boundary) and a *clamp* (defend the output even if the gate is bypassed). Either one alone is one-bug-from-catastrophic. When the spec says "honor requested X," ask "what's the worst X a malicious client could request?" before accepting that as policy.

## Lesson 3: `on_template_update` must NOT rotate job_id when only coinbase changed

**Category**: gotcha
**Context**: Live OCEAN run #2 surfaced this. mining_device opened a Standard channel, started hashing, and 15 seconds later began receiving `invalid-job-id` rejections on every share submission.
**Symptom**: 147 `SubmitSharesError { error_code: "invalid-job-id" }` replies in ~90 seconds. Pattern: receive `NewMiningJob (job_id=N+1, future) + SetNewPrevHash` → mining_device's hashing thread mid-share for `job_id=N` → submits `job_id=N` → rejected. **Prev_hash bytes were unchanged**; only the coinbase blob shifted (GBT polled, coinbaser updated outputs).
**Root cause**: Our `Listener::run` watches `template_rx.changed()` (TemplateState transitions). Every change unconditionally calls `mgr.on_template_update(&state)` which mints a new job_id and re-emits both `NewMiningJob` AND `SetNewPrevHash` — even when prev_hash is byte-identical to the previous emission. Spec says: only emit `SetNewPrevHash` when the chain tip rolled. Coinbase-only updates should emit a *new future job* and let it sit; the active job stays active.
**Fix** (deferred — TODO): In `ChannelManager::on_template_update`, compare `state.prev_hash` to `last_set_new_prev_hash`. If unchanged, skip `SetNewPrevHash`. Mint a future `NewMiningJob` only when client uses Extended (so they can roll into it next prevhash). For Standard-only listeners with no coinbase rolling, don't even mint the future job — the existing active job continues to be valid until the *real* prevhash transition.
**Rule**: A spec-level lifecycle event (here: "chain tip changed") must NOT be conflated with an implementation-level state transition (here: "any field of TemplateState changed"). Map the implementation channel onto the spec channel explicitly: `prev_hash bytes change → SetNewPrevHash`, everything else → quieter.

## Lesson 4: Past-job shares are `stale-share`, not `invalid-job-id`

**Category**: rule
**Context**: Bug C from live run #2. After Bug D's spurious prevhash rotation (Lesson 3), mining_device's in-flight share against the old job_id arrived after we'd already activated a new one.
**Symptom**: Our `validate_standard_share` returned `ERROR_CODE_SUBMIT_SHARES_INVALID_JOB_ID` for any submission whose job_id wasn't currently active.
**Root cause**: `validate_*_share` only consults the *active* job. SRI's `ExtendedChannel` has `get_active_job` AND `get_past_job(job_id)` — the past-jobs ring exists for exactly this case, but our wrapper validation path doesn't use it.
**Fix shape** (deferred — TODO): When active-job lookup fails, consult past-jobs. If found AND share would have been valid against that past job's target → `Stale`. If not found at all → `InvalidJobId`. Stale matters operationally — accounting needs to know the share *would have counted* but arrived too late.
**Rule**: SV2's per-error-code semantics are not interchangeable. `invalid-job-id` says "I never had this job." `stale-share` says "I had this job, but the chain tip moved on." Conflating them produces misleading diagnostics and undercounts contributions. Whenever you reject by error code, ask: "is there a past-state where this would have been Valid?"

## Lesson 5: SRI `mining_device` panics on `OpenMiningChannelError` instead of handling it

**Category**: discovery
**Context**: Live OCEAN run #2 regression check for Bug B. mining_device with `--nominal-hashrate-multiplier 0.001` advertised 5 KH/s; our listener correctly rejected with `invalid-nominal-hashrate` per Bug B's gate.
**Symptom**: Instead of mining_device handling the error frame and exiting cleanly, it panicked: `thread 'main' panicked at lib/mining_device/mod.rs:501:9: not yet implemented`.
**Root cause**: SRI's `mining_device` source at rev `c7113e7b…` literally has `fn handle_open_mining_channel_error(&mut self, _) { todo!() }`. The reference SV2 client cannot handle `OpenMiningChannelError`. This is upstream-incomplete, not our bug.
**Fix**: Document the behavior; rely on the panic-as-success-signal for our regression test. (mining_device's panic IS our proof that rejection works.) When SRI fixes it, our test gets cleaner.
**Rule**: When a third-party reference implementation has `todo!()` in a path you exercise, treat its panic as a *positive* signal — your code reached the right protocol state. But document loudly that the test depends on a `todo!()` and may break (in either direction) when SRI fixes it.

## Lesson 6: Live validation surfaces bugs that hermetic tests structurally cannot

**Category**: pattern
**Context**: After 282 unit + integration tests passed clean, two live OCEAN runs surfaced 4 distinct bugs (A, B, C, D) that no hermetic test had caught.
**Symptom**: All four bugs require BOTH a real-world client AND real chain-tip dynamics AND real time advancing to manifest:
  - Bug A: requires a producer fast enough to overflow a bounded mpsc — only happens at high share rates.
  - Bug B: requires a client that self-advertises low hashrate — synthetic test fixtures hard-code reasonable hashrates.
  - Bug C: requires a real client mid-nonce-search at the moment of a job rotation.
  - Bug D: requires a `TemplateState` driver actually advancing (GBT polling, coinbaser shifting).
**Fix**: Make live validation a *first-class step* in any protocol-implementation arc, not an afterthought. The cost (12 minutes, ~5 min CPU) bought 4 bugs that would otherwise have shipped to users.
**Rule**: For any protocol implementation, hermetic test coverage proves correctness *of the test fixtures*, not of the system. A short live run against a real third-party client catches a different class of bugs by construction. Budget time for it.

## Lesson 7: SRI MSRV pin (1.75) is a contributor constraint, NOT a consumer one

**Category**: correction
**Context**: The original Phase-3 plan said "blocked on SRI MSRV bump upstream." After the Phase 2 agent investigated, this turned out to be wrong.
**Symptom**: A doc-comment in `crates/datum-stratum-sv2/src/lib.rs` said "the SRI integration is gated on an MSRV bump upstream (we're 1.89; SRI master is 1.75)."
**Root cause**: Misconception about Rust's compatibility model. SRI pins MSRV 1.75 because *they* commit not to introduce features past 1.75 in their library code. Consumers on a higher MSRV (datum-rs at 1.89) build SRI's 1.75 library code just fine — Rust is forward-compatible. There was never a blocker; only a pin + naming-alignment task.
**Fix**: Phase 2 (commit `7ac0379`) removed the doc-comment paragraph and replaced it with: "SRI lib MSRV is 1.75 and apps MSRV is 1.85; Rust is forward-compatible; integration prerequisites are pin + naming alignment, NOT a wait."
**Rule**: When a downstream Rust crate documents an MSRV "lower than" yours, that's not a blocker for you — it's a constraint on *their* internal feature use. Always cross-reference compiler-version compatibility with Rust's actual semver model before deciding an integration is "blocked."

---

## Bonus observations (not full lessons)

These are smaller patterns observed across the session that didn't rise to a full lesson but are worth a one-liner each in case they recur:

- **Background workflow + live diagnostics interleave**: when an agent workflow is running in the background, the LSP-level diagnostics that surface mid-run are *transient compilation states* — not bugs at HEAD. Always verify against fresh `cargo check` from HEAD before reacting.
- **`disown` + bash background ID**: backgrounded long-running daemons in our Bash tool show up as "completed" via the wrapper-shell exit signal even though the daemon itself is still running. Verify with `ps aux | grep <name>` before assuming the daemon died.
- **30 GB log file = smoking gun for misconfigured target**: any time a CPU miner produces > 1 GB of "Found share" lines, the channel target is broken (likely max). Bug-B-class issue.
- **Workflow agent prompts**: pre-fetch network-access info (HEAD shas, READMEs, config schemas) and inline them in the agent prompt when the agent's Bash sandbox might not have curl/gh. Cuts dead-end runs in half.

## Inventory candidates

These are durable follow-ups worth tracking as inventory items (the wiki's `inventory/candidates/`):

1. **Fix Bug C**: validate_*_share consults past-jobs ring → `stale-share` instead of `invalid-job-id`. ~10-20 lines. Priority: p1 (operational accuracy).
2. **Fix Bug D**: `on_template_update` skips `SetNewPrevHash` when prev_hash unchanged. Priority: p0 (real bug masking Bug C in the wild — every coinbase rotation breaks active mining).
3. **Watch SRI mining_device #?**: file or watch for SRI's fix to `handle_open_mining_channel_error: todo!()` so our Bug-B regression test can become non-panicking. Low priority.
4. **mujina#65 merge watcher**: revisit once the PR merges to main; expected 3-5 dev-day integration of a second e2e test path. Already mentioned in `.wiki/wiki/topics/sv2-downstream-architecture.md` §12.
