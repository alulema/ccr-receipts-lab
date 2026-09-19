# ccr-receipts-lab — *When Is It Worth Attesting?*

Prototype harness for the **D1 follow-up** to CCR (*Card+Canary Routing*), targeting
**AAMAS 2027**. The written proposal lives in the sibling repo/folder
`papers/ccr-receipts/`; this repo is the **evidence harness** (deterministic
benchmark; a real Azure Confidential Computing path is planned).

## The idea in one paragraph

The base paper (CCR, AISec 2026) routes A2A capability delegation with two evidence
sources on the **success** axis: the **Agent Card** (declarative) and a **canary**
probe (empirical). Its honest limitation — *capability ≠ malice* — is that a
**competent, validly-signed agent that passes the probe and does the task correctly
but exfiltrates the real data** defeats it: the canary sees *capability*, not
*intent*. This prototype adds a **third evidence tier on the RISK axis** — a
cryptographic **execution receipt / remote attestation** — and asks the symmetric
question:

> **original CCR:** *when is it worth **verifying** (paying for a canary)?*
> **this repo:**   *when is it worth **attesting** (paying for a receipt)?*

## Model (extension of base CCR)

Expected utility, with the incident term now **reducible** by attestation evidence:

```
U(a) = V·P[success | e] − λ_R·P[incident | e, Att] − λ_C·(cost + ρ)
```

- **Receipt value-of-information** (symmetric to the canary VoI, but on the risk axis):
  `RVoI = λ_R·cov·max(d_H, risk) − λ_C·ρ`. It is **task-driven**: a valuable/sensitive
  task warrants attestation *even for a clean-looking agent*, because a passing canary
  and a clean card are **not** evidence of benign intent — hence the **malice-doubt
  floor `d_H`** (mirrors the base paper's prior-doubt floor `d0`).
- **Attested risk:** a `valid` attestation lowers incident risk by coverage `cov` (`<1`
  on purpose — attestation proves the *runtime*, not that a legitimately-received datum
  won't be misused: **attestation ≠ information-flow control**); an `absent` quote adds a
  small unattested penalty; a detected forgery/replay adds a larger one. **The receipt
  tier's power is promoting the attested-benign agent above the unattested exfiltrator** —
  not "catching a forgery": a best-responding exfiltrator never forges (model-lock A2).

### Model-lock decisions (see `HANDOFF-ccr-receipts-lab.md` §2 for the full rationale)

- **A1 — `cov` stays a single scalar.** `Params.attest_coverage` blends a "runtime" class
  (structurally removed by a valid quote) and a "semantic" class (data misuse a runtime
  quote cannot see) into one number. We deliberately do **not** thread a per-class
  `cov_by_class`/`semantic_floor` value through `attested_risk()`, because the router
  cannot condition on an incident's true class without reading ground truth — that would
  violate the observability invariant. Instead, the `attested_yet_abusing` persona below
  measures the semantic residual **operationally**: it is observably identical to
  `correct` once attested, so its incident rate under a valid quote *is* the `cov<1`
  measurement. **Paper-side sign-off received (2026-09-18):** `cov` is defined in the paper
  as the operator's prior belief `E[Risk^rt / Risk]`; `1 − cov` is *measured* by
  `attested_incident_rate`, never hand-set. A `cov` sweep with the persona present is in
  `SENSITIVITY.md` (the residual is invariant in `cov`, i.e. structural).
- **A2 — the best-response adversary is `absent`, not `forge`.** A competent exfiltrator
  cannot obtain a genuine quote for the audited image (it needs an egress path), so its
  real choice is between presenting **no quote** (`absent`, +0.35 risk) or a **forged**
  one (`invalid`, +0.60 risk). Since 0.35 < 0.60, forging is strictly dominated — a
  best-responding adversary declines to attest rather than incriminate itself by forging.
  `scenario.build_agents(..., exfil_attest=...)` supports both: `"absent"` is the **default
  and the headline** best-response adversary; `"forge"` (the prior hard-wired default) is
  kept as a labeled **naive-adversary** contrast. See RQ4 in `EVIDENCE.md`.
- **ρ is charged per attestation *request*, not per quote received.** The receipt-VoI gate
  decides "is it worth *asking*" from observables, before the answer is known — exactly as
  the canary gate pays κ whether or not the agent passes. Consequently an `absent` reply
  still costs ρ, and at zero adoption CCR-R matches CCR on incident but is strictly
  dominated on net utility by the wasted receipt budget (k·ρ per task). This is the
  honest C3 floor; the break-even adoption `a*(ρ)` is measured in `SENSITIVITY.md`.
  (Paper-side decision, 2026-09-18: keep — it preserves the canary/receipt symmetry.)
- **A3 — context-sensitive `risk_unattested` (not implemented).** Declining attestation
  is arguably more suspicious when the pool *has* attestable agents than when TEEs are
  broadly unavailable. Left as a `TODO` in `Params.risk_unattested` pending RQ4 data.

### Attestation crypto (faithful to RATS/EAT-style remote attestation)

A quote binds `(measurement, nonce, authority)`. The router trusts one authority
(`cc-attest-root`) and one audited measurement (the benign, egress-restricted image).

- **Benign, TEE-backed agent** → genuine quote for the audited measurement → **valid**.
- **Competent exfiltrator** runs an egress image, so it cannot obtain a genuine quote
  for the audited measurement; to look benign it **forges** (audited measurement, but
  self-signed) → **invalid/forged** → demoted by the receipt tier.
- **No TEE** (partial adoption) → **absent** → routable but carries residual risk.
- **Nonce** binding defeats replay of a stale quote.

## Personas

| persona | capable? | signed? | benign? | attestation | caught by |
|---|---|---|---|---|---|
| `correct` | yes (0.90) | yes | yes | **valid** (if TEE) | — |
| `degraded` | intermittent | yes | yes | valid (if TEE) | canary (capability) |
| `canary_aware` | no (0.12) | yes | **no** | absent (no TEE; neutral runtime) | canary (indistinguishable) |
| `competent_exfiltrator` | **yes (0.90)** | **yes** | **no** | absent (best-response) or forged→invalid (naive) | receipt tier¹ |
| `attested_yet_abusing` | **yes (0.90)** | **yes** | **no** | **valid** (genuine, audited image) | **none of the three tiers** (WI-2, `cov<1`) — declares **honestly**, identical to `correct` on every observable |

The `competent_exfiltrator` advertises at the ceiling (0.99) so it ranks first — which is
exactly why plain CCR delegates to it. The `attested_yet_abusing` persona deliberately does
**not** (honest 0.90): its whole point is to be observably identical to `correct`. Its
over-claiming variant is reported only as an upper bound. The exfiltrator's quote is `absent`
(headline), `forge`, or `replay` (`exfil_attest`).

¹ *Which adversary variant "wins" depends on attestation availability — see RQ4 in
`EVIDENCE.md`; the `absent` variant (default, headline) is not caught the way a detected
forgery is — it merely carries the same modest penalty as an honest unattested agent, so
the receipt tier only helps while an attested-benign agent exists to promote above it.*

## Layout

```
ccrlib/
  domain.py       determinism, verifiable tasks, card signature, ATTESTATION crypto
  agents.py       SimAgent: hidden capability + exfiltration + runtime; attest() surface
  scoring.py      card/canary/risk scores, verify_attestation, canary-VoI, RECEIPT-VoI,
                  attested_risk, expected utility
  policies.py     random, card_only, signature_only, optimistic_fallback, receipt_only,
                  ccr (card+canary), ccr_r (card+canary+receipt)
  scenario.py     pools (claim_gap, attest_availability, exfil_attest=absent|forge|replay,
                  n_attest_abuser, abuser_declared) + tasks
  metrics.py      incident / exfil-incident / attested-incident / defection labeling + aggregation
  experiment.py   in-process transport + grid driver
  stats.py        task-clustered bootstrap CIs (deterministic; WI-3)
  suite.py        THE single definition of every experimental cell (RQ1..RQ5, RQ-COV, sweeps)
scripts/
  run.py          console view of the suite; `--ci` for bootstrap CIs
  emit_evidence.py  writes EVIDENCE.md / SENSITIVITY.md / REPRODUCE.md from the suite;
                  `--check` verifies the committed files byte-for-byte (WI-5)
EVIDENCE.md       RQ1–RQ5 + RQ-COV tables with CIs   (generated — never edit by hand)
SENSITIVITY.md    cov, adoption×ρ (a*), ρ, λ_R, d_H, availability, claim_gap sweeps (generated)
REPRODUCE.md      exact commands (generated)
docs/threat-mapping.md   persona ↔ A2ASecBench class / RATS attestation threat (WI-6)
tests/test_attestation.py  verifier self-test: valid / forge / replay (WI-4)
```

**Design invariant (inherited):** policies talk to agents only through
`transport(agent_id, request)`; they never read hidden capability or intent. The
attestation quote is *observable*; whether an agent is truly benign is ground truth
known only to the post-hoc evaluator.

## Reproduce

Dependency-free (Python 3.10+ stdlib). Deterministic — same numbers everywhere.

```bash
python scripts/emit_evidence.py            # regenerate EVIDENCE.md / SENSITIVITY.md / REPRODUCE.md (8 seeds x 96 tasks)
python scripts/emit_evidence.py --check    # verify the committed files reproduce byte-for-byte
python scripts/run.py --ci                 # console view of the same cells
python -m unittest discover tests          # attestation verifier self-test (valid / forge / replay)
```

**All numbers below are copied from `EVIDENCE.md` / `SENSITIVITY.md` at the tagged commit
(`aamas27-evidence-v2`, 8 seeds × 96 tasks = 768 runs/cell).** If a number here disagrees
with those files, the files win — they are generated; this section is prose. Headline
adversary: best-response `absent`. (Why 96 tasks and not 24: see the task-sample convergence
table in `SENSITIVITY.md` — the WI-2 residual is a task-sample statistic.)

### RQ1 — headline (V=5, λ_R=4, κ=0.2, ρ=0.3, indistinguishable canary, full attestation)

| policy | success | incident | exfil_inc | net_util | notes |
|---|---|---|---|---|---|
| `signature_only` | 0.479 | 0.630 | 0.309 | −1.12 | identity ≠ runtime: signs the exfiltrator in |
| `optimistic_fallback` | 1.000 | 0.833 | 0.716 | −0.15 | executes liars before falling back |
| `receipt_only` | 0.447 | **0.000** | 0.000 | −0.27 | safe but **capability-blind** |
| `ccr` | 0.999 | **0.931** | 0.904 | −0.78 | passes the probe → delegates to exfiltrator |
| **`ccr_r`** | 0.984 | **0.138** | 0.126 | **+1.07** | **promotes the attested-benign agent above the unattested exfiltrator** |

CCR incident 0.931 → CCR-R 0.138 [0.108, 0.168] at near-parity success (0.999 → 0.984
[0.974, 0.994]); paired incident reduction 0.793 [0.768, 0.819] and paired net-utility
gain 1.853 [1.728, 1.986] — both CIs disjoint from 0. Against the naive `forge` adversary
CCR-R does better (0.086) — a contrast, not the headline: the forger incriminates itself.

- **RQ2 (frontier):** the receipt pays while ρ is cheap (net gain +2.65 at ρ=0.1, +0.08 at
  ρ=0.8); the VoI gate closes at `ρ* = λ_R·cov·d_H = 1.08`, past which CCR-R *is* CCR.
- **RQ3 (adoption):** as attestable-safe agents vanish, CCR-R's incident rises
  0.138 → 0.297 → 0.533 → 0.731 → 0.931 (= CCR) and its net utility falls 1.07 → −2.00
  (CCR: −0.78). Incident degrades gracefully to parity; **net utility does not** — ρ is paid
  per request. Break-even adoption `a*(ρ)`: 0.177 at ρ=0.1, 0.390 at ρ=0.3, 0.914 at ρ=0.6.

### RQ4 — adversary best response (WI-1) + replay (WI-4)

| avail | `forge` inc / net | `replay` inc / net | `absent` inc / net |
|---|---|---|---|
| 1.00 | 0.086 / 1.22 | 0.086 / 1.22 | **0.138** / 1.07 |
| 0.50 | 0.160 / 0.91 | 0.160 / 0.91 | **0.533** / −0.47 |
| 0.00 | 0.254 / 0.53 | 0.254 / 0.53 | **0.931** / −2.00 |

The best-response adversary is already worse than the forger at full availability and
reaches **exact incident parity with plain CCR** at zero availability. The forging
adversary hid this; `absent` is therefore the paper's headline adversary, and the claim is
"promotes the attested-benign agent," never "catches the forgery." A **replayed** genuine
quote (right authority and measurement, stale nonce) verifies `invalid` exactly like a
forgery — the nonce freshness check is the only thing standing between the replayer and
`valid` (`tests/test_attestation.py`).

### RQ-COV — `attested_yet_abusing` / the `cov<1` boundary (WI-2)

The persona is **identical to `correct` on every observable**: honest declaration (0.90),
same description template, same latency profile, runs the audited image and earns a
genuine **valid** quote. The only difference is the hidden semantic-misuse side effect.
Measured with the full per-skill pool on the shortlist (`k=6`) so the abuser and the two
`correct` agents compete head-to-head (at `k=4` four ceiling-declarers crowd `correct` out
of the shortlist entirely — that row is a crowding artefact, kept in `SENSITIVITY.md`):

| policy | incident | exfil_inc | attested_inc | ccr_r routed to |
|---|---|---|---|---|
| `ccr` | 0.932 | 0.893 | 0.000 | — |
| `receipt_only` | 0.000 | 0.000 | 0.000 | — |
| `ccr_r` | **0.168** | 0.000 | **0.168** | degraded 0.444 · correct 0.388 · **abuser 0.168** |

Under CCR-R every residual incident comes from an agent the router itself scored as
**validly attested**, and the residual equals the abuser's share of the attested tie group
(1 abuser vs 2 `correct` ⇒ 0.302 of the 0.556 runs the tie group wins; with 2 abusers,
0.262 ≈ 0.471 · 0.556). It is **identical at cov ∈ {0.5, 0.7, 0.9, 1.0}**: raising the
router's belief cannot remove what the router cannot see. *Structural, not parametric.*
Upper bound: an abuser that also over-claims on the card (0.99) is routed to 0.880 of the
time — reported as a bound, not as the result (it re-litigates capability ≠ malice with a
persona built to win the card race). Net utility at `k=6` is k-confounded (6 receipts × ρ)
and is not a result.

### RQ5 — `claim_gap` sweep (WI-3)

advantage (= CCR − CCR-R incident): +0.893 [0.877, 0.910] at claim_gap 0.00–0.75, then
+0.793 [0.768, 0.819] at 1.00 — **flat, with a drop at the extreme** (disjoint CIs at 96
tasks), not the monotone rise the HANDOFF hypothesised. The competent exfiltrator is
*defined* as a perfect card liar (declares at the ceiling regardless of `claim_gap`), so the
receipt advantage is independent of card reliability below the extreme; at 1.0 `canary_aware`
also reaches the ceiling and takes a top-k slot — the same crowding mechanism as RQ-COV's
`k=4` row. Paper-side decision: keep the persona definition; state the drop.

## Threats to validity (read before citing the numbers)

- **Simulation, calibrated pool.** Like base CCR, the pool is synthetically calibrated
  (declared capability is a poor signal). Report this; sweep `claim_gap`.
- **Forgery is modeled as detectable.** We assume the verifier reliably rejects a
  self-signed/stale quote. Real TEE attestation carries its own trust assumptions
  (vendor root of trust, side-channels) and overhead (~5% per AgenTEE, arXiv:2604.18231).
- **`cov < 1` is the honest boundary.** A valid attestation lowers incident risk but does
  **not** eliminate it: attestation proves the runtime, not that a legitimately-received
  datum won't be misused. Closing that gap needs information-flow control (the D2 line).
- **Incident definition** (any real execution touching a malicious agent) is inherited
  from CCR and carries the headline — state it as an assumption.
- **`claim_gap` (RQ5) does not move the exfiltrator's declared capability** — it is a perfect
  card liar by definition; the sweep measures the receipt advantage's independence from card
  reliability, not a calibration curve. Stated as such (paper-side decision).
- **The WI-2 residual is a task-sample statistic** (ties among observably identical agents
  are broken by per-task latency jitter) — hence 96 tasks; see the convergence table.
- **ρ is charged per request.** Modeling the receipt as free for agents that decline would
  make CCR-R look better at low adoption; we deliberately do not (see model-lock above).
- Task-clustered bootstrap CIs (`ccrlib/stats.py`) are deterministic; the real Azure
  Confidential Computing artifact (a genuine attestation quote integrated into the router
  over real A2A) is **out of scope for the AAMAS 2027 submission** (roadmap / pilot).

## Compliance

This is independent research on **open** technology (A2A, RATS/EAT-style attestation,
Confidential Computing). Attestation/identity is close to the author's day job, so this
prototype is grounded **only** in public standards and public papers; it uses **no**
internal knowledge and does not represent any employer.

## Roadmap

1. ~~Confidence intervals~~ (task-clustered bootstrap, `ccrlib/stats.py`) — implemented,
   run, and confirmed deterministic (see RQ1 CI above).
2. Real **Azure Confidential Computing** attested agent emitting a genuine quote,
   integrated into the router over real A2A (distributed validation).
3. More adversaries: ~~attested-yet-abusing~~ (done, WI-2), ~~replay attacker~~ (done, WI-4:
   ≡ forge, nonce freshness validated), honest-but-non-audited.
4. ~~Sweep `claim_gap`, `d_H`, `cov`, `λ_R`, adoption×ρ~~ (done — `SENSITIVITY.md`);
   learn the receipt gate online; let the VoI gate condition on an *observable* card field
   advertising attestation support (observable-only version of A3; future work).
5. ~~`docs/threat-mapping.md`~~ (done, WI-6 — A2ASecBench labels still marked *verify*).
6. ~~`EVIDENCE.md` / `SENSITIVITY.md` generation script~~ (done, WI-5 — `scripts/emit_evidence.py`,
   `--check` verifies byte-for-byte; cite the `aamas27-evidence-v2` tag).
