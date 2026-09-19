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
| `canary_aware` | no (0.12) | yes | **no** | absent | canary (indistinguishable) |
| `competent_exfiltrator` | **yes (0.90)** | **yes** | **no** | absent (best-response) or forged→invalid (naive) | receipt tier¹ |
| `attested_yet_abusing` | **yes (0.90)** | **yes** | **no** | **valid** (genuine, audited image) | **none of the three tiers** (WI-2, `cov<1`) |

The `competent_exfiltrator` and `attested_yet_abusing` both advertise at the ceiling
(0.99) so they rank first — which is exactly why plain CCR delegates to either.

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
  scenario.py     pools (claim_gap, attest_availability, exfil_attest, n_attest_abuser) + tasks
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
```

**Design invariant (inherited):** policies talk to agents only through
`transport(agent_id, request)`; they never read hidden capability or intent. The
attestation quote is *observable*; whether an agent is truly benign is ground truth
known only to the post-hoc evaluator.

## Reproduce

Dependency-free (Python 3.10+ stdlib). Deterministic — same numbers everywhere.

```bash
python scripts/emit_evidence.py            # regenerate EVIDENCE.md / SENSITIVITY.md / REPRODUCE.md
python scripts/emit_evidence.py --check    # verify the committed files reproduce byte-for-byte
python scripts/run.py --ci                 # console view of the same cells (8 seeds x 24 tasks)
```

**All numbers below are copied from `EVIDENCE.md` / `SENSITIVITY.md` at the tagged commit
(`aamas27-evidence-v1`).** If a number here disagrees with those files, the files win —
they are generated; this section is prose. Headline adversary: best-response `absent`.

### RQ1 — headline (V=5, λ_R=4, κ=0.2, ρ=0.3, indistinguishable canary, full attestation)

| policy | success | incident | exfil_inc | net_util | notes |
|---|---|---|---|---|---|
| `signature_only` | 0.536 | 0.620 | 0.349 | −0.80 | identity ≠ runtime: signs the exfiltrator in |
| `optimistic_fallback` | 1.000 | 0.786 | 0.677 | 0.11 | executes liars before falling back |
| `receipt_only` | 0.573 | **0.000** | 0.000 | 0.36 | safe but **capability-blind** |
| `ccr` | 1.000 | **0.896** | 0.859 | −0.61 | passes the probe → delegates to exfiltrator |
| **`ccr_r`** | **1.000** | **0.083** | 0.073 | **+1.44** | **promotes the attested-benign agent above the unattested exfiltrator** |

CCR incident 0.896 → CCR-R 0.083 at success parity; paired incident reduction
0.812 [0.767, 0.859] and paired net-utility gain 2.045 [1.845, 2.248] — both CIs disjoint
from 0. Against the naive `forge` adversary CCR-R does better (0.047) — that number is a
contrast, not the headline: the forger incriminates itself.

- **RQ2 (frontier):** the receipt pays while ρ is cheap (net gain +2.84 at ρ=0.1, +0.09 at
  ρ=0.8); the VoI gate closes at `ρ ≥ λ_R·cov·d_H = 1.08`, past which CCR-R *is* CCR.
- **RQ3 (adoption):** as attestable-safe agents vanish, CCR-R's incident rises
  0.083 → 0.245 → 0.458 → 0.693 → 0.896 (= CCR) and its net utility falls 1.44 → −1.81
  (CCR: −0.61). Incident degrades gracefully to parity; **net utility does not** — ρ is paid
  per request. Break-even adoption `a*(ρ)`: 0.169 at ρ=0.1, 0.348 at ρ=0.3, 0.843 at ρ=0.6.

### RQ4 — adversary best response (WI-1)

| avail | `forge` inc / net | `absent` inc / net |
|---|---|---|
| 1.00 | 0.047 / 1.55 | **0.083** / 1.44 |
| 0.50 | 0.125 / 1.20 | **0.458** / −0.09 |
| 0.00 | 0.203 / 0.86 | **0.896** / −1.81 |

The best-response adversary is already worse than the forger at full availability and
reaches **exact incident parity with plain CCR** at zero availability. The forging
adversary hid this; `absent` is therefore the paper's headline adversary, and the claim
is "promotes the attested-benign agent," never "catches the forgery."

### RQ-COV — `attested_yet_abusing` / the `cov<1` boundary (WI-2)

Headline pool + one `attested_yet_abusing` agent per skill (valid quote, semantic misuse):

| policy | incident | exfil_inc | attested_inc | net_util |
|---|---|---|---|---|
| `ccr` | 0.990 | 0.521 | 0.000 | −0.94 |
| `receipt_only` | 0.490 | 0.000 | 0.490 | −1.09 |
| `ccr_r` | 0.922 | 0.120 | **0.802** | −1.85 |

Under CCR-R, 0.802 of the 0.922 incident rate is attributable to an agent the router
itself scored as **validly attested**, and (`SENSITIVITY.md`) that residual is **identical
at cov ∈ {0.5, 0.7, 0.9, 1.0}** — raising the router's belief cannot remove what the
router cannot see. The residual is structural, not a parameter. **Magnitude caveat:** this
pool has one abuser per skill declaring at the ceiling, so it out-competes `correct` for
routing; the *existence* of the residual is the claim, not the 0.80 figure.

### RQ5 — `claim_gap` sweep (WI-3)

advantage (= CCR − CCR-R incident): +0.865 [0.830, 0.902] at claim_gap 0.00–0.75, then
+0.812 [0.767, 0.859] at 1.00 — **flat, with a small dip at the extreme, not the
monotone rise the HANDOFF hypothesised.** Root cause (code inspection): `competent_exfiltrator`
always declares at the fixed `CEILING` and is never routed through `_declared(true, claim_gap)`,
so `claim_gap` never changes how the exfiltrator ranks against `correct`; it only matters at
1.0, where `canary_aware` also reaches the ceiling and competes for top-k slots. Whether the
exfiltrator's declared capability should also scale with `claim_gap` is a modeling-scope
question routed to the paper side; the wording the paper may use is decided by this curve.

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
- **`claim_gap` sweep (RQ5) does not exercise the exfiltrator's own declared capability**
  (hardcoded at the ceiling) — see the RQ5 write-up above; the calibration claim needs
  paper-side scoping before it can be cited.
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
3. More adversaries: ~~attested-yet-abusing~~ (done, WI-2, measured), replay attacker
   (WI-4, not yet implemented), honest-but-non-audited.
4. ~~Sweep `claim_gap`, `d_H`, `cov`, `λ_R`, adoption×ρ~~ (done — `SENSITIVITY.md`);
   learn the receipt gate online; let the VoI gate condition on an *observable* card field
   advertising attestation support (observable-only version of A3; future work).
5. `docs/threat-mapping.md` — map each persona to its A2ASecBench threat class (WI-6).
6. ~~`EVIDENCE.md` / `SENSITIVITY.md` generation script~~ (done, WI-5 — `scripts/emit_evidence.py`,
   `--check` verifies byte-for-byte; cite the `aamas27-evidence-v1` tag).
