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
  small unattested penalty; a **detected forgery/replay adds a large penalty** (trying to
  forge an attestation is itself a strong signal of malice).

### Model-lock decisions (see `HANDOFF-ccr-receipts-lab.md` §2 for the full rationale)

- **A1 — `cov` stays a single scalar.** `Params.attest_coverage` blends a "runtime" class
  (structurally removed by a valid quote) and a "semantic" class (data misuse a runtime
  quote cannot see) into one number. We deliberately do **not** thread a per-class
  `cov_by_class`/`semantic_floor` value through `attested_risk()`, because the router
  cannot condition on an incident's true class without reading ground truth — that would
  violate the observability invariant. Instead, the `attested_yet_abusing` persona below
  measures the semantic residual **operationally**: it is observably identical to
  `correct` once attested, so its incident rate under a valid quote *is* the `cov<1`
  measurement. Exact numeric split/justification for the paper: pending paper-side sign-off.
- **A2 — the best-response adversary is `absent`, not `forge`.** A competent exfiltrator
  cannot obtain a genuine quote for the audited image (it needs an egress path), so its
  real choice is between presenting **no quote** (`absent`, +0.35 risk) or a **forged**
  one (`invalid`, +0.60 risk). Since 0.35 < 0.60, forging is strictly dominated — a
  best-responding adversary declines to attest rather than incriminate itself by forging.
  `scenario.build_agents(..., exfil_attest=...)` now supports both: `"absent"` is the
  headline best-response adversary; `"forge"` (the prior hard-wired default) is kept as a
  labeled **naive-adversary** contrast. See RQ4 in `scripts/run.py`.
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

¹ *Which adversary variant "wins" depends on attestation availability — see RQ4
(`scripts/run.py`); the `absent` variant is not automatically caught the way a
detected forgery is, it merely carries the same modest penalty as an honest
unattested agent.*

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
scripts/
  run.py          RQ1 coverage, RQ2 frontier, RQ3 adoption, RQ4 adversary best-response,
                  RQ-COV (cov<1 boundary), RQ5 claim_gap sweep; `--ci` for bootstrap CIs
```

**Design invariant (inherited):** policies talk to agents only through
`transport(agent_id, request)`; they never read hidden capability or intent. The
attestation quote is *observable*; whether an agent is truly benign is ground truth
known only to the post-hoc evaluator.

## Reproduce

Dependency-free (Python 3.10+ stdlib). Deterministic — same numbers everywhere.

```bash
python scripts/run.py                 # 8 seeds x 24 tasks = 192 runs/cell
python scripts/run.py --seeds 12 --tasks 48
python scripts/run.py --ci             # add task-clustered bootstrap 95% CIs (RQ1)
```

### Headline (RQ1: V=5, λ_R=4, κ=0.2, ρ=0.3, indistinguishable canary, full attestation)

| policy | success | incident | exfil_inc | net_util | notes |
|---|---|---|---|---|---|
| `signature_only` | 0.536 | 0.620 | 0.349 | −0.80 | identity ≠ runtime: signs the exfiltrator in |
| `optimistic_fallback` | 1.000 | 0.786 | 0.677 | 0.11 | executes liars before falling back |
| `receipt_only` | 0.573 | **0.000** | 0.000 | 0.37 | safe but **capability-blind** |
| `ccr` | 1.000 | **0.896** | 0.859 | −0.61 | passes the probe → delegates to exfiltrator |
| **`ccr_r`** | **1.000** | **0.047** | 0.026 | **+1.55** | **receipt catches the exfiltrator** |

**CCR incident 0.896 → CCR-R 0.047 at success parity (1.000); net −0.61 → +1.55.**
95% CI (task-clustered bootstrap, n=2000): incident 0.047 [0.021, 0.078]; the CCR −
CCR-R incident reduction is 0.849 [0.808, 0.894] — **disjoint from 0** at the hostile cell.

- **RQ2 (frontier):** while ρ is cheap the receipt pays (net gain +2.96 at ρ=0.1); the
  VoI gate closes at `ρ ≥ λ_R·cov·d_H = 1.08`, past which CCR-R falls back to CCR.
- **RQ3 (adoption):** as attestable-safe agents vanish (`attest_availability` 1.0→0.0),
  CCR-R's incident rises gracefully (0.047→0.203) toward CCR's — never worse
  *(measured with the **naive `forge`** adversary — see RQ4 for the honest picture)*.

### RQ4 — adversary best response (WI-1) — MEASURED

| avail | adversary | ccrR_incident | ccrR_exfil_incident | ccrR_net |
|---|---|---|---|---|
| 1.00 | forge | 0.047 | 0.026 | 1.55 |
| 1.00 | **absent** | **0.083** | 0.073 | 1.44 |
| 0.50 | forge | 0.125 | 0.062 | 1.20 |
| 0.50 | **absent** | **0.458** | 0.448 | −0.09 |
| 0.00 | forge | 0.203 | 0.068 | 0.86 |
| 0.00 | **absent** | **0.896** | 0.859 | −1.81 |

**Confirmed, more starkly than the hypothesis:** the best-response (`absent`) adversary
is *already* worse than the naive forger at full attestation availability (0.083 vs
0.047), and at `attest_availability=0` it reaches **exact parity with plain CCR**
(0.896 = 0.896) — CCR-R's advantage **completely evaporates** against an adversary that
declines to incriminate itself once no agent in the pool can attest. Per the HANDOFF's
own instruction, **`absent` — not `forge` — must be the paper's headline adversary**;
RQ3's graceful-degradation story is only honest for the naive adversary and must be
re-stated (or scoped explicitly to "forging" attackers) once this reaches the paper.

### RQ-COV — `attested_yet_abusing` / the `cov<1` boundary (WI-2) — MEASURED

Same pool as RQ1 plus one `attested_yet_abusing` agent per skill (declares at the
ceiling, genuinely runs the audited image ⇒ earns a **valid** quote):

| policy | incident | exfil_incident | attested_incident | net_util |
|---|---|---|---|---|
| `ccr` | 0.990 | 0.521 | 0.000 | −0.94 |
| `receipt_only` | 0.490 | 0.000 | **0.490** | −1.09 |
| `ccr_r` | 0.922 | 0.016 | **0.901** | −1.92 |

**Confirmed, dramatically:** under CCR-R, `attested_incident_rate` = 0.901 out of an
0.922 total incident rate — i.e. **98% of CCR-R's residual incidents in this pool come
from an agent CCR-R itself scored as validly attested.** This is the `cov<1` boundary
made operational: a valid quote is necessary evidence, not sufficient. **Caveat on
magnitude:** this pool adds one `attested_yet_abusing` agent per skill (same weight as
the one `competent_exfiltrator`), and the persona declares at the ceiling like the
exfiltrator does, so it out-competes even `correct` agents for routing priority — the
*existence* of a non-zero `cov<1` residual is the load-bearing claim; the exact 0.90+
magnitude is an artifact of this pool's malice fraction and should not be quoted as a
general rate without discussing pool composition.

### RQ5 — `claim_gap` sweep (WI-3) — MEASURED, **contradicts the stated hypothesis**

Same pool as RQ4 with the `absent` best-response exfiltrator, sweeping `claim_gap`:

| claim_gap | ccr_incident | ccrR_incident | advantage (ccr − ccrR) |
|---|---|---|---|
| 0.00 | 0.880 | 0.016 | +0.865 |
| 0.25 | 0.880 | 0.016 | +0.865 |
| 0.50 | 0.880 | 0.016 | +0.865 |
| 0.75 | 0.880 | 0.016 | +0.865 |
| 1.00 | 0.896 | 0.083 | +0.812 |

**This does not match the hypothesis in `HANDOFF-ccr-receipts-lab.md` §3 (WI-3)**, which
expected the advantage to be **≈0 at `claim_gap=0`, rising monotonically toward
`claim_gap=1`.** Instead the advantage is **flat (~0.865) from 0.00–0.75, then *drops*
slightly to 0.812 at 1.00.** Root cause (verified by code inspection, not guessed):
`competent_exfiltrator` always declares its capability at the fixed `CEILING` (0.99) in
`scenario.py::build_agents` — unlike `degraded`/`canary_aware`, it is never routed
through `_declared(true_cap, claim_gap)`. Since `claim_gap` therefore never changes how
the exfiltrator ranks against `correct` agents, and the exfiltrator drives most of this
pool's incident rate, sweeping `claim_gap` barely moves the incident-based advantage —
it only measurably shifts things at the `claim_gap=1.0` extreme (where `canary_aware`'s
declared cap also reaches the ceiling and starts competing for the same top-k routing
slots). **This is a modeling-scope question, not a bug, and per the HANDOFF's
Coordination rule it is not resolved here:** should `competent_exfiltrator`'s declared
capability *also* scale with `claim_gap` (making the sweep meaningful for this incident
metric), or is the calibration claim better measured on a different pool/metric (e.g.
`degraded` vs `card_only`, mirroring the base CCR paper's own calibration test)? Flagged
for the paper side; **do not cite a "rising advantage" claim from this sweep as-is.**

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
- Task-clustered bootstrap CIs (`ccrlib/stats.py`, `--ci` flag) are implemented and
  confirmed deterministic; the real Azure Confidential Computing artifact (a genuine
  attestation quote integrated into the router over real A2A) is still future work.

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
4. ~~Sweep `claim_gap`~~ (done, WI-3/RQ5 — result contradicts the original monotonicity
   hypothesis, see RQ5 write-up; needs paper-side scoping); sweep `d_H`, `cov`, `λ_R`;
   learn the receipt gate online.
5. `docs/threat-mapping.md` — map each persona to its A2ASecBench threat class (WI-6).
6. `EVIDENCE.md` / `SENSITIVITY.md` generation script (WI-5) so headline numbers are
   always regenerated from the artifact, never hand-typed.
