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
| `competent_exfiltrator` | **yes (0.90)** | **yes** | **no** | **forged→invalid** | **receipt only** |

The `competent_exfiltrator` advertises at the ceiling (0.99) so it ranks first — which
is exactly why plain CCR delegates to it.

## Layout

```
ccrlib/
  domain.py       determinism, verifiable tasks, card signature, ATTESTATION crypto
  agents.py       SimAgent: hidden capability + exfiltration + runtime; attest() surface
  scoring.py      card/canary/risk scores, verify_attestation, canary-VoI, RECEIPT-VoI,
                  attested_risk, expected utility
  policies.py     random, card_only, signature_only, optimistic_fallback, receipt_only,
                  ccr (card+canary), ccr_r (card+canary+receipt)
  scenario.py     pools (claim_gap, attest_availability) + tasks
  metrics.py      incident / exfil-incident / defection labeling + aggregation
  experiment.py   in-process transport + grid driver
scripts/
  run.py          RQ1 coverage, RQ2 attestation frontier, RQ3 partial adoption
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

- **RQ2 (frontier):** while ρ is cheap the receipt pays (net gain +2.96 at ρ=0.1); the
  VoI gate closes at `ρ ≥ λ_R·cov·d_H = 1.08`, past which CCR-R falls back to CCR.
- **RQ3 (adoption):** as attestable-safe agents vanish (`attest_availability` 1.0→0.0),
  CCR-R's incident rises gracefully (0.047→0.203) toward CCR's — never worse.

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
- No CIs yet; the real Azure Confidential Computing artifact (a genuine attestation quote
  integrated into the router over real A2A) is future work.

## Compliance

This is independent research on **open** technology (A2A, RATS/EAT-style attestation,
Confidential Computing). Attestation/identity is close to the author's day job, so this
prototype is grounded **only** in public standards and public papers; it uses **no**
internal knowledge and does not represent any employer.

## Roadmap

1. Confidence intervals (task-clustered bootstrap, as in base CCR).
2. Real **Azure Confidential Computing** attested agent emitting a genuine quote,
   integrated into the router over real A2A (distributed validation).
3. More adversaries: replay attacker, honest-but-non-audited, attested-yet-abusing.
4. Sweep `d_H`, `cov`, `λ_R`; learn the receipt gate online.
