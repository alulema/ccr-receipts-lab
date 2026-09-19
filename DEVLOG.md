# DEVLOG — `ccr-receipts-lab`

A running, dated log of what changed and why. Newest entry on top. Companion to
`HANDOFF-ccr-receipts-lab.md` (the spec/plan) and `README.md` (the user-facing docs).

---

## 2026-09-18 (night) — v2: WI-6, WI-4, RQ-COV re-measured (decision A/C), artifact at 8×96

### Paper-side decisions received this session (binding)
- **RQ-COV confound** (found by the paper side against v1): at k=4 four ceiling-declarers fill the
  shortlist and `correct` is never probed — the v1 residual (0.802) was crowding, not the cov<1
  boundary. **Decision (A):** `attested_yet_abusing` declares **honestly** (0.90), same description
  and latency as `correct` — identical on every observable. **(C):** the over-claiming (0.99) variant
  is kept as a labelled upper bound. RQ-COV cell at `k=6`; k sweep {4,5,6}; abuser-share {1,2};
  cov sweep at k=6; chosen-persona shares printed.
- **Artifact size → 8 seeds × 96 tasks** (option 1 of three; mixed-n and a seed-dependent jitter
  rejected). Reason: with an honest-card abuser the residual is decided by a per-task latency
  jitter, so it is a task-sample statistic; at 24 tasks it read 0.052, at 96 → 0.168, at 240 →
  0.179 (≈ ⅓ of the 0.556 tie-group wins). The convergence table is in `SENSITIVITY.md` so the
  choice of n is auditable. RQ-COV net utility at k=6 is k-confounded and will not be quoted.
- WI-6: drop `status_ok` (not fix the ternary); replay ≡ forge stated in one sentence.

### Done
- **WI-6:** `docs/threat-mapping.md` (persona ↔ A2ASecBench *(verify)* / RATS RFC 9334; attestation
  threats framed as an extension of A2ASecBench); `canary_score` = 0.7·success + 0.2·schema +
  0.1·latency (the always-200 `httpStatus` factor removed, weight moved to the verifiable signal;
  `httpStatus` removed from the observable reply); `canary_aware` runtime = `UNATTESTED_MEASUREMENT`.
- **WI-4:** `exfil_attest="replay"` — a genuine quote (trusted authority, audited measurement) with
  `STALE_NONCE` → verifies `invalid`. `tests/test_attestation.py` (5 tests, stdlib) asserts valid /
  absent / forge / replay and that the nonce is the *only* check the replayer fails.
- **RQ-COV (A/C)** as above: `build_agents(abuser_declared=None|CEILING)`, `_BASE_LATENCY` 120.
- `ccrlib/suite.py`: `REPLAY_ADVERSARY`, `COV_K=6`, `chosen_shares`, `sens_cov_k`,
  `sens_cov_abusers`, `sens_cov_declared`, `sens_cov_convergence`. `emit_evidence.py` / `run.py`
  default `--tasks 96`. `--check` OK; ~55 s.
- README results rewritten from v2; persona table and roadmap updated.

### Measured (v2, 8×96) — what moved vs v1 (8×24) and what the paper must reconcile
- RQ1–RQ5 were **unchanged by WI-6/WI-4 at 24 tasks** (canary_score reweight is identical for
  success=1; no decision flipped). All movement below is the 24→96 task change.
- **RQ1:** ccr_r incident 0.083 → **0.138** [0.108, 0.168]; ccr 0.896 → 0.931; reduction 0.812 →
  **0.793** [0.768, 0.819]; net gain 2.045 → **1.853** [1.728, 1.986]. **ccr_r success 1.000 →
  0.984** [0.974, 0.994] (ccr 0.999) — "success parity" becomes "near parity".
- **RQ2:** gate still closes at ρ*=1.08; net gain +2.65 / +1.85 / +1.06 / +0.08 at ρ=.1/.3/.5/.8.
- **RQ3/RQ4 (absent):** 0.138 / 0.297 / 0.533 / 0.731 / 0.931; net 1.07 → −2.00. forge ≡ replay:
  0.086 / 0.160 / 0.254. **a*(ρ):** 0.169/0.348/0.843 → **0.177 / 0.390 / 0.914**.
- **RQ5:** advantage +0.893 [0.877, 0.910] at ≤0.75, **+0.793 [0.768, 0.819] at 1.0 — CIs now
  DISJOINT** (were overlapping at 24 tasks). "Flat within CI" no longer holds; it is "flat, then a
  real drop at the extreme" (canary_aware reaches the ceiling and takes a top-k slot).
- **RQ-COV (A, k=6):** ccr_r incident = attested_inc = **0.168** (exfil 0.000); routed to degraded
  0.444 / correct 0.388 / abuser 0.168; 2 abusers → 0.262. **cov-invariant** (0.168 at cov
  0.5/0.7/0.9/1.0). Upper bound (C): 0.880. k sweep: 0.193 / 0.247 / 0.168 attested_inc at k=4/5/6
  (k=4 also carries 0.128 exfil incidents from crowding).
- λ_R=8 now ccr_r incident 0.073 (was 0.042); d_H=0: 0.927 (was 0.896) with 1.59 receipts.

### Pending
- Paper-side re-cross-check of the v0.1 draft against v2 (all RQ1–RQ5 figures moved).
- A2ASecBench class names in `docs/threat-mapping.md` still marked *verify* (OpenReview gated).
- Roadmap only: online receipt gate; observable "attestation-capable" card field (A3-lite).

---

## 2026-09-18 (evening) — WI-5: evidence artifact, `suite.py`, paper-side decisions locked

### Paper-side sync (via the `papers` Claude Code session, same day)
Decisions received and applied (binding for the paper unless the author overrides):
- **A1:** scalar `cov` + operational WI-2 measurement **accepted**; no `cov_by_class` /
  `semantic_floor`. Paper defines `cov` as the operator's belief `E[Risk^rt/Risk]`; `1−cov` is
  *measured* via `attested_incident_rate`. New requirement: `cov` sweep with the persona present.
- **A2:** `absent` **confirmed** as headline adversary; `forge` = labelled naive contrast. A3 stays
  a TODO (would read as calibration against a known adversary).
- **ρ accounting:** keep charging ρ per attestation *request* (an `absent` reply still costs ρ) —
  symmetric with κ. The paper withdraws "CCR-R is never worse than CCR": at zero adoption CCR-R
  matches CCR on incident but is dominated on net utility by k·ρ. New requirement: adoption×ρ grid
  with break-even `a*(ρ)`.
- **WI-2 framing:** "in scope for measurement, out of scope for defense" — CCR-R closes the
  runtime-integrity sub-case of Limitation C only; the residual is D2/IFC.
- **WI-3 wording:** decided by the measured curve (monotone / flat-within-CI / dip); "significantly"
  only if the paired CI excludes 0.
- **WI-6:** drop the `status_ok` factor from `canary_score` (don't fix the dead ternary); persona ↔
  A2ASecBench/RATS mapping received for `docs/threat-mapping.md`.
- **Logistics:** AAMAS 2027 abstract **Oct 1**, paper **Oct 8, 2026** (AoE); 8 pages + refs, LaTeX,
  double-blind. **C4 (Azure CC) is out** of this submission (author confirmed). Paper 1 submitted to
  ICITS'27 (author confirmed).

### Done this session
- **`ccrlib/suite.py` (new):** the single definition of every experimental cell (RQ1–RQ5, RQ-COV,
  all sweeps, `a*(ρ)` break-even). `scripts/run.py` was refactored to format these rows only, so
  console numbers and committed numbers come from one code path (the #88B "25/31 vs 29/35" class of
  error is now structurally impossible).
- **`scripts/emit_evidence.py` (new, WI-5):** writes `EVIDENCE.md`, `SENSITIVITY.md`, `REPRODUCE.md`
  deterministically (no timestamps/hashes). `--check` regenerates and diffs → exit 1 on mismatch.
  Verified: two consecutive runs are byte-identical; ~12 s on a laptop.
- **Default adversary flipped:** `scenario.build_agents(exfil_attest="absent")` is now the default.
  Headline numbers changed accordingly (CCR-R incident 0.047 → **0.083**; the 0.047 is the `forge`
  contrast). RQ-COV also re-measured with `absent` (attested_inc 0.901 → **0.802**).
- **README:** results section rewritten from the generated files; forgery narrative reframed
  ("promotes the attested-benign agent," not "catches the forgery"); ρ-per-request rule and A1
  sign-off documented; C4 marked out of scope.

### Measured results the paper must reconcile (sent to the paper side)
- **cov sweep (hypothesis CONFIRMED):** with `attested_yet_abusing` present, CCR-R's
  `attested_incident_rate` = 0.802 at every cov ∈ {0.5, 0.7, 0.9, 1.0} — invariant. The residual is
  structural. (Mechanically: `cov` scales the risk of *every* valid agent equally, so it cannot
  re-rank a valid abuser below a valid `correct`.)
- **Adoption×ρ / a*(ρ):** 0.169 (ρ=0.1), 0.348 (ρ=0.3), 0.843 (ρ=0.6). At ρ=0.6 CCR-R is net-positive
  only at full adoption (+0.26).
- **claim_gap (hypothesis NOT confirmed, as already noted 09-18 morning):** advantage +0.865
  [0.830, 0.902] flat at 0.00–0.75, +0.812 [0.767, 0.859] at 1.00. CIs overlap. Root cause: the
  exfiltrator declares at the fixed `CEILING`, so `claim_gap` never moves it. Modeling-scope
  question for the paper side (scale the exfiltrator's declared cap too, or measure calibration on
  a different pool/metric).
- **RQ1 CIs (absent):** CCR-R incident 0.083 [0.052, 0.120]; paired reduction 0.812 [0.767, 0.859];
  paired net gain 2.045 [1.845, 2.248] — both disjoint from 0.
- **d_H = 0 quirk:** the gate formula at the floor says "no" yet CCR-R still attests 1.52 agents/task
  (obs_risk > 0 from card/canary signals), incident stays at CCR's 0.896 and net drops to −1.06:
  without the malice-doubt floor the receipt is bought for the wrong agents. Worth one sentence.

### Pending (HANDOFF §3, paper-side priority order)
- **WI-6:** `docs/threat-mapping.md` (mapping received); drop `status_ok` from `canary_score`;
  neutral `runtime` for `canary_aware`. Not started.
- **WI-4:** `replay_attacker` persona + `--selftest`. Not started (one RQ4 row when done).
- Re-run `emit_evidence.py` after WI-4/WI-6 (both change the artifact) and re-tag.

---

## 2026-09-18 (morning) — Model-lock (A1/A2) + WI-1/WI-2/WI-3 implemented

> Committed as `3dc9595` ("Algunos avances en el lab").

### Context
This lab is the evidence harness for the follow-up paper (**D1, target AAMAS 2027**) to
**CCR = Card+Canary Routing** (AISec 2026 #88, rejected). It adds a third evidence tier on the
**risk axis** — a cryptographic execution **receipt / remote attestation** — and asks *"when is it
worth attesting?"* This session executed the first batch of the plan in
`HANDOFF-ccr-receipts-lab.md`, hardening the lab against the two AISec reviews (#88B: "you tested the
adversary that incriminates itself — model the best response and show where it fails"; #88A: "ablations
are just parameter sweeps — ablate components; define every function").

### Done this session

- **A1 — model-lock: `cov` stays a single scalar.** Documented in `ccrlib/scoring.py`
  (`Params.attest_coverage`) and `README.md` why we deliberately do *not* thread a per-class
  `cov_by_class`/`semantic_floor` through `attested_risk()`: the router cannot condition on an incident's
  true class without reading ground truth (violates the observability invariant). The semantic residual is
  measured **operationally** by the WI-2 persona instead.
- **A2 — model-lock: best-response adversary is `absent`, not `forge`.** The `competent_exfiltrator` is no
  longer hard-wired to forge. New knob `exfil_attest` (`"forge"` = naive contrast | `"absent"` = best
  response, +0.35 < +0.60 so forging is strictly dominated). `ccrlib/scenario.py`, `README.md`.
- **A3 — noted, NOT implemented.** Context-sensitive `risk_unattested` left as a `TODO` in
  `ccrlib/scoring.py` pending RQ4 data (correct per HANDOFF §2).
- **WI-1 — adversary best-response experiment → `RQ4`.** New driver `_print_rq4` in `scripts/run.py`
  sweeping `attest_availability ∈ {1.0, 0.5, 0.0} × {forge, absent}` for `ccr_r`.
- **WI-2 — `attested_yet_abusing` persona → `RQ-COV`.** Runs the audited image → earns a **valid** quote yet
  is still malicious (semantic misuse) → measures the `cov<1` boundary directly. Touched
  `ccrlib/agents.py` (`_effective_capability`, `_BASE_LATENCY`), `ccrlib/scenario.py` (`PERSONA_TRUE`,
  `n_attest_abuser` knob), `ccrlib/metrics.py` (added to `MALICIOUS`; new `attested_incident_rate` =
  incidents where `chosen_attestation == "valid"`). New driver `_print_rq_cov` in `scripts/run.py`.
- **WI-3 — `claim_gap` sweep → `RQ5`, plus bootstrap CIs.** New driver `_print_rq5_claimgap` (sweeps
  `claim_gap ∈ {0,.25,.5,.75,1}`, `ccr` vs `ccr_r`, "absent" adversary). New module **`ccrlib/stats.py`**:
  task-clustered bootstrap 95% CIs, **deterministic** (resamples via `domain.det_unit`, no `random`). New
  `--ci` flag on `scripts/run.py` prints CIs for the RQ1 headline and the paired CCR−CCR-R reduction.
- **Docs.** `README.md` +130 lines (model-lock decisions, persona table, measured RQ4 results). `.gitignore`
  minor additions.

Files touched (uncommitted):
```
 modified: .gitignore  README.md  ccrlib/agents.py  ccrlib/metrics.py
           ccrlib/scenario.py  ccrlib/scoring.py  scripts/run.py
untracked: ccrlib/stats.py  DEVLOG.md  HANDOFF-ccr-receipts-lab.md
           ccr-receipts-aamas2027-proposal.md
```

### Verification
- `python scripts/run.py --seeds 3 --tasks 6 --ci` runs clean; RQ1–RQ5 + RQ-COV all print.
- Determinism is by construction (guardrail §1.2: no `random`; hashing via `domain.det_unit`).
- **Notable measured result:** against the `absent` best-response exfiltrator at `attest_availability=0`,
  CCR-R reaches **exact parity with plain CCR** (its advantage evaporates) — the honest "where it fails"
  answer #88B demanded. The naive `forge` adversary hid this.

### How to run
```
python scripts/run.py                      # defaults: 8 seeds x 24 tasks
python scripts/run.py --seeds 12 --tasks 48
python scripts/run.py --ci                 # + task-clustered bootstrap 95% CIs (RQ1)
```

### Pending / next up (HANDOFF §3–§4)
- **WI-4 — replay adversary** (validate the nonce mechanism; `replays` flag in `agents.attest()` +
  `replay_attacker` persona + a `--selftest`/unit check). Not started.
- **WI-5 — reproducibility artifacts** (`scripts/emit_evidence.py` → `EVIDENCE.md` / `SENSITIVITY.md` /
  `REPRODUCE.md`, byte-for-byte reproducible). Not started. **Required before writing any paper RQ prose** so
  every claimed number is traceable (avoid the #88B "25/31 vs 29/35" mismatch).
- **WI-6 — small fixes:** dead `httpStatus` ternary in `agents.execute()`; clarify `canary_aware`'s
  `runtime`; add `docs/threat-mapping.md` (persona ↔ A2ASecBench class). Not started.

### ⚠️ Route to the paper-side Copilot before locking (HANDOFF §6) — do NOT decide alone
- Exact `cov` numeric split (runtime vs semantic) and the WI-2 `semantic_floor` value.
- Confirm `absent` is the headline adversary; whether to add the A3 refinement.
- How WI-2's incident is framed in the paper (the D2/IFC scope boundary).
- What each result licenses the paper to claim (esp. WI-3 monotonicity wording).
- Threat-model / A2ASecBench mapping per persona (WI-6).

### Guardrails (never break — HANDOFF §1)
Observability invariant (policies/scorers read only card + canary + quote, never ground truth) ·
determinism (no `random`) · dependency-free stdlib core · public standards only (RATS/EAT, DICE, TPM,
FIDO, CCC, public Azure CC docs) · every reported number regenerated from a committed run, labeled
measured vs hypothesis.
