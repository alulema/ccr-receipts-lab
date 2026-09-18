# DEVLOG — `ccr-receipts-lab`

A running, dated log of what changed and why. Newest entry on top. Companion to
`HANDOFF-ccr-receipts-lab.md` (the spec/plan) and `README.md` (the user-facing docs).

---

## 2026-09-18 — Model-lock (A1/A2) + WI-1/WI-2/WI-3 implemented

> ### ⚠️ Continuing on another machine — read first
> All the work below lives in the **working tree only — nothing is committed**. Switching
> computers will **not** carry it over unless you move it first. Do one of:
>
> - **Commit + push (recommended):** review file-by-file, then
>   `git add -A && git commit && git push origin master`, and `git pull` on the other machine.
> - **Or carry a patch:** `git stash` / `git diff > wip.patch` (note: `git diff` excludes the
>   three **untracked** files — `DEVLOG.md`, `HANDOFF-ccr-receipts-lab.md`,
>   `ccr-receipts-aamas2027-proposal.md`, `ccrlib/stats.py` — use `git add -A` first or copy them by hand).
>
> Repo: `https://github.com/alulema/ccr-receipts-lab.git` · base commit before this work:
> `e3ea301` ("Additional to 1st commit") on `master`.

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
