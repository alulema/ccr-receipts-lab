# Handoff — `ccr-receipts-lab` improvement plan (for the lab's Copilot)

**Audience:** the Copilot working inside `~\Projects\ccr-receipts-lab` (has write access to the repo).
**Author of this spec:** the Copilot working in `~\Projects\papers` (reviewed the full lab via GitHub
`alulema/ccr-receipts-lab` + the AAMAS proposal `papers/ccr-receipts/ccr-receipts-aamas2027-proposal.md`).
**You do not have our conversation history — this document is self-contained.** Read it fully before editing.

> ### ⚠️ Coordination rule (read first)
> **Route every *theoretical / research* decision back to the paper side (the `~\Projects\papers` Copilot),
> via the author — do not decide them unilaterally.** These include: the formal model in proposal §4
> (the utility/VoI equations, the `cov` semantics and its per-threat-class split, the `d_H` malice-doubt
> floor), the **adversary model** (best-response assumptions, what counts as an "incident"), the
> **threat-model scope / A2ASecBench mapping**, and **what the paper is allowed to claim** from a result.
> The paper's argument drives the lab, not the other way around — a modeling choice made only in code can
> silently change what the paper can honestly say (and mismatches are exactly what got the base paper
> criticized).
>
> **You own the *engineering* decisions:** code structure, function/param naming, test layout, output
> formatting, refactors, performance, and how to implement a spec item — provided you keep the guardrails
> in §1. When in doubt whether something is "theoretical" or "engineering," treat it as theoretical and
> ask. Surface such questions to the author for the paper-side Copilot; collect them (see §6) rather than
> firing them one at a time.

---

## 0. Context you need (why this lab exists)

- This lab is the **evidence harness** for a follow-up paper (**D1, target AAMAS 2027**) to a prior paper
  **CCR = Card+Canary Routing** (A2A capability routing; submitted to AISec 2026 as #88, **rejected**).
- Base CCR routes A2A delegation using two evidence sources on the **success axis**: the declarative
  **Agent Card** and an empirical **canary** probe. Its honest limitation (**"Limitation C: capability ≠
  malice"**) is that a **competent, validly-signed agent that passes the probe and does the task correctly
  but exfiltrates the real data** defeats it.
- This lab adds a **third evidence tier on the RISK axis** — a cryptographic **execution receipt / remote
  attestation** — and asks the symmetric question: *"when is it worth **attesting**?"* (mirror of the base
  paper's *"when is it worth **verifying**?"*).
- The lab is already well-built and faithful to the proposal. This plan **hardens it against the exact
  reviewer critiques that sank the base paper**, and adds the honesty/robustness experiments AAMAS will
  expect. Do **not** rewrite it; apply targeted changes.

### The two real AISec reviews that must shape this work
- **#88B (most important):** *"you tested the adversary that helpfully incriminates itself."* They demanded:
  **sweep the adversary's competence / model its best response**, and *"report where the defense stops
  working."* They also flagged **overselling** and a **claim mismatch** (text said "25 of 31 sweep settings"
  while the artifact shipped "29 of 35"). Lesson: **every number must match the artifact; label hypotheses
  vs measured; show where CCR-R fails.**
- **#88A:** hard to read (bold overuse, jargon), **weak bibliography** (blogs/preprints, missing authors,
  one wrong title), **method under-specified** (score/risk functions not defined), and **"most ablations
  are just parameter sweeps with no component ablation."** Lesson: **define every function; ablate CCR-R's
  components, don't just sweep parameters.**

---

## 1. Non-negotiable guardrails (preserve these in every change)

1. **Observability invariant (the thing reviewers praised).** Policies interact with agents **only** through
   `ctx.transport` and may read **only** the observable surface: the card, canary metrics, and the
   attestation quote. Hidden fields (`persona`, whether it exfiltrates, the true `runtime`, true capability)
   are known **only** to the post-hoc evaluator in `metrics.py`. **Never** let a policy or scorer read
   ground truth. If a change needs ground truth in a policy, the change is wrong.
2. **Determinism.** No `random`. Use `domain.det_unit(...)` / `domain._h(...)` hashing so runs are identical
   across machines and the local↔cloud boundary. Same seeds ⇒ same numbers, byte-for-byte.
3. **Dependency-free core.** `ccrlib/` + `scripts/run.py` stay Python 3.10+ stdlib only (a bootstrap CI can
   be pure stdlib). Optional extras (plots, real Azure attestation client) may add deps in a clearly
   separated module, never in the core.
4. **Compliance (author constraint).** Attestation/identity is close to the author's day job. Ground
   everything in **public** standards/papers only (RATS/EAT, DICE, TPM, FIDO, Confidential Computing
   Consortium, public Azure Confidential Computing docs). **No internal knowledge; no employer claims.**
5. **Honesty of reporting.** Regenerate `EVIDENCE.md`/`SENSITIVITY.md` from the artifact; label any number
   in prose as **measured** (from a committed run) or **hypothesis** (not yet run). Never hand-write a
   result.

---

## 2. Part A — "Model-lock" decisions (apply FIRST; they change the code shape)

Lock these three modeling decisions before running experiments, because they alter data structures.

### A1 — Make attestation coverage `cov` **per threat-class**, not a global scalar
- **Now:** `Params.attest_coverage = 0.9` (a single scalar in `ccrlib/scoring.py`).
- **Why:** attestation structurally removes **runtime-integrity** risk (unaudited/egress-capable stack) but
  removes **zero** "semantic-misuse-of-a-legitimately-received-datum" risk (that needs information-flow
  control — the sibling **D2/IFC** line). A single scalar hides this boundary, which is the whole honest
  point (`cov < 1`). It also sets up Work Item WI-2.
- **Change (minimal, back-compatible):** keep the scalar as the default but let `attested_risk` accept a
  per-agent/threat coverage. Concretely, add `Params.cov_by_class: dict[str,float]` defaulting to
  `{"runtime": 0.9, "semantic": 0.0}` and have the risk fold use the class of the residual risk. If you
  prefer the smallest step now: keep `attest_coverage` scalar for WI-1 and introduce `cov_by_class` together
  with WI-2 (the `attested_yet_abusing` persona), which is the first consumer of a `semantic` coverage of 0.
- **Document** the chosen `cov` values and their justification in the README (reviewers asked for justified
  parameters, not magic numbers).

### A2 — Model the adversary's **best response** (this is the #88B fix)
- **Now:** `competent_exfiltrator` is hard-wired `forges=True` in `ccrlib/scenario.py`, so its quote is
  `invalid` → `attested_risk` adds `risk_forged = 0.60`.
- **Problem:** forging is **not** the exfiltrator's best move. It cannot obtain a genuine quote for the
  audited (no-egress) image because it needs an egress path to exfiltrate; its options are therefore
  **forge** (`invalid`, +0.60) or present **absent** (no TEE, +0.35). **Absent strictly dominates forge**
  (0.35 < 0.60). A best-responding exfiltrator presents `absent`. Testing only the forger is exactly the
  "adversary that incriminates itself" that #88B called out.
- **Decision:** the **primary** adversary is the **best-response (`absent`)** exfiltrator. Keep `forge` as a
  labeled **"naive adversary"** contrast. WI-1 implements and measures both.
- **Narrative reframe (do this in README + eventual paper):** the receipt tier's power is **promoting the
  attested-benign agent above the unattested exfiltrator**, *not* "catching a forgery." The
  "detected forgery is a strong signal of malice" story only bites a naive adversary; state this honestly.

### A3 — Optional model refinement (note for later, don't block on it)
- Consider making `risk_unattested` **context-sensitive**: declining attestation is more suspicious when the
  pool *has* attestable agents (adoption high) than when TEEs are broadly unavailable (adoption low). This
  is a natural lever once WI-1 shows the `absent` adversary hiding among unattested agents. Leave a `TODO`
  and a single `Params` hook; do not implement until WI-1 data justifies it.

---

## 3. Part B — Work items (schedulable; priority order)

Each item lists: **goal · why (reviewer tie-in) · exact change · acceptance · expected outcome (HYPOTHESIS —
must be verified by running, not assumed).**

### WI-1 — Adversary best-response experiment (forge vs absent) — **PRIORITY 1**
- **Goal:** show whether CCR-R still wins when the exfiltrator does **not** incriminate itself.
- **Why:** direct answer to #88B's "model the best response / show where it fails."
- **Change 1 — `ccrlib/scenario.py`, `build_agents` signature:** add a knob.
  ```python
  def build_agents(
      claim_gap: float = 1.0,
      attest_availability: float = 1.0,
      n_correct: int = 2,
      n_degraded: int = 1,
      n_canary_aware: int = 1,
      n_exfil: int = 1,
      exfil_attest: str = "forge",   # "forge" (naive) | "absent" (best response)
  ) -> list[dict]:
  ```
- **Change 2 — same file, the exfiltrator construction loop:** replace the hard-wired `forges=True`.
  ```python
      for i in range(n_exfil):
          forges = (exfil_attest == "forge")   # "absent" => no quote at all (best response)
          agents.append(_agent("competent_exfiltrator", skill, "adventureworks", i,
                               CEILING,
                               signed=True, poison=False, scope="narrow",
                               desc=f"Premium {skill} specialist. {kw}",
                               attestable=False, forges=forges,
                               runtime=EXFIL_MEASUREMENT))
  ```
  (No change needed in `agents.py`: with `forges=False, attestable=False`, `attest()` returns
  `{"present": False}` → `verify_attestation` → `"absent"` → `attested_risk` adds `risk_unattested`.)
- **Change 3 — `scripts/run.py`, add a driver** (call it from `main()` after `_print_rq3`):
  ```python
  def _print_rq4(seeds: list[int], tasks: list[dict]) -> None:
      print("\n" + "=" * 78)
      print("RQ4 — ADVERSARY BEST RESPONSE  (V=5, lambda_r=4, rho=0.3; CCR-R)")
      print("      forge => invalid quote (+0.60); absent => no quote (+0.35). 'absent' is the")
      print("      exfiltrator's best response (0.35 < 0.60), i.e. it declines to incriminate itself.")
      print("=" * 78)
      hdr = f"{'avail':>7}{'adversary':>11}{'ccrR_inc':>10}{'ccrR_exfil':>12}{'ccrR_net':>10}"
      print(hdr); print("-" * len(hdr))
      for avail in [1.0, 0.5, 0.0]:
          for adv in ["forge", "absent"]:
              specs = scenario.build_agents(claim_gap=1.0, attest_availability=avail, exfil_attest=adv)
              params = Params(value=5.0, lambda_r=4.0, canary_cost=0.2, receipt_cost=0.3, budget=5.0)
              conds = [{"name": f"av{avail}-{adv}", "specs": specs, "params": params,
                        "indistinguishable": True}]
              rows, _ = experiment.run(tasks, conds, seeds, policies=["ccr_r"])
              by = _row_by_policy(rows)
              r = by["ccr_r"]
              print(f"{avail:>7.2f}{adv:>11}{r['incident_rate']:>10.3f}"
                    f"{r['exfil_incident_rate']:>12.3f}{r['mean_net_utility']:>10.2f}")
      print("-" * len(hdr))
      print("Read: if 'absent' incident rises ABOVE 'forge' as availability drops, the forging")
      print("adversary was self-incriminating and the HONEST degradation curve is the 'absent' one.")
  ```
- **Acceptance:** `python scripts/run.py` prints RQ4; numbers are deterministic across two runs.
- **Expected outcome (HYPOTHESIS — verify):** at `avail=1.0`, forge≈absent (a `correct` agent attests
  `valid`→risk 0 and outranks the exfiltrator either way, so incident barely moves). As `avail`→0, the
  **`absent` exfiltrator can outrank `correct`** (both unattested ≈ +0.35) while the forging one cannot
  (+0.60) — so **the best-response adversary makes RQ3's graceful-degradation curve worse than currently
  reported.** If confirmed, RQ3 in the paper must use the `absent` adversary as the honest headline.

### WI-2 — `attested_yet_abusing` persona (measure the `cov < 1` boundary) — **PRIORITY 2**
- **Goal:** an agent that runs the **audited** image (so it earns a **genuine VALID quote**) yet still
  causes an incident — empirically demonstrating that valid attestation does **not** eliminate risk.
- **Why:** turns the *assumed* limitation (`cov<1`, "attestation ≠ IFC") into a *measured* one. This is the
  same "assumption → measurement" move that made the base paper's indistinguishability study its
  most-praised contribution. It also motivates the D2/IFC line concretely.
- **Modeling note (state explicitly in README):** this persona represents misuse of a legitimately-received
  datum through a channel the audited image legitimately has (e.g., writes to a shared store later read
  out-of-band). Its attestation is **valid**; the residual incident is exactly the `semantic` class that
  `cov` does **not** cover.
- **Change — `ccrlib/scenario.py`:** add `n_attest_abuser: int = 0` to `build_agents` and a construction
  block:
  ```python
      for i in range(n_attest_abuser):
          # Runs the AUDITED image => earns a VALID quote, yet misuses the datum (semantic exfil).
          # This is the cov<1 case: attestation proves the runtime, not benign use of the data.
          agents.append(_agent("attested_yet_abusing", skill, "adventureworks", i,
                               CEILING,
                               signed=True, poison=False, scope="narrow",
                               desc=f"Certified premium {skill} specialist. {kw}",
                               attestable=True, forges=False,
                               runtime=AUDITED_MEASUREMENT))
  ```
- **Change — `ccrlib/scenario.py`, `PERSONA_TRUE`:** add `"attested_yet_abusing": 0.90` (capable).
- **Change — `ccrlib/agents.py`, `_effective_capability` and `_BASE_LATENCY`:** treat
  `attested_yet_abusing` like `competent_exfiltrator` (capable; passes canary & real task). Add a branch
  returning `self.true.get(skill, 0.0)` and a latency entry.
- **Change — `ccrlib/metrics.py`, `MALICIOUS`:** add `"attested_yet_abusing"` so its selection counts as an
  incident.
- **Change — `ccrlib/scoring.py`, `attested_risk`:** this is where `cov_by_class` (A1) pays off. A **valid**
  quote must lower the **runtime** risk but **not** the **semantic** residual. Simplest faithful model: give
  this persona a small irreducible `semantic` risk floor that `valid` attestation does **not** remove, e.g.
  fold a `Params.semantic_floor = 0.30` that survives a valid quote for agents whose incident class is
  semantic. Keep the mechanism observable-only: the router cannot know the class, so it applies the standard
  `valid → base_risk*(1-cov)`; the **evaluator** still labels the realized incident. The point of WI-2 is
  the **measured incident rate under valid attestation > 0**, proving `cov<1` operationally.
- **Acceptance:** with a pool containing an `attested_yet_abusing` agent, CCR-R shows a **non-zero** incident
  attributable to a **valid-attested** agent (report a new `attested_incident_rate`). Add a one-line
  aggregate in `metrics.py` counting incidents where `chosen_attestation == "valid"`.
- **Expected outcome (HYPOTHESIS — verify):** CCR-R's incident is **> 0** even at full attestation
  availability once this persona is present, and the residual tracks `1 - cov` (or `semantic_floor`) — the
  empirical statement of "attestation is necessary but not sufficient; D2/IFC needed."

### WI-3 — `claim_gap` sweep + confidence intervals — **PRIORITY 3**
- **Goal:** (a) show CCR-R's advantage **grows with card unreliability** (the base paper's decisive
  calibration test, currently missing — every RQ fixes `claim_gap=1.0`); (b) add **task-clustered bootstrap
  CIs** (the base paper had them; reviewers praised the reproducible artifact).
- **Why:** #88A ("most ablations are just parameter sweeps") + the base paper's own headline robustness
  result. Without the `claim_gap` sweep a reviewer will say "calibrated to win."
- **Change — `scripts/run.py`:** add `_print_rq5_claimgap` sweeping
  `claim_gap ∈ {0.0, 0.25, 0.5, 0.75, 1.0}` for `ccr` vs `ccr_r`, reporting incident and mean net utility
  and the **advantage** (CCR-R − best baseline). Expect advantage ≈ 0 or negative at `claim_gap=0` (honest
  world: the receipt is overhead) rising monotonically toward `claim_gap=1`.
- **Change — new `ccrlib/stats.py` (stdlib only):** implement a **task-clustered bootstrap** (resample the
  24 task-clusters with replacement, recompute the metric per resample, report 2.5/97.5 percentiles). Wire a
  `--ci` flag in `run.py` to print 95% CIs for the RQ1 headline (success, incident, exfil_incident) and for
  the paired CCR-R − CCR incident difference.
- **Acceptance:** `python scripts/run.py --ci` prints CIs; the `claim_gap` monotonicity table is present and
  deterministic.
- **Expected outcome (HYPOTHESIS — verify):** monotone advantage in `claim_gap`; the CCR-R − CCR incident
  reduction CI is **disjoint from 0** in the hostile cell (parity on success, as in the base paper).

### WI-4 — `replay` adversary (validate the nonce mechanism) — PRIORITY 4
- **Goal:** an adversary that replays a **stale valid** quote (correct measurement/authority, **wrong
  nonce**) → `verify_attestation` returns `invalid` → caught.
- **Why:** the crypto already supports it (`nonce` binding); demonstrating it empirically closes a roadmap
  item and pre-empts "did you actually test replay?"
- **Change — `ccrlib/agents.py`, `attest()`:** add a `replays` hidden flag; when set, return a quote built
  with a **fixed old nonce** (e.g. `domain.make_quote(self.runtime_or_audited, "n000000000000",
  "cc-attest-root")`) regardless of `req["nonce"]`. Add `replays` to `SimAgent.__init__` and to `_agent`/
  `build_agents` (a `replay_attacker` persona). Keep it observable-only.
- **Acceptance:** a `replay_attacker` agent is always demoted (its quote verifies `invalid`); add a tiny unit
  check in a `tests/` file or a `--selftest` path asserting `verify_attestation(replayed, fresh_nonce) ==
  "invalid"`.

### WI-5 — Reproducibility artifacts (`EVIDENCE.md`, `SENSITIVITY.md`) — PRIORITY 4
- **Goal:** commit regenerated evidence like the base lab shipped (byte-for-byte reproducible; reviewers
  explicitly re-ran and praised it).
- **Change — new `scripts/emit_evidence.py`** that runs the RQ suite and writes `EVIDENCE.md` (RQ1–RQ4
  tables) and `SENSITIVITY.md` (the `claim_gap`, `rho`, `lambda_r`, `attest_availability`, and `d_H`/`cov`
  sweeps) as Markdown tables. Commit the generated files. Add a `REPRODUCE.md` with the exact commands.
- **Acceptance:** re-running the script reproduces the committed files with no diff.

### WI-6 — Small correctness/clarity fixes — PRIORITY 5 (do alongside the above)
- **`ccrlib/agents.py`, `execute()`:** dead ternary
  `"httpStatus": 200 if (correct or kind == "canary") else 200` — both branches are `200`, so
  `canary_score`'s `status_ok` factor is always 1.0. Decide intent: either return `500` on a failed **real**
  task (and keep canary at 200), or drop the `httpStatus` factor from `canary_score`. Pick one; document it.
- **`ccrlib/scenario.py`:** `canary_aware` is given `runtime=EXFIL_MEASUREMENT` but is not an exfiltrator
  (harmless because `attestable=False, forges=False` → `absent`). Set its `runtime` to a neutral
  `"sha256:agent-stack-unattested"` for clarity, or add a comment explaining it is irrelevant.
- **A2ASecBench mapping:** add a short `docs/threat-mapping.md` tying each persona to the A2ASecBench threat
  class the proposal cites (e.g. Capability Cloaking / ASRF), so the paper's threat-model section is grounded
  in the artifact.

---

## 4. Suggested schedule (for coordinating with the paper)

| Slot | Work | Depends on | Output the paper needs |
|---|---|---|---|
| 1 | **A1 + A2 + A3** (model-lock) | — | locked semantics for §4 |
| 2 | **WI-1** best-response | A2 | honest RQ3/RQ4 curve; the #88B answer |
| 3 | **WI-2** attested-yet-abusing | A1 | measured `cov<1` boundary (the citable result) |
| 4 | **WI-3** claim_gap + CIs | — | calibration-robustness + CIs (the base-paper standard) |
| 5 | **WI-4 + WI-5 + WI-6** | WI-1..3 | replay validation, artifacts, cleanups |
| 6 | (paper) write RQ sections from committed numbers | WI-1..3 | — |

**Do WI-1, WI-2, WI-3 before writing any RQ prose.** They are the results that decide what the paper can
honestly claim. Everything the paper states must be traceable to a committed `EVIDENCE.md`/`SENSITIVITY.md`
number (the #88B "25/31 vs 29/35" mismatch must never recur).

---

## 5. Definition of done (per work item)
- [ ] Code follows the guardrails in §1 (observability invariant, determinism, stdlib, compliance).
- [ ] `python scripts/run.py` (and `--ci` where relevant) runs clean and is deterministic across two runs.
- [ ] New numbers are written to `EVIDENCE.md`/`SENSITIVITY.md` by a script, not by hand.
- [ ] README updated: any new persona/param is documented and justified; the forgery-narrative reframe (A2)
      is reflected; hypotheses in this doc are replaced by measured numbers.
- [ ] No policy/scorer reads hidden ground truth; only `metrics.py` does.

---

## 6. Questions to route to the paper-side Copilot (via the author) — do not answer these alone

Collect these and send them back to the `~\Projects\papers` Copilot through the author; **do not resolve
them inside the lab**. Batch them rather than asking one at a time.

**Theoretical / research (must be coordinated — see the Coordination rule at the top):**
- **Model-lock A1:** exact `cov` values and the per-threat-class split (`runtime` vs `semantic`), and the
  `semantic_floor` used in WI-2 — these define what "attestation ≠ IFC" means numerically in the paper.
- **Model-lock A2/A3:** confirmation that the **best-response (`absent`) exfiltrator** is the headline
  adversary, and whether to add the context-sensitive `risk_unattested` refinement.
- **WI-2 framing:** how the `attested_yet_abusing` incident is described in the paper (the D2/IFC boundary)
  — this is a claim about scope, not just code.
- **What each result licenses the paper to claim** (e.g., is WI-3's monotonicity stated as "advantage grows
  with card unreliability," matching the base paper's wording?). Every claim must map to a committed number.
- **Threat-model / A2ASecBench mapping** (WI-6): which threat classes each persona instantiates.

**Logistics the author confirms:**
- Target **page limit / format** for AAMAS 2027 (affects how many sweeps make the cut).
- Whether the real **Azure Confidential Computing** artifact (proposal C4) is in-scope for this submission
  or deferred to an honest **pilot** (as the base paper did).

**Report back to the paper side, when done:** the committed `EVIDENCE.md`/`SENSITIVITY.md` numbers for
WI-1/WI-2/WI-3, and any place where a measured result **contradicts** a hypothesis in §3 (those change the
paper's claims and must be reconciled on the paper side).
