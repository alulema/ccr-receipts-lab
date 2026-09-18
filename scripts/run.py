"""Local reproduction of the CCR-Receipts headline results.

    python scripts/run.py                 # defaults: 8 seeds x 24 tasks = 192 runs/cell
    python scripts/run.py --seeds 12 --tasks 48
    python scripts/run.py --ci             # add task-clustered bootstrap 95% CIs (RQ1)

Produces:
  RQ1     Coverage    — against a competent, valid-signed exfiltrator, does CCR-R cut the
                        incident vs CCR / signature_only, at parity success?
  RQ2     Frontier    — "when is it worth attesting?": as the receipt cost rho grows, when
                        does CCR-R stop beating CCR (the attestation frontier)?
  RQ3     Adoption    — as fewer benign agents can attest, does CCR-R degrade gracefully
                        toward CCR (no attested-safe agent left to route to)?
  RQ4     Adversary   — best-response exfiltrator (WI-1): does the headline hold when the
                        exfiltrator declines to incriminate itself (absent, not forge)?
  RQ-COV  cov<1       — attested_yet_abusing (WI-2): a validly-attested agent that is still
                        malicious (semantic misuse) — measures the cov<1 boundary directly.
  RQ5     claim_gap   — WI-3: does CCR-R's advantage grow with card unreliability?

Deterministic and dependency-free: same numbers on every machine.
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ccrlib import experiment, scenario, stats  # noqa: E402
from ccrlib.scoring import Params  # noqa: E402

POLICY_ORDER = ["random", "card_only", "signature_only", "optimistic_fallback",
                "receipt_only", "ccr", "ccr_r"]


def _row_by_policy(rows: list[dict]) -> dict[str, dict]:
    return {r["policy"]: r for r in rows}


def _print_rq1(seeds: list[int], tasks: list[dict], ci: bool = False) -> None:
    specs = scenario.build_agents(claim_gap=1.0, attest_availability=1.0)
    params = Params(value=5.0, lambda_r=4.0, canary_cost=0.2, receipt_cost=0.3, budget=5.0)
    conditions = [{"name": "rq1", "specs": specs, "params": params, "indistinguishable": True}]
    rows, raw = experiment.run(tasks, conditions, seeds)
    by = _row_by_policy(rows)

    print("\n" + "=" * 78)
    print("RQ1 — COVERAGE  (V=5, lambda_r=4, kappa=0.2, rho=0.3, mixed pool w/ competent")
    print("      exfiltrator, indistinguishable canary, full attestation availability)")
    print("=" * 78)
    hdr = f"{'policy':<20}{'success':>9}{'incident':>10}{'exfil_inc':>11}{'defect':>8}{'net_util':>10}{'canary':>8}{'receipt':>8}"
    print(hdr)
    print("-" * len(hdr))
    for pol in POLICY_ORDER:
        r = by.get(pol)
        if not r:
            continue
        print(f"{pol:<20}{r['success_rate']:>9.3f}{r['incident_rate']:>10.3f}"
              f"{r['exfil_incident_rate']:>11.3f}{r['defection_rate']:>8.3f}"
              f"{r['mean_net_utility']:>10.3f}{r['mean_canaries']:>8.2f}{r['mean_receipts']:>8.2f}")

    ccr, ccrr = by["ccr"], by["ccr_r"]
    print("-" * len(hdr))
    print(f"VERDICT: CCR incident {ccr['incident_rate']:.3f} -> CCR-R incident "
          f"{ccrr['incident_rate']:.3f}  (success {ccr['success_rate']:.3f} -> "
          f"{ccrr['success_rate']:.3f}); net {ccr['mean_net_utility']:.2f} -> "
          f"{ccrr['mean_net_utility']:.2f}.")

    if ci:
        print("-" * len(hdr))
        print("95% CI (task-clustered bootstrap, n=2000 resamples, ccr_r):")
        for field, label in [("success", "success_rate"), ("incident", "incident_rate"),
                              ("exfil_incident", "exfil_incident_rate")]:
            pt, lo, hi = stats.bootstrap_ci(raw, stats.rate(field, "ccr_r"))
            print(f"  ccr_r.{label:<20} {pt:.3f}  [{lo:.3f}, {hi:.3f}]")
        pt, lo, hi = stats.bootstrap_ci(raw, stats.paired_diff("incident", "ccr", "ccr_r"))
        print(f"  ccr.incident - ccr_r.incident (reduction): {pt:.3f}  [{lo:.3f}, {hi:.3f}]")
        print("  (disjoint from 0 => the incident reduction is not a fluke of these seeds)")


def _print_rq2(seeds: list[int], tasks: list[dict]) -> None:
    specs = scenario.build_agents(claim_gap=1.0, attest_availability=1.0)
    print("\n" + "=" * 78)
    print("RQ2 — ATTESTATION FRONTIER  (V=5, lambda_r=4; sweep receipt cost rho)")
    print("      gate fires when lambda_r*cov*d_H - rho > 0  =>  rho < 4*0.9*0.3 = 1.08")
    print("=" * 78)
    hdr = f"{'rho':>6}{'gate':>6}{'ccr_inc':>9}{'ccrR_inc':>10}{'ccr_net':>9}{'ccrR_net':>10}{'net_gain':>10}"
    print(hdr)
    print("-" * len(hdr))
    for rho in [0.1, 0.3, 0.5, 0.8, 1.08, 1.5, 2.5]:
        params = Params(value=5.0, lambda_r=4.0, canary_cost=0.2, receipt_cost=rho, budget=5.0)
        conds = [{"name": f"rho{rho}", "specs": specs, "params": params, "indistinguishable": True}]
        rows, _ = experiment.run(tasks, conds, seeds, policies=["ccr", "ccr_r"])
        by = _row_by_policy(rows)
        gate = params.lambda_r * params.attest_coverage * params.malice_doubt - params.lambda_c * rho
        gain = by["ccr_r"]["mean_net_utility"] - by["ccr"]["mean_net_utility"]
        print(f"{rho:>6.2f}{('yes' if gate > 0 else 'no'):>6}"
              f"{by['ccr']['incident_rate']:>9.3f}{by['ccr_r']['incident_rate']:>10.3f}"
              f"{by['ccr']['mean_net_utility']:>9.2f}{by['ccr_r']['mean_net_utility']:>10.2f}"
              f"{gain:>+10.2f}")
    print("-" * len(hdr))
    print("Read: while rho is cheap the receipt pays (CCR-R cuts incident, higher net);")
    print("past the frontier the gate stops firing and CCR-R falls back to CCR.")


def _print_rq3(seeds: list[int], tasks: list[dict]) -> None:
    print("\n" + "=" * 78)
    print("RQ3 — PARTIAL ADOPTION  (V=5, lambda_r=4, rho=0.3; sweep attest_availability)")
    print("=" * 78)
    hdr = f"{'avail':>7}{'ccrR_inc':>10}{'ccrR_exfil':>12}{'ccrR_net':>10}{'ccr_inc(ref)':>14}"
    print(hdr)
    print("-" * len(hdr))
    for avail in [1.0, 0.75, 0.5, 0.25, 0.0]:
        specs = scenario.build_agents(claim_gap=1.0, attest_availability=avail)
        params = Params(value=5.0, lambda_r=4.0, canary_cost=0.2, receipt_cost=0.3, budget=5.0)
        conds = [{"name": f"av{avail}", "specs": specs, "params": params, "indistinguishable": True}]
        rows, _ = experiment.run(tasks, conds, seeds, policies=["ccr", "ccr_r"])
        by = _row_by_policy(rows)
        print(f"{avail:>7.2f}{by['ccr_r']['incident_rate']:>10.3f}"
              f"{by['ccr_r']['exfil_incident_rate']:>12.3f}{by['ccr_r']['mean_net_utility']:>10.2f}"
              f"{by['ccr']['incident_rate']:>14.3f}")
    print("-" * len(hdr))
    print("Read: with no attestable-safe agent left (avail=0), CCR-R can only fall back")
    print("to CCR — the incident rises toward CCR's, i.e. graceful degradation.")


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


def _print_rq_cov(seeds: list[int], tasks: list[dict]) -> None:
    """WI-2: attested_yet_abusing runs the AUDITED image (earns a VALID quote) yet is
    malicious (semantic misuse a runtime attestation cannot see). Measures the cov<1
    boundary directly: a non-zero incident rate attributable to a validly-attested
    agent, i.e. attestation lowers risk but is not, by itself, sufficient."""
    specs = scenario.build_agents(claim_gap=1.0, attest_availability=1.0, n_attest_abuser=1)
    params = Params(value=5.0, lambda_r=4.0, canary_cost=0.2, receipt_cost=0.3, budget=5.0)
    conds = [{"name": "cov-boundary", "specs": specs, "params": params, "indistinguishable": True}]
    rows, _ = experiment.run(tasks, conds, seeds, policies=["ccr", "receipt_only", "ccr_r"])
    by = _row_by_policy(rows)

    print("\n" + "=" * 78)
    print("RQ-COV — ATTESTED-YET-ABUSING  (cov<1 boundary, WI-2; pool adds an agent that")
    print("         earns a VALID quote yet is malicious: semantic misuse, not runtime)")
    print("=" * 78)
    hdr = f"{'policy':<20}{'incident':>10}{'exfil_inc':>11}{'attested_inc':>13}{'net_util':>10}"
    print(hdr); print("-" * len(hdr))
    for pol in ["ccr", "receipt_only", "ccr_r"]:
        r = by.get(pol)
        if not r:
            continue
        print(f"{pol:<20}{r['incident_rate']:>10.3f}{r['exfil_incident_rate']:>11.3f}"
              f"{r['attested_incident_rate']:>13.3f}{r['mean_net_utility']:>10.2f}")
    print("-" * len(hdr))
    print("Read: attested_incident_rate > 0 under CCR-R measures cov<1 operationally --")
    print("a VALID attestation lowers risk but does not eliminate it (needs D2/IFC).")


def _print_rq5_claimgap(seeds: list[int], tasks: list[dict]) -> None:
    """WI-3: does CCR-R's advantage over CCR grow as the card becomes less reliable
    (claim_gap -> 1)? Uses the 'absent' best-response exfiltrator (WI-1/A2) as the
    honest headline adversary. At claim_gap=0 cards are honest and the receipt is
    pure overhead, so the advantage should be ~0; it should rise toward claim_gap=1."""
    print("\n" + "=" * 78)
    print("RQ5 — CLAIM_GAP SWEEP  (V=5, lambda_r=4, rho=0.3; ccr vs ccr_r; 'absent'")
    print("      best-response exfiltrator; advantage = ccr_incident - ccrR_incident)")
    print("=" * 78)
    hdr = f"{'claim_gap':>10}{'ccr_inc':>9}{'ccrR_inc':>10}{'ccr_net':>9}{'ccrR_net':>10}{'advantage':>11}"
    print(hdr); print("-" * len(hdr))
    for cg in [0.0, 0.25, 0.5, 0.75, 1.0]:
        specs = scenario.build_agents(claim_gap=cg, attest_availability=1.0, exfil_attest="absent")
        params = Params(value=5.0, lambda_r=4.0, canary_cost=0.2, receipt_cost=0.3, budget=5.0)
        conds = [{"name": f"cg{cg}", "specs": specs, "params": params, "indistinguishable": True}]
        rows, _ = experiment.run(tasks, conds, seeds, policies=["ccr", "ccr_r"])
        by = _row_by_policy(rows)
        advantage = by["ccr"]["incident_rate"] - by["ccr_r"]["incident_rate"]
        print(f"{cg:>10.2f}{by['ccr']['incident_rate']:>9.3f}{by['ccr_r']['incident_rate']:>10.3f}"
              f"{by['ccr']['mean_net_utility']:>9.2f}{by['ccr_r']['mean_net_utility']:>10.2f}"
              f"{advantage:>+11.3f}")
    print("-" * len(hdr))
    print("Read: advantage = CCR incident - CCR-R incident (incident REDUCTION). Expect")
    print("~0 at claim_gap=0 (honest world, receipt is overhead), rising toward 1.0.")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=8)
    ap.add_argument("--tasks", type=int, default=24)
    ap.add_argument("--ci", action="store_true", help="print task-clustered bootstrap 95%% CIs")
    args = ap.parse_args()
    seeds = list(range(args.seeds))
    tasks = scenario.build_tasks(args.tasks)
    print(f"ccr-receipts-lab | seeds={args.seeds} tasks={args.tasks} "
          f"(n={args.seeds * args.tasks}/cell)")
    _print_rq1(seeds, tasks, ci=args.ci)
    _print_rq2(seeds, tasks)
    _print_rq3(seeds, tasks)
    _print_rq4(seeds, tasks)
    _print_rq_cov(seeds, tasks)
    _print_rq5_claimgap(seeds, tasks)
    print()


if __name__ == "__main__":
    main()

