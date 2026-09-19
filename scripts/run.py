"""Local reproduction of the CCR-Receipts headline results (console view).

    python scripts/run.py                 # defaults: 8 seeds x 24 tasks = 192 runs/cell
    python scripts/run.py --seeds 12 --tasks 48
    python scripts/run.py --ci             # add task-clustered bootstrap 95% CIs (RQ1, RQ5)

Every cell is defined ONCE in `ccrlib/suite.py`; this script only formats it. The
committed artifact (`EVIDENCE.md`, `SENSITIVITY.md`) is written from the same functions
by `scripts/emit_evidence.py`, so console and artifact numbers cannot diverge.

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

The HEADLINE adversary is the best-response `absent` exfiltrator (model-lock A2).
Deterministic and dependency-free: same numbers on every machine.
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ccrlib import scenario, suite  # noqa: E402

POLICY_ORDER = ["random", "card_only", "signature_only", "optimistic_fallback",
                "receipt_only", "ccr", "ccr_r"]


def _banner(*lines: str) -> None:
    print("\n" + "=" * 78)
    for ln in lines:
        print(ln)
    print("=" * 78)


def _print_rq1(seeds, tasks, ci: bool = False) -> None:
    by, cis = suite.rq1(seeds, tasks, ci=ci)
    _banner("RQ1 — COVERAGE  (V=5, lambda_r=4, kappa=0.2, rho=0.3, mixed pool w/ competent",
            "      exfiltrator [best-response 'absent'], indistinguishable canary, full",
            "      attestation availability)")
    hdr = (f"{'policy':<20}{'success':>9}{'incident':>10}{'exfil_inc':>11}{'defect':>8}"
           f"{'net_util':>10}{'canary':>8}{'receipt':>8}")
    print(hdr); print("-" * len(hdr))
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
        print(f"95% CI (task-clustered bootstrap, n={suite.N_RESAMPLES} resamples):")
        for k, c in cis.items():
            print(f"  {k:<24} {c['pt']:.3f}  [{c['lo']:.3f}, {c['hi']:.3f}]")
        print("  (reduction.incident disjoint from 0 => the incident reduction is not a fluke)")


def _print_rq2(seeds, tasks) -> None:
    p = suite.headline_params()
    _banner("RQ2 — ATTESTATION FRONTIER  (V=5, lambda_r=4; sweep receipt cost rho)",
            f"      gate fires when lambda_r*cov*d_H - rho > 0  =>  rho < "
            f"{p.lambda_r * p.attest_coverage * p.malice_doubt:.2f}")
    hdr = f"{'rho':>6}{'gate':>6}{'ccr_inc':>9}{'ccrR_inc':>10}{'ccr_net':>9}{'ccrR_net':>10}{'net_gain':>10}"
    print(hdr); print("-" * len(hdr))
    for r in suite.rq2_rho(seeds, tasks):
        print(f"{r['rho']:>6.2f}{('yes' if r['gate'] else 'no'):>6}"
              f"{r['ccr_inc']:>9.3f}{r['ccrR_inc']:>10.3f}"
              f"{r['ccr_net']:>9.2f}{r['ccrR_net']:>10.2f}{r['net_gain']:>+10.2f}")
    print("-" * len(hdr))
    print("Read: while rho is cheap the receipt pays (CCR-R cuts incident, higher net);")
    print("past the frontier the gate stops firing and CCR-R falls back to CCR.")


def _print_rq3(seeds, tasks) -> None:
    _banner("RQ3 — PARTIAL ADOPTION  (V=5, lambda_r=4, rho=0.3; sweep attest_availability;",
            "      best-response 'absent' exfiltrator)")
    hdr = f"{'avail':>7}{'ccrR_inc':>10}{'ccrR_exfil':>12}{'ccrR_net':>10}{'ccr_inc(ref)':>14}{'ccr_net(ref)':>14}"
    print(hdr); print("-" * len(hdr))
    for r in suite.rq3_adoption(seeds, tasks, suite.HEADLINE_ADVERSARY):
        print(f"{r['avail']:>7.2f}{r['ccrR_inc']:>10.3f}{r['ccrR_exfil']:>12.3f}"
              f"{r['ccrR_net']:>10.2f}{r['ccr_inc']:>14.3f}{r['ccr_net']:>14.2f}")
    print("-" * len(hdr))
    print("Read: with no attestable-safe agent left (avail=0) CCR-R's incident reaches CCR's")
    print("(parity) but its net utility does NOT: rho is paid per attestation request whether")
    print("or not a quote comes back, so at zero adoption CCR-R is dominated by the wasted")
    print("receipt budget. See SENSITIVITY.md (adoption x rho grid) for the break-even a*(rho).")


def _print_rq4(seeds, tasks) -> None:
    _banner("RQ4 — ADVERSARY BEST RESPONSE  (V=5, lambda_r=4, rho=0.3; CCR-R)",
            "      forge => invalid quote (+0.60); absent => no quote (+0.35). 'absent' is the",
            "      exfiltrator's best response (0.35 < 0.60), i.e. it declines to incriminate itself.")
    hdr = f"{'avail':>7}{'adversary':>11}{'ccrR_inc':>10}{'ccrR_exfil':>12}{'ccrR_net':>10}"
    print(hdr); print("-" * len(hdr))
    for r in suite.rq4_best_response(seeds, tasks):
        print(f"{r['avail']:>7.2f}{r['adversary']:>11}{r['ccrR_inc']:>10.3f}"
              f"{r['ccrR_exfil']:>12.3f}{r['ccrR_net']:>10.2f}")
    print("-" * len(hdr))
    print("Read: if 'absent' incident rises ABOVE 'forge' as availability drops, the forging")
    print("adversary was self-incriminating and the HONEST degradation curve is the 'absent' one.")


def _print_rq_cov(seeds, tasks) -> None:
    by = suite.rq_cov(seeds, tasks)
    _banner("RQ-COV — ATTESTED-YET-ABUSING  (cov<1 boundary, WI-2; pool adds an agent that",
            "         earns a VALID quote yet is malicious: semantic misuse, not runtime)")
    hdr = f"{'policy':<20}{'incident':>10}{'exfil_inc':>11}{'attested_inc':>13}{'net_util':>10}"
    print(hdr); print("-" * len(hdr))
    for pol in ["ccr", "receipt_only", "ccr_r"]:
        r = by[pol]
        print(f"{pol:<20}{r['incident_rate']:>10.3f}{r['exfil_incident_rate']:>11.3f}"
              f"{r['attested_incident_rate']:>13.3f}{r['mean_net_utility']:>10.2f}")
    print("-" * len(hdr))
    print("Read: attested_incident_rate > 0 under CCR-R measures cov<1 operationally --")
    print("a VALID attestation lowers risk but does not eliminate it (needs D2/IFC).")


def _print_rq5_claimgap(seeds, tasks, ci: bool = False) -> None:
    _banner("RQ5 — CLAIM_GAP SWEEP  (V=5, lambda_r=4, rho=0.3; ccr vs ccr_r; 'absent'",
            "      best-response exfiltrator; advantage = ccr_incident - ccrR_incident)")
    hdr = f"{'claim_gap':>10}{'ccr_inc':>9}{'ccrR_inc':>10}{'ccr_net':>9}{'ccrR_net':>10}{'advantage':>11}"
    if ci:
        hdr += f"{'95% CI':>18}"
    print(hdr); print("-" * len(hdr))
    for r in suite.rq5_claimgap(seeds, tasks, ci=ci):
        line = (f"{r['claim_gap']:>10.2f}{r['ccr_inc']:>9.3f}{r['ccrR_inc']:>10.3f}"
                f"{r['ccr_net']:>9.2f}{r['ccrR_net']:>10.2f}{r['advantage']:>+11.3f}")
        if ci:
            c = r["advantage_ci"]
            line += f"   [{c['lo']:.3f}, {c['hi']:.3f}]"
        print(line)
    print("-" * len(hdr))
    print("Read: advantage = CCR incident - CCR-R incident (incident REDUCTION). The paper's")
    print("wording (monotone / flat / dip) is decided by this measured curve, not in advance.")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=8)
    ap.add_argument("--tasks", type=int, default=24)
    ap.add_argument("--ci", action="store_true",
                    help="print task-clustered bootstrap 95%% CIs (RQ1, RQ5)")
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
    _print_rq5_claimgap(seeds, tasks, ci=args.ci)
    print()


if __name__ == "__main__":
    main()
