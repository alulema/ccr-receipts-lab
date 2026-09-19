"""The experiment suite: ONE definition of every cell the paper cites.

`scripts/run.py` (console view) and `scripts/emit_evidence.py` (EVIDENCE.md /
SENSITIVITY.md) both call these functions, so a number printed on a terminal and a
number committed to the artifact can never come from different code paths. Every
function returns plain rows (list[dict]) — no printing, no formatting.

Conventions:
- The HEADLINE cell is V=5, lambda_r=4, kappa=0.2, rho=0.3, budget=5, claim_gap=1,
  indistinguishable canary, full attestation availability.
- The HEADLINE adversary is the best-response `absent` exfiltrator (model-lock A2);
  `forge` is kept as the labelled naive contrast.
- Stdlib only; deterministic (no `random`).
"""
from __future__ import annotations

from . import experiment, scenario, stats
from .scoring import Params

HEADLINE_ADVERSARY = "absent"
NAIVE_ADVERSARY = "forge"

RHO_GRID = [0.1, 0.3, 0.5, 0.8, 1.08, 1.5, 2.5]
AVAIL_GRID = [1.0, 0.75, 0.5, 0.25, 0.0]
CLAIM_GAP_GRID = [0.0, 0.25, 0.5, 0.75, 1.0]
COV_GRID = [0.5, 0.7, 0.9, 1.0]
LAMBDA_R_GRID = [1.0, 2.0, 4.0, 8.0]
MALICE_DOUBT_GRID = [0.0, 0.1, 0.3, 0.5]
ADOPTION_GRID = [0.0, 0.1, 0.25, 0.5, 0.75, 1.0]
ADOPTION_RHO_GRID = [0.1, 0.3, 0.6]

N_RESAMPLES = 2000


def headline_params(**overrides) -> Params:
    base = dict(value=5.0, lambda_r=4.0, canary_cost=0.2, receipt_cost=0.3, budget=5.0)
    base.update(overrides)
    return Params(**base)


def _by_policy(rows: list[dict]) -> dict[str, dict]:
    return {r["policy"]: r for r in rows}


def _cell(tasks, seeds, specs, params, policies, name="cell"):
    conds = [{"name": name, "specs": specs, "params": params, "indistinguishable": True}]
    rows, raw = experiment.run(tasks, conds, seeds, policies=policies)
    return _by_policy(rows), raw


def _ci(raw, metric) -> dict:
    pt, lo, hi = stats.bootstrap_ci(raw, metric, n_resamples=N_RESAMPLES)
    return {"pt": round(pt, 4), "lo": round(lo, 4), "hi": round(hi, 4)}


# --- RQ1: coverage --------------------------------------------------------------

def rq1(seeds, tasks, adversary: str = HEADLINE_ADVERSARY, ci: bool = False):
    """All policies at the headline cell. Returns (rows_by_policy, cis).
    `cis` (only when ci=True) holds the ccr_r headline CIs and the paired
    ccr - ccr_r incident reduction."""
    specs = scenario.build_agents(claim_gap=1.0, attest_availability=1.0, exfil_attest=adversary)
    by, raw = _cell(tasks, seeds, specs, headline_params(), None, f"rq1-{adversary}")
    cis = {}
    if ci:
        for f in ("success", "incident", "exfil_incident"):
            cis[f"ccr_r.{f}"] = _ci(raw, stats.rate(f, "ccr_r"))
        cis["ccr.incident"] = _ci(raw, stats.rate("incident", "ccr"))
        cis["reduction.incident"] = _ci(raw, stats.paired_diff("incident", "ccr", "ccr_r"))
        cis["diff.net_utility"] = _ci(raw, stats.paired_diff("net_utility", "ccr_r", "ccr"))
    return by, cis


# --- RQ2: attestation frontier (rho sweep) ----------------------------------------

def gate_margin(p: Params) -> float:
    """Receipt-VoI margin at the malice-doubt floor: lambda_r*cov*d_H - lambda_c*rho."""
    return p.lambda_r * p.attest_coverage * p.malice_doubt - p.lambda_c * p.receipt_cost


def rq2_rho(seeds, tasks, adversary: str = HEADLINE_ADVERSARY, rhos=RHO_GRID) -> list[dict]:
    specs = scenario.build_agents(claim_gap=1.0, attest_availability=1.0, exfil_attest=adversary)
    out = []
    for rho in rhos:
        p = headline_params(receipt_cost=rho)
        by, _ = _cell(tasks, seeds, specs, p, ["ccr", "ccr_r"], f"rho{rho}")
        out.append({
            "rho": rho, "gate": gate_margin(p) > 0,
            "ccr_inc": by["ccr"]["incident_rate"], "ccrR_inc": by["ccr_r"]["incident_rate"],
            "ccr_net": by["ccr"]["mean_net_utility"], "ccrR_net": by["ccr_r"]["mean_net_utility"],
            "net_gain": round(by["ccr_r"]["mean_net_utility"] - by["ccr"]["mean_net_utility"], 4),
            "ccrR_receipts": by["ccr_r"]["mean_receipts"],
        })
    return out


# --- RQ3/RQ4: partial adoption x adversary ------------------------------------------

def rq3_adoption(seeds, tasks, adversary: str, avails=AVAIL_GRID, rho: float = 0.3) -> list[dict]:
    out = []
    for avail in avails:
        specs = scenario.build_agents(claim_gap=1.0, attest_availability=avail, exfil_attest=adversary)
        by, _ = _cell(tasks, seeds, specs, headline_params(receipt_cost=rho),
                      ["ccr", "ccr_r"], f"av{avail}-{adversary}")
        out.append({
            "avail": avail, "adversary": adversary, "rho": rho,
            "ccr_inc": by["ccr"]["incident_rate"], "ccrR_inc": by["ccr_r"]["incident_rate"],
            "ccrR_exfil": by["ccr_r"]["exfil_incident_rate"],
            "ccr_net": by["ccr"]["mean_net_utility"], "ccrR_net": by["ccr_r"]["mean_net_utility"],
            "ccrR_receipts": by["ccr_r"]["mean_receipts"],
        })
    return out


def rq4_best_response(seeds, tasks, avails=(1.0, 0.5, 0.0)) -> list[dict]:
    """forge (naive, self-incriminating) vs absent (best response) at three adoption levels."""
    out = []
    for avail in avails:
        for adv in (NAIVE_ADVERSARY, HEADLINE_ADVERSARY):
            out.extend(rq3_adoption(seeds, tasks, adv, avails=[avail]))
    return out


# --- RQ-COV: attested_yet_abusing (cov<1 boundary) ----------------------------------

def rq_cov(seeds, tasks, cov: float | None = None, adversary: str = HEADLINE_ADVERSARY):
    """Headline pool + one attested_yet_abusing agent per skill. `cov` overrides the
    router's attest_coverage belief (used by the SENSITIVITY cov sweep)."""
    specs = scenario.build_agents(claim_gap=1.0, attest_availability=1.0,
                                  exfil_attest=adversary, n_attest_abuser=1)
    p = headline_params() if cov is None else headline_params(attest_coverage=cov)
    by, _ = _cell(tasks, seeds, specs, p, ["ccr", "receipt_only", "ccr_r"], f"cov{cov}")
    return by


def sens_cov(seeds, tasks, covs=COV_GRID) -> list[dict]:
    out = []
    for cov in covs:
        by = rq_cov(seeds, tasks, cov=cov)
        r = by["ccr_r"]
        out.append({
            "cov": cov, "gate": gate_margin(headline_params(attest_coverage=cov)) > 0,
            "ccrR_inc": r["incident_rate"], "ccrR_exfil": r["exfil_incident_rate"],
            "ccrR_attested_inc": r["attested_incident_rate"], "ccrR_net": r["mean_net_utility"],
            "ccr_inc": by["ccr"]["incident_rate"],
        })
    return out


# --- RQ5: claim_gap sweep (with paired CIs) -----------------------------------------

def rq5_claimgap(seeds, tasks, adversary: str = HEADLINE_ADVERSARY, gaps=CLAIM_GAP_GRID,
                 ci: bool = False) -> list[dict]:
    out = []
    for cg in gaps:
        specs = scenario.build_agents(claim_gap=cg, attest_availability=1.0, exfil_attest=adversary)
        by, raw = _cell(tasks, seeds, specs, headline_params(), ["ccr", "ccr_r"], f"cg{cg}")
        row = {
            "claim_gap": cg,
            "ccr_inc": by["ccr"]["incident_rate"], "ccrR_inc": by["ccr_r"]["incident_rate"],
            "ccr_net": by["ccr"]["mean_net_utility"], "ccrR_net": by["ccr_r"]["mean_net_utility"],
            "advantage": round(by["ccr"]["incident_rate"] - by["ccr_r"]["incident_rate"], 4),
        }
        if ci:
            row["advantage_ci"] = _ci(raw, stats.paired_diff("incident", "ccr", "ccr_r"))
        out.append(row)
    return out


# --- SENSITIVITY: lambda_r, d_H ------------------------------------------------------

def sens_lambda_r(seeds, tasks, adversary: str = HEADLINE_ADVERSARY, grid=LAMBDA_R_GRID) -> list[dict]:
    specs = scenario.build_agents(claim_gap=1.0, attest_availability=1.0, exfil_attest=adversary)
    out = []
    for lr in grid:
        p = headline_params(lambda_r=lr)
        by, _ = _cell(tasks, seeds, specs, p, ["ccr", "ccr_r"], f"lr{lr}")
        out.append({
            "lambda_r": lr, "gate": gate_margin(p) > 0,
            "ccr_inc": by["ccr"]["incident_rate"], "ccrR_inc": by["ccr_r"]["incident_rate"],
            "ccr_net": by["ccr"]["mean_net_utility"], "ccrR_net": by["ccr_r"]["mean_net_utility"],
            "ccrR_receipts": by["ccr_r"]["mean_receipts"],
        })
    return out


def sens_malice_doubt(seeds, tasks, adversary: str = HEADLINE_ADVERSARY,
                      grid=MALICE_DOUBT_GRID) -> list[dict]:
    specs = scenario.build_agents(claim_gap=1.0, attest_availability=1.0, exfil_attest=adversary)
    out = []
    for dh in grid:
        p = headline_params(malice_doubt=dh)
        by, _ = _cell(tasks, seeds, specs, p, ["ccr", "ccr_r"], f"dh{dh}")
        out.append({
            "d_H": dh, "gate": gate_margin(p) > 0,
            "ccr_inc": by["ccr"]["incident_rate"], "ccrR_inc": by["ccr_r"]["incident_rate"],
            "ccr_net": by["ccr"]["mean_net_utility"], "ccrR_net": by["ccr_r"]["mean_net_utility"],
            "ccrR_receipts": by["ccr_r"]["mean_receipts"],
        })
    return out


# --- SENSITIVITY: adoption x rho grid, break-even adoption a*(rho) (C3) -----------------

def break_even_adoption(rows: list[dict]) -> float | None:
    """a*(rho): the smallest adoption fraction at which CCR-R's net utility is >= CCR's.
    `rows` are one rho's adoption rows in ascending `avail`. Returns the first grid
    point where ccrR_net >= ccr_net, linearly interpolated from the previous grid
    point when the crossing happens between two points; None if never."""
    prev = None
    for r in rows:
        gap = r["ccrR_net"] - r["ccr_net"]
        if gap >= 0:
            if prev is None or prev[1] >= 0:
                return r["avail"]
            a0, g0 = prev
            a1, g1 = r["avail"], gap
            return round(a0 + (a1 - a0) * (-g0) / (g1 - g0), 4)
        prev = (r["avail"], gap)
    return None


def sens_adoption_rho(seeds, tasks, adversary: str = HEADLINE_ADVERSARY,
                      avails=ADOPTION_GRID, rhos=ADOPTION_RHO_GRID) -> list[dict]:
    """Returns one entry per rho: {"rho", "rows": [...ascending avail...], "a_star"}."""
    out = []
    for rho in rhos:
        rows = rq3_adoption(seeds, tasks, adversary, avails=list(avails), rho=rho)
        out.append({"rho": rho, "rows": rows, "a_star": break_even_adoption(rows)})
    return out
