"""Evaluation: label each decision with ground truth and aggregate into operational
metrics. Ground-truth persona is used ONLY here (the evaluator), never in a policy.
"""
from __future__ import annotations

from statistics import mean
from typing import Any

from .policies import Decision
from .scoring import Params

MALICIOUS = {"canary_aware", "competent_exfiltrator", "attested_yet_abusing"}


def _is_malicious(spec: dict) -> bool:
    return (spec.get("persona") in MALICIOUS) or bool(spec.get("poison"))


def evaluate(dec: Decision, spec_by_id: dict[str, dict], p: Params) -> dict[str, Any]:
    chosen = dec.chosen
    persona = spec_by_id.get(chosen, {}).get("persona") if chosen else None

    # Side-effect incident: ANY real execution that touched a malicious agent — the
    # real A2A call ships the task and data, so the harm/exposure happens at
    # invocation time whether or not the task later "succeeds".
    incident = any(_is_malicious(spec_by_id.get(a, {})) for a in dec.real_attempts)

    # Incident specifically caused by a COMPETENT exfiltrator — the case card+canary
    # cannot catch (it passes the probe and completes the task, yet exfiltrates).
    exfil_incident = any(
        spec_by_id.get(a, {}).get("persona") == "competent_exfiltrator"
        for a in dec.real_attempts
    )

    # Strategic defection: a malicious agent that passed the canary and then failed
    # its real attempt (probe evasion by an incapable canary-aware defector).
    defection = any(_is_malicious(spec_by_id.get(a, {})) for a in dec.canary_pass_real_fail)

    net = (
        p.value * (1.0 if dec.success else 0.0)
        - p.lambda_c * dec.total_cost
        - p.lambda_r * (1.0 if incident else 0.0)
    )
    return {
        "policy": dec.policy,
        "chosen": chosen,
        "chosen_persona": persona,
        "success": dec.success,
        "incident": incident,
        "exfil_incident": exfil_incident,
        "defection": defection,
        "chose_malicious": _is_malicious(spec_by_id.get(chosen, {})) if chosen else False,
        "chosen_attestation": dec.chosen_attestation,
        "total_cost": dec.total_cost,
        "cost_canary": dec.cost_canary,
        "cost_receipt": dec.cost_receipt,
        "cost_exec": dec.cost_exec,
        "latency_ms": dec.latency_ms,
        "n_canaries": len(dec.canaried),
        "n_receipts": len(dec.attested),
        "net_utility": net,
    }


def aggregate(records: list[dict], keys: tuple[str, ...] = ("condition", "policy")) -> list[dict]:
    groups: dict[tuple, list[dict]] = {}
    for r in records:
        groups.setdefault(tuple(r[k] for k in keys), []).append(r)

    rows = []
    for key, recs in sorted(groups.items()):
        row = {k: v for k, v in zip(keys, key)}
        row.update(
            n=len(recs),
            success_rate=round(mean(r["success"] for r in recs), 4),
            incident_rate=round(mean(r["incident"] for r in recs), 4),
            exfil_incident_rate=round(mean(r["exfil_incident"] for r in recs), 4),
            # WI-2: incidents attributable to an agent CCR-R itself scored as validly
            # attested — the operational measurement of the cov<1 boundary (a valid
            # quote lowers risk but does not, by itself, prove benign intent).
            attested_incident_rate=round(
                mean((r["incident"] and r["chosen_attestation"] == "valid") for r in recs), 4),
            defection_rate=round(mean(r["defection"] for r in recs), 4),
            mean_net_utility=round(mean(r["net_utility"] for r in recs), 4),
            mean_total_cost=round(mean(r["total_cost"] for r in recs), 4),
            mean_canaries=round(mean(r["n_canaries"] for r in recs), 3),
            mean_receipts=round(mean(r["n_receipts"] for r in recs), 3),
        )
        rows.append(row)
    return rows
