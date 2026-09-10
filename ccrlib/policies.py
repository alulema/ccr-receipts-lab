"""Routing policies: the proposed CCR-R (Card+Canary+Receipt) and baselines.

A policy receives a `Context` and returns a `Decision`, interacting with agents
ONLY through `ctx.transport` and verifying success by comparing returned outputs
to the known true answer. It cannot read hidden capability, intent, or the true
runtime — only the observable card, canary metrics, and attestation quote.

Baselines
---------
- random              : control.
- card_only           : argmax declarative card score.
- signature_only      : among IDENTITY-signature-valid agents, argmax card score.
                        Models "attested routing" in the identity sense (Provenance
                        Paradox): it verifies WHO, not runtime integrity — so a
                        validly-signed competent exfiltrator is happily chosen.
- optimistic_fallback : run the real task on the best card; on failure fall to the
                        next, within budget. No probing. The "why probe at all?" foil.
- ccr                 : Card+Canary Routing (base paper). Catches incapable/degraded
                        and canary-aware defectors, but NOT a competent exfiltrator
                        (it passes the probe).
- receipt_only        : among RUNTIME-attestation-valid agents, argmax card score.
                        Safe but capability-blind (may pick an attested-but-degraded
                        agent) — shows attestation alone is not enough.
- ccr_r               : PROPOSED. CCR plus a receipt tier: a value-of-information gate
                        decides when to pay for remote attestation, and the result is
                        folded into incident risk. Catches the competent exfiltrator.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from . import domain, scoring
from .scoring import Params

Transport = Callable[[str, dict], dict]


@dataclass
class Context:
    task: dict
    cards: dict[str, dict]
    transport: Transport
    params: Params
    run_seed: int
    indistinguishable: bool = True

    @property
    def expected(self) -> str:
        return domain.true_answer(self.task["payload"])

    @property
    def canary_payload(self) -> str:
        return f"canary::{self.task['skill']}::{self.task['id']}"

    @property
    def canary_expected(self) -> str:
        return domain.true_answer(self.canary_payload)

    def nonce(self, agent_id: str) -> str:
        """Fresh verifier nonce for an attestation request (anti-replay)."""
        return f"n{domain._h(self.run_seed, self.task['id'], agent_id, 'nonce') % (10**12):012d}"


@dataclass
class Decision:
    policy: str
    chosen: str | None
    canaried: list[str] = field(default_factory=list)
    attested: list[str] = field(default_factory=list)
    attestation_status: dict = field(default_factory=dict)   # agent -> status
    real_attempts: list[str] = field(default_factory=list)
    success: bool = False
    cost_canary: float = 0.0
    cost_receipt: float = 0.0
    cost_exec: float = 0.0
    latency_ms: int = 0
    chosen_passed_canary: bool | None = None
    chosen_attestation: str | None = None
    canary_pass_real_fail: list[str] = field(default_factory=list)

    @property
    def total_cost(self) -> float:
        return self.cost_canary + self.cost_receipt + self.cost_exec


# --- low-level calls -----------------------------------------------------------

def _real_call(ctx: Context, agent_id: str, attempt: int) -> tuple[bool, int]:
    resp = ctx.transport(agent_id, {
        "kind": "task", "taskId": ctx.task["id"], "skill": ctx.task["skill"],
        "payload": ctx.task["payload"], "runSeed": ctx.run_seed, "attempt": attempt,
        "canaryIndistinguishable": ctx.indistinguishable,
    })
    return resp["output"] == ctx.expected, resp["latencyMs"]


def _canary_call(ctx: Context, agent_id: str) -> tuple[float, int]:
    resp = ctx.transport(agent_id, {
        "kind": "canary", "taskId": ctx.task["id"], "skill": ctx.task["skill"],
        "payload": ctx.canary_payload, "runSeed": ctx.run_seed, "attempt": 0,
        "canaryIndistinguishable": ctx.indistinguishable,
    })
    return scoring.canary_score(resp, ctx.canary_expected), resp["latencyMs"]


def _attest_call(ctx: Context, agent_id: str) -> tuple[str, int]:
    nonce = ctx.nonce(agent_id)
    resp = ctx.transport(agent_id, {
        "kind": "attest", "taskId": ctx.task["id"], "agentId": agent_id,
        "nonce": nonce, "runSeed": ctx.run_seed,
    })
    return scoring.verify_attestation(resp, nonce), resp.get("latencyMs", 0)


def _candidates(ctx: Context) -> list[str]:
    return [aid for aid, c in ctx.cards.items() if scoring.hard_compatible(c, ctx.task)]


def _tie(ctx: Context, a: str) -> float:
    """Seeded uniform tie-break: two validly-signed agents can declare identical
    capability and pass identical probes; resolving that tie by insertion order
    would be an artifact, so we average over it across seeds."""
    return domain.det_unit(ctx.run_seed, ctx.task["id"], a, "tiebreak")


def _single_real(ctx: Context, policy: str, chosen: str | None) -> Decision:
    d = Decision(policy=policy, chosen=chosen)
    if chosen is None:
        return d
    ok, lat = _real_call(ctx, chosen, 0)
    d.real_attempts.append(chosen)
    d.success, d.cost_exec, d.latency_ms = ok, ctx.params.exec_cost, lat
    return d


# --- baselines -----------------------------------------------------------------

def random_policy(ctx: Context) -> Decision:
    cands = sorted(_candidates(ctx))
    if not cands:
        return Decision(policy="random", chosen=None)
    idx = int(domain.det_unit(ctx.run_seed, ctx.task["id"], "random") * len(cands)) % len(cands)
    return _single_real(ctx, "random", cands[idx])


def card_only(ctx: Context) -> Decision:
    cands = _candidates(ctx)
    if not cands:
        return Decision(policy="card_only", chosen=None)
    chosen = max(cands, key=lambda a: (scoring.card_score(ctx.cards[a], ctx.task, ctx.params), _tie(ctx, a)))
    return _single_real(ctx, "card_only", chosen)


def signature_only(ctx: Context) -> Decision:
    cands = [a for a in _candidates(ctx) if scoring.verify_signature(ctx.cards[a]) == "valid"]
    if not cands:
        return Decision(policy="signature_only", chosen=None)
    chosen = max(cands, key=lambda a: (scoring.card_score(ctx.cards[a], ctx.task, ctx.params), _tie(ctx, a)))
    return _single_real(ctx, "signature_only", chosen)


def optimistic_fallback(ctx: Context) -> Decision:
    p = ctx.params
    d = Decision(policy="optimistic_fallback", chosen=None)
    cands = _candidates(ctx)
    if not cands:
        return d
    order = sorted(cands, key=lambda a: (scoring.card_score(ctx.cards[a], ctx.task, p), _tie(ctx, a)), reverse=True)
    budget, attempt = p.budget, 0
    for a in order:
        if budget < p.exec_cost:
            break
        ok, lat = _real_call(ctx, a, attempt)
        d.real_attempts.append(a); d.cost_exec += p.exec_cost; d.latency_ms += lat
        budget -= p.exec_cost; d.chosen = a; attempt += 1
        if ok:
            d.success = True
            break
    return d


def receipt_only(ctx: Context) -> Decision:
    """Route only to agents with a VALID runtime attestation (capability-blind)."""
    p = ctx.params
    d = Decision(policy="receipt_only", chosen=None)
    cands = _candidates(ctx)
    if not cands:
        return d
    valid = []
    for a in cands:
        if d.cost_receipt + p.receipt_cost > p.budget - p.exec_cost:
            break
        st, lat = _attest_call(ctx, a)
        d.attested.append(a); d.attestation_status[a] = st
        d.cost_receipt += p.receipt_cost; d.latency_ms += lat
        if st == "valid":
            valid.append(a)
    pool = valid or cands
    chosen = max(pool, key=lambda a: (scoring.card_score(ctx.cards[a], ctx.task, p), _tie(ctx, a)))
    ok, lat = _real_call(ctx, chosen, 0)
    d.real_attempts.append(chosen); d.chosen = chosen
    d.success = ok; d.cost_exec += p.exec_cost; d.latency_ms += lat
    d.chosen_attestation = d.attestation_status.get(chosen)
    return d


# --- proposed: CCR (card + canary) and CCR-R (+ receipt) -----------------------

def _canary_tier(ctx: Context, topk: list[str], budget: float, d: Decision):
    p = ctx.params
    canary_cs: dict[str, float] = {}
    for a in sorted(topk, key=lambda x: scoring.base_risk_score(ctx.cards[x], None, p), reverse=True):
        cs0 = scoring.card_score(ctx.cards[a], ctx.task, p)
        voi = scoring.value_of_information(cs0, scoring.base_risk_score(ctx.cards[a], None, p), p)
        if voi > p.voi_threshold and budget >= p.canary_cost:
            cs, lat = _canary_call(ctx, a)
            canary_cs[a] = cs; d.canaried.append(a)
            d.cost_canary += p.canary_cost; d.latency_ms += lat; budget -= p.canary_cost
    return canary_cs, budget


def _receipt_tier(ctx: Context, topk: list[str], budget: float, canary_cs: dict, d: Decision):
    """VoI-gated attestation. The gate is TASK-driven (V, lambda_r, rho, d_H): when a
    task is valuable/sensitive we attest even agents that look clean, because a clean
    look is not evidence of benign intent."""
    p = ctx.params
    att: dict[str, str] = {}
    order = sorted(topk, key=lambda a: (scoring.base_risk_score(ctx.cards[a],
                   {"_canary_score": canary_cs[a]} if a in canary_cs else None, p)), reverse=True)
    for a in order:
        obs_risk = scoring.base_risk_score(ctx.cards[a],
                    {"_canary_score": canary_cs[a]} if a in canary_cs else None, p)
        rvoi = scoring.receipt_value_of_information(obs_risk, p)
        # Reserve enough budget for at least one real execution before attesting.
        if rvoi > p.receipt_voi_threshold and budget - p.receipt_cost >= p.exec_cost:
            st, lat = _attest_call(ctx, a)
            att[a] = st; d.attested.append(a); d.attestation_status[a] = st
            d.cost_receipt += p.receipt_cost; d.latency_ms += lat; budget -= p.receipt_cost
    return att, budget


def _ccr_core(ctx: Context, policy: str, use_receipt: bool) -> Decision:
    p = ctx.params
    d = Decision(policy=policy, chosen=None)
    cands = _candidates(ctx)
    if not cands:
        return d

    scored = sorted(cands, key=lambda a: (scoring.card_score(ctx.cards[a], ctx.task, p), _tie(ctx, a)), reverse=True)
    topk = scored[: p.k_candidates]

    budget = p.budget
    canary_cs, budget = _canary_tier(ctx, topk, budget, d)
    att: dict[str, str] = {}
    if use_receipt:
        att, budget = _receipt_tier(ctx, topk, budget, canary_cs, d)

    def utility(a: str) -> float:
        card_sc = scoring.card_score(ctx.cards[a], ctx.task, p)
        if a in canary_cs:
            p_hat = p.alpha * card_sc + (1 - p.alpha) * canary_cs[a]
            metrics = {"_canary_score": canary_cs[a]}
        else:
            p_hat, metrics = card_sc, None
        base_risk = scoring.base_risk_score(ctx.cards[a], metrics, p)
        risk_eff = scoring.attested_risk(base_risk, att.get(a), p) if use_receipt else base_risk
        return scoring.expected_utility(p_hat, risk_eff, p.exec_cost, p)

    plan = sorted(topk, key=lambda a: (utility(a), _tie(ctx, a)), reverse=True)

    attempt = 0
    for a in plan:
        if budget < p.exec_cost:
            break
        ok, lat = _real_call(ctx, a, attempt)
        d.real_attempts.append(a); d.cost_exec += p.exec_cost; d.latency_ms += lat
        budget -= p.exec_cost; d.chosen = a
        d.chosen_passed_canary = (canary_cs.get(a, 1.0) >= 0.5) if a in canary_cs else None
        d.chosen_attestation = att.get(a)
        if not ok and canary_cs.get(a, 0.0) >= 0.5:
            d.canary_pass_real_fail.append(a)
        attempt += 1
        if ok:
            d.success = True
            break
    return d


def ccr(ctx: Context) -> Decision:
    return _ccr_core(ctx, "ccr", use_receipt=False)


def ccr_r(ctx: Context) -> Decision:
    return _ccr_core(ctx, "ccr_r", use_receipt=True)


POLICIES: dict[str, Callable[[Context], Decision]] = {
    "random": random_policy,
    "card_only": card_only,
    "signature_only": signature_only,
    "optimistic_fallback": optimistic_fallback,
    "receipt_only": receipt_only,
    "ccr": ccr,
    "ccr_r": ccr_r,
}
