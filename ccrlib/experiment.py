"""Experiment driver: runs the policy suite across a grid of conditions and returns
raw per-run records plus aggregated rows.

`inprocess_env(specs)` builds the in-process transport (SimAgent calls). The SAME
policies could later run over HTTP against real A2A agents (and an Azure Confidential
Computing attestation endpoint) with an equivalent transport — determinism makes the
two produce identical numbers, so the cloud run is a distributed validation.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Callable

from . import agents as agents_mod
from . import metrics
from .policies import POLICIES, Context, Decision
from .scoring import Params


def inprocess_env(specs: list[dict]) -> tuple[dict, Callable]:
    agents = agents_mod.load_agents(specs)
    cards = {aid: ag.card() for aid, ag in agents.items()}

    def transport(agent_id: str, req: dict) -> dict:
        return agents[agent_id].handle(req)

    return cards, transport


def run(
    tasks: list[dict],
    conditions: list[dict],
    seeds: list[int],
    policies: list[str] | None = None,
) -> tuple[list[dict], list[dict]]:
    policies = policies or list(POLICIES.keys())
    raw: list[dict] = []

    for cond in conditions:
        specs: list[dict] = cond["specs"]
        params: Params = cond["params"]
        indistinguishable: bool = cond.get("indistinguishable", True)
        cards, transport = inprocess_env(specs)
        spec_by_id = {s["id"]: s for s in specs}

        for task in tasks:
            for seed in seeds:
                ctx = Context(task, cards, transport, params, seed, indistinguishable)
                for pol in policies:
                    dec: Decision = POLICIES[pol](ctx)
                    rec = metrics.evaluate(dec, spec_by_id, params)
                    rec.update(condition=cond["name"], task=task["id"], skill=task["skill"],
                               seed=seed, value=params.value, receipt_cost=params.receipt_cost,
                               lambda_r=params.lambda_r, indistinguishable=indistinguishable)
                    raw.append(rec)

    rows = metrics.aggregate(raw, keys=("condition", "policy"))
    return rows, raw


def with_params(base: Params, **overrides) -> Params:
    return replace(base, **overrides)
