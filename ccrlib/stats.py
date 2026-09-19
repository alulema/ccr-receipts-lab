"""Task-clustered bootstrap confidence intervals (WI-3). Stdlib only.

Resamples TASK CLUSTERS (not individual seed-runs) with replacement, so that
within-task correlation across seeds is respected, then recomputes a metric on
each resample. Reports the 2.5/97.5 percentiles as a 95% CI.

Deterministic by construction (guardrail #2): resampling uses `domain.det_unit`
instead of the `random` module, so the same records always produce the same CI,
byte-for-byte, on any machine.
"""
from __future__ import annotations

from statistics import mean
from typing import Callable

from . import domain

Metric = Callable[[list[dict]], float]


def _resample_clusters(clusters: list[str], resample_idx: int) -> list[str]:
    """Deterministic stand-in for `random.choices(clusters, k=len(clusters))`."""
    n = len(clusters)
    return [clusters[int(domain.det_unit("bootstrap", resample_idx, j) * n) % n]
            for j in range(n)]


def bootstrap_ci(
    records: list[dict],
    metric: Metric,
    cluster_key: str = "task",
    n_resamples: int = 2000,
    alpha: float = 0.05,
) -> tuple[float, float, float]:
    """Return (point_estimate, lo, hi) for `metric(records)`, clustering by
    `cluster_key` (default: task id) and resampling clusters with replacement."""
    by_cluster: dict[str, list[dict]] = {}
    for r in records:
        by_cluster.setdefault(r[cluster_key], []).append(r)
    clusters = sorted(by_cluster)
    point = metric(records)
    if not clusters:
        return point, point, point

    samples = []
    for i in range(n_resamples):
        chosen = _resample_clusters(clusters, i)
        sample = [rec for c in chosen for rec in by_cluster[c]]
        samples.append(metric(sample))
    samples.sort()
    lo_idx = int((alpha / 2) * n_resamples)
    hi_idx = min(n_resamples - 1, int((1 - alpha / 2) * n_resamples))
    return point, samples[lo_idx], samples[hi_idx]


def rate(field: str, policy: str | None = None) -> Metric:
    """Metric factory: mean of a boolean/0-1 field, optionally filtered to one policy."""
    def _m(records: list[dict]) -> float:
        recs = [r for r in records if policy is None or r["policy"] == policy]
        return mean(r[field] for r in recs) if recs else 0.0
    return _m


def paired_diff(field: str, policy_a: str, policy_b: str) -> Metric:
    """Metric factory: mean(policy_a[field] - policy_b[field]), paired by (task, seed).
    Records for both policies must be present in the input (do not pre-filter by
    policy before passing to `bootstrap_ci` when using this metric)."""
    def _m(records: list[dict]) -> float:
        a = {(r["task"], r["seed"]): r[field] for r in records if r["policy"] == policy_a}
        b = {(r["task"], r["seed"]): r[field] for r in records if r["policy"] == policy_b}
        keys = sorted(set(a) & set(b))
        return mean(a[k] - b[k] for k in keys) if keys else 0.0
    return _m
