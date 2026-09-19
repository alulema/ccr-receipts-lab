"""ccrlib (receipts) — Card + Canary + Receipt Routing experimental core.

Prototype for the D1 follow-up to CCR ("When Is It Worth Attesting?", AAMAS 2027).
It EXTENDS the original CCR model (card + canary evidence on the success axis) with
a third evidence tier on the RISK axis: cryptographic **execution receipts /
remote attestation**. The research question is symmetric to the original one:

    original:  when is it worth VERIFYING (paying for a canary)?
    this repo: when is it worth ATTESTING (paying for a receipt)?

Design invariant (inherited, do not break): routing policies in `policies.py`
interact with agents ONLY through a `transport(agent_id, request) -> observable`
callable. They never read an agent's hidden capability, persona, or intent. The
attestation quote an agent returns is *observable*; whether the agent is actually
benign is ground truth known ONLY to the post-hoc evaluator (metrics.py).

Everything is deterministic: outcomes are a pure function of (run_seed, task,
agent), so results are reproducible and a future Azure Confidential Computing
deployment can be a distributed validation of the same numbers.
"""

__version__ = "0.1.0"
