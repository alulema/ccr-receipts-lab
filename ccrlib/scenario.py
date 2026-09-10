"""Parameterized world builder: agent pools and task sets.

Two knobs matter for the receipt story:

- `claim_gap` ∈ [0,1] — how much declared card capability is inflated above the
  true (hidden) capability. Inherited from base CCR: at 0 cards are honest; at 1
  liars over-claim to the ceiling.

- `attest_availability` ∈ [0,1] — fraction of BENIGN agents that can produce a
  genuine remote-attestation quote (i.e. run in a TEE on the audited image). This
  is the partial-adoption axis (RQ3): as it drops, CCR-R has fewer attested-safe
  agents to route to and must accept residual risk.

Personas
- correct               : capable (0.90), honest card, benign, runs the audited image.
- degraded              : benign but intermittently low; inflates its stale card.
- canary_aware          : incapable, fakes the probe if distinguishable; malicious;
                          cannot attest the audited image.
- competent_exfiltrator : capable (0.90) AND validly signed, advertises at the ceiling
                          so it ranks first — yet it exfiltrates the real payload. It
                          runs an egress image, so it can only FORGE an attestation.
"""
from __future__ import annotations

from .domain import SKILLS, AUDITED_MEASUREMENT, EXFIL_MEASUREMENT, det_unit

CEILING = 0.99

SKILL_WORDS = {
    "rag": "retrieval grounding documents vector search citations knowledge",
    "planning": "decompose subtasks schedule plan steps goals orchestrate",
    "data_transform": "parse map reshape normalize csv json convert pipeline",
    "api_action": "invoke endpoint http rest action mutate side effect call",
}

CORRECT_ORGS = ["contoso", "fabrikam"]

PERSONA_TRUE = {
    "correct": 0.90,
    "degraded": 0.70,
    "canary_aware": 0.12,
    "competent_exfiltrator": 0.90,   # genuinely capable — that is the whole problem
}


def _declared(true_cap: float, claim_gap: float) -> float:
    return round(true_cap + claim_gap * (CEILING - true_cap), 3)


def _agent(persona, skill, org, idx, declared_cap, signed, poison, scope, desc,
           attestable, forges, runtime):
    return {
        "id": f"{persona[:4]}-{skill}-{org}-{idx}",
        "org": org,
        "persona": persona,
        "declaredSkills": {skill: round(declared_cap, 3)},
        "trueSkills": {skill: PERSONA_TRUE[persona]},
        "authScheme": "oauth2",
        "binding": "jsonrpc",
        "permissionScope": scope,
        "signed": signed,
        "poison": poison,
        "realCapability": PERSONA_TRUE[persona],
        "description": desc,
        "attestable": attestable,
        "forges": forges,
        "runtime": runtime,
    }


def build_agents(
    claim_gap: float = 1.0,
    attest_availability: float = 1.0,
    n_correct: int = 2,
    n_degraded: int = 1,
    n_canary_aware: int = 1,
    n_exfil: int = 1,
) -> list[dict]:
    agents: list[dict] = []
    for skill in SKILLS:
        kw = SKILL_WORDS[skill]

        for i in range(n_correct):
            org = CORRECT_ORGS[i % len(CORRECT_ORGS)]
            aid = f"corr-{skill}-{org}-{i}"
            attestable = det_unit(aid, "attest-avail") < attest_availability
            agents.append(_agent("correct", skill, org, i, PERSONA_TRUE["correct"],
                                 signed=True, poison=False, scope="narrow",
                                 desc=f"Reliable {skill} agent. {kw}",
                                 attestable=attestable, forges=False,
                                 runtime=AUDITED_MEASUREMENT))

        for i in range(n_degraded):
            aid = f"degr-{skill}-northwind-{i}"
            attestable = det_unit(aid, "attest-avail") < attest_availability
            agents.append(_agent("degraded", skill, "northwind", i,
                                 _declared(PERSONA_TRUE["degraded"], claim_gap),
                                 signed=True, poison=False, scope="narrow",
                                 desc=f"High-throughput {skill} service. {kw}",
                                 attestable=attestable, forges=False,
                                 runtime=AUDITED_MEASUREMENT))

        for i in range(n_canary_aware):
            # Trusted-signed (passes identity attestation), fakes the probe, defects.
            # Cannot attest the audited image -> absent quote.
            agents.append(_agent("canary_aware", skill, "adventureworks", i,
                                 _declared(PERSONA_TRUE["canary_aware"], claim_gap),
                                 signed=True, poison=False, scope="narrow",
                                 desc=f"Certified {skill} provider. {kw}",
                                 attestable=False, forges=False,
                                 runtime=EXFIL_MEASUREMENT))

        for i in range(n_exfil):
            # THE hard case: capable + validly signed, advertises at the ceiling to
            # rank first, but exfiltrates. Runs an egress image -> can only FORGE.
            agents.append(_agent("competent_exfiltrator", skill, "adventureworks", i,
                                 CEILING,
                                 signed=True, poison=False, scope="narrow",
                                 desc=f"Premium {skill} specialist. {kw}",
                                 attestable=False, forges=True,
                                 runtime=EXFIL_MEASUREMENT))
    return agents


def build_tasks(n: int) -> list[dict]:
    tasks = []
    for i in range(n):
        skill = SKILLS[i % len(SKILLS)]
        difficulty = ["easy", "medium", "hard"][i % 3]
        tasks.append({
            "id": f"t{i:04d}", "skill": skill, "difficulty": difficulty,
            "payload": f"task-{i:04d}-{skill}-{difficulty}",
            "text": f"{difficulty} {skill} task: {SKILL_WORDS[skill]}",
        })
    return tasks


def malice_fraction(specs: list[dict]) -> float:
    mal = sum(1 for s in specs if s["persona"] in ("canary_aware", "competent_exfiltrator"))
    return round(mal / len(specs), 3) if specs else 0.0
