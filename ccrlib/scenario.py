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
                          runs an egress image, so its best response is to present NO
                          quote (absent); forging (claiming the audited measurement) is
                          a labeled naive-adversary contrast (see `exfil_attest`).
- attested_yet_abusing  : capable (0.90), validly signed, runs the AUDITED image (earns
                          a genuine VALID quote) yet still causes an incident (semantic
                          misuse of a legitimately-received datum). Measures the cov<1
                          boundary: attestation proves the runtime, not benign use of
                          the data (WI-2; `n_attest_abuser`).
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
    "attested_yet_abusing": 0.90,    # capable AND validly attested; misuse is semantic
                                     # (the cov<1 boundary — attestation != IFC, WI-2)
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
    exfil_attest: str = "absent",  # "absent" (best response, HEADLINE, model-lock A2)
                                   # | "forge" (naive, self-incriminating contrast; WI-1)
    n_attest_abuser: int = 0,      # attested_yet_abusing count per skill (WI-2)
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
            # rank first, but exfiltrates. Runs an egress image -> cannot obtain a
            # genuine quote for the audited measurement. Its best response is ABSENT
            # (+risk_unattested=0.35), NOT forge (+risk_forged=0.60): forging is
            # strictly dominated (0.60 > 0.35), i.e. it is the adversary that
            # "incriminates itself" (AISec #88B). "forge" stays as a labeled naive
            # contrast; "absent" is the headline best-response adversary (WI-1).
            forges = (exfil_attest == "forge")
            agents.append(_agent("competent_exfiltrator", skill, "adventureworks", i,
                                 CEILING,
                                 signed=True, poison=False, scope="narrow",
                                 desc=f"Premium {skill} specialist. {kw}",
                                 attestable=False, forges=forges,
                                 runtime=EXFIL_MEASUREMENT))

        for i in range(n_attest_abuser):
            # Runs the AUDITED image => earns a VALID quote, yet misuses a
            # legitimately-received datum through a channel the audited image
            # legitimately has (e.g. writes to a shared store read out-of-band later).
            # Observably indistinguishable from `correct` once attested — that
            # indistinguishability IS the measured cov<1 boundary (WI-2): attestation
            # proves the runtime, not benign use of the data (semantic, not runtime).
            agents.append(_agent("attested_yet_abusing", skill, "adventureworks", i,
                                 CEILING,
                                 signed=True, poison=False, scope="narrow",
                                 desc=f"Certified premium {skill} specialist. {kw}",
                                 attestable=True, forges=False,
                                 runtime=AUDITED_MEASUREMENT))
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
    mal = sum(1 for s in specs
              if s["persona"] in ("canary_aware", "competent_exfiltrator", "attested_yet_abusing"))
    return round(mal / len(specs), 3) if specs else 0.0
