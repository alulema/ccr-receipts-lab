"""Router-side scoring. Operates ONLY on observable data (cards, canary metrics,
attestation quotes). Implements the decision-theoretic pieces:

  success axis (from base CCR):
    card_score    — declarative evidence, [0,1], modulated by signature validity
    canary_score  — empirical capability evidence, [0,1]
    value_of_information — the gate deciding WHETHER to spend a canary

  risk axis (NEW — the receipt tier):
    verify_attestation        — 'valid' | 'absent' | 'invalid' (forged/replayed)
    receipt_value_of_information — the gate deciding WHETHER to spend an attestation
    attested_risk             — folds the attestation result into incident risk

  utility:
    U = V * p_hat - lambda_r * risk_eff - lambda_c * cost
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import domain

# Identity trust anchor: issuer keys the router accepts ('rogue-llc' absent).
TRUSTED_ISSUERS = {org: s for org, s in domain.ISSUER_SECRETS.items() if org != "rogue-llc"}

# Attestation trust anchor: authorities the verifier accepts, and the one audited
# measurement it will treat as benign.
TRUSTED_ATTESTATION_AUTHORITIES = {"cc-attest-root"}
AUDITED_MEASUREMENT = domain.AUDITED_MEASUREMENT

_POISON_PATTERNS = [
    r"ignore (all|previous) instructions",
    r"\bsystem\s*:",
    r"grant (full|all) (scope|permissions?)",
    r"exfiltrat",
]


@dataclass
class Params:
    # --- success axis (base CCR) ---
    alpha: float = 0.45
    lambda_c: float = 1.0
    voi_threshold: float = 0.0
    voi_prior_doubt: float = 0.3      # d0: capability-doubt floor for the canary gate
    k_candidates: int = 4
    value: float = 3.0                # V
    canary_cost: float = 0.2          # kappa
    exec_cost: float = 1.0
    sig_factor_valid: float = 1.0
    sig_factor_absent: float = 0.6
    sig_factor_invalid: float = 0.2
    budget: float = 5.0               # B: enough to afford canary + receipts + a
                                      # bounded fallback (so probing does not starve
                                      # execution and tank the success rate)
    # --- risk axis (receipt tier, NEW) ---
    lambda_r: float = 2.0             # price of an incident
    receipt_cost: float = 0.5         # rho: cost/overhead of one attestation (> kappa)
    receipt_voi_threshold: float = 0.0  # tau_A
    malice_doubt: float = 0.3         # d_H: prior floor that a clean-looking agent may be
                                      # malicious. A passing canary + clean card is NOT
                                      # evidence of benign INTENT (the D1 thesis).
    attest_coverage: float = 0.9      # cov ∈ [0,1): fraction of incident risk a VALID
                                      # attestation removes. <1 on purpose: attestation
                                      # proves the runtime, not that a legitimately
                                      # received datum won't be misused (attestation != IFC).
                                      # MODEL-LOCK A1 (see HANDOFF §2): a single scalar
                                      # blends the "runtime" class (cov~0.9, structurally
                                      # removed by a valid quote) and the "semantic" class
                                      # (cov~0.0, NOT removable by runtime attestation --
                                      # that is D2/IFC). Kept as one scalar deliberately:
                                      # attested_risk() cannot condition on the incident's
                                      # true class without reading ground truth (would
                                      # violate the observability invariant, §1). WI-2's
                                      # `attested_yet_abusing` persona measures the
                                      # semantic residual OPERATIONALLY instead (it is
                                      # observably identical to `correct` once attested,
                                      # so its incident rate under a valid quote IS the
                                      # cov<1 boundary) -- no separate `cov_by_class` /
                                      # `semantic_floor` parameter is threaded through the
                                      # formula. Exact numeric split and paper-facing
                                      # justification: pending paper-side sign-off (§6).
    risk_unattested: float = 0.35     # risk added when attestation requested but ABSENT
                                      # TODO (A3, optional, not implemented yet): could be made
                                      # context-sensitive -- declining attestation is more
                                      # suspicious when the pool HAS attestable agents
                                      # (adoption high) than when TEEs are broadly
                                      # unavailable (adoption low). Left as a single
                                      # constant until WI-1 data justifies the refinement.
    risk_forged: float = 0.60         # risk added when a forged/invalid quote is detected
    extra: dict = field(default_factory=dict)


# --- identity signature (card) -------------------------------------------------

def verify_signature(card: dict) -> str:
    sig = card.get("signature") or {"present": False}
    if not sig.get("present"):
        return "absent"
    issuer = sig.get("issuer")
    if issuer not in TRUSTED_ISSUERS:
        return "invalid"
    core = {"agentId": card["agentId"], "org": card["org"], "skills": card["skills"],
            "authScheme": card["authScheme"], "binding": card["binding"]}
    expected = domain.sign_card(domain.canonical_card(core), issuer)
    return "valid" if sig.get("value") == expected else "invalid"


def detect_poison(text: str) -> bool:
    t = (text or "").lower()
    return any(re.search(p, t) for p in _POISON_PATTERNS)


def sig_factor(status: str, p: Params) -> float:
    return {"valid": p.sig_factor_valid, "absent": p.sig_factor_absent,
            "invalid": p.sig_factor_invalid}[status]


def card_score(card: dict, task: dict, p: Params) -> float:
    skill = task["skill"]
    claimed = next((s["capabilityClaimed"] for s in card["skills"] if s["id"] == skill), 0.0)
    return max(0.0, min(1.0, claimed * sig_factor(verify_signature(card), p)))


def hard_compatible(card: dict, task: dict) -> bool:
    declares = any(s["id"] == task["skill"] for s in card["skills"])
    return declares and card.get("binding") == "jsonrpc" and \
        card.get("authScheme") in {"oauth2", "mtls", "apikey"}


# --- capability canary ---------------------------------------------------------

def canary_score(metrics: dict, expected_answer: str) -> float:
    success = 1.0 if metrics.get("output") == expected_answer else 0.0
    schema = 1.0 if metrics.get("schemaOk") else 0.0
    status_ok = 1.0 if metrics.get("httpStatus", 500) < 400 else 0.0
    lat = metrics.get("latencyMs", 800)
    lat_factor = max(0.0, 1.0 - lat / 800.0)
    return max(0.0, min(1.0, 0.6 * success + 0.2 * schema + 0.1 * status_ok + 0.1 * lat_factor))


# --- attestation receipt (NEW) -------------------------------------------------

def verify_attestation(resp: dict, expected_nonce: str) -> str:
    """Verify a remote-attestation quote. 'valid' requires: present, a trusted
    authority, the freshness nonce (anti-replay), the audited measurement, and a
    signature that checks out under that authority. Otherwise 'absent'/'invalid'."""
    quote = (resp or {}).get("quote") or {"present": False}
    if not quote.get("present"):
        return "absent"
    if quote.get("authority") not in TRUSTED_ATTESTATION_AUTHORITIES:
        return "invalid"          # e.g. self-signed forgery
    if quote.get("nonce") != expected_nonce:
        return "invalid"          # stale/replayed quote
    if quote.get("measurement") != AUDITED_MEASUREMENT:
        return "invalid"          # untrusted (non-audited) runtime image
    expected = domain.sign_quote(quote["measurement"], quote["nonce"], quote["authority"])
    return "valid" if quote.get("value") == expected else "invalid"


def receipt_value_of_information(observable_risk: float, p: Params) -> float:
    """Expected risk-utility gain from requesting an attestation, minus its cost.
    Symmetric to the canary VoI, but on the RISK axis. Driven by the TASK's stakes,
    not by how clean the agent looks: we keep a prior malice-doubt floor d_H because
    a passing canary and a clean card are NOT evidence of benign intent."""
    doubt = max(p.malice_doubt, observable_risk)
    return p.lambda_r * p.attest_coverage * doubt - p.lambda_c * p.receipt_cost


def base_risk_score(card: dict, canary_metrics: dict | None, p: Params) -> float:
    """Observable risk BEFORE attestation, in [0,1]. Note a competent exfiltrator
    looks clean here (valid sig, no poison, narrow scope, passes the canary): that
    is exactly why the success-axis evidence cannot separate it."""
    r = 0.0
    if verify_signature(card) == "invalid":
        r += 0.40
    if detect_poison(card.get("description", "")):
        r += 0.35
    if card.get("permissionScope") == "broad":
        r += 0.15
    if canary_metrics is not None:
        claimed = max((s["capabilityClaimed"] for s in card["skills"]), default=0.0)
        if claimed > 0.7 and canary_metrics.get("_canary_score", 1.0) < 0.5:
            r += 0.30
    return min(1.0, r)


def attested_risk(base_risk: float, att_status: str | None, p: Params) -> float:
    """Fold the attestation result into incident risk.

      valid   -> risk * (1 - cov)         (structurally lowered; cov<1: not IFC)
      absent  -> risk + risk_unattested   (runtime unverifiable)
      invalid -> risk + risk_forged       (a DETECTED forgery/replay is a strong
                                           positive signal of malice)
      None    -> risk                     (attestation not requested)
    """
    if att_status is None:
        return base_risk
    if att_status == "valid":
        return max(0.0, base_risk * (1.0 - p.attest_coverage))
    if att_status == "absent":
        return min(1.0, base_risk + p.risk_unattested)
    return min(1.0, base_risk + p.risk_forged)  # invalid / forged / replayed


# --- gates & utility -----------------------------------------------------------

def value_of_information(card_sc: float, base_risk: float, p: Params) -> float:
    """Canary gate (success axis), unchanged from base CCR."""
    uncertainty = max(p.voi_prior_doubt, 4.0 * card_sc * (1.0 - card_sc), base_risk)
    return p.value * uncertainty - p.lambda_c * p.canary_cost


def expected_utility(p_hat: float, risk_eff: float, cost: float, p: Params) -> float:
    return p.value * p_hat - p.lambda_r * risk_eff - p.lambda_c * cost
