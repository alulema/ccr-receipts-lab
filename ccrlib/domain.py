"""Shared, non-secret domain primitives computable by BOTH the agent host and the
router: deterministic RNG, verifiable synthetic tasks, the AgentCard signature
(identity attestation), and the NEW **remote-attestation / execution-receipt**
crypto that this prototype adds.

The hidden part of an agent (its true capability AND whether it exfiltrates) lives
in agents.py and is never exposed on the observable surface.
"""
from __future__ import annotations

import hashlib
from typing import Any

# Skill taxonomy (same as the base CCR lab, for comparable numbers).
SKILLS = ["rag", "planning", "data_transform", "api_action"]


# --- Deterministic RNG ---------------------------------------------------------

def _h(*parts: object) -> int:
    """Stable 256-bit hash of the parts, as an int."""
    raw = "|".join(str(p) for p in parts).encode("utf-8")
    return int.from_bytes(hashlib.sha256(raw).digest(), "big")


def det_unit(*parts: object) -> float:
    """Deterministic pseudo-random float in [0, 1) — replaces random.random() so
    runs are identical across machines, processes, and the local/cloud boundary."""
    return (_h(*parts) % 10_000_000) / 10_000_000.0


# --- Verifiable synthetic tasks ------------------------------------------------
# The correct answer is a deterministic function of the payload that a *capable*
# agent can compute and an *incapable* one cannot. The router verifies outputs
# against it — it never trusts a self-reported success flag.

def true_answer(payload: str) -> str:
    return hashlib.sha256(("ANS::" + payload).encode("utf-8")).hexdigest()[:16]


def agent_output(payload: str, correct: bool) -> str:
    if correct:
        return true_answer(payload)
    return hashlib.sha256(("WRONG::" + payload).encode("utf-8")).hexdigest()[:16]


# --- AgentCard signature (identity attestation, from base CCR) -----------------
# Proves WHO an agent is / that the card was not tampered with. It does NOT prove
# current capability (that is the canary) nor runtime integrity (that is the
# receipt below). 'rogue-llc' is deliberately absent from the router allow-list.

ISSUER_SECRETS = {
    "contoso": "k_contoso_9f12",
    "fabrikam": "k_fabrikam_77aa",
    "northwind": "k_northwind_31cd",
    "adventureworks": "k_adv_5bb0",
    "rogue-llc": "k_rogue_unknown",
}


def sign_card(canonical: str, issuer: str) -> str:
    secret = ISSUER_SECRETS.get(issuer, "k_unknown")
    return hashlib.sha256((canonical + "::" + secret).encode("utf-8")).hexdigest()[:24]


def canonical_card(card: dict) -> str:
    skills = ",".join(f"{s['id']}:{s['capabilityClaimed']:.3f}" for s in card["skills"])
    return f"{card['agentId']}|{card['org']}|{skills}|{card['authScheme']}|{card['binding']}"


# --- Remote attestation / execution receipt (NEW in this prototype) ------------
# A receipt is verifiable evidence about the agent's RUNTIME, not its identity or
# capability. We model TEE remote attestation faithfully:
#
#   * An attestation service (a "root of trust") signs a quote for the code
#     MEASUREMENT it actually observes running inside the enclave, bound to a
#     fresh NONCE supplied by the verifier (anti-replay).
#   * The router trusts only certain authorities (its verifier anchor) and only
#     ONE audited measurement: the benign, egress-restricted agent image.
#
# Consequences that make the receipt catch what card+canary cannot:
#   * A benign agent running the AUDITED image gets a quote the router accepts.
#   * A competent-but-malicious agent runs a DIFFERENT image (it has an egress
#     path), so the honest attestation service would sign a NON-audited
#     measurement; to look benign it must FORGE the quote (claim the audited
#     measurement signed by an authority it does not control) -> detectable.
#
# This is deliberately generic (RATS/EAT-style: measurement + nonce + signature by
# a trusted attestation authority). No Microsoft-internal detail is used.

# Attestation authorities (roots of trust) and their signing secrets. Only
# 'cc-attest-root' is in the router's verifier anchor (see scoring). 'self-signed'
# models an attacker signing its own quote.
ATTESTATION_AUTHORITIES = {
    "cc-attest-root": "att_cc_root_5e21",
    "self-signed": "att_self_forged_00xx",
}

# The single measurement the router audited and accepts: the benign, no-egress
# agent stack. Any other measurement is untrusted by definition.
AUDITED_MEASUREMENT = "sha256:agent-stack-noegress-v1"

# What a competent exfiltrator is actually running (has an outbound data path).
EXFIL_MEASUREMENT = "sha256:agent-stack-egress-x9"


def sign_quote(measurement: str, nonce: str, authority: str) -> str:
    """An attestation authority signs (measurement, nonce). Only the authority that
    actually observes `measurement` in the enclave would legitimately sign it."""
    secret = ATTESTATION_AUTHORITIES.get(authority, "att_unknown")
    return hashlib.sha256(f"{measurement}|{nonce}|{secret}".encode("utf-8")).hexdigest()[:24]


def make_quote(measurement: str, nonce: str, authority: str) -> dict[str, Any]:
    """Build an observable attestation quote bound to the verifier's nonce."""
    return {
        "present": True,
        "measurement": measurement,
        "nonce": nonce,
        "authority": authority,
        "value": sign_quote(measurement, nonce, authority),
    }
