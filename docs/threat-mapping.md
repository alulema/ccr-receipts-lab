# Threat mapping — personas ↔ threat classes

Each simulated persona in `ccrlib/scenario.py` instantiates one threat the router must
route around. Two taxonomies apply:

- **A2ASecBench** (ICLR 2026; the taxonomy the base CCR paper uses) covers threats on
  the *capability / delegation* surface. Labels below marked *(verify)* must be checked
  against the paper's exact class names before citation — the OpenReview text is
  CAPTCHA-gated and was not re-opened while writing this file.
- **Attestation-specific threats** are **an extension of the A2ASecBench taxonomy, not
  part of it.** They are grounded in the RATS architecture (IETF **RFC 9334**: attester,
  verifier, relying party, evidence, freshness) and the EAT token format (IETF RFC 9711 —
  *verify number before citing*). Nothing here relies on any vendor-internal knowledge.

| persona | capable | signed | benign | quote presented | A2ASecBench class *(verify)* | attestation threat (RATS) | which tier catches it |
|---|---|---|---|---|---|---|---|
| `correct` | yes (0.90) | yes | yes | **valid** (if TEE available) | — (benign baseline) | — | — |
| `degraded` | intermittent (0.70) | yes | yes | valid (if TEE available) | Agent-Card over-declaration (stale card; weak-form card poisoning) | — | canary (capability) |
| `canary_aware` | no (0.12) | yes | **no** | **absent** (no TEE) | capability cloaking / probe evasion (behaves differently on probe vs. real task) | attester declines to produce evidence (opt-out) | canary only if the probe is indistinguishable; receipt tier demotes it as unattested |
| `competent_exfiltrator` — `absent` (**headline**, best response) | **yes (0.90)** | **yes** | **no** | **absent** | data exfiltration / leakage | attester declines to produce evidence (opt-out; not an attestation attack per se) | receipt tier **indirectly**: it promotes an attested-benign agent above the unattested exfiltrator; nothing catches it once no benign agent can attest (RQ3/RQ4) |
| `competent_exfiltrator` — `forge` (naive contrast) | yes (0.90) | yes | no | **invalid** (self-signed / wrong measurement) | data exfiltration / leakage | **forged evidence** — fails the verifier's signature / trust-anchor check | receipt tier directly (`risk_forged`) |
| `replay_attacker` (WI-4) | yes (0.90) | yes | no | **invalid** (genuine old quote, wrong nonce) | — (not in A2ASecBench) | **evidence replay** — defeated by nonce freshness (RFC 9334 §10, Freshness) | receipt tier directly (`verify_attestation` → `invalid`) |
| `attested_yet_abusing` (WI-2) | yes (0.90) | yes | **no** | **valid** (genuine, runs the audited image) | — (not in A2ASecBench) | **not a RATS threat**: the evidence is truthful. Label: *post-delegation data misuse — D2 / information-flow-control scope* | **none of the three tiers** — this is the measured `cov < 1` boundary |

Notes.

1. *Signed* means the Agent Card carries a valid `AgentCardSignature` from a trusted
   issuer. Identity attestation is orthogonal to runtime attestation: every malicious
   persona here is validly signed (identity ≠ intent — the base paper's premise).
2. The base CCR paper's `adversarial` persona (Agent-Card poisoning + card forgery,
   invalid signature) is not in this lab's headline pool: `signature_only` already
   removes it, and the question here is the residual *after* identity checks.
3. The receipt tier's power against the headline adversary is **promotion of the
   attested-benign agent**, not detection: an `absent` reply carries the same modest
   `risk_unattested` penalty as an honest agent without a TEE. When no benign agent can
   attest (`attest_availability = 0`) the tier has nothing to promote and CCR-R matches
   CCR on incident while still paying ρ per request (`SENSITIVITY.md`, a*(ρ)).
4. `attested_yet_abusing` is *in scope for measurement, out of scope for defense*: a
   valid quote proves which code ran on which stack, not what that code did with a datum
   it legitimately received. Its incidents are `Risk^sem`, which no attestation strength or
   coverage removes; they mark the boundary of this line of work (D1) and the starting
   point of information-flow control (D2, cf. FIDES).
