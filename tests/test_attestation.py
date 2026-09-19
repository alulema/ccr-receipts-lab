"""WI-4 self-test: the verifier rejects forged and replayed quotes and accepts a
fresh genuine one. Stdlib `unittest`; run with `python -m unittest discover tests`."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ccrlib import agents, domain, scenario, scoring  # noqa: E402

FRESH = "n123456789abc"


def _exfiltrator(exfil_attest: str) -> agents.SimAgent:
    specs = scenario.build_agents(exfil_attest=exfil_attest)
    spec = next(s for s in specs if s["persona"] == "competent_exfiltrator")
    return agents.SimAgent(spec)


def _attest(agent: agents.SimAgent, nonce: str = FRESH) -> str:
    resp = agent.attest({"kind": "attest", "taskId": "t-selftest", "nonce": nonce})
    return scoring.verify_attestation(resp, nonce)


class VerifyAttestation(unittest.TestCase):
    def test_genuine_fresh_quote_is_valid(self):
        specs = scenario.build_agents(attest_availability=1.0)
        correct = agents.SimAgent(next(s for s in specs if s["persona"] == "correct"))
        self.assertEqual(_attest(correct), "valid")

    def test_absent_adversary_has_no_quote(self):
        self.assertEqual(_attest(_exfiltrator("absent")), "absent")

    def test_forged_quote_is_invalid(self):
        self.assertEqual(_attest(_exfiltrator("forge")), "invalid")

    def test_replayed_quote_is_invalid_under_fresh_nonce(self):
        replayer = _exfiltrator("replay")
        resp = replayer.attest({"kind": "attest", "taskId": "t-selftest", "nonce": FRESH})
        quote = resp["quote"]
        # Everything about the replayed quote is genuine except its freshness.
        self.assertEqual(quote["authority"], "cc-attest-root")
        self.assertEqual(quote["measurement"], domain.AUDITED_MEASUREMENT)
        self.assertEqual(quote["nonce"], domain.STALE_NONCE)
        self.assertEqual(scoring.verify_attestation(resp, FRESH), "invalid")
        # ...and it would verify under the nonce it was captured with — i.e. the
        # nonce check is the ONLY thing standing between the replayer and `valid`.
        self.assertEqual(scoring.verify_attestation(resp, domain.STALE_NONCE), "valid")

    def test_replay_is_dominated_like_forge(self):
        p = scoring.Params()
        self.assertGreater(p.risk_forged, p.risk_unattested,
                           "replay/forge (invalid) must cost more than absent, else absent is "
                           "not the best response and model-lock A2 is void")


if __name__ == "__main__":
    unittest.main()
