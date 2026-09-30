import unittest

from src.case_models import CaseBuilder
from src.reasoning_contract import ClaimVerifier, StructuredReasoning


class ReasoningContractTests(unittest.TestCase):
    def setUp(self):
        self.case = CaseBuilder.from_seed_result("CASE-VERIFY", {"ok": True, "data": [{
            "alert_id": "a1", "timestamp": "2026-08-10T10:00:00Z", "host": "WS-001", "rule": {"groups": ["sysmon"]},
            "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {
                "processGuid": "{ps}", "parentProcessGuid": "{word}", "image": "powershell.exe",
                "commandLine": "powershell.exe -EncodedCommand AAAA", "destinationIp": "203.0.113.20",
            }}}},
        }]})

    def test_verifier_accepts_only_claims_supported_by_cited_fields(self):
        reasoning = StructuredReasoning.from_json({
            "verdict": "suspicious_requires_review", "llm_confidence": 0.8,
            "claims": [
                {"claim_type": "process_parent", "evidence_ids": ["E001"], "subject": "{ps}", "object": "{word}"},
                {"claim_type": "encoded_powershell", "evidence_ids": ["E001"], "subject": None, "object": None},
                {"claim_type": "network_connection", "evidence_ids": ["E001"], "subject": "{ps}", "object": "8.8.8.8"},
            ],
            "benign_alternatives": ["Approved automation is not yet verified"], "unknowns": ["Change context unavailable"], "recommended_actions": [],
        })
        outcomes = ClaimVerifier().verify(self.case, reasoning)
        self.assertEqual([outcome.accepted for outcome in outcomes], [True, True, False])

    def test_contract_rejects_free_form_or_unknown_claim_types(self):
        with self.assertRaises(ValueError):
            StructuredReasoning.from_json({"verdict": "malicious"})

    def test_verifier_accepts_observed_authentication_user_and_source(self):
        case = CaseBuilder.from_seed_result("CASE-AUTH-CLAIM", {"ok": True, "data": [{
            "alert_id": "auth-1", "host": "DC-01", "rule": {"groups": ["authentication"]},
            "event": {"data": {"win": {"eventdata": {"targetUserName": "jsmith", "ipAddress": "203.0.113.10"}}}},
        }]})
        reasoning = StructuredReasoning.from_json({"verdict": "inconclusive", "llm_confidence": 0.2,
            "claims": [{"claim_type": "authentication_window", "evidence_ids": ["E001"], "subject": "jsmith", "object": "203.0.113.10"}],
            "benign_alternatives": [], "unknowns": ["Outcome unavailable"], "recommended_actions": []})
        self.assertTrue(ClaimVerifier().verify(case, reasoning)[0].accepted)


if __name__ == "__main__":
    unittest.main()
