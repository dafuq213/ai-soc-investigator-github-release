import unittest

from src.assessment import AssessmentPipeline, evaluate_with_model
from src.case_models import CaseBuilder


def build_case():
    return CaseBuilder.from_seed_result("CASE-ASSESS", {"ok": True, "data": [{
        "alert_id": "a1", "timestamp": "2026-08-10T10:00:00Z", "host": "WS-001", "rule": {"groups": ["sysmon"]},
        "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {
            "processGuid": "{ps}", "parentProcessGuid": "{word}", "image": "powershell.exe",
            "commandLine": "powershell.exe -EncodedCommand AAAA",
        }}}},
    }]})


def payload(claim_object="{word}", action=None):
    return {
        "verdict": "suspicious_requires_review", "llm_confidence": 0.8,
        "claims": [{"claim_type": "process_parent", "evidence_ids": ["E001"], "subject": "{ps}", "object": claim_object}],
        "benign_alternatives": ["Approved automation is unverified"], "unknowns": ["Change record unavailable"],
        "recommended_actions": [] if action is None else [action],
    }


class AssessmentPipelineTests(unittest.TestCase):
    def test_accepts_fully_supported_reasoning(self):
        assessment = AssessmentPipeline().evaluate(build_case(), payload())
        self.assertEqual(assessment.status, "accepted")
        self.assertEqual(assessment.verdict, "suspicious_requires_review")

    def test_rejects_entire_assessment_when_any_claim_is_unsupported(self):
        assessment = AssessmentPipeline().evaluate(build_case(), payload("{invented}"))
        self.assertEqual(assessment.status, "rejected")
        self.assertEqual(assessment.verdict, "inconclusive")
        self.assertFalse(assessment.recommended_actions)

    def test_rejects_schema_valid_but_empty_assessment(self):
        assessment = AssessmentPipeline().evaluate(build_case(), {
            "verdict": "inconclusive", "llm_confidence": 0.0,
            "claims": [], "benign_alternatives": [], "unknowns": [], "recommended_actions": [],
        })
        self.assertEqual(assessment.status, "rejected")
        self.assertEqual(assessment.error, "model returned an empty assessment")

    def test_resolves_compact_model_selections_without_guid_copying(self):
        assessment = AssessmentPipeline().evaluate(build_case(), {
            "verdict": "inconclusive", "confidence": "low", "claim_ids": ["C01", "C02"], "claim_verification_id": "V01", "next_check_id": "N01",
            "benign_ids": [], "unknown_ids": [], "action_ids": ["A01"],
        })
        self.assertEqual(assessment.status, "accepted")
        self.assertEqual({claim.claim_type for claim in assessment.accepted_claims}, {"encoded_powershell", "process_parent"})

    def test_compact_contract_allows_omitted_empty_selection_arrays(self):
        assessment = AssessmentPipeline().evaluate(build_case(), {
            "verdict": "inconclusive", "confidence": "low", "claim_ids": ["C01"], "claim_verification_id": "V01", "next_check_id": "N01",
        })
        self.assertEqual(assessment.status, "accepted")

    def test_accepts_one_fenced_assessment_json_object(self):
        case = build_case()
        output = "```json\n{\"verdict\":\"inconclusive\",\"confidence\":\"low\",\"action_ids\":[\"A01\"],\"claim_verification_id\":\"V01\",\"next_check_id\":\"N01\"}\n```"
        self.assertEqual(AssessmentPipeline().evaluate(case, output).status, "accepted")

    def test_resolves_authentication_claim_label(self):
        case = CaseBuilder.from_seed_result("CASE-AUTH", {"ok": True, "data": [{
            "alert_id": "auth-1", "host": "DC-01", "rule": {"groups": ["authentication"]},
            "event": {"data": {"win": {"system": {"eventID": "4624"}, "eventdata": {"targetUserName": "jsmith", "ipAddress": "127.0.0.1", "logonType": "11"}}}},
        }]})
        assessment = AssessmentPipeline().evaluate(case, {
            "verdict": "inconclusive", "confidence": "low", "claim_ids": ["C01"], "benign_ids": ["B02"], "unknown_ids": ["U04"], "action_ids": ["A02"], "claim_verification_id": "V01", "next_check_id": "N01",
        })
        self.assertEqual(assessment.status, "accepted")
        self.assertEqual(assessment.accepted_claims[0].claim_type, "authentication_window")


    def test_rejects_recommendation_without_evidence(self):
        action = {"action": "isolate_host", "reason": "Risk", "risk": "Business interruption", "evidence_ids": ["E999"]}
        assessment = AssessmentPipeline().evaluate(build_case(), payload(action=action))
        self.assertEqual(assessment.status, "rejected")

    def test_rejects_host_isolation_without_network_evidence(self):
        action = {"action": "isolate_host", "reason": "Risk", "risk": "Business interruption", "evidence_ids": ["E001"]}
        assessment = AssessmentPipeline().evaluate(build_case(), payload(action=action))
        self.assertEqual(assessment.status, "rejected")

    def test_provider_failure_fails_closed(self):
        assessment = evaluate_with_model(build_case(), lambda _: (_ for _ in ()).throw(RuntimeError("offline")))
        self.assertEqual(assessment.status, "rejected")
        self.assertIn("provider failed", assessment.error)


if __name__ == "__main__":
    unittest.main()
