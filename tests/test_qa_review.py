import unittest

from src.assessment import AssessmentPipeline
from src.case_models import CaseBuilder
from src.qa_review import QualityGate, apply_quality_gate, qa_prompt


def case_and_assessment():
    case = CaseBuilder.from_seed_result("CASE-QA", {"ok": True, "data": [{
        "alert_id": "a1", "timestamp": "2026-08-10T10:00:00Z", "host": "WS-001", "rule": {"groups": ["sysmon"]},
        "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {
            "processGuid": "{ps}", "parentProcessGuid": "{word}", "image": "powershell.exe",
            "commandLine": "powershell.exe -EncodedCommand AAAA",
        }}}},
    }]})
    assessment = AssessmentPipeline().evaluate(case, {
        "verdict": "suspicious_requires_review", "llm_confidence": 0.8,
        "claims": [{"claim_type": "process_parent", "evidence_ids": ["E001"], "subject": "{ps}", "object": "{word}"}],
        "benign_alternatives": [], "unknowns": ["Change context unavailable"], "recommended_actions": [],
    })
    return case, assessment


class QualityGateTests(unittest.TestCase):
    def test_accepts_a_bounded_clean_review(self):
        case, assessment = case_and_assessment()
        review = QualityGate().review(case, assessment, {"decision": "accept", "issues": [], "required_changes": []})
        gated = apply_quality_gate(assessment, review)
        self.assertEqual(review.status, "accepted")
        self.assertEqual(gated.status, "accepted")

    def test_revision_blocks_findings_from_the_reportable_assessment(self):
        case, assessment = case_and_assessment()
        review = QualityGate().review(case, assessment, {"decision": "revise", "issues": [{
            "issue_type": "missing_uncertainty", "target": "C1", "reason": "Change context remains unavailable.", "evidence_ids": ["E001"],
        }], "required_changes": ["State the missing change context."]})
        gated = apply_quality_gate(assessment, review)
        self.assertEqual(gated.status, "qa_revision_required")
        self.assertFalse(gated.accepted_claims)

    def test_rejects_critic_that_cites_unknown_evidence(self):
        case, assessment = case_and_assessment()
        review = QualityGate().review(case, assessment, {"decision": "revise", "issues": [{
            "issue_type": "overstatement", "target": "C1", "reason": "Unsupported.", "evidence_ids": ["E999"],
        }], "required_changes": ["Revise."]})
        self.assertEqual(review.status, "rejected")

    def test_rejects_activity_card_as_a_critic_target(self):
        case, assessment = case_and_assessment()
        review = QualityGate().review(case, assessment, {
            "decision": "revise",
            "issues": [{
                "issue_type": "missing_uncertainty", "target": "R01",
                "reason": "Activity-card IDs are not review targets.", "evidence_ids": ["E001"],
            }],
            "required_changes": ["Target the assessment instead."],
        })
        self.assertEqual(review.status, "rejected")

    def test_rejects_unbounded_assessment_as_a_critic_target(self):
        case, assessment = case_and_assessment()
        review = QualityGate().review(case, assessment, {
            "decision": "revise",
            "issues": [{
                "issue_type": "overstatement", "target": "assessment",
                "reason": "Narrative cannot be an independent QA target.", "evidence_ids": ["E001"],
            }],
            "required_changes": ["Target a verified claim or action."],
        })
        self.assertEqual(review.status, "rejected")

    def test_accepts_one_fenced_json_object_then_applies_schema_validation(self):
        case, assessment = case_and_assessment()
        review = QualityGate().review(case, assessment, "```json\n{\"decision\":\"accept\",\"issues\":[],\"required_changes\":[]}\n```")
        self.assertEqual(review.status, "accepted")
        self.assertEqual(review.decision, "accept")

    def test_rejects_review_that_exceeds_bounded_issue_limits(self):
        case, assessment = case_and_assessment()
        issues = [{"issue_type": "overstatement", "target": "C1", "reason": "Unsupported.", "evidence_ids": ["E001"]}] * 3
        review = QualityGate().review(case, assessment, {"decision": "revise", "issues": issues, "required_changes": ["Revise."]})
        self.assertEqual(review.status, "rejected")

    def test_rejects_critic_request_for_out_of_scope_authorization_context(self):
        case, assessment = case_and_assessment()
        review = QualityGate().review(case, assessment, {
            "decision": "revise",
            "issues": [{
                "issue_type": "missing_uncertainty", "target": "C1",
                "reason": "No change record or expected-activity context was collected.",
                "evidence_ids": ["E001"],
            }],
            "required_changes": ["Include change records and expected-activity context to determine authorization."],
        })
        self.assertEqual(review.status, "rejected")
        self.assertIn("out-of-scope operational context", review.error)

    def test_prompt_has_only_accepted_assessment_material(self):
        case, assessment = case_and_assessment()
        prompt = qa_prompt(case, assessment)
        self.assertIn('"ref":"C1"', prompt)
        self.assertIn("rendered verbatim in the analyst report", prompt)
        self.assertNotIn('"narrative":', prompt)
        self.assertNotIn("full_log", prompt)
        self.assertNotIn('"subject":"{ps}"', prompt)
        self.assertNotIn("{word}", prompt)


if __name__ == "__main__":
    unittest.main()
