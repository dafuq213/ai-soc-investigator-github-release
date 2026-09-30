import unittest

from src.assessment import VerifiedAssessment
from src.case_models import CaseBuilder
from src.correlation import attach_deterministic_correlations
from src.report_quality import assess_l3_readiness


class ReportQualityTests(unittest.TestCase):
    def test_qa_revision_is_not_reported_as_an_assessor_rejection(self):
        case = CaseBuilder.from_seed_result("QUALITY-QA", {"ok": True, "data": [{
            "alert_id": "a1", "host": "WS-01", "agent_id": "001",
            "rule": {"id": "100520", "description": "Lab alert"},
            "event": {"data": {"win": {"system": {"eventID": "10"}, "eventdata": {}}}},
        }]})
        case.correlations["telemetry_profiles"] = [{"profile_id": "windows_sysmon_process_access", "status": "selected"}]
        quality = assess_l3_readiness(case, VerifiedAssessment(
            "qa_revision_required", "inconclusive", 0.0, [], [], [],
            ["QA review requires revision."], [], quality_review={"status": "accepted", "decision": "revise"},
        ))
        self.assertIn("QA requested revision; the otherwise verified assessor output is withheld.", quality.gaps)
        self.assertNotIn("LLM assessment was not accepted.", quality.gaps)

    def test_missing_critic_cannot_be_l3_ready_even_at_nine_points(self):
        seed = {"alert_id": "a1", "host": "WS-01", "agent_id": "001", "rule": {"id": "100520", "description": "Lab alert"}, "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {"processGuid": "{p}", "image": "cmd.exe"}}}}}
        case = CaseBuilder.from_seed_result("QUALITY-NO-QA", {"ok": True, "data": [seed]})
        case.correlations["telemetry_profiles"] = [{"profile_id": "windows_sysmon_process", "status": "selected"}]
        assessment = VerifiedAssessment("accepted", "inconclusive", 0.3, [], [], [], ["Authorization context was not collected."], [{"action": "validate_change", "reason": "Validate authorization.", "risk": "Delayed review.", "evidence_ids": ["E001"]}], narrative=[{"card_ids": ["R01"], "text": "Observed execution; intent is not established."}])
        quality = assess_l3_readiness(case, assessment)
        self.assertEqual(quality.score, 9)
        self.assertFalse(quality.ready_for_l3)

    def test_raw_archive_seed_cannot_claim_l3_ready(self):
        seed = {"alert_id": "a1", "host": "WS-01", "agent_id": "001", "rule": {}, "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {"processGuid": "{p}", "image": "cmd.exe"}}}}}
        case = CaseBuilder.from_seed_result("QUALITY", {"ok": True, "data": [seed]})
        case.correlations["telemetry_profiles"] = [{"profile_id": "windows_sysmon_process", "status": "selected"}]
        attach_deterministic_correlations(case)
        assessment = VerifiedAssessment("accepted", "inconclusive", 0.35, [], [], [], ["Authorization context was not collected."], [{"action": "validate_change", "reason": "Validate authorization.", "risk": "Delayed review.", "evidence_ids": ["E001"]}], None, narrative=[{"card_ids": ["R01"], "text": "Observed process execution; intent is not established."}], quality_review={"status": "accepted", "decision": "accept"})
        quality = assess_l3_readiness(case, assessment)
        self.assertFalse(quality.ready_for_l3)
        self.assertFalse(quality.checks["wazuh_trigger_preserved"])


if __name__ == "__main__":
    unittest.main()
