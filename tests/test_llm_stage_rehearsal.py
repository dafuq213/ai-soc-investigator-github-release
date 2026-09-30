"""Offline regression of the live dossier -> assessor -> critic contract."""
import json
import unittest

from src.assessment import AssessmentPipeline
from src.assessment_dossier import build_dossier
from src.assessment_prompt import assessment_prompt
from src.case_models import CaseBuilder
from src.correlation import attach_deterministic_correlations
from src.qa_review import QualityGate, qa_prompt


def _record(alert_id, event_id, fields):
    return {
        "alert_id": alert_id, "timestamp": "2026-08-20T17:10:09Z", "host": "WS-01", "agent_id": "001",
        "rule": {"id": "100520", "level": 7, "description": "Lab process-access alert", "groups": ["sysmon"]},
        "event": {"full_log": "must never reach an LLM", "data": {"win": {"system": {"eventID": str(event_id), "providerName": "Microsoft-Windows-Sysmon"}, "eventdata": fields}}},
    }


class LlmStageRehearsalTests(unittest.TestCase):
    def _case(self):
        case = CaseBuilder.from_seed_result("CASE-LLM-REHEARSAL", {"ok": True, "data": [_record("seed", 10, {
            "sourceProcessGuid": "{source-guid}", "targetProcessGuid": "{target-guid}",
            "sourceImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "targetImage": "C:\\Windows\\System32\\notepad.exe", "grantedAccess": "0x1000", "callTrace": "sensitive raw trace",
        })]})
        case.add_alert_evidence(_record("source", 1, {"processGuid": "{source-guid}", "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}))
        case.add_alert_evidence(_record("target", 1, {"processGuid": "{target-guid}", "image": "C:\\Windows\\System32\\notepad.exe"}))
        case.correlations["telemetry_profiles"] = [{"profile_id": "windows_sysmon_process_access", "status": "selected"}]
        attach_deterministic_correlations(case)
        return case

    def test_exact_compact_data_and_fenced_outputs_pass_both_stages(self):
        case = self._case()
        dossier = build_dossier(case)
        prompt = assessment_prompt(case)
        card = next(item for item in dossier["activity_cards"] if item["kind"] == "process_access")
        self.assertEqual(card["observed"]["source_process"], "powershell.exe")
        self.assertEqual(card["observed"]["target_process"], "notepad.exe")
        for forbidden in ("source-guid", "target-guid", "sensitive raw trace", "full_log"):
            self.assertNotIn(forbidden, prompt)

        assessor_output = "```json\n" + json.dumps({
            "verdict": "inconclusive", "confidence": "low", "action_ids": ["A01"], "claim_verification_id": "V01", "next_check_id": "N01",
            "narrative": [{"card_ids": [card["card_id"]], "text": "The cited card records a PowerShell-to-Notepad process-access relationship. It does not establish authorization, intent, or outcome."}],
        }) + "\n```"
        assessment = AssessmentPipeline().evaluate(case, assessor_output)
        self.assertEqual(assessment.status, "accepted")

        critic_prompt = qa_prompt(case, assessment)
        self.assertNotIn("source-guid", critic_prompt)
        review = QualityGate().review(case, assessment, "```json\n{\"decision\":\"accept\",\"issues\":[],\"required_changes\":[]}\n```")
        self.assertEqual(review.status, "accepted")
        self.assertEqual(review.decision, "accept")

    def test_fenced_json_with_extra_prose_remains_rejected(self):
        case = self._case()
        assessment = AssessmentPipeline().evaluate(case, '{"verdict":"inconclusive","confidence":"low","action_ids":["A01"],"claim_verification_id":"V01","next_check_id":"N01"}')
        review = QualityGate().review(case, assessment, "prefix ```json\n{\"decision\":\"accept\",\"issues\":[],\"required_changes\":[]}\n```")
        self.assertEqual(review.status, "rejected")


if __name__ == "__main__":
    unittest.main()
