import json
import unittest

from src.assessment import AssessmentPipeline, VerifiedAssessment
from src.assessment_dossier import build_dossier
from src.assessment_prompt import assessment_prompt
from src.case_models import CaseBuilder
from src.correlation import attach_deterministic_correlations
from src.qa_review import QualityGate, qa_prompt
from src.telemetry_profiles import select_telemetry_profiles


FIELDS = {
    "1": {"processGuid": "{p}", "image": "cmd.exe"},
    "3": {"processGuid": "{p}", "destinationIp": "203.0.113.10", "destinationPort": "443"},
    "7": {"processGuid": "{p}", "imageLoaded": "C:\\Windows\\System32\\version.dll"},
    "10": {"sourceProcessGuid": "{p}", "targetProcessGuid": "{q}", "grantedAccess": "0x1000"},
    "11": {"processGuid": "{p}", "targetFilename": "C:\\Temp\\x.txt"},
    "12": {"processGuid": "{p}", "targetObject": "HKCU\\Software\\Example"},
    "13": {"processGuid": "{p}", "targetObject": "HKCU\\Software\\Example\\Value"},
    "14": {"processGuid": "{p}", "targetObject": "HKCU\\Software\\Example"},
    "22": {"processGuid": "{p}", "queryName": "example.com"},
}

EXPECTED_OBSERVED_VALUE = {
    "1": "cmd.exe", "3": "destination ip=203.0.113.10", "7": "version.dll",
    "10": "0x1000", "11": "x.txt", "12": "HKCU\\Software\\Example",
    "13": "HKCU\\Software\\Example\\Value", "14": "HKCU\\Software\\Example",
    "22": "example.com",
}


class LlmProfileContractTests(unittest.TestCase):
    def _case(self, event_id, fields):
        seed = {
            "alert_id": f"a-{event_id}", "host": "WS-01", "agent_id": "001",
            "rule": {"id": f"900{event_id}", "level": 7, "description": f"Test Sysmon Event {event_id}", "groups": ["sysmon"]},
            "event": {"data": {"win": {"system": {"eventID": event_id, "providerName": "Microsoft-Windows-Sysmon"}, "eventdata": fields}}},
        }
        case = CaseBuilder.from_seed_result(f"CASE-{event_id}", {"ok": True, "data": [seed]})
        case.correlations["telemetry_profiles"] = [{"profile_id": select_telemetry_profiles(case)[0], "status": "selected"}]
        attach_deterministic_correlations(case)
        return case

    def test_every_supported_sysmon_profile_has_a_replay_valid_small_assessment_prompt(self):
        for event_id, fields in FIELDS.items():
            with self.subTest(event_id=event_id):
                prompt = assessment_prompt(self._case(event_id, fields))
                example = json.loads(prompt.split("Rules:", 1)[0].strip().splitlines()[-1])
                dossier = json.loads(prompt.split("STANDARDIZED DOSSIER:\n", 1)[1])
                valid_cards = {item["card_id"] for item in dossier["activity_cards"]}
                cited = {card_id for item in example.get("narrative", []) for card_id in item["card_ids"]}
                self.assertTrue(cited.issubset(valid_cards))
                self.assertLess(len(prompt.encode("utf-8")), 9000)
                self.assertNotIn("{p}", prompt)

    def test_qa_uses_same_reduced_guid_free_cards_as_assessor(self):
        case = self._case("10", FIELDS["10"])
        assessment = VerifiedAssessment("accepted", "inconclusive", 0.35, [], [], [], ["Parent not collected."], [], [])
        prompt = qa_prompt(case, assessment)
        self.assertIn('"reduced_activity_cards"', prompt)
        self.assertNotIn("{p}", prompt)
        self.assertNotIn("{q}", prompt)

    def test_every_profile_uses_a_bounded_reduced_packet_at_both_llm_stages(self):
        """Regression against raw Wazuh fields leaking into either model call.

        This is deliberately profile-wide: all currently supported Sysmon
        event families pass through the same dossier boundary, so a future
        profile change cannot silently reintroduce Event 10's raw-data bug.
        """
        forbidden = ("RAW_FULL_LOG_SECRET", "RAW_CALL_TRACE_SECRET", "RAW_UNMODELED_SECRET", "{p}", "{q}")
        for event_id, base_fields in FIELDS.items():
            with self.subTest(event_id=event_id):
                fields = dict(base_fields)
                fields.update({
                    "callTrace": "RAW_CALL_TRACE_SECRET",
                    "unmodeledRawField": "RAW_UNMODELED_SECRET",
                })
                case = self._case(event_id, fields)
                case.evidence[0].record["event"]["full_log"] = "RAW_FULL_LOG_SECRET"
                attach_deterministic_correlations(case)

                prompt = assessment_prompt(case)
                dossier = build_dossier(case)
                self.assertLess(len(prompt.encode("utf-8")), 9000)
                # This checks the inverse of the leakage test: each profile
                # retains its own decision-relevant observed value.
                self.assertIn(json.dumps(EXPECTED_OBSERVED_VALUE[event_id])[1:-1], json.dumps(dossier))
                for value in forbidden:
                    self.assertNotIn(value, prompt)

                card_id = dossier["activity_cards"][0]["card_id"]
                assessor_output = "```json\n" + json.dumps({
                    "verdict": "inconclusive", "confidence": "low", "action_ids": ["A01"], "claim_verification_id": "V01", "next_check_id": "N01",
                    "narrative": [{"card_ids": [card_id], "text": "The cited card records observed activity. It does not establish intent, authorization, or outcome."}],
                }) + "\n```"
                assessment = AssessmentPipeline().evaluate(case, assessor_output)
                self.assertEqual(assessment.status, "accepted")

                critic_prompt = qa_prompt(case, assessment)
                for value in forbidden:
                    self.assertNotIn(value, critic_prompt)
                review = QualityGate().review(case, assessment, "```json\n{\"decision\":\"accept\",\"issues\":[],\"required_changes\":[]}\n```")
                self.assertEqual((review.status, review.decision), ("accepted", "accept"))


if __name__ == "__main__":
    unittest.main()
