import unittest

from src.assessment import VerifiedAssessment
from src.case_models import CaseBuilder
from src.correlation import attach_deterministic_correlations
from src.report_quality import assess_l3_readiness
from src.telemetry_profiles import select_telemetry_profiles


_FIELDS = {
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


class ReportQualityProfileTests(unittest.TestCase):
    def test_each_supported_sysmon_seed_can_meet_generic_l3_quality_gate(self):
        for event_id, fields in _FIELDS.items():
            with self.subTest(event_id=event_id):
                seed = {
                    "alert_id": f"a-{event_id}", "host": "WS-01", "agent_id": "001",
                    "rule": {"id": f"900{event_id}", "level": 7, "description": f"Test Sysmon Event {event_id}", "groups": ["sysmon"]},
                    "event": {"data": {"win": {"system": {"eventID": event_id, "providerName": "Microsoft-Windows-Sysmon"}, "eventdata": fields}}},
                }
                case = CaseBuilder.from_seed_result(f"CASE-{event_id}", {"ok": True, "data": [seed]})
                case.correlations["telemetry_profiles"] = [{"profile_id": select_telemetry_profiles(case)[0], "status": "selected"}]
                attach_deterministic_correlations(case)
                assessment = VerifiedAssessment(
                    "accepted", "inconclusive", 0.35, [], [], [], ["Authorization context was not collected."],
                    [{"action": "validate_change", "reason": "Validate authorization.", "risk": "A delayed review may postpone a decision.", "evidence_ids": ["E001"]}],
                    narrative=[{"card_ids": ["R01"], "text": "The cited alert establishes an observed event, but authorization and outcome are not established."}],
                    quality_review={"status": "accepted", "decision": "accept"},
                )
                quality = assess_l3_readiness(case, assessment)
                self.assertGreaterEqual(quality.score, 9)
                self.assertTrue(quality.ready_for_l3)


if __name__ == "__main__":
    unittest.main()
