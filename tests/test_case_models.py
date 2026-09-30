import unittest

from src.case_models import CaseBuilder


class CaseBuilderTests(unittest.TestCase):
    def test_builds_stable_evidence_ids_and_process_entities_from_sysmon_event(self):
        result = {"ok": True, "data": [{
            "alert_id": "alert-1", "timestamp": "2026-08-10T12:00:00Z", "host": "WS-001",
            "rule": {"description": "Process Create", "groups": ["sysmon", "windows"]},
            "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "parentImage": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                "processGuid": "{process-guid}", "parentProcessGuid": "{parent-guid}",
                "user": "ACME\\analyst", "destinationIp": "203.0.113.20",
                "destinationHostname": "example.test", "hashes": "SHA256=abc123",
            }}}},
        }]}
        case = CaseBuilder.from_seed_result("CASE-001", result)
        self.assertEqual(case.evidence[0].evidence_id, "E001")
        self.assertEqual(case.timeline[0].event_type, "process_creation")
        self.assertEqual(case.entities["hosts"], {"WS-001"})
        self.assertEqual(case.entities["process_guids"], {"{process-guid}"})
        self.assertEqual(case.entities["parent_process_guids"], {"{parent-guid}"})
        self.assertEqual(case.entities["ips"], {"203.0.113.20"})
        self.assertEqual(case.entities["hashes"], {"abc123"})

    def test_retains_profile_dossier_fields_and_excludes_raw_only_call_trace(self):
        seed = {"alert_id": "alert-10", "host": "WS-001", "rule": {}, "event": {"data": {"win": {
            "system": {"eventID": "10", "providerName": "Microsoft-Windows-Sysmon"},
            "eventdata": {"sourceProcessGUID": "{source}", "targetProcessGUID": "{target}", "sourceUser": "ACME\\a", "targetUser": "ACME\\b", "grantedAccess": "0x1000", "callTrace": "do-not-store"},
        }}}}
        case = CaseBuilder.from_seed_result("CASE-10", {"ok": True, "data": [seed]})
        fields = case.evidence[0].record["event"]["data"]["win"]["eventdata"]
        self.assertEqual(fields["sourceUser"], "ACME\\a")
        self.assertEqual(fields["targetUser"], "ACME\\b")
        self.assertNotIn("callTrace", fields)


if __name__ == "__main__":
    unittest.main()
