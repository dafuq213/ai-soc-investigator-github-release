import unittest

from src.assessment_dossier import build_dossier
from src.case_models import CaseBuilder
from src.sysmon_profile_contracts import PROFILE_BY_EVENT_ID, contract_for_event_id


class SysmonProfileContractTests(unittest.TestCase):
    def test_every_supported_profile_has_keys_and_a_small_dossier_field_set(self):
        self.assertEqual(set(PROFILE_BY_EVENT_ID), {"1", "3", "7", "10", "11", "12", "13", "14", "22"})
        for event_id in PROFILE_BY_EVENT_ID:
            with self.subTest(event_id=event_id):
                contract = contract_for_event_id(event_id)
                self.assertIsNotNone(contract)
                self.assertTrue(contract.required_keys)
                self.assertGreaterEqual(len(contract.dossier_fields), 3)
                self.assertLessEqual(len(contract.dossier_fields), 7)

    def test_event_10_aliases_are_correlation_keys_not_dossier_values(self):
        contract = contract_for_event_id("10")
        fields = {"sourceProcessGUID": "{source}", "targetProcessGUID": "{target}", "sourceImage": "powershell.exe", "callTrace": "raw"}
        self.assertEqual(contract.key_values(fields), {"source_process_guid": "{source}", "target_process_guid": "{target}"})
        self.assertNotIn("callTrace", contract.values(fields))
        self.assertEqual(contract.values(fields)["source_image"], "powershell.exe")

    def test_event_3_dossier_contains_only_its_named_profile_fields(self):
        seed = {"alert_id": "a3", "host": "WS-01", "agent_id": "001", "rule": {"groups": ["sysmon"]}, "event": {"data": {"win": {
            "system": {"eventID": "3", "providerName": "Microsoft-Windows-Sysmon"},
            "eventdata": {"processGuid": "{actor}", "image": "powershell.exe", "destinationIp": "203.0.113.9", "destinationPort": "443", "protocol": "tcp", "unmodeled": "must-not-enter"},
        }}}}
        case = CaseBuilder.from_seed_result("EVENT-3", {"ok": True, "data": [seed]})
        observation = build_dossier(case)["profile_observation"]
        self.assertEqual(observation["profile_id"], "windows_sysmon_network")
        self.assertEqual(observation["fields"]["destination_ip"], "203.0.113.9")
        self.assertEqual(observation["fields"]["destination_port"], "443")
        self.assertNotIn("process_guid", observation["fields"])
        self.assertNotIn("unmodeled", observation["fields"])


if __name__ == "__main__":
    unittest.main()
