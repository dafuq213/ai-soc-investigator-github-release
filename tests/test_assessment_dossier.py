import unittest

from src.assessment_dossier import build_dossier, compact_reasoning_to_legacy
from src.case_models import CaseBuilder


class AssessmentDossierTests(unittest.TestCase):
    def test_process_without_parent_guid_has_an_explicit_unknown(self):
        case = CaseBuilder.from_seed_result("NO-PARENT", {"ok": True, "data": [{
            "alert_id": "a1", "host": "WS-01", "agent_id": "001", "rule": {},
            "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {"processGuid": "{p}", "image": "powershell.exe"}}}},
        }]})
        unknowns = build_dossier(case)["unknown_options"]
        self.assertTrue(any("The seed process has no ParentProcessGuid" in item["text"] for item in unknowns))
        self.assertTrue(any("No change record" in item["text"] for item in unknowns))

    def test_nonencoded_seed_command_is_in_the_process_profile_fact(self):
        case = CaseBuilder.from_seed_result("DISCOVERY", {"ok": True, "data": [{
            "alert_id": "a2", "host": "WS-01", "agent_id": "001", "rule": {},
            "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {"processGuid": "{p}", "parentProcessGuid": "{parent}", "image": "cmd.exe", "commandLine": "cmd.exe /c whoami /all"}}}},
        }]})
        self.assertIn("Observed command: cmd.exe /c whoami /all", [item["text"] for item in build_dossier(case)["facts"]])

    def test_allowlisted_action_name_is_safely_normalized(self):
        case = CaseBuilder.from_seed_result("ACTIONS", {"ok": True, "data": [{
            "alert_id": "a3", "host": "WS-01", "agent_id": "001", "rule": {},
            "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {"processGuid": "{p}", "image": "cmd.exe"}}}},
        }]})
        from src.assessment_dossier import compact_reasoning_to_legacy
        converted = compact_reasoning_to_legacy(case, {"verdict": "inconclusive", "confidence": "low", "claim_ids": [], "benign_ids": [], "unknown_ids": [], "action_ids": ["preserve_evidence"], "claim_verification_id": "V01", "next_check_id": "N01"})
        self.assertEqual(converted["recommended_actions"][0]["action"], "preserve_evidence")

    def test_wazuh_detection_metadata_is_preserved_as_a_trigger(self):
        case = CaseBuilder.from_seed_result("TRIGGER", {"ok": True, "data": [{
            "alert_id": "a4", "host": "WS-01", "agent_id": "001",
            "rule": {"id": "100001", "level": 10, "description": "Possible process injection", "mitre": {"id": ["T1055"]}},
            "event": {"data": {"win": {"system": {"eventID": "10"}, "eventdata": {"sourceProcessGuid": "{a}", "targetProcessGuid": "{b}"}}}},
        }]})
        trigger = build_dossier(case)["trigger"]
        self.assertEqual(trigger["title"], "Possible process injection")
        self.assertEqual(trigger["status"], "detection_trigger_not_analyst_conclusion")

    def test_generic_alert_keeps_claim_separate_from_compact_observations(self):
        case = CaseBuilder.from_seed_result("GENERIC-ALERT", {"ok": True, "data": [{
            "alert_id": "a-generic", "host": "WS-01",
            "rule": {"id": "200001", "description": "Unusual application alert"},
            "event": {},
        }]})
        dossier = build_dossier(case)
        self.assertEqual(dossier["alert_claim"]["status"], "not_independently_verified")
        self.assertIn("detection trigger", dossier["alert_claim"]["text"])
        self.assertEqual(dossier["derived_observations"][0]["evidence_id"], "E001")
        self.assertTrue(dossier["next_check_options"])

    def test_compact_contract_resolves_claim_status_and_next_check(self):
        case = CaseBuilder.from_seed_result("ANALYSIS-SELECTORS", {"ok": True, "data": [{
            "alert_id": "a-selectors", "host": "WS-01", "rule": {},
            "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {"image": "cmd.exe"}}}},
        }]})
        converted = compact_reasoning_to_legacy(case, {
            "verdict": "inconclusive", "confidence": "low", "claim_ids": [], "benign_ids": [],
            "unknown_ids": [], "action_ids": [], "claim_verification_id": "V01", "next_check_id": "N01",
        })
        self.assertEqual(converted["_analysis"]["claim_verification"]["status"], "not_independently_verified")
        self.assertIn("Preserve", converted["_analysis"]["next_check"])

    def test_event_ten_derives_source_target_and_access_observation(self):
        case = CaseBuilder.from_seed_result("PROCESS-ACCESS", {"ok": True, "data": [{
            "alert_id": "a-access", "host": "WS-01", "rule": {},
            "event": {"data": {"win": {"system": {"eventID": "10"}, "eventdata": {
                "sourceImage": "powershell.exe", "targetImage": "explorer.exe", "grantedAccess": "0x40",
            }}}},
        }]})
        observations = build_dossier(case)["derived_observations"]
        self.assertIn("powershell.exe accessed explorer.exe; granted access=0x40", observations[0]["text"])

    def test_llm_dossier_hides_internal_process_guids_but_retains_card_ids(self):
        case = CaseBuilder.from_seed_result("NO-GUIDS", {"ok": True, "data": [{
            "alert_id": "a5", "host": "WS-01", "agent_id": "001", "rule": {},
            "event": {"data": {"win": {"system": {"eventID": "10"}, "eventdata": {
                "sourceProcessGuid": "{secret-source}", "targetProcessGuid": "{secret-target}", "grantedAccess": "0x1000",
            }}}},
        }]})
        dossier = build_dossier(case)
        self.assertEqual(dossier["activity_cards"][0]["card_id"], "R01")
        self.assertNotIn("secret-source", str(dossier))
        self.assertNotIn("secret-target", str(dossier))


if __name__ == "__main__":
    unittest.main()
