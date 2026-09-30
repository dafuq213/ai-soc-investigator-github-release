import json
import unittest

from src.assessment_prompt import assessment_prompt
from src.case_models import CaseBuilder


class AssessmentPromptTests(unittest.TestCase):
    def test_prompt_contains_only_case_data_and_strict_contract(self):
        case = CaseBuilder.from_seed_result("CASE-PROMPT", {"ok": True, "data": [{"alert_id": "a-1", "event": {}, "rule": {}}]})
        prompt = assessment_prompt(case)
        self.assertIn('"case_id":"CASE-PROMPT"', prompt)
        self.assertIn("Return exactly one JSON object", prompt)
        self.assertIn("Select IDs only", prompt)

    def test_prompt_has_one_unambiguous_verdict_and_confidence_rule(self):
        case = CaseBuilder.from_seed_result("CASE-PROMPT", {"ok": True, "data": [{"alert_id": "a-1", "event": {}, "rule": {}}]})
        prompt = assessment_prompt(case)
        self.assertNotIn("confidence must be exactly one of low, medium, or high", prompt)
        self.assertIn("confidence` must be an integer from 0 to 100", prompt)

    def test_prompt_excludes_full_log_and_bounds_large_command_values(self):
        command = "A" * 2000
        case = CaseBuilder.from_seed_result("CASE-PROMPT", {"ok": True, "data": [{
            "alert_id": "a-1", "host": "ws-01", "rule": {},
            "event": {"full_log": "secret raw event", "data": {"win": {"eventdata": {"commandLine": command}}}},
        }]})
        prompt = assessment_prompt(case)
        self.assertNotIn("secret raw event", prompt)
        self.assertNotIn(command, prompt)
        self.assertNotIn("commandLine", prompt)

    def test_example_cites_only_cards_that_exist_in_this_dossier(self):
        case = CaseBuilder.from_seed_result("CASE-ACCESS", {"ok": True, "data": [{
            "alert_id": "a-10", "host": "ws-01", "rule": {},
            "event": {"data": {"win": {"system": {"eventID": "10"}, "eventdata": {
                "sourceProcessGuid": "{source}", "targetProcessGuid": "{target}", "grantedAccess": "0x1000",
            }}}},
        }]})
        prompt = assessment_prompt(case)
        example = json.loads(prompt.split("Rules:", 1)[0].strip().splitlines()[-1])
        dossier = json.loads(prompt.split("STANDARDIZED DOSSIER:\n", 1)[1])
        cited = {card_id for item in example.get("narrative", []) for card_id in item["card_ids"]}
        self.assertTrue(cited.issubset({item["card_id"] for item in dossier["activity_cards"]}))
        self.assertNotIn("R03\",\"R04", prompt)


if __name__ == "__main__":
    unittest.main()
