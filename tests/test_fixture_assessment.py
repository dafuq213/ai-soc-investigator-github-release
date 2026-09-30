import tempfile
import unittest
from pathlib import Path

from src.fixture_assessment import assess_fixture


class FixtureAssessmentTests(unittest.TestCase):
    def test_saves_prompt_and_renders_only_verified_compact_output(self):
        fixture = {
            "case_id": "FIXTURE-ASSESS", "scenario": "benign_process", "marker": "SOC_PROCESS_FIXTURE_a_1", "expected_observables": {}, "coverage": {},
            "tool_results": {"seed": {"ok": True, "data": [{"alert_id": "a1", "host": "WS-01", "agent_id": "001", "rule": {}, "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {"image": "powershell.exe", "processGuid": "{p}", "commandLine": "powershell.exe -NoProfile"}}}}}], "meta": {"source": "telemetry", "index": "wazuh-archives-*", "count": 1}, "error": None}, "parent": {"ok": True, "data": [], "meta": {"count": 0}, "error": None}, "children": {"ok": True, "data": [], "meta": {"count": 0}, "error": None}, "network": {"ok": True, "data": [], "meta": {"count": 0}, "error": None}},
        }
        output = '{"verdict":"inconclusive","confidence":"low","unknown_ids":[],"action_ids":["A01"],"claim_verification_id":"V01","next_check_id":"N01"}'
        with tempfile.TemporaryDirectory() as directory:
            assessment, paths = assess_fixture(fixture, directory, lambda _: output)
            report = Path(paths["report"]).read_text(encoding="utf-8")
            prompt = Path(paths["prompt"]).read_text(encoding="utf-8")
        self.assertEqual(assessment.status, "accepted")
        self.assertIn("preserve_evidence", report)
        self.assertNotIn("full_log", prompt)


if __name__ == "__main__":
    unittest.main()
