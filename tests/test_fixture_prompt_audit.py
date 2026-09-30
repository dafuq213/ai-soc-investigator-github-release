import json
import tempfile
import unittest
from pathlib import Path

from src.fixture_prompt_audit import write_prompt_audit


class FixturePromptAuditTests(unittest.TestCase):
    def test_writes_exact_compact_prompt_without_raw_log(self):
        fixture = {
            "case_id": "PROMPT-AUDIT", "scenario": "benign_process", "marker": "SOC_PROCESS_FIXTURE_a_1", "expected_observables": {}, "coverage": {},
            "tool_results": {"seed": {"ok": True, "data": [{"alert_id": "a1", "host": "WS-01", "agent_id": "001", "rule": {}, "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {"image": "powershell.exe", "processGuid": "{p}", "commandLine": "powershell.exe -NoProfile"}}}}}], "meta": {"source": "telemetry", "index": "wazuh-archives-*", "count": 1}, "error": None}, "parent": {"ok": True, "data": [], "meta": {"count": 0}, "error": None}, "children": {"ok": True, "data": [], "meta": {"count": 0}, "error": None}, "network": {"ok": True, "data": [], "meta": {"count": 0}, "error": None}},
        }
        with tempfile.TemporaryDirectory() as directory:
            outcome = write_prompt_audit(fixture, directory)
            prompt = Path(outcome["prompt"]).read_text(encoding="utf-8")
            dossier = json.loads(Path(outcome["dossier"]).read_text(encoding="utf-8"))
        self.assertFalse(outcome["llm_called"])
        self.assertNotIn("full_log", prompt)
        self.assertEqual(dossier["case_id"], "PROMPT-AUDIT")


if __name__ == "__main__":
    unittest.main()
