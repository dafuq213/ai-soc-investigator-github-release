import json
import tempfile
import unittest
from pathlib import Path

from src.generic_fixture_corpus import build_generic_fixture_artifact


class GenericFixtureCorpusTests(unittest.TestCase):
    def test_converts_captured_tool_shape_without_model(self):
        fixture = {
            "case_id": "FIXTURE-1", "scenario": "controlled", "marker": "marker",
            "tool_results": {
                "seed": {"ok": True, "data": [{"wazuh_alert_id": "a", "timestamp": "2026-09-05T10:00:00Z", "agent": {"id": "001", "name": "WS"}, "rule": {"description": "Alert", "level": 7}, "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {"Image": "C:\\cmd.exe", "ProcessGuid": "{p}"}}}}}]},
                "children": {"ok": True, "data": [{"alert_id": "b", "timestamp": "2026-09-05T10:00:01Z", "agent": {"id": "001", "name": "WS"}, "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {"Image": "C:\\child.exe"}}}}}]},
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "fixture.json"
            source.write_text(json.dumps(fixture), encoding="utf-8")
            result = build_generic_fixture_artifact(source, root / "out")
            artifact = json.loads(Path(result["artifact"]).read_text(encoding="utf-8"))
        self.assertEqual(result["evidence_count"], 2)
        self.assertFalse(artifact["model_execution"]["invoked"])
        self.assertEqual(artifact["evidence_packet"]["evidence"][0]["id"], "E01")


if __name__ == "__main__":
    unittest.main()
