import json
import tempfile
import unittest
from pathlib import Path

from src.unseen_alert_selector import investigated_alert_ids, select_unseen_alert
from src.alert_scope import AlertScope


class _Tools:
    def get_alerts(self, severity, limit):
        rows = {
            3: [
                {"wazuh_alert_id": "known", "timestamp": "t1", "host": "WS-01", "rule": {"level": 3, "id": "1", "description": "Known"}},
                {"wazuh_alert_id": "unseen", "timestamp": "t2", "host": "WS-02", "rule": {"level": 3, "id": "2", "description": "Unseen"}},
            ]
        }.get(severity, [])
        return {"ok": True, "data": rows}


class UnseenAlertSelectorTests(unittest.TestCase):
    def test_reads_ids_from_generic_artifacts_and_ignores_bad_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "investigations"
            nested.mkdir()
            (nested / "generic.json").write_text(json.dumps({"evidence_packet": {"alert": {"alert_id": "a-1"}}}), encoding="utf-8")
            (root / "legacy.json").write_text(json.dumps({"case": {"seed_alert_id": "a-2", "evidence": [{"record": {"event": {"id": "a-3"}}}]}}), encoding="utf-8")
            (root / "bad.json").write_text("{", encoding="utf-8")
            self.assertEqual(investigated_alert_ids(root), {"a-1", "a-2", "a-3"})

    def test_selects_only_unseen_alert(self):
        result = select_unseen_alert(_Tools(), {"known"}, minimum_severity=3, maximum_severity=3, seed=7)
        self.assertTrue(result["ok"])
        self.assertEqual(result["alert_id"], "unseen")
        self.assertEqual(result["title"], "Unseen")

    def test_reports_when_every_candidate_has_already_been_investigated(self):
        result = select_unseen_alert(_Tools(), {"known", "unseen"}, minimum_severity=3, maximum_severity=3)
        self.assertFalse(result["ok"])
        self.assertIn("no unseen alert", result["message"])

    def test_scope_excludes_vulnerability_group_without_changing_selection_logic(self):
        class Tools:
            def get_alerts(self, severity, limit):
                if severity != 3:
                    return {"ok": True, "data": []}
                return {"ok": True, "data": [{"wazuh_alert_id": "vuln", "rule": {"level": 3, "id": "1", "description": "CVE-2026-0001", "groups": ["vulnerability-detector"]}}, {"wazuh_alert_id": "process", "rule": {"level": 3, "id": "2", "description": "Process alert", "groups": ["windows"]}}]}
        scope = AlertScope(frozenset({"vulnerability-detector"}), (), frozenset())
        result = select_unseen_alert(Tools(), set(), minimum_severity=3, maximum_severity=3, seed=1, scope=scope)
        self.assertEqual(result["alert_id"], "process")
        self.assertEqual(result["excluded_by_scope"], 1)
