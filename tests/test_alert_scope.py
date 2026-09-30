import json
import tempfile
import unittest
from pathlib import Path

from src.alert_scope import AlertScope


class AlertScopeTests(unittest.TestCase):
    def test_scope_matches_rule_group_and_title_without_event_id_logic(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.json"
            path.write_text(json.dumps({"schema_version": "alert_scope_v1", "excluded_rule_groups": ["vulnerability-detector", "sca"], "excluded_title_patterns": ["\\bCIS Benchmark\\b"], "excluded_rule_ids": []}), encoding="utf-8")
            scope = AlertScope.from_path(path)
        self.assertTrue(scope.exclusion_reasons({"title": "CVE-2026-0001", "source": {"groups": ["vulnerability-detector"]}}))
        self.assertTrue(scope.exclusion_reasons({"title": "CIS Benchmark report", "source": {"groups": ["windows"]}}))
        self.assertEqual(scope.exclusion_reasons({"title": "New Windows Service Created", "source": {"groups": ["windows"]}}), [])
