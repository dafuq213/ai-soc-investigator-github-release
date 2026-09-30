import unittest

from src.archive_retention import ArchiveRetention
from src.wazuh_tools import WazuhConfig


class ArchiveRetentionTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        def http(method, url, headers):
            self.calls.append((method, url, headers))
            if method == "GET":
                return 200, [
                    {"index": "wazuh-archives-4.x-2026.08.13", "store.size": "700"},
                    {"index": "wazuh-archives-4.x-2026.08.14", "store.size": "900"},
                    {"index": "wazuh-alerts-4.x-2026.08.14", "store.size": "999999"},
                ]
            return 200, {"acknowledged": True}
        self.retention = ArchiveRetention(WazuhConfig("https://indexer:9200", "reader", "password"), http)

    def test_plan_only_selects_oldest_archive_indices(self):
        plan = self.retention.plan(cap_bytes=1000)
        self.assertEqual(plan["current_bytes"], 1600)
        self.assertEqual(plan["projected_bytes"], 900)
        self.assertEqual(plan["delete"], [{"index": "wazuh-archives-4.x-2026.08.13", "bytes": 700}])

    def test_apply_refuses_an_index_outside_archive_scope(self):
        with self.assertRaises(ValueError):
            self.retention.apply({"delete": [{"index": "wazuh-alerts-4.x-2026.08.14", "bytes": 1}]})

    def test_apply_deletes_only_planned_archive_index(self):
        plan = self.retention.plan(cap_bytes=1000)
        self.assertEqual(self.retention.apply(plan), ["wazuh-archives-4.x-2026.08.13"])
        self.assertEqual(self.calls[-1][0], "DELETE")
        self.assertIn("wazuh-archives-4.x-2026.08.13", self.calls[-1][1])
