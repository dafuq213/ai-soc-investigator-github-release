import unittest

from src.entity_collection import plan_entity_collection


def normalized(**entities):
    values = {"host": "WS-01", "agent_id": "001", "user": None, "process_guid": None, "parent_process_guid": None, "target_process_guid": None, "registry_key": None, "file_path": None, "file_hashes": [], "source_ip": None, "destination_ip": None, "domain": None}
    values.update(entities)
    return {"timestamp_utc": "2026-09-04T10:00:00Z", "source": {"channel": "Microsoft-Windows-Sysmon/Operational", "groups": ["windows", "sysmon"]}, "entities": values}


class EntityCollectionPlanTests(unittest.TestCase):
    def test_process_keys_select_exact_lineage_only(self):
        plan = plan_entity_collection(normalized(process_guid="{actor}", parent_process_guid="{parent}"))
        self.assertEqual([item["kind"] for item in plan["actions"]], ["process_lineage", "parent_process_origin"])
        self.assertTrue(all(item["arguments"]["agent_id"] == "001" for item in plan["actions"]))
        self.assertTrue(all(item["arguments"]["start_time"] == "2026-09-04T09:30:00Z" for item in plan["actions"]))

    def test_offsetless_utc_timestamp_does_not_shift_with_host_timezone(self):
        alert = normalized(process_guid="{actor}")
        alert["timestamp_utc"] = "2026-09-04 10:00:00.123"
        plan = plan_entity_collection(alert)
        self.assertEqual(plan["actions"][0]["arguments"]["start_time"], "2026-09-04T09:30:00.123000Z")
        self.assertEqual(plan["actions"][0]["arguments"]["end_time"], "2026-09-04T10:30:00.123000Z")

    def test_registry_network_and_domain_use_exact_observed_values(self):
        plan = plan_entity_collection(normalized(registry_key="HKCU\\Software\\Example", destination_ip="203.0.113.9", domain="example.test"))
        kinds = [item["kind"] for item in plan["actions"]]
        self.assertEqual(kinds, ["exact_registry_key", "same_host_ip", "same_host_domain"])
        self.assertEqual(plan["actions"][0]["arguments"]["registry_key"], "HKCU\\Software\\Example")

    def test_user_only_process_alert_does_not_query_authentication(self):
        plan = plan_entity_collection(normalized(user="ACME\\alice", process_guid="{actor}"))
        self.assertEqual([item["kind"] for item in plan["actions"]], ["process_lineage"])

    def test_hash_is_a_fallback_when_process_topology_is_unavailable(self):
        with_topology = plan_entity_collection(normalized(process_guid="{actor}", file_hashes=["a" * 64]))
        without_topology = plan_entity_collection(normalized(file_hashes=["b" * 64]))
        self.assertNotIn("exact_hash", [item["kind"] for item in with_topology["actions"]])
        self.assertEqual([item["kind"] for item in without_topology["actions"]], ["exact_hash"])

    def test_security_alert_can_select_bounded_authentication_context(self):
        alert = normalized(user="ACME\\alice", source_ip="203.0.113.10")
        alert["source"] = {"channel": "Security", "groups": ["windows"]}
        plan = plan_entity_collection(alert)
        self.assertEqual([item["kind"] for item in plan["actions"]], ["same_host_ip", "authentication_context"])
        self.assertEqual(plan["actions"][1]["arguments"]["user"], "ACME\\alice")

    def test_missing_scope_or_time_fails_closed_without_actions(self):
        alert = normalized(process_guid="{actor}")
        alert["entities"]["host"] = None
        alert["entities"]["agent_id"] = None
        plan = plan_entity_collection(alert)
        self.assertEqual(plan["actions"], [])
        self.assertIn("Host or agent identity", plan["limitations"][0])


if __name__ == "__main__":
    unittest.main()
