import unittest

from src.wazuh_tools import WazuhConfig, WazuhToolLayer


class WazuhToolLayerTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        def transport(method, url, headers, payload):
            self.calls.append((method, url, headers, payload))
            return 200, {"hits": {"total": {"value": 1}, "hits": [{"_id": "abc-1", "_source": {"@timestamp": "2026-08-06T10:00:00Z", "agent": {"name": "ws-01", "id": "001"}, "rule": {"id": "1001", "level": 12, "description": "Suspicious process"}}}]}}
        config = WazuhConfig("https://indexer:9200", "reader", "password")
        self.tools = WazuhToolLayer(config, transport)

    def test_alerts_return_normalised_envelope(self):
        result = self.tools.get_alerts(12)
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"][0]["alert_id"], "abc-1")
        self.assertEqual(result["data"][0]["host"], "ws-01")
        self.assertEqual(self.calls[0][3]["query"], {"term": {"rule.level": 12}})

    def test_alert_lookup_accepts_wazuh_event_id_or_index_document_id(self):
        result = self.tools.get_alert_by_id("1787328423.404790")
        self.assertTrue(result["ok"])
        should = self.calls[-1][3]["query"]["bool"]["should"]
        self.assertIn({"ids": {"values": ["1787328423.404790"]}}, should)
        self.assertIn({"term": {"id.keyword": "1787328423.404790"}}, should)
        self.assertIn({"match_phrase": {"id": "1787328423.404790"}}, should)

    def test_rejects_unbounded_or_invalid_arguments(self):
        self.assertEqual(self.tools.get_alerts("12")["error"]["code"], "validation_error")
        self.assertEqual(self.tools.search_logs({"filters": [{"field": "_script", "operator": "equals", "value": "x"}]})["error"]["code"], "validation_error")

    def test_search_builds_only_allowlisted_dsl(self):
        result = self.tools.search_logs({"filters": [{"field": "agent.name", "operator": "equals", "value": "ws-01"}], "hours": 4})
        self.assertTrue(result["ok"])
        body = self.calls[0][3]
        self.assertEqual(body["query"]["bool"]["filter"][0], {"term": {"agent.name": "ws-01"}})
        self.assertNotIn("_script", str(body))

    def test_search_allows_observed_registry_target(self):
        result = self.tools.search_logs({"filters": [{"field": "data.win.eventdata.targetObject", "operator": "contains", "value": "CurrentVersion\\Run"}], "hours": 4})
        self.assertTrue(result["ok"])
        body = self.calls[0][3]
        self.assertEqual(body["query"]["bool"]["filter"][0], {"match_phrase": {"data.win.eventdata.targetObject": "CurrentVersion\\Run"}})

    def test_process_guid_tools_build_bounded_internal_queries(self):
        result = self.tools.get_process_children("{parent-guid}", hours=6, limit=10)
        self.assertTrue(result["ok"])
        filters = self.calls[0][3]["query"]["bool"]["filter"]
        self.assertIn({"term": {"data.win.eventdata.parentProcessGuid": "{parent-guid}"}}, filters)
        self.assertIn({"bool": {"should": [{"term": {"data.win.system.eventID": "1"}}], "minimum_should_match": 1}}, filters)
        self.assertIn({"range": {"@timestamp": {"gte": "now-6h", "lte": "now"}}}, filters)
        self.assertEqual(self.tools.get_process_by_guid("", hours=6)["error"]["code"], "validation_error")

    def test_process_context_uses_configured_telemetry_index(self):
        config = WazuhConfig("https://indexer:9200", "reader", "password", telemetry_index="wazuh-archives-*")
        tools = WazuhToolLayer(config, self.tools._transport)
        result = tools.get_process_by_guid("{parent-guid}", hours=6)
        self.assertTrue(result["ok"])
        self.assertEqual(result["meta"]["source"], "telemetry")
        self.assertIn("/wazuh-archives-*/_search", self.calls[-1][1])

    def test_profile_tool_uses_exact_guid_role_event_ids_and_seed_window(self):
        result = self.tools.get_sysmon_profile_events("{guid}", "001", "2026-08-19T10:00:00Z", "2026-08-19T10:05:00Z", ["10"], "access")
        self.assertTrue(result["ok"])
        filters = self.calls[-1][3]["query"]["bool"]["filter"]
        self.assertIn({"term": {"agent.id": "001"}}, filters)
        self.assertIn({"term": {"data.win.system.providerName": "Microsoft-Windows-Sysmon"}}, filters)
        self.assertIn({"range": {"@timestamp": {"gte": "2026-08-19T10:00:00Z", "lte": "2026-08-19T10:05:00Z"}}}, filters)
        self.assertIn("sourceProcessGuid", str(filters))
        self.assertEqual(self.tools.get_sysmon_profile_events("{guid}", "001", "bad", "bad", ["10"], "access")["error"]["code"], "validation_error")

    def test_profile_coverage_is_bounded_to_agent_event_family_and_window(self):
        result = self.tools.get_sysmon_profile_coverage("001", "2026-08-19T10:00:00Z", "2026-08-19T10:05:00Z", ["10", "22"])
        self.assertTrue(result["ok"])
        filters = self.calls[-1][3]["query"]["bool"]["filter"]
        self.assertIn({"term": {"agent.id": "001"}}, filters)
        self.assertIn({"term": {"data.win.system.providerName": "Microsoft-Windows-Sysmon"}}, filters)
        self.assertIn("eventID", str(filters))
        self.assertEqual(self.tools.get_sysmon_profile_coverage("001", "bad", "bad", ["10"])["error"]["code"], "validation_error")

    def test_sysmon_alert_coverage_uses_alert_index_and_requires_provider(self):
        result = self.tools.get_sysmon_alert_coverage("001", "2026-08-19T10:00:00Z", "2026-08-19T10:05:00Z", ["10"])
        self.assertTrue(result["ok"])
        self.assertIn("/wazuh-alerts-*/_search", self.calls[-1][1])
        filters = self.calls[-1][3]["query"]["bool"]["filter"]
        self.assertIn({"term": {"data.win.system.providerName": "Microsoft-Windows-Sysmon"}}, filters)

    def test_fixture_marker_lookup_is_exact_and_not_a_general_log_search(self):
        marker = "SOC_PROCESS_FIXTURE_benign_process_20260819142443"
        result = self.tools.get_process_fixture_by_marker(marker, "ws-01")
        self.assertTrue(result["ok"])
        filters = self.calls[0][3]["query"]["bool"]["filter"]
        self.assertIn({"term": {"data.win.system.eventID": "1"}}, filters)
        self.assertIn({"wildcard": {"data.win.eventdata.commandLine": f"*{marker}*"}}, filters)
        self.assertEqual(self.tools.get_process_fixture_by_marker("arbitrary", "ws-01")["error"]["code"], "validation_error")
        self.assertTrue(self.tools.get_process_fixture_by_marker("SOC_SYSMON_FIXTURE_20260819_0003", "ws-01")["ok"])

    def test_sysmon_fixture_lookup_requires_marker_and_child_pid(self):
        result = self.tools.get_sysmon_fixture_process("SOC_SYSMON_FIXTURE_20260819_0003", "ws-01", "13576")
        self.assertTrue(result["ok"])
        filters = self.calls[-1][3]["query"]["bool"]["filter"]
        self.assertIn({"term": {"data.win.eventdata.processId": "13576"}}, filters)
        self.assertEqual(self.tools.get_sysmon_fixture_process("SOC_SYSMON_FIXTURE_20260819_0003", "ws-01", "not-a-pid")["error"]["code"], "validation_error")

    def test_telemetry_status_requires_explicit_index_configuration(self):
        self.assertEqual(self.tools.get_telemetry_status()["error"]["code"], "configuration_error")

    def test_entity_tools_use_bounded_allowlisted_queries(self):
        self.assertTrue(self.tools.get_hash_activity("A" * 64, hours=6)["ok"])
        self.assertIn("wildcard", str(self.calls[-1][3]))
        self.assertTrue(self.tools.get_ip_activity("203.0.113.10", hours=6)["ok"])
        self.assertTrue(self.tools.get_domain_activity("example.org", hours=6)["ok"])
        self.assertEqual(self.tools.get_ip_activity("not-an-ip")["error"]["code"], "validation_error")
        self.assertEqual(self.tools.get_domain_activity("not a domain")["error"]["code"], "validation_error")

    def test_entity_activity_is_exact_scoped_and_time_bounded(self):
        result = self.tools.get_entity_activity("registry_key", "HKCU\\Software\\Example", "2026-09-04T09:30:00Z", "2026-09-04T10:30:00Z", agent_id="001", limit=5)
        self.assertTrue(result["ok"])
        filters = self.calls[-1][3]["query"]["bool"]["filter"]
        self.assertIn({"term": {"agent.id": "001"}}, filters)
        self.assertIn({"range": {"@timestamp": {"gte": "2026-09-04T09:30:00Z", "lte": "2026-09-04T10:30:00Z"}}}, filters)
        self.assertIn("data.win.eventdata.targetObject", str(filters))
        self.assertEqual(self.tools.get_entity_activity("unknown", "x", "2026-09-04T09:30:00Z", "2026-09-04T10:30:00Z", agent_id="001")["error"]["code"], "validation_error")
        self.assertEqual(self.tools.get_entity_activity("ip", "203.0.113.10", "2026-09-04T09:30:00Z", "2026-09-04T10:30:00Z")["error"]["code"], "validation_error")

    def test_agent_all_status_omits_invalid_api_filter(self):
        calls = []
        def transport(method, url, headers, payload):
            calls.append((method, url, headers, payload))
            if url.endswith("/security/user/authenticate"):
                return 200, {"data": {"token": "token"}}
            return 200, {"data": {"affected_items": [], "total_affected_items": 0}}
        config = WazuhConfig("https://indexer:9200", "reader", "password", api_url="https://manager:55000", api_username="api", api_password="password")
        result = WazuhToolLayer(config, transport).get_agents("all")
        self.assertTrue(result["ok"])
        self.assertIn("limit=100", calls[-1][1])
        self.assertNotIn("status=all", calls[-1][1])

    def test_authentication_activity_uses_observed_identity_or_ip_filters(self):
        result = self.tools.get_authentication_activity(user="jsmith", source_ip="203.0.113.10", hours=6)
        self.assertTrue(result["ok"])
        filters = self.calls[0][3]["query"]["bool"]["filter"]
        self.assertIn({"range": {"@timestamp": {"gte": "now-6h", "lte": "now"}}}, filters)
        self.assertIn({"term": {"data.win.system.channel": "Security"}}, filters)
        self.assertIn("4625", str(filters))
        self.assertEqual(self.tools.get_authentication_activity()["error"]["code"], "validation_error")


if __name__ == "__main__":
    unittest.main()
