import unittest

from src.case_enrichment import CaseEnricher
from src.case_models import CaseBuilder, InvestigationCase


class StubProcessTools:
    def __init__(self):
        self.calls = []

    def get_process_by_guid(self, **kwargs):
        self.calls.append(("get_process_by_guid", kwargs))
        return {"ok": True, "data": [{"alert_id": "parent", "timestamp": "2026-08-10T10:00:00Z", "host": "WS-001", "rule": {}, "event": {}}]}

    def get_process_children(self, **kwargs):
        self.calls.append(("get_process_children", kwargs))
        return {"ok": True, "data": [{"alert_id": "child", "timestamp": "2026-08-10T10:00:02Z", "host": "WS-001", "rule": {}, "event": {}}]}

    def get_process_network_activity(self, **kwargs):
        self.calls.append(("get_process_network_activity", kwargs))
        return {"ok": True, "data": []}

    def get_process_siblings(self, **kwargs):
        self.calls.append(("get_process_siblings", kwargs))
        return {"ok": True, "data": [{"alert_id": "sibling", "timestamp": "2026-08-10T10:00:03Z", "host": "WS-001", "rule": {}, "event": {}}]}


class CaseEnrichmentTests(unittest.TestCase):
    def test_enrichment_uses_only_observed_process_guids_and_records_tool_history(self):
        case = CaseBuilder.from_seed_result("CASE-ENRICH", {"ok": True, "data": [{
            "alert_id": "seed", "timestamp": "2026-08-10T10:00:01Z", "host": "WS-001", "agent_id": "001", "rule": {},
            "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {"processGuid": "{ps}", "parentProcessGuid": "{parent}"}}}},
        }]})
        tools = StubProcessTools()
        CaseEnricher(tools).enrich_process_context(case, hours=6, limit=10)
        self.assertEqual([name for name, _ in tools.calls], ["get_process_by_guid", "get_process_children", "get_process_network_activity", "get_process_siblings"])
        self.assertEqual(len(case.tool_history), 4)
        self.assertEqual(case.tool_history[0]["source"], None)
        self.assertEqual([item.evidence_id for item in case.evidence], ["E001", "E002", "E003", "E004"])
        self.assertEqual(case.contextual_evidence_ids, {"E004"})

    def test_authentication_enrichment_uses_only_case_user_and_ip(self):
        class AuthTools:
            def get_authentication_activity(self, **arguments):
                self.arguments = arguments
                return {"ok": True, "data": []}
        case = InvestigationCase("CASE-AUTH", "seed")
        case.add_alert_evidence({"alert_id": "a1", "host": "DC-01", "rule": {"groups": ["authentication"]}, "event": {"data": {"win": {"eventdata": {"targetUserName": "jsmith", "ipAddress": "203.0.113.10"}}}}})
        tools = AuthTools()
        CaseEnricher(tools).enrich_authentication_context(case, hours=6)
        self.assertEqual(tools.arguments["user"], "jsmith")
        self.assertEqual(tools.arguments["source_ip"], "203.0.113.10")
        self.assertEqual(tools.arguments["agent_id"], None)
        self.assertEqual([item.evidence_id for item in case.evidence], ["E001"])

    def test_generic_enrichment_uses_only_observed_hash_ip_domain_and_host(self):
        class EntityTools:
            def __init__(self):
                self.calls = []
            def __getattr__(self, name):
                def call(**arguments):
                    self.calls.append((name, arguments))
                    return {"ok": True, "data": [], "meta": {}}
                return call
        case = CaseBuilder.from_seed_result("CASE-ENTITY", {"ok": True, "data": [{
            "alert_id": "a3", "host": "WS-01", "rule": {}, "event": {"data": {"win": {"eventdata": {
                "hashes": "SHA256=" + "A" * 64, "destinationIp": "203.0.113.10", "destinationHostname": "example.org"
            }}}}
        }]})
        tools = EntityTools()
        CaseEnricher(tools).enrich_entity_context(case, hours=6, limit=10)
        self.assertEqual([name for name, _ in tools.calls], [
            "get_host_process_activity", "get_network_activity", "get_dns_activity", "get_host_file_activity",
            "get_hash_activity", "get_ip_activity", "get_domain_activity",
        ])
        self.assertEqual(tools.calls[4][1]["hash_value"], "A" * 64)
        self.assertEqual(tools.calls[5][1]["ip"], "203.0.113.10")
        self.assertEqual(tools.calls[6][1]["domain"], "example.org")


if __name__ == "__main__":
    unittest.main()
