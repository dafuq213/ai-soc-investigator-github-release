import unittest

from src.entity_collection_executor import execute_entity_collection


class _Tools:
    def __init__(self): self.calls = []
    def get_entity_activity(self, **kwargs):
        self.calls.append(("entity", kwargs)); return {"ok": True, "data": [{"alert_id": str(len(self.calls))}], "meta": {}, "error": None}
    def get_authentication_activity(self, **kwargs):
        self.calls.append(("auth", kwargs)); return {"ok": True, "data": [], "meta": {}, "error": None}


class EntityCollectionExecutorTests(unittest.TestCase):
    def test_process_lineage_uses_only_exact_guid_and_bounded_scope(self):
        tools = _Tools()
        plan = {"actions": [{"id": "C01", "kind": "process_lineage", "reason": "test", "arguments": {"agent_id": "001", "start_time": "2026-09-04T09:30:00Z", "end_time": "2026-09-04T10:30:00Z", "process_guid": "{actor}"}}], "limitations": []}
        output = execute_entity_collection(tools, plan)
        self.assertEqual([call[1]["entity_type"] for call in tools.calls], ["process_guid", "parent_process_guid"])
        self.assertTrue(all(call[1]["value"] == "{actor}" for call in tools.calls))
        self.assertEqual(output["executed_actions"][0]["action_id"], "C01")

    def test_authentication_context_preserves_observed_user_and_ip(self):
        tools = _Tools()
        plan = {"actions": [{"id": "C01", "kind": "authentication_context", "reason": "test", "arguments": {"agent_id": "001", "start_time": "2026-09-04T09:30:00Z", "end_time": "2026-09-04T10:30:00Z", "user": "ACME\\alice", "source_ip": "203.0.113.10"}}], "limitations": []}
        execute_entity_collection(tools, plan)
        self.assertEqual(tools.calls[0][0], "auth")
        self.assertEqual(tools.calls[0][1]["user"], "ACME\\alice")
        self.assertEqual(tools.calls[0][1]["source_ip"], "203.0.113.10")

    def test_deduplicates_records_across_overlapping_actions(self):
        class DuplicateTools(_Tools):
            def get_entity_activity(self, **kwargs):
                self.calls.append(("entity", kwargs)); return {"ok": True, "data": [{"alert_id": "same", "agent_id": "001", "event": {"data": {"win": {"system": {"eventRecordID": "42"}}}}}], "meta": {}, "error": None}
        tools = DuplicateTools()
        plan = {"actions": [
            {"id": "C01", "kind": "parent_process_origin", "reason": "a", "arguments": {"agent_id": "001", "start_time": "2026-09-04T09:30:00Z", "end_time": "2026-09-04T10:30:00Z", "process_guid": "{a}"}},
            {"id": "C02", "kind": "target_process_origin", "reason": "b", "arguments": {"agent_id": "001", "start_time": "2026-09-04T09:30:00Z", "end_time": "2026-09-04T10:30:00Z", "process_guid": "{b}"}},
        ], "limitations": []}
        output = execute_entity_collection(tools, plan)
        counts = [len(item["result"]["data"]) for action in output["executed_actions"] for item in action["executions"]]
        self.assertEqual(counts, [1, 0])

    def test_prefers_exact_sysmon_process_creation_when_available(self):
        class SysmonTools(_Tools):
            def get_sysmon_profile_events(self, **kwargs):
                self.calls.append(("sysmon", kwargs))
                record = {"alert_id": "creation", "agent_id": "001", "event": {"data": {"win": {"system": {"eventRecordID": "77", "eventID": "1"}}}}}
                return {"ok": True, "data": [record], "meta": {}, "error": None}
        tools = SysmonTools()
        plan = {"actions": [{"id": "C01", "kind": "parent_process_origin", "reason": "test", "arguments": {"agent_id": "001", "start_time": "2026-09-04T09:30:00Z", "end_time": "2026-09-04T10:30:00Z", "process_guid": "{parent}"}}], "limitations": []}
        output = execute_entity_collection(tools, plan)
        self.assertEqual([call[0] for call in tools.calls], ["sysmon"])
        self.assertEqual(tools.calls[0][1]["event_ids"], ["1"])
        self.assertEqual(output["executed_actions"][0]["executions"][0]["tool"], "get_sysmon_profile_events")
