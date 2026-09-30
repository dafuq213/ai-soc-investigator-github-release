import unittest

from src.correlation_validation import record_matches_authentication, record_matches_entity, validate_collection_execution


def record(**fields):
    return {"alert_id": "a-1", "event": {"data": {"win": {"eventdata": fields}}}}


class CorrelationValidationTests(unittest.TestCase):
    def test_matches_exact_eventdata_aliases_without_event_id_logic(self):
        self.assertTrue(record_matches_entity(record(SourceProcessGUID="{source}"), "process_guid", "{source}"))
        self.assertTrue(record_matches_entity(record(TargetObject="HKCU\\Software\\Example"), "registry_key", "HKCU\\Software\\Example"))
        self.assertFalse(record_matches_entity(record(TargetObject="HKCU\\Software\\Other"), "registry_key", "HKCU\\Software\\Example"))

    def test_reports_an_invalid_returned_record(self):
        execution = {"executed_actions": [{"action_id": "C01", "executions": [{"tool": "get_entity_activity", "arguments": {"entity_type": "process_guid", "value": "{actor}"}, "result": {"data": [record(ProcessGuid="{actor}"), record(ProcessGuid="{other}")]}}]}]}
        check = validate_collection_execution(execution)[0]
        self.assertFalse(check["passed"])
        self.assertEqual(check["matched"], 1)
        self.assertEqual(check["invalid_record_ids"], ["a-1"])

    def test_authentication_validation_requires_all_query_keys(self):
        event = record(TargetUserName="ACME\\alice", IpAddress="203.0.113.10")
        self.assertTrue(record_matches_authentication(event, "ACME\\alice", "203.0.113.10"))
        self.assertFalse(record_matches_authentication(event, "ACME\\alice", "203.0.113.11"))
