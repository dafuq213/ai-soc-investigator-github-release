import unittest
import base64

from src.evidence_packet import MAX_COMMAND_LINE_CHARS, build_evidence_packet


def _normalized():
    return {
        "alert_id": "seed-1", "timestamp_utc": "2026-09-04T10:00:00Z", "title": "Observed activity", "rule_id": "100", "severity": 8,
        "source": {
            "channel": "Sysmon", "event_id": "1", "provider": "Sysmon", "groups": ["windows"],
            "mitre": {"id": ["T1059.003"], "technique": ["Windows Command Shell"], "tactic": ["Execution"]},
        },
        "entities": {"host": "WS-01", "process_name": "C:\\Windows\\System32\\cmd.exe", "process_guid": "{seed}", "parent_process_guid": "{parent}", "command_line": "x" * (MAX_COMMAND_LINE_CHARS + 10)},
        "raw_reference": {"document_id": "seed-document"},
    }


def _record(alert_id="related-1", record_id="42", target="HKCU\\Software\\Example"):
    return {"alert_id": alert_id, "agent_id": "001", "timestamp": "2026-09-04T10:01:00Z", "event": {"data": {"win": {"system": {"eventID": "13", "eventRecordID": record_id}, "eventdata": {"Image": "C:\\Program Files\\App\\app.exe", "TargetObject": target, "Details": "value", "CallTrace": "must never appear"}}}}}


class EvidencePacketTests(unittest.TestCase):
    def test_packet_is_compact_readable_and_source_traceable(self):
        execution = {"related_record_cap": 12, "limitations": ["None"], "executed_actions": [{"action_id": "C01", "kind": "exact_registry_key", "reason": "observed key", "executions": [{"arguments": {"entity_type": "registry_key"}, "result": {"data": [_record()]}}]}]}
        packet = build_evidence_packet(_normalized(), execution)
        self.assertEqual(packet["alert"]["source"]["mitre"]["id"], ["T1059.003"])
        self.assertEqual(packet["schema_version"], "evidence_packet_v1")
        self.assertEqual([item["id"] for item in packet["evidence"]], ["E01", "E02"])
        self.assertEqual(packet["evidence"][1]["relationship"], "same_registry_key")
        self.assertEqual(packet["evidence"][1]["fields"]["process_name"], "C:\\Program Files\\App\\app.exe")
        self.assertNotIn("CallTrace", str(packet))
        self.assertNotIn("process_guid", packet["observed_entities"])
        self.assertTrue(packet["evidence"][0]["fields"]["command_line"].endswith("…[truncated]"))

    def test_related_event_prefers_producer_time_over_ingestion_time(self):
        record = _record()
        record["event"]["data"]["win"]["eventdata"]["UtcTime"] = "2026-09-04 10:00:59.123"
        packet = build_evidence_packet(_normalized(), {"executed_actions": [{"action_id": "C01", "kind": "exact_registry_key", "executions": [{"arguments": {}, "result": {"data": [record]}}]}]})
        self.assertEqual(packet["evidence"][1]["timestamp_utc"], "2026-09-04 10:00:59.123")

    def test_coalesces_identical_related_observations_and_keeps_sources(self):
        execution = {"executed_actions": [{"action_id": "C01", "kind": "exact_registry_key", "executions": [{"arguments": {}, "result": {"data": [_record("one", "1"), _record("two", "2")]}}]}]}
        packet = build_evidence_packet(_normalized(), execution)
        self.assertEqual(len(packet["evidence"]), 2)
        related = packet["evidence"][1]
        self.assertEqual(related["occurrence_count"], 2)
        self.assertEqual([source["alert_id"] for source in related["sources"]], ["one", "two"])

    def test_excludes_seed_and_deduplicates_related_records(self):
        execution = {"executed_actions": [
            {"action_id": "C01", "kind": "process_lineage", "executions": [{"arguments": {"entity_type": "process_guid"}, "result": {"data": [_record("seed-1", "10"), _record("related-1", "42")]}}]},
            {"action_id": "C02", "kind": "exact_registry_key", "executions": [{"arguments": {"entity_type": "registry_key"}, "result": {"data": [_record("related-2", "42")]}}]},
        ]}
        packet = build_evidence_packet(_normalized(), execution)
        self.assertEqual(len(packet["evidence"]), 2)
        self.assertEqual(packet["evidence"][1]["source"]["alert_id"], "related-1")

    def test_excludes_seed_when_wazuh_id_and_document_id_differ(self):
        seed = _normalized()
        seed["raw_reference"]["document_id"] = "seed-document"
        execution = {"executed_actions": [{"action_id": "C01", "kind": "process_lineage", "executions": [{"arguments": {}, "result": {"data": [_record("seed-document", "10")]}}]}]}
        self.assertEqual(len(build_evidence_packet(seed, execution)["evidence"]), 1)

    def test_collapses_exact_archive_copy_of_seed_and_preserves_both_sources(self):
        seed = _normalized()
        seed["entities"].update({
            "agent_id": "001",
            "process_path": "C:\\Windows\\System32\\cmd.exe",
            "command_line": "cmd.exe /c whoami",
        })
        archive_copy = {
            "alert_id": "archive-document-99",
            "agent_id": "001",
            "timestamp": "2026-09-04T10:00:00.000000Z",
            "event": {"data": {"win": {
                "system": {"eventID": "1", "eventRecordID": "900", "providerName": "Sysmon", "channel": "Sysmon"},
                "eventdata": {"UtcTime": "2026-09-04 10:00:00.000", "ProcessGuid": "{seed}", "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c whoami"},
            }}},
        }
        execution = {"executed_actions": [{"action_id": "C01", "kind": "process_lineage", "executions": [{"arguments": {}, "result": {"data": [archive_copy]}}]}]}
        packet = build_evidence_packet(seed, execution)
        self.assertEqual(len(packet["evidence"]), 1)
        self.assertEqual([item["document_id"] for item in packet["evidence"][0]["sources"]], ["seed-document", "archive-document-99"])

    def test_does_not_collapse_same_process_guid_at_different_exact_time(self):
        seed = _normalized()
        seed["entities"].update({"agent_id": "001", "process_path": "C:\\Windows\\System32\\cmd.exe", "command_line": "cmd.exe /c whoami"})
        later = {
            "alert_id": "later", "agent_id": "001", "timestamp": "2026-09-04T10:00:01Z",
            "event": {"data": {"win": {"system": {"eventID": "1", "eventRecordID": "901", "providerName": "Sysmon", "channel": "Sysmon"}, "eventdata": {"UtcTime": "2026-09-04 10:00:01.000", "ProcessGuid": "{seed}", "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c whoami"}}}},
        }
        execution = {"executed_actions": [{"action_id": "C01", "kind": "process_lineage", "executions": [{"arguments": {}, "result": {"data": [later]}}]}]}
        self.assertEqual(len(build_evidence_packet(seed, execution)["evidence"]), 2)

    def test_sparse_packet_is_valid_without_related_events(self):
        packet = build_evidence_packet(_normalized(), {"executed_actions": [], "limitations": ["No usable correlation entity."]})
        self.assertEqual(len(packet["evidence"]), 1)
        self.assertEqual(packet["collection"]["limitations"], ["No usable correlation entity."])

    def test_decodes_utf16le_encoded_powershell_without_executing_it(self):
        payload = "Write-Output 'safe marker'; Test-NetConnection -ComputerName 127.0.0.1 -Port 65534"
        encoded = base64.b64encode(payload.encode("utf-16-le")).decode()
        seed = _normalized()
        seed["entities"]["command_line"] = "powershell.exe -NoProfile -EncodedCommand " + encoded
        packet = build_evidence_packet(seed, {"executed_actions": [], "limitations": []})
        fields = packet["evidence"][0]["fields"]
        self.assertEqual(fields["decoded_command"], payload)
        self.assertIn("-EncodedCommand", fields["command_line"])

    def test_preserves_compact_service_and_vulnerability_seed_fields(self):
        service = _normalized()
        service["entities"] = {"host": "WS-01", "service_name": "Example", "service_image_path": "C:\\Tools\\example.exe", "service_account": "LocalSystem"}
        vulnerability = _normalized()
        vulnerability["entities"] = {"host": "WS-01", "vulnerability_cve": "CVE-2026-0001", "vulnerability_package": "Example", "vulnerability_severity": "High", "vulnerability_cvss": "7.5"}
        self.assertEqual(build_evidence_packet(service, {"executed_actions": []})["evidence"][0]["fields"]["service_name"], "Example")
        self.assertEqual(build_evidence_packet(vulnerability, {"executed_actions": []})["evidence"][0]["fields"]["vulnerability_cve"], "CVE-2026-0001")


if __name__ == "__main__":
    unittest.main()
