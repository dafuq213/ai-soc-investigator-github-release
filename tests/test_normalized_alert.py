import unittest

from src.normalized_alert import normalize_alert, unexpected_normalized_values


class NormalizedAlertTests(unittest.TestCase):
    def test_normalizes_process_alert_with_wazuh_aliases(self):
        normalized = normalize_alert({
            "alert_id": "document-1", "wazuh_alert_id": "event-1", "timestamp": "2026-09-04T10:00:00Z", "host": "WS-01", "agent_id": "001",
            "rule": {"id": "92041", "level": "10", "description": "Process alert", "groups": ["windows", "sysmon"]},
            "event": {"data": {"win": {"system": {"eventID": "1", "channel": "Microsoft-Windows-Sysmon/Operational"}, "eventdata": {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ProcessGuid": "{process}", "ProcessId": "123",
                "ParentImage": "C:\\Windows\\explorer.exe", "ParentProcessGuid": "{parent}", "CommandLine": "powershell -NoProfile", "User": "ACME\\alice",
                "DestinationIp": "203.0.113.8", "DestinationPort": "443", "Hashes": "SHA256=abc123",
            }}}},
        })
        entities = normalized["entities"]
        self.assertEqual(normalized["alert_id"], "event-1")
        self.assertEqual(normalized["severity"], 10)
        self.assertEqual(entities["host"], "WS-01")
        self.assertEqual(entities["process_guid"], "{process}")
        self.assertEqual(entities["parent_process_guid"], "{parent}")
        self.assertEqual(entities["destination_ip"], "203.0.113.8")
        self.assertEqual(entities["file_hashes"], ["abc123"])

    def test_prefers_observed_event_time_over_index_ingestion_time(self):
        normalized = normalize_alert({
            "timestamp": "2026-09-04T10:00:03Z",
            "event": {"data": {"win": {"system": {"systemTime": "2026-09-04T10:00:01Z"}, "eventdata": {"UtcTime": "2026-09-04 10:00:00.123"}}}},
        })
        self.assertEqual(normalized["timestamp_utc"], "2026-09-04 10:00:00.123")

    def test_normalizes_registry_and_authentication_fields(self):
        normalized = normalize_alert({
            "id": "event-2", "agent": {"name": "WS-02", "id": "002"}, "rule": {"description": "Registry change", "level": 8},
            "event": {"data": {"win": {"system": {"eventID": 13}, "eventdata": {
                "SourceImage": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "TargetObject": "HKCU\\Software\\Example\\Run\\Updater",
                "Details": "C:\\Program Files\\Google\\Chrome\\updater.exe", "TargetUserName": "ACME\\bob",
            }}}},
        })
        self.assertEqual(normalized["entities"]["process_name"], "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")
        self.assertEqual(normalized["entities"]["registry_key"], "HKCU\\Software\\Example\\Run\\Updater")
        self.assertEqual(normalized["entities"]["registry_value"], "C:\\Program Files\\Google\\Chrome\\updater.exe")
        self.assertEqual(normalized["entities"]["user"], "ACME\\bob")

    def test_sparse_alert_retains_null_entities_without_guessing(self):
        normalized = normalize_alert({"alert_id": "document-3", "host": "WS-03", "rule": {"description": "Multiple Sysmon error events", "level": 10}, "event": {}})
        self.assertEqual(normalized["entities"]["host"], "WS-03")
        self.assertIsNone(normalized["entities"]["process_guid"])
        self.assertIsNone(normalized["entities"]["registry_key"])
        self.assertEqual(normalized["entities"]["file_hashes"], [])

    def test_normalized_values_are_traceable_to_source_values(self):
        alert = {
            "alert_id": "document-4", "host": "WS-04", "rule": {"description": "Process alert", "level": "7"},
            "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {"Image": "C:\\Windows\\System32\\cmd.exe", "Hashes": "SHA256=abc"}}}},
        }
        self.assertEqual(unexpected_normalized_values(alert, normalize_alert(alert)), [])

    def test_normalizes_observed_service_and_vulnerability_entities_without_event_id_logic(self):
        service = normalize_alert({"alert_id": "service", "host": "WS-05", "event": {"data": {"win": {"eventdata": {"ServiceName": "Example Service", "ImagePath": "C:\\Tools\\example.exe -service", "AccountName": "LocalSystem", "StartType": "demand start"}}}}})
        vulnerability = normalize_alert({"alert_id": "vulnerability", "host": "WS-05", "event": {"data": {"vulnerability": {"cve": "CVE-2026-0001", "severity": "High", "package": {"name": "Example", "version": "1.0"}, "score": {"base": "7.5"}}}}})
        self.assertEqual(service["entities"]["service_name"], "Example Service")
        self.assertEqual(service["entities"]["service_image_path"], "C:\\Tools\\example.exe -service")
        self.assertEqual(vulnerability["entities"]["vulnerability_cve"], "CVE-2026-0001")
        self.assertEqual(vulnerability["entities"]["vulnerability_package"], "Example")


if __name__ == "__main__":
    unittest.main()
