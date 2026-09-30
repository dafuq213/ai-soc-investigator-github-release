import unittest

from src.capture_process_fixture import capture_fixture, make_missing_parent_fixture


def record(command_line, event_id="1", process_guid="{seed}", parent_guid="{parent}"):
    return {"alert_id": "r1", "agent_id": "001", "host": "WS-01", "event": {"data": {"win": {"system": {"eventID": event_id}, "eventdata": {"commandLine": command_line, "processGuid": process_guid, "parentProcessGuid": parent_guid}}}}}


class Tools:
    def get_process_fixture_by_marker(self, marker, host, hours):
        return {"ok": True, "tool": "get_host_process_activity", "data": [record("Write-Output 'FIXTURE-1'"), record("stop", event_id="5")], "meta": {"source": "telemetry", "count": 2}, "error": None}
    def get_process_by_guid(self, process_guid, agent_id):
        return {"ok": True, "tool": "get_process_by_guid", "data": [record("parent", process_guid=process_guid, parent_guid="{grandparent}")], "meta": {"count": 1}, "error": None}
    def get_process_children(self, parent_process_guid, agent_id):
        return {"ok": True, "tool": "get_process_children", "data": [], "meta": {"count": 0}, "error": None}
    def get_process_network_activity(self, process_guid, agent_id):
        return {"ok": True, "tool": "get_process_network_activity", "data": [], "meta": {"count": 0}, "error": None}


class CaptureProcessFixtureTests(unittest.TestCase):
    def test_captures_only_event_id_one_and_creates_missing_parent_variant(self):
        fixture = capture_fixture(Tools(), "P1", "benign_process", "FIXTURE-1", "WS-01", timeout_seconds=1, poll_seconds=1)
        self.assertEqual(fixture["expected_observables"]["verdict"], "not_prejudged")
        self.assertEqual(fixture["tool_results"]["seed"]["data"][0]["event"]["data"]["win"]["system"]["eventID"], "1")
        self.assertIn("telemetry coverage is not independently established", fixture["coverage"]["process_network"])
        broken = make_missing_parent_fixture(fixture, "P1-BROKEN")
        fields = broken["tool_results"]["seed"]["data"][0]["event"]["data"]["win"]["eventdata"]
        self.assertNotIn("parentProcessGuid", fields)
        self.assertIn("parent origin unknown", broken["expected_observables"]["required_limitation"])

    def test_selects_discovery_cmd_child_from_the_marked_launcher(self):
        carrier = record("Write-Output 'FIXTURE-1'", process_guid="{launcher}", parent_guid="{outer}")
        child = record("cmd.exe /c whoami /all", process_guid="{cmd}", parent_guid="{launcher}")
        child["event"]["data"]["win"]["eventdata"]["image"] = "C:\\Windows\\System32\\cmd.exe"
        class DiscoveryTools(Tools):
            def get_process_fixture_by_marker(self, marker, host, hours):
                return {"ok": True, "data": [carrier], "meta": {"source": "telemetry", "count": 1}, "error": None}
            def get_process_children(self, parent_process_guid, agent_id):
                return {"ok": True, "data": [child] if parent_process_guid == "{launcher}" else [], "meta": {"count": 1 if parent_process_guid == "{launcher}" else 0}, "error": None}
        fixture = capture_fixture(DiscoveryTools(), "P2", "process_discovery", "FIXTURE-1", "WS-01", timeout_seconds=1, poll_seconds=1)
        self.assertEqual(fixture["tool_results"]["seed"]["data"][0]["event"]["data"]["win"]["eventdata"]["processGuid"], "{cmd}")


if __name__ == "__main__":
    unittest.main()
