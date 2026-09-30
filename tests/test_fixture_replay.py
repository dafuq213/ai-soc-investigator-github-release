import base64
import tempfile
import unittest
from pathlib import Path

from src.capture_process_fixture import make_missing_parent_fixture
from src.fixture_replay import replay_fixture
from src.verified_reporting import write_verified_report


def _record(alert_id, guid, parent_guid, command_line, image="powershell.exe"):
    fields = {"processGuid": guid, "image": image, "commandLine": command_line}
    if parent_guid:
        fields["parentProcessGuid"] = parent_guid
    return {"alert_id": alert_id, "timestamp": "2026-08-19T10:30:00Z", "host": "WS-01", "agent_id": "001", "rule": {}, "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": fields}}}}


def _result(tool, records):
    return {"ok": True, "tool": tool, "data": records, "meta": {"source": "telemetry", "index": "wazuh-archives-*", "count": len(records), "total": len(records), "truncated": False}, "error": None}


class FixtureReplayTests(unittest.TestCase):
    def fixture(self):
        encoded = base64.b64encode("Write-Output 'FIXTURE-1'".encode("utf-16le")).decode()
        seed = _record("seed", "{child}", "{parent}", f"powershell.exe -EncodedCommand {encoded}")
        parent = _record("parent", "{parent}", "{grandparent}", "pwsh.exe -File runner.ps1", image="pwsh.exe")
        return {"case_id": "FIXTURE-REPLAY", "scenario": "encoded_loopback", "marker": "SOC_PROCESS_FIXTURE_test_1", "expected_observables": {}, "coverage": {}, "tool_results": {"seed": _result("fixture_seed_selection", [seed]), "parent": _result("get_process_by_guid", [parent]), "children": _result("get_process_children", []), "network": _result("get_process_network_activity", [])}}

    def test_replay_creates_evidence_only_report_with_parent_and_network_limit(self):
        case, assessment = replay_fixture(self.fixture())
        self.assertEqual(assessment.status, "evidence_only")
        self.assertEqual(len(case.evidence), 3)  # seed, parent, decoded command
        with tempfile.TemporaryDirectory() as directory:
            text = Path(write_verified_report(case, assessment, Path(directory) / "report.md")).read_text(encoding="utf-8")
        self.assertIn("Parent process: image=pwsh.exe", text)
        self.assertIn("No process-linked network telemetry was returned", text)
        self.assertIn("Decoded command evidence", text)

    def test_missing_parent_replay_reports_the_limit_without_inference(self):
        broken = make_missing_parent_fixture(self.fixture(), "FIXTURE-MISSING-PARENT")
        case, assessment = replay_fixture(broken)
        with tempfile.TemporaryDirectory() as directory:
            text = Path(write_verified_report(case, assessment, Path(directory) / "report.md")).read_text(encoding="utf-8")
        self.assertIn("The seed process has no ParentProcessGuid", text)
        self.assertNotIn("Direct parent process observed", text)


if __name__ == "__main__":
    unittest.main()
