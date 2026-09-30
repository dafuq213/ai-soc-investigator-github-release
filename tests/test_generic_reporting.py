import tempfile
import unittest
from pathlib import Path

from src.generic_reporting import write_generic_report


class GenericReportingTests(unittest.TestCase):
    def test_renders_cited_assessment_without_raw_guid(self):
        packet = {"alert": {"alert_id": "a", "title": "Alert", "timestamp_utc": "t", "rule_id": "92000", "severity": 7, "source": {"mitre": {"id": ["T1059.003"], "technique": ["Windows Command Shell"], "tactic": ["Execution"]}}}, "observed_entities": {"host": "WS-01"}, "evidence": [{"id": "E01", "relationship": "seed_alert", "summary": r"Event 1; process C:\\Windows\\System32\\cmd.exe", "fields": {"process_name": r"C:\\Windows\\System32\\cmd.exe", "parent_process_name": r"C:\\Windows\\System32\\powershell.exe", "command_line": "cmd.exe /c whoami", "source_ip": "::1"}}]}
        assessment = {"assessment_status": "accepted_with_flags", "verdict": "inconclusive", "confidence": 40, "what_happened": [{"text": "The cited record shows an observed process on the endpoint.", "evidence_ids": ["E01"]}], "alert_claim_assessment": {"status": "not_assessable", "text": "The cited record does not establish the alert claim.", "evidence_ids": ["E01"]}, "hypotheses": [], "quality_flags": [{"message": "Unverified operational context.", "evidence_ids": ["E01"]}], "unknowns": [], "recommended_actions": [{"category": "investigate", "action": "Review subsequent process activity around the alert time.", "reason": "The cited process requires additional scoping before disposition.", "evidence_ids": ["E01"], "target": None, "priority": "high"}], "analyst_question": ""}
        with tempfile.TemporaryDirectory() as directory:
            path = write_generic_report(packet, assessment, {"provider": "ollama", "model": "x", "invoked": True}, Path(directory) / "report.md")
            text = path.read_text(encoding="utf-8")
        self.assertIn("[E01]", text)
        self.assertIn("Assessment model", text)
        self.assertIn("Case ID: `report`", text)
        self.assertIn("Hostname: `WS-01`", text)
        self.assertIn("Wazuh rule ID: `92000`", text)
        self.assertIn("Executive summary", text)
        self.assertIn("INCONCLUSIVE", text)
        self.assertIn("Activity tree", text)
        self.assertIn("Evidence timeline", text)
        self.assertIn("Confidence rationale", text)
        self.assertIn("Possible legitimate context", text)
        self.assertIn("Concern factors", text)
        self.assertIn("Key gaps and cautions", text)
        self.assertIn("accepted_with_flags", text)
        self.assertIn("Evidence limitations", text)
        self.assertIn("Recommended analyst actions", text)
        self.assertIn("### Investigation", text)
        self.assertIn("- [ ] **High:**", text)
        self.assertIn("Recommendation only; no action was executed", text)
        self.assertIn("cmd.exe /c whoami", text)
        self.assertIn("Source-provided MITRE ATT&CK context", text)
        self.assertIn("`T1059.003`", text)
        self.assertIn(r"C:\Windows\System32\cmd.exe", text)
        self.assertNotIn(r"C:\\Windows", text)
        self.assertNotIn("ProcessGuid", text)
        tree = text.split("## Activity tree", 1)[1].split("```", 2)[1]
        self.assertNotIn("whoami", tree)

    def test_renders_retained_wazuh_transport_escaping_as_readable_text(self):
        packet = {"alert": {"title": "Alert"}, "evidence": [{"id": "E01", "relationship": "seed_alert", "summary": "Observed.", "fields": {"command_line": '\\"cmd.exe\\" /c whoami &amp; hostname', "process_name": r"C:\\Windows\\System32\\cmd.exe"}}]}
        with tempfile.TemporaryDirectory() as directory:
            path = write_generic_report(packet, None, {}, Path(directory) / "report.md")
            text = path.read_text(encoding="utf-8")
        self.assertIn('`"cmd.exe" /c whoami & hostname`', text)
        self.assertIn(r"`C:\Windows\System32\cmd.exe`", text)

    def test_omits_process_chain_and_mitre_when_not_supported_by_packet(self):
        packet = {"alert": {"title": "Authentication alert", "source": {}}, "evidence": [{"id": "E01", "relationship": "seed_alert", "summary": "Observed authentication event.", "fields": {"user": "DOMAIN\\user"}}]}
        with tempfile.TemporaryDirectory() as directory:
            path = write_generic_report(packet, None, {}, Path(directory) / "report.md")
            text = path.read_text(encoding="utf-8")
        self.assertNotIn("Activity tree", text)
        self.assertNotIn("MITRE ATT&CK context", text)


if __name__ == "__main__":
    unittest.main()
