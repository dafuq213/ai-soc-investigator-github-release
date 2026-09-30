import tempfile
import unittest
from pathlib import Path

from src.assessment import AssessmentPipeline
from src.case_models import CaseBuilder
from src.evidence_transforms import decode_powershell_commands
from src.verified_reporting import write_verified_report


class VerifiedReportingTests(unittest.TestCase):
    def test_rejected_assessment_never_renders_model_claim_or_response(self):
        case = CaseBuilder.from_seed_result("CASE-REPORT", {"ok": True, "data": [{"alert_id": "a1", "rule": {}, "event": {}}]})
        assessment = AssessmentPipeline().evaluate(case, {"verdict": "inconclusive", "llm_confidence": 0.5, "claims": [{"claim_type": "process_parent", "evidence_ids": ["E001"], "subject": "x", "object": "y"}], "benign_alternatives": [], "unknowns": [], "recommended_actions": []})
        with tempfile.TemporaryDirectory() as directory:
            text = Path(write_verified_report(case, assessment, Path(directory) / "report.md")).read_text(encoding="utf-8")
        self.assertIn("No model assessment was accepted", text)
        self.assertNotIn("process_parent - evidence", text)

    def test_report_explains_decoded_evidence_and_asks_analyst_question(self):
        case = CaseBuilder.from_seed_result("CASE-DECODE-REPORT", {"ok": True, "data": [{
            "alert_id": "a2", "rule": {}, "event": {"data": {"win": {"eventdata": {
                "image": "powershell.exe", "commandLine": "powershell.exe -EncodedCommand UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAGMAbQBkAC4AZQB4AGUAIAAtAEEAcgBnAHUAbQBlAG4AdABMAGkAcwB0ACAAJwAvAGMAIAB3AGgAbwBhAG0AaQAnAA=="
            }}}}
        }]})
        decode_powershell_commands(case)
        assessment = AssessmentPipeline().evaluate(case, {})
        with tempfile.TemporaryDirectory() as directory:
            text = Path(write_verified_report(case, assessment, Path(directory) / "report.md")).read_text(encoding="utf-8")
        self.assertIn("Runs whoami, which prints the current Windows identity.", text)
        self.assertIn("## Analyst decision and next steps", text)

    def test_report_discloses_alerts_only_context_limit(self):
        case = CaseBuilder.from_seed_result("CASE-COVERAGE", {"ok": True, "data": [{"alert_id": "a3", "rule": {}, "event": {}}]})
        case.add_tool_result("get_process_by_guid", {"process_guid": "{p}"}, {"ok": True, "data": [], "meta": {"source": "alerts_fallback", "index": "wazuh-alerts-*", "count": 0}})
        assessment = AssessmentPipeline().evaluate(case, {})
        with tempfile.TemporaryDirectory() as directory:
            text = Path(write_verified_report(case, assessment, Path(directory) / "report.md")).read_text(encoding="utf-8")
        self.assertIn("ordinary non-alert endpoint activity may be unavailable", text)
        self.assertNotIn("## Collection coverage", text)

    def test_report_makes_embedded_null_normalization_explicit(self):
        encoded = "VwByAGkAdABlAC0AAABPAHUAdABwAHUAdAAgACcAeAAnAA=="  # Write-\x00Output 'x'
        case = CaseBuilder.from_seed_result("CASE-NULLS", {"ok": True, "data": [{
            "alert_id": "a4", "rule": {}, "event": {"data": {"win": {"eventdata": {"image": "powershell.exe", "commandLine": f"powershell.exe -EncodedCommand {encoded}"}}}}
        }]})
        decode_powershell_commands(case)
        assessment = AssessmentPipeline.evidence_only()
        with tempfile.TemporaryDirectory() as directory:
            text = Path(write_verified_report(case, assessment, Path(directory) / "report.md")).read_text(encoding="utf-8")
        self.assertIn("embedded NUL character", text)

    def test_report_has_bounded_template_and_uses_process_names_not_guids(self):
        seed = {
            "alert_id": "a5", "timestamp": "2026-08-21T01:02:03Z", "host": "WS-01", "agent_id": "001",
            "rule": {"id": "100520", "level": 7, "description": "PowerShell accessed Notepad"},
            "event": {"data": {"win": {"system": {"eventID": "10"}, "eventdata": {
                "sourceProcessGuid": "{power-guid}", "targetProcessGuid": "{note-guid}", "sourceImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "targetImage": "C:\\Windows\\System32\\notepad.exe", "grantedAccess": "0x1000",
            }}}},
        }
        source = {"alert_id": "a6", "host": "WS-01", "agent_id": "001", "rule": {}, "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {"processGuid": "{power-guid}", "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}}}}}
        target = {"alert_id": "a7", "host": "WS-01", "agent_id": "001", "rule": {}, "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {"processGuid": "{note-guid}", "image": "C:\\Windows\\System32\\notepad.exe"}}}}}
        case = CaseBuilder.from_seed_result("CASE-TEMPLATE", {"ok": True, "data": [seed]})
        case.add_alert_evidence(source)
        case.add_alert_evidence(target)
        from src.correlation import attach_deterministic_correlations
        attach_deterministic_correlations(case)
        case.correlations["telemetry_profiles"] = [{"profile_id": "windows_sysmon_process_access", "status": "selected"}]
        assessment = AssessmentPipeline.evidence_only()
        with tempfile.TemporaryDirectory() as directory:
            text = Path(write_verified_report(case, assessment, Path(directory) / "report.md")).read_text(encoding="utf-8")
        for heading in ("## Case snapshot", "## Detection context", "## Observed evidence", "## Assessment", "## Evidence gaps and alternatives", "## Analyst decision and next steps"):
            self.assertIn(heading, text)
        self.assertIn("source process=powershell.exe", text)
        self.assertIn("target process=notepad.exe", text)
        self.assertIn("Seed event (Sysmon Event ID 10)", text)
        self.assertIn("target image=C:\\Windows\\System32\\notepad.exe", text)
        self.assertNotIn("{power-guid}", text)
        self.assertNotIn("{note-guid}", text)

    def test_seed_card_retains_readable_parent_and_user_for_cited_reasoning(self):
        case = CaseBuilder.from_seed_result("CASE-PROVENANCE", {"ok": True, "data": [{
            "alert_id": "a-provenance", "host": "WS-01", "rule": {},
            "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {
                "image": "C:\\Windows\\System32\\reg.exe", "parentImage": "C:\\Windows\\System32\\svchost.exe",
                "user": "NT AUTHORITY\\SYSTEM", "commandLine": "reg.exe add HKLM\\Software\\Vendor /v value /d 1",
            }}}},
        }]})
        from src.evidence_reduction import build_activity_cards
        card = build_activity_cards(case)[0]
        self.assertEqual(card["observed"]["parent_image"], "C:\\Windows\\System32\\svchost.exe")
        self.assertEqual(card["observed"]["user"], "NT AUTHORITY\\SYSTEM")

    def test_report_includes_model_metadata_without_credentials(self):
        case = CaseBuilder.from_seed_result("CASE-MODEL", {"ok": True, "data": [{"alert_id": "a8", "rule": {}, "event": {}}]})
        case.correlations["model_execution"] = {
            "assessment": {"provider": "ollama", "model": "llama3.2", "invoked": True},
            "qa": {"provider": "anthropic", "model": "claude-haiku", "invoked": False},
        }
        with tempfile.TemporaryDirectory() as directory:
            text = Path(write_verified_report(case, AssessmentPipeline.evidence_only(), Path(directory) / "report.md")).read_text(encoding="utf-8")
        self.assertIn("Assessment model: `ollama/llama3.2` (called)", text)
        self.assertNotIn("QA model:", text)

    def test_event_with_unknown_seed_image_is_not_labeled_as_a_process(self):
        seed = {"alert_id": "a9", "host": "WS-01", "rule": {}, "event": {"data": {"win": {"system": {"eventID": "10"}, "eventdata": {"sourceProcessGuid": "{a}", "targetProcessGuid": "{b}"}}}}}
        case = CaseBuilder.from_seed_result("CASE-SEED-LABEL", {"ok": True, "data": [seed]})
        with tempfile.TemporaryDirectory() as directory:
            text = Path(write_verified_report(case, AssessmentPipeline.evidence_only(), Path(directory) / "report.md")).read_text(encoding="utf-8")
        self.assertIn("Alerting event", text)

    def test_report_renders_verified_model_claim_status_and_next_check(self):
        case = CaseBuilder.from_seed_result("CASE-GUIDANCE", {"ok": True, "data": [{
            "alert_id": "a-guidance", "host": "WS-01", "rule": {"description": "Generic detection"},
            "event": {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {"image": "cmd.exe"}}}},
        }]})
        assessment = AssessmentPipeline().evaluate(case, {
            "verdict": "inconclusive", "confidence": "low", "claim_ids": [], "benign_ids": [], "unknown_ids": [],
            "action_ids": [], "claim_verification_id": "V01", "next_check_id": "N01",
        })
        with tempfile.TemporaryDirectory() as directory:
            text = Path(write_verified_report(case, assessment, Path(directory) / "report.md")).read_text(encoding="utf-8")
        self.assertIn("Alert-claim status: `not_independently_verified`", text)
        self.assertIn("Model-selected claim verification: `not_independently_verified`", text)
        self.assertIn("Priority evidence check: Preserve", text)


if __name__ == "__main__":
    unittest.main()
