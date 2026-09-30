import json
import tempfile
import unittest
from pathlib import Path

from src.generic_evaluation import evaluate_generic_artifact, evaluate_many
from src.generic_reporting import write_generic_report
from src.replay_generic_assessment import replay_generic_artifact


PACKET = {
    "schema_version": "evidence_packet_v1",
    "alert": {"alert_id": "a-1", "title": "Generic alert", "timestamp_utc": "2026-09-05T10:00:00Z", "severity": 7, "source": {}},
    "evidence": [{"id": "E01", "relationship": "seed_alert", "source": {"alert_id": "a-1"}, "summary": "Observed process execution.", "fields": {"process_name": "cmd.exe"}}],
    "collection": {"limitations": []},
}


def response(hypotheses=None):
    return json.dumps({
        "verdict": "inconclusive", "confidence": 40,
        "what_happened": [{"evidence_ids": ["E01"], "text": "The cited record shows a process execution on the monitored endpoint."}],
        "alert_claim_assessment": {"status": "not_assessable", "evidence_ids": ["E01"], "text": "The cited record shows activity but does not establish the detection claim."},
        "hypotheses": hypotheses or [], "unknowns": ["No additional related records were included in the bounded packet."],
        "recommended_actions": [{"category": "preserve_evidence", "action": "Preserve the cited process record before the retention period expires.", "reason": "The cited alert is the primary record available for subsequent analyst review.", "evidence_ids": ["E01"], "target": None, "priority": "medium"}], "analyst_question": "Can the observed process be associated with an approved activity?",
    })


class GenericEvaluationTests(unittest.TestCase):
    def _artifact(self, directory, raw, assessment, report_assessment=None):
        root = Path(directory)
        audit = root / "response.json"
        audit.write_text(json.dumps({"response": raw}), encoding="utf-8")
        case = root / "CASE.json"
        artifact = {"evidence_packet": PACKET, "assessment": assessment, "model_execution": {"invoked": True}, "prompt_audit": {"response_path": str(audit)}}
        case.write_text(json.dumps(artifact), encoding="utf-8")
        write_generic_report(PACKET, report_assessment if report_assessment is not None else assessment, {"provider": "test", "model": "test", "invoked": True}, case.with_suffix(".md"))
        return case

    def test_accepts_current_cited_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = response()
            assessment = json.loads(raw) | {"assessment_status": "accepted", "quality_flags": []}
            result = evaluate_generic_artifact(self._artifact(directory, raw, assessment))
        self.assertTrue(result["passed"])
        self.assertEqual(result["outcome"], "accepted")

    def test_fails_stale_report_when_current_replay_adds_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = response([{"type": "possible_legitimate_context", "evidence_ids": ["E01"], "text": "The observed sequence is consistent with expected maintenance activity."}])
            # Simulates a historical report rendered before the present flag policy.
            stale = json.loads(response()) | {"assessment_status": "accepted", "quality_flags": []}
            result = evaluate_generic_artifact(self._artifact(directory, raw, stale, stale))
        self.assertFalse(result["passed"])
        self.assertIn("report does not render every current assessment caution", result["issues"])

    def test_safe_rejection_is_distinct_from_an_accepted_assessment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = root / "response.json"
            audit.write_text(json.dumps({"response": "{bad"}), encoding="utf-8")
            case = root / "CASE.json"
            artifact = {"evidence_packet": PACKET, "assessment": None, "model_execution": {"invoked": True}, "prompt_audit": {"response_path": str(audit)}}
            case.write_text(json.dumps(artifact), encoding="utf-8")
            write_generic_report(PACKET, None, {"provider": "test", "model": "test", "invoked": True}, case.with_suffix(".md"), "invalid JSON")
            result = evaluate_many([case])
        self.assertTrue(result["quality_gate_passed"])
        self.assertEqual(result["results"][0]["outcome"], "safe_rejection")

    def test_offline_replay_updates_only_from_saved_response(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = response([{"type": "possible_legitimate_context", "evidence_ids": ["E01"], "text": "The observed sequence is consistent with expected maintenance activity."}])
            stale = json.loads(response()) | {"assessment_status": "accepted", "quality_flags": []}
            case = self._artifact(directory, raw, stale, stale)
            preview = replay_generic_artifact(case)
            self.assertFalse(preview["written"])
            result = replay_generic_artifact(case, write=True)
            self.assertEqual(result["assessment_status"], "accepted_with_flags")
            self.assertTrue(evaluate_generic_artifact(case)["passed"])

    def test_offline_replay_migrates_only_saved_source_mitre_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = response()
            assessment = json.loads(raw) | {"assessment_status": "accepted", "quality_flags": []}
            case = self._artifact(directory, raw, assessment)
            artifact = json.loads(case.read_text(encoding="utf-8"))
            artifact["normalized_alert"] = {"source": {"mitre": {"id": ["T1059.003"], "technique": ["Windows Command Shell"], "tactic": ["Execution"]}}}
            case.write_text(json.dumps(artifact), encoding="utf-8")
            replay_generic_artifact(case, write=True)
            updated = json.loads(case.read_text(encoding="utf-8"))
            self.assertEqual(updated["evidence_packet"]["alert"]["source"]["mitre"]["id"], ["T1059.003"])
            report = case.with_suffix(".md").read_text(encoding="utf-8")
            self.assertIn("Source-provided MITRE ATT&CK context", report)

    def test_offline_replay_safely_withholds_response_rejected_by_current_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = response()
            parsed = json.loads(raw)
            parsed["what_happened"] = [{"evidence_ids": ["E01"], "text": "The file was deleted by the observed process."}]
            case = self._artifact(directory, json.dumps(parsed), parsed | {"assessment_status": "accepted", "quality_flags": []})
            preview = replay_generic_artifact(case)
            self.assertEqual(preview["assessment_status"], "rejected")
            result = replay_generic_artifact(case, write=True)
            self.assertIn("command-line intent", result["validation_error"])
            self.assertTrue(evaluate_generic_artifact(case)["passed"])
            self.assertEqual(evaluate_generic_artifact(case)["outcome"], "safe_rejection")


if __name__ == "__main__":
    unittest.main()
