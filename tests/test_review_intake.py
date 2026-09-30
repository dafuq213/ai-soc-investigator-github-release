import json
import tempfile
import unittest
from pathlib import Path

from src.review_intake import append_review_record, build_review_worksheet


class ReviewIntakeTests(unittest.TestCase):
    def _artifact(self, root: Path) -> Path:
        path = root / "data" / "investigations" / "case-a.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({
            "evidence_packet": {
                "alert": {"alert_id": "a-1", "title": "Example", "timestamp_utc": "2026-01-01T00:00:00Z", "severity": 5, "source": {"provider": "Sysmon", "event_id": "1"}},
                "evidence": [{"id": "E01", "summary": "Process create", "fields": {"host": "HOST", "process_name": "cmd.exe", "command_line": "do-not-render"}}],
            },
            "assessment": {"assessment_status": "accepted", "verdict": "inconclusive", "confidence": 42},
            "model_execution": {"provider": "test", "model": "model", "invoked": True},
        }), encoding="utf-8")
        return path

    def test_worksheet_contains_compact_observed_evidence_and_blank_review_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            worksheet = build_review_worksheet(self._artifact(Path(directory)))
        self.assertIn("**E01** Process create", worksheet)
        self.assertIn("process: `cmd.exe`", worksheet)
        self.assertNotIn("do-not-render", worksheet)
        self.assertIn("## Analyst review record", worksheet)
        self.assertNotIn("## Analyst review inputs", worksheet)
        self.assertIn('"evidence_citations_verified": null', worksheet)

    def test_explicit_review_record_can_be_appended_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = self._artifact(root)
            manifest = root / "benchmarks" / "reviews.json"
            manifest.parent.mkdir()
            manifest.write_text('{"cases": []}', encoding="utf-8")
            record = append_review_record(manifest, artifact, alert_family="process", final_disposition="insufficient_evidence", analyst_conclusion="No parent process is present.", model_assessment_agreement="agree", evidence_citations_verified=True, unsupported_claims=0, unsafe_response=False)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            with self.assertRaises(ValueError):
                append_review_record(manifest, artifact, alert_family="process", final_disposition="insufficient_evidence", analyst_conclusion="No parent process is present.", model_assessment_agreement="agree", evidence_citations_verified=True, unsupported_claims=0, unsafe_response=False)
        self.assertEqual(record["case_id"], "case-a")
        self.assertEqual(len(payload["cases"]), 1)
        self.assertTrue(payload["cases"][0]["evidence_citations_verified"])

    def test_rejects_non_generic_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                build_review_worksheet(path)
